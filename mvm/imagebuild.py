"""Confined image builds: `mvm image build -t localhost/NAME:TAG -f Containerfile`.

`podman --runtime krun build` runs every RUN step in a KVM microVM, and its network is
the same confined pasta link as fetch, to a per-run Smokescreen proxy (TCP 443 only)
with the TLS observer. The build context is an empty temp dir holding only the
Containerfile: project sources and secrets are never in it, so COPY/ADD of local files
fail. Base images missing locally come through the confined pull first; the build runs
with --pull=never. The result is built under a temporary tag and gets the requested
localhost/ tag only after a clean run (exit 0, proxy healthy, nothing held, observer
healthy); otherwise the temporary image is deleted.

Refused up front, because podman would do them on the host or outside the proxy:
ADD of a URL or git repository, RUN --network=..., and FROM with build variables.
"""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import core, egress, observer

MAX_CONTAINERFILE = 1 << 20


def instructions(text: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) per logical line: comments dropped, `\\` continuations joined.
    Heredoc bodies are kept as part of their instruction's line."""
    out: list[tuple[str, str]] = []
    cur = ""
    heredoc: str | None = None
    for raw in text.splitlines():
        if heredoc is not None:
            cur += "\n" + raw
            if raw.strip() == heredoc:
                heredoc = None
                out.append(_split(cur))
                cur = ""
            continue
        line = raw.strip()
        if not cur and (not line or line.startswith("#")):
            continue
        if cur and line.startswith("#"):
            continue                              # a comment inside a continuation
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        m = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", cur)
        if m and cur.split(None, 1)[0].upper() in ("RUN", "COPY", "ADD"):
            heredoc = m.group(1)
            continue
        out.append(_split(cur))
        cur = ""
    if cur:
        out.append(_split(cur))
    return out


def _split(line: str) -> tuple[str, str]:
    parts = line.split(None, 1)
    return parts[0].upper(), parts[1] if len(parts) > 1 else ""


def base_images(text: str) -> list[str]:
    """External images named by FROM (not `scratch`, not an earlier stage). Refuses what the
    host or podman would fetch outside the proxy."""
    stages: set[str] = set()
    images: list[str] = []
    for ins, arg in instructions(text):
        if ins == "FROM":
            words = [w for w in arg.split() if not w.startswith("--")]
            if not words:
                raise core.MvmError("FROM without an image")
            ref = words[0]
            if "$" in ref:
                raise core.MvmError(f"FROM {ref}: build variables in FROM are not supported "
                                    "(name the image, so it can be pulled through the egress first)")
            if len(words) >= 3 and words[1].upper() == "AS":
                stages.add(words[2].lower())
            if ref.lower() == "scratch" or ref.lower() in stages:
                continue
            if "/" not in ref or "." not in ref.split("/")[0] and ref.split("/")[0] != "localhost":
                raise core.MvmError(f"FROM {ref}: give the full name, registry included "
                                    f"(e.g. docker.io/library/{ref})")
            if ref not in images:
                images.append(ref)
        elif ins == "ADD":
            for w in arg.split():
                if not w.startswith("--") and (re.match(r"[a-z][a-z0-9+.-]*://", w, re.I) or w.startswith("git@")):
                    raise core.MvmError(f"ADD {w}: podman fetches ADD URLs on the host, outside the egress; "
                                        "download it in a RUN step instead")
        elif ins == "RUN":
            for w in arg.split():                 # RUN's own options come before the command
                if not w.startswith("--"):
                    break
                if w == "--network" or w.startswith("--network="):
                    raise core.MvmError("RUN --network=...: a build step may not choose its own network")
    return images


def build_argv(tag: str, context: Path, memory: str, net_args: list[str], port: int) -> list[str]:
    url = f"http://127.0.0.1:{port}"
    argv = ["podman", "--runtime", "krun", "build", "--pull=never", "--no-cache", "--layers=false",
            "--memory", memory, *net_args, "-f", str(context / "Containerfile"), "-t", tag]
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        argv += ["--build-arg", f"{k}={url}"]
    return argv + [str(context)]


def image_id(ref: str) -> str:
    r = subprocess.run(["podman", "image", "inspect", "--format", "{{.Id}}", ref], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def build(tag: str, containerfile: Path, cfg: dict) -> tuple[int, dict]:
    """-> (exit code, the run's egress summary). COPY --from / RUN --mount from another
    image: --pull=never makes a missing one fail, never fetched."""
    from .runtime import Plan, execute

    if not tag.startswith("localhost/") or ":" not in tag.split("/")[-1] or "@" in tag:
        raise core.MvmError(f"-t {tag}: the tag must be localhost/NAME:TAG")
    if not containerfile.is_file():
        raise core.MvmError(f"no Containerfile at {containerfile}")
    data = containerfile.read_bytes()
    if len(data) > MAX_CONTAINERFILE:
        raise core.MvmError(f"{containerfile} is larger than 1 MiB")
    text = data.decode()
    for ref in base_images(text):
        if not ref.startswith("localhost/"):
            core.pinned(ref)                     # pulls through the egress when missing
        elif subprocess.run(["podman", "image", "exists", ref]).returncode != 0:
            raise core.MvmError(f"FROM {ref}: no such local image (build it first)")
    tmp_tag = f"localhost/mvm-build-tmp:{secrets.token_hex(6)}"
    ctx = Path(tempfile.mkdtemp(prefix="mvm-image-build-"))
    try:
        (ctx / "Containerfile").write_bytes(data)  # the only file in the context
        allow = egress.allowlist(cfg, "image-build")
        plan = Plan(kind="image-build", eco=None, image=tmp_tag, memory=str(cfg.get("memory", {}).get("run", "2g")),
                    cmd=[], src=None, net=True, allow=allow, observe=observer.enabled(cfg),
                    notify=cfg.get("notify", {}).get("ntfy", ""))
        plan.argv_fn = lambda net_args, port: build_argv(tmp_tag, ctx, plan.memory, net_args, port)
        rc = execute(plan)
        if rc == 0 and image_id(tmp_tag):
            subprocess.run(["podman", "tag", tmp_tag, tag], check=True)
            subprocess.run(["podman", "untag", tmp_tag, tmp_tag], check=True)
            core.say(f"image build: tagged {tag} ({image_id(tag)[:12]})")
            return 0, plan.egress_result
        if rc != 0 and plan.egress_result.get("denied") and rc not in (core.EXIT_PROXY_FAILED, core.EXIT_OBSERVER_FAILED):
            if rc != core.EXIT_EGRESS_DENIED:       # the step failed because the proxy refused it
                core.say("image build: HELD, nothing tagged: it tried hosts that are not allowed: "
                         + ", ".join(sorted(plan.egress_result["denied"])))
            rc = core.EXIT_EGRESS_DENIED
        if rc in (0, core.EXIT_EGRESS_DENIED):
            core.say(f"image build: nothing tagged; the temporary image is deleted (exit {rc or 1})")
        return rc or 1, plan.egress_result
    finally:
        subprocess.run(["podman", "rmi", "-f", tmp_tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(ctx, ignore_errors=True)
