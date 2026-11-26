"""Confined image pulls: registry traffic goes through the same egress as fetch.

skopeo (a static pure-Go build, `make skopeo`, in a FROM scratch image) runs as the
microVM's only process, behind the per-run Smokescreen proxy and the TLS observer, and
copies the image into a `dir:` layout on disk under ~/.cache/mvm/pulls. Only when that
run is clean (exit 0, proxy healthy, nothing held, observer healthy) does the host load
it, offline, with `podman pull dir:...`, which re-checks every blob against the manifest.
`dir:` keeps the registry's manifest bytes as they are (an oci-archive would convert
Docker manifests and change the digest), so the pin is sha256 of those bytes: the
per-platform manifest digest. The pull directory is removed whatever happens.

Bootstrap: the proxy (alpine), firewall, observer (python) and Go build images are
pulled by the make targets with plain podman; everything mvm pulls after that is
confined. localhost/ images are local builds and never pulled.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import core, egress, observer

SKOPEO_IMAGE = "localhost/mvm-skopeo:1"
CA_BUNDLE = Path("/etc/pki/tls/certs/ca-bundle.crt")
# Inside the VM: signatures are not checked (trust is the digest pin, on first use);
# every transport but the registry and the local output is refused.
POLICY = {"default": [{"type": "reject"}],
          "transports": {"docker": {"": [{"type": "insecureAcceptAnything"}]},
                         "dir": {"": [{"type": "insecureAcceptAnything"}]}}}
DIGEST_RE = "sha256:"


def pulls_dir() -> Path:
    return core.CACHE_ROOT / "pulls"


def local_only(ref: str) -> bool:
    return ref.startswith("localhost/")


def ready() -> str:
    """Why a confined pull cannot run, or ''."""
    if subprocess.run(["podman", "image", "exists", SKOPEO_IMAGE]).returncode != 0:
        return f"image pulls need {SKOPEO_IMAGE} (run `make skopeo` in the mvm repo)"
    if not CA_BUNDLE.is_file():
        return f"image pulls need the host CA bundle {CA_BUNDLE}"
    return ""


def copy_argv(ref: str) -> list[str]:
    return ["/skopeo", "--policy", "/etc/mvm/policy.json", "copy", "--quiet", "--retry-times", "2",
            f"docker://{ref}", "dir:/out/img"]


def manifest_digest(img: Path) -> str:
    return "sha256:" + hashlib.sha256((img / "manifest.json").read_bytes()).hexdigest()


def confined_pull(ref: str, cfg: dict | None = None) -> str:
    """Pull `ref` (repo:tag or repo@sha256:...) through the egress; return repo@digest."""
    from .runtime import Plan, execute      # runtime imports core, which calls us

    if local_only(ref):
        raise core.MvmError(f"{ref} is a local image (localhost/): build it, it is never pulled")
    why = ready()
    if why:
        raise core.MvmError(why)
    cfg = core.load_config() if cfg is None else cfg
    repo = core.image_repo(ref)
    want = ref.split("@", 1)[1] if "@" in ref else ""
    if want and not want.startswith(DIGEST_RE):
        raise core.MvmError(f"bad digest in {ref}")
    base = pulls_dir()
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="pull-", dir=base))
    try:
        (work / "tmp").mkdir()
        (work / "img").mkdir()
        (work / "policy.json").write_text(json.dumps(POLICY))
        # Copied fresh per pull: the host file is labelled cert_t, and relabelling a
        # system file (:z) is not an option.
        shutil.copyfile(CA_BUNDLE, work / "ca.crt")
        plan = Plan(kind="pull", eco=None, image=SKOPEO_IMAGE, memory="1g", cmd=copy_argv(ref),
                    src=None, net=True, allow=egress.allowlist(cfg, "pull"), observe=observer.enabled(cfg),
                    env={"TMPDIR": "/out/tmp", "HOME": "/out/tmp", "SSL_CERT_FILE": "/etc/mvm/ca.crt"},
                    volumes=[f"{work / 'ca.crt'}:/etc/mvm/ca.crt:ro,z",
                             f"{work / 'policy.json'}:/etc/mvm/policy.json:ro,z", f"{work}:/out:z"],
                    notify=cfg.get("notify", {}).get("ntfy", ""), quiet=True)
        rc = execute(plan)
        if rc != 0:
            denied = sorted(plan.egress_result.get("denied", {}))
            if denied:                              # skopeo fails when the proxy refuses a host
                rc = core.EXIT_EGRESS_DENIED
                err = core.MvmError(f"pull {ref}: HELD, nothing loaded: it tried hosts that are not "
                                    f"allowed: {', '.join(denied)}")
            else:
                err = core.MvmError(f"pull {ref}: nothing loaded (exit {rc})")
            err.egress = plan.egress_result         # for the [allow] suggestion
            err.rc = rc
            raise err
        img = work / "img"
        digest = manifest_digest(img)
        if want and digest != want:
            raise core.MvmError(f"pull {ref}: got manifest {digest}; give the digest of the image for "
                                "this platform, not of a multi-platform index")
        load = subprocess.run(["podman", "pull", "-q", f"dir:{img}"], capture_output=True, text=True)
        if load.returncode != 0:
            raise core.MvmError(f"pull {ref}: podman refused the downloaded image: {load.stderr.strip()[:300]}")
        image_id = load.stdout.strip().splitlines()[-1]
        # A name with the repository makes repo@digest resolvable locally.
        name = ref if not want else f"{repo}:mvm-{digest[7:19]}"
        subprocess.run(["podman", "tag", image_id, name], check=True)
        pinned_ref = f"{repo}@{digest}"
        got = core.podman_out(["image", "inspect", "--format", "{{.Id}}", pinned_ref])
        if got != image_id:
            raise core.MvmError(f"pull {ref}: {pinned_ref} resolves to {got[:12]}, not the loaded {image_id[:12]}")
        return pinned_ref
    finally:
        shutil.rmtree(work, ignore_errors=True)
