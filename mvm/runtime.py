"""One microVM run: podman argv, run records, commit or discard."""

from __future__ import annotations

import contextlib
import os
import secrets
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import core, egress
from .cache import Locks, cache_img, commit_copy, ensure_cache, make_run_copy
from .core import KEEP_RUNS, now_iso, podman_out, say, write_json_atomic
from .ecos import Cache


@dataclass
class Plan:
    kind: str                 # fetch | build | run
    eco: str | None
    image: str                # pinned ref
    memory: str
    cmd: list[str]
    src: Path | None          # host dir mounted read-only at /src
    net: bool = False
    caches: list[Cache] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    writable: list[str] = field(default_factory=list)   # project-relative dirs
    masks: tuple[list[str], list[str]] = ([], [])
    interactive: bool = False
    project: Path | None = None
    src_rw: bool = False      # only the throwaway fetch tree is writable
    learn: bool = False       # fetch --learn: proxy reports instead of enforcing; never commits
    allow: list[str] = field(default_factory=list)      # egress allowlist for net runs


def new_run_id() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)


def podman_argv(plan: Plan, run_id: str, mounts: dict[str, Path], empty_dir: Path,
                net_args: list[str] | None = None) -> list[str]:
    """Build the podman command. `mounts` maps cache name -> image file to attach.

    A networked plan must come with `net_args` (the confined pasta network); there is
    no unconfined network any more.
    """
    if plan.net and not net_args:
        raise core.MvmError("networked run without egress confinement")
    argv = ["podman", "run", "--rm", "--runtime", "krun", "--memory", plan.memory,
            "--name", f"mvm-{run_id}", "--label", f"mvm.run={run_id}",
            "--label", f"mvm.pid={os.getpid()}"]
    argv += net_args if plan.net else ["--network=none"]
    if plan.interactive:
        argv.append("-it")
    if plan.src is not None:
        argv += ["-v", f"{plan.src}:/src:{'z' if plan.src_rw else 'ro,z'}", "-w", "/src"]
        # Writable dirs first, masks after: later mounts win, so a mask inside a -w dir still hides.
        for w in plan.writable:
            argv += ["-v", f"{plan.src / w}:/src/{w}:z"]
        mdirs, mfiles = plan.masks
        # podman --tmpfs is ignored under krun; an empty read-only dir hides a directory.
        for d in mdirs:
            argv += ["-v", f"{empty_dir}:/src/{d}:ro,z"]
        for f in mfiles:
            argv += ["-v", f"/dev/null:/src/{f}:ro"]
    for k, v in sorted(plan.env.items()):
        argv += ["-e", f"{k}={v}"]
    lines = ["set -eu"]
    umounts = []
    for idx, c in enumerate(plan.caches):
        guest_img = f"/run/mvm-imgs/{idx}-{c.name}.img"
        argv += ["-v", f"{mounts[c.name]}:{guest_img}:{'z' if c.rw else 'ro,z'}"]
        lines.append(f"mkdir -p {shlex.quote(c.guest)} && "
                     f"mount -o {'loop' if c.rw else 'loop,ro'} {shlex.quote(guest_img)} {shlex.quote(c.guest)}")
        umounts.append(c.guest)
    argv.append(plan.image)
    if not umounts:
        return argv + plan.cmd
    # Unmount explicitly so the ext4 image is clean before it is committed.
    lines.append(f"cleanup() {{ sync; umount {' '.join(shlex.quote(p) for p in reversed(umounts))} 2>/dev/null || true; }}")
    lines.append("trap cleanup EXIT")
    lines.append(" ".join(shlex.quote(a) for a in plan.cmd))
    return argv + ["sh", "-c", "\n".join(lines)]


def run_podman(argv: list[str]) -> int:
    return subprocess.run(argv).returncode


def kill_container(run_id: str) -> None:
    subprocess.run(["podman", "kill", f"mvm-{run_id}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def reap_orphans() -> list[str]:
    """Kill mvm containers whose mvm process is gone (e.g. mvm was SIGKILLed)."""
    try:
        out = podman_out(["ps", "--filter", "label=mvm.run",
                          "--format", '{{.Names}} {{index .Labels "mvm.pid"}}'])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    reaped = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        name, pid = parts
        if not Path(f"/proc/{pid}").exists():
            subprocess.run(["podman", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            reaped.append(name)
    return reaped


def record_path(run_id: str) -> Path:
    return core.STATE_ROOT / "runs" / f"{run_id}.json"


def latest_record() -> dict:
    recs = sorted((core.STATE_ROOT / "runs").glob("*.json"))
    return core.read_json(recs[-1], {}) if recs else {}


def prune_records() -> None:
    recs = sorted((core.STATE_ROOT / "runs").glob("*.json"))
    for old in recs[:-KEEP_RUNS]:
        old.unlink(missing_ok=True)


def execute(plan: Plan) -> int:
    run_id = new_run_id()
    reap_orphans()
    project = plan.project
    for c in plan.caches:
        ensure_cache(c, project if c.name.startswith("nm-") else None)
    mode = ("learn" if plan.learn else "enforce") if plan.net else "none"
    rec = {"id": run_id, "kind": plan.kind, "eco": plan.eco, "image": plan.image,
           "cmd": plan.cmd, "cwd": str(project or Path.cwd()), "started_at": now_iso(),
           "egress": {"mode": mode, "allow": plan.allow if plan.net else []},
           "caches": {c.name: ("rw" if c.rw else "ro") for c in plan.caches}}
    write_json_atomic(record_path(run_id), rec)

    copies: dict[str, Path] = {}
    rc = 130
    result = "interrupted"
    label = f"{plan.kind} {plan.eco}" if plan.eco else plan.kind
    try:
        with Locks(plan.caches), tempfile.TemporaryDirectory(prefix="mvm-empty-") as empty:
            mounts = {}
            for c in plan.caches:
                if c.rw and c.name not in copies:
                    copies[c.name] = make_run_copy(c.name, run_id)
                mounts[c.name] = copies.get(c.name, cache_img(c.name))
            with contextlib.ExitStack() as stack:
                net_args = None
                if plan.net:
                    px = stack.enter_context(
                        egress.Proxy(run_id, plan.allow, "report" if plan.learn else "enforce"))
                    plan.env = {**plan.env, **egress.proxy_env(px.port)}
                    net_args = egress.vm_network_args(px.port)
                argv = podman_argv(plan, run_id, mounts, Path(empty), net_args)
                try:
                    rc = run_podman(argv)
                except KeyboardInterrupt:
                    kill_container(run_id)
                    raise
            if plan.net:                      # the proxy has stopped: its log is complete
                rec["egress"].update(px.summary)
                say(f"{label}: {egress.summary_line(px.summary)}")
            if rc == 0 and plan.learn:
                result = "learned"            # learning never changes caches
            elif rc == 0:
                rec["generations"] = {n: commit_copy(n, cp, run_id) for n, cp in copies.items()}
                copies.clear()
                result = "committed" if rec["generations"] else "ok"
            else:
                result = "failed"
    finally:
        for copy in copies.values():          # anything not committed is discarded
            copy.unlink(missing_ok=True)
        rec.update(exit=rc, result=result, finished_at=now_iso())
        write_json_atomic(record_path(run_id), rec)
        prune_records()
        if result == "committed":
            gens = ", ".join(f"{k} gen {v}" for k, v in rec["generations"].items())
            say(f"{label}: committed {gens} (run {run_id})")
        elif copies:
            say(f"{label}: {result}, exit {rc}, cache writes discarded (run {run_id})")
    return rc
