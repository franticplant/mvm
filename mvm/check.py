"""Dependency check: osv-scanner (Google, OSV.dev) on lockfiles, in a microVM.

The scanner gets only the lockfiles (a manifest-only tree, like fetch) and reaches
only api.osv.dev, through the same per-run allowlist proxy as fetch. A package with
an OSV `MAL-` advisory (OpenSSF malicious packages) is a trip: fetch refuses to start
(or, after a fetch that changed the lockfile, refuses to commit) and `mvm check`
exits 6. Known vulnerabilities are reported and recorded, never blocking.

Proven with a real krun run: flatmap-stream@0.1.1 -> MAL-2025-20690, lodash@4.17.15 ->
5 GHSA advisories; one connection to api.osv.dev, no other host.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.request
from pathlib import Path

from . import core
from .core import now_iso, read_json, say, write_json_atomic
from .ecos import ECOS, project_cache_name

OSV_IMAGE = "ghcr.io/google/osv-scanner:v2.7.1"
OSV_ALLOW = ["api.osv.dev"]
# Files osv-scanner reads per ecosystem (go.sum is not a lockfile it extracts).
LOCKFILES = {"go": ["go.mod"], "rust": ["Cargo.lock"], "node": ["package-lock.json", "npm-shrinkwrap.json"]}
OUT = ".mvm-osv.json"
NO_PACKAGES = 128     # osv-scanner: "No package sources found" (e.g. a fresh `npm init` lockfile)
TRIP_RESULTS = {"held", "proxy-failed", "observer-failed", "malicious"}


def before_fetch(cfg: dict) -> bool:
    return bool(cfg.get("check", {}).get("before_fetch", True))


def lockfiles(tree: Path, eco: str) -> list[str]:
    """Lockfiles under tree. The tree may have been writable inside a fetch VM, so
    symlinks (files or directories) are never followed and only regular files count."""
    from .project import _regular
    names, out = set(LOCKFILES[eco]), []
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        d = Path(dirpath)
        dirnames[:] = sorted(n for n in dirnames if n not in core.SKIP_DIRS and not (d / n).is_symlink())
        out += [str((d / f).relative_to(tree)) for f in filenames if f in names and _regular(d / f)]
    return sorted(out)


def _read_nofollow(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise core.MvmError(f"{path.name}: larger than {limit} bytes")
    return data


def lockfile_empty(data: bytes, name: str) -> bool:
    """True only when the lockfile provably lists no dependency: osv-scanner's exit 128 is
    accepted as "0 packages" only then, never for a lockfile it merely failed to read."""
    text = data.decode("utf-8", "replace")
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            d = json.loads(text)
        except ValueError:
            return False
        return (isinstance(d, dict) and not d.get("dependencies")
                and set(d.get("packages") or {}) <= {""})
    if name == "Cargo.lock":                     # strict substring checks: any doubt fails closed
        return "package" not in text
    if name == "go.mod":
        return "require" not in text
    return False


def parse(data: dict) -> dict:
    """osv-scanner JSON -> {packages, malicious: [...], vulnerable: [...]}, every package kept."""
    mal, vul, n = [], [], 0
    for res in data.get("results") or []:
        src = (res.get("source") or {}).get("path", "")
        for p in res.get("packages") or []:
            n += 1
            pkg = p.get("package") or {}
            ids = sorted(v.get("id", "") for v in p.get("vulnerabilities") or [] if v.get("id"))
            if not ids:
                continue
            e = {"package": pkg.get("name", "?"), "version": pkg.get("version", "?"),
                 "ecosystem": pkg.get("ecosystem", ""), "source": src.removeprefix("/src/"), "ids": ids}
            (mal if any(i.startswith("MAL-") for i in ids) else vul).append(e)
    return {"packages": n, "malicious": mal, "vulnerable": vul}


def summary_line(s: dict) -> str:
    if s.get("skipped"):
        return f"check: skipped ({s['skipped']})"
    out = f"check: {s['packages']} package(s)"
    if s["malicious"]:
        out += "; MALICIOUS: " + ", ".join(
            f"{m['package']}@{m['version']} ({', '.join(i for i in m['ids'] if i.startswith('MAL-'))})"
            for m in s["malicious"])
    if s["vulnerable"]:
        out += f"; {len(s['vulnerable'])} with known vulnerabilities: " + ", ".join(
            f"{v['package']}@{v['version']}" for v in s["vulnerable"][:5]) + (" ..." if len(s["vulnerable"]) > 5 else "")
    if not s["malicious"] and not s["vulnerable"]:
        out += ", no known vulnerabilities"
    return out


def scan_tree(tree: Path, eco: str, cfg: dict, project: Path) -> dict:
    """Scan the lockfiles under `tree` (a throwaway copy). Raises MvmError when the scan
    itself fails: callers fail closed."""
    from . import observer, runtime           # runtime imports this module
    found = lockfiles(tree, eco)
    if not found:
        return {"skipped": "no lockfile", "packages": 0, "malicious": [], "vulnerable": []}
    with tempfile.TemporaryDirectory(prefix=f"mvm-check-{eco}-") as tmp:
        work = Path(tmp)
        from .project import MAX_MANIFEST
        copied = {}                               # what the scanner got; work/ is VM-writable
        for rel in found:
            (work / rel).parent.mkdir(parents=True, exist_ok=True)
            copied[rel] = _read_nofollow(tree / rel, MAX_MANIFEST)
            (work / rel).write_bytes(copied[rel])
        plan = runtime.Plan(kind="check", eco=eco, image=core.pinned(OSV_IMAGE), memory="1g",
                            cmd=["scan", "source", "--recursive", "--all-packages", "--no-resolve",
                                 "--no-call-analysis=all", "--format", "json",
                                 "--output-file", f"/src/{OUT}", "/src"],
                            src=work, src_rw=True, net=True, allow=list(OSV_ALLOW), project=project,
                            ok_exit=(0, 1, NO_PACKAGES), observe=observer.enabled(cfg), notify=notify_url(cfg))
        rc = runtime.execute(plan)
        if rc == NO_PACKAGES and all(lockfile_empty(b, Path(r).name) for r, b in copied.items()):
            return {"packages": 0, "malicious": [], "vulnerable": [], "lockfiles": found}
        if rc not in (0, 1):
            raise core.MvmError(f"dependency check failed (osv-scanner exit {rc}); "
                                "set [check] before_fetch = false to fetch without it")
        try:
            data = json.loads(_read_nofollow(work / OUT, 256 * 1024 * 1024))
        except (OSError, ValueError) as e:          # incl. JSONDecodeError, a symlink (ELOOP)
            raise core.MvmError(f"dependency check wrote no readable result: {e}") from e
    s = parse(data)
    s["lockfiles"] = found
    return s


def scan_project(root: Path, eco: str, cfg: dict) -> dict:
    from .project import manifest_tree
    with tempfile.TemporaryDirectory(prefix=f"mvm-check-src-{eco}-") as tmp:
        manifest_tree(root, ECOS[eco], Path(tmp))
        return scan_tree(Path(tmp), eco, cfg, root)


def checks_dir() -> Path:
    return core.STATE_ROOT / "checks"


def record(project: Path, eco: str, s: dict) -> None:
    p = checks_dir() / f"{project_cache_name('check', project)}.json"
    rec = read_json(p, {})
    rec.update(project=str(project), checked_at=now_iso())
    rec.setdefault("ecos", {})[eco] = {**s, "checked_at": now_iso()}
    write_json_atomic(p, rec)


def known_projects() -> list[Path]:
    """Projects mvm has fetched or checked, that still exist."""
    seen: dict[str, None] = {}
    for p in sorted((core.STATE_ROOT / "runs").glob("*.json")):
        r = read_json(p, {})
        if r.get("kind") == "fetch" and r.get("cwd"):
            seen[r["cwd"]] = None
    for p in sorted(checks_dir().glob("*.json")):
        proj = read_json(p, {}).get("project")
        if proj:
            seen[proj] = None
    return [Path(x) for x in seen if Path(x).is_dir()]


def notify_url(cfg: dict) -> str:
    return str(cfg.get("notify", {}).get("ntfy", ""))


def notify(url: str, title: str, message: str) -> bool:
    """Best effort ntfy post (stdlib). Never raises: a notification must not change a result."""
    if not url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        return False                          # also enforced by load_config; never file: or others
    req = urllib.request.Request(url, data=message.encode()[:3000], method="POST",  # noqa: S310 (scheme checked above)
                                 headers={"Title": title[:200], "Tags": "warning", "Priority": "high"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:   # noqa: S310 (scheme checked above)
            return 200 <= r.status < 300
    except Exception as e:                    # noqa: BLE001 (HTTPException, ValueError, ...: never fatal)
        say(f"notify failed: {e}")
        return False
