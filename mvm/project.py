"""Project inspection: ecosystem detection, masks, manifest-only fetch trees, safe copy-back."""

from __future__ import annotations

import fnmatch
import os
import shutil
import stat
import tomllib
from pathlib import Path

from .core import MvmError, SKIP_DIRS, die
from .ecos import ECOS, Eco


def walk_project(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        yield Path(dirpath), dirnames, filenames


def detect_ecos(root: Path) -> list[str]:
    return [e.name for e in ECOS.values() if (root / e.detect).is_file()]


def find_masks(root: Path, patterns: list[str]) -> tuple[list[str], list[str]]:
    """Return (dirs, files) relative to root whose basename matches a mask pattern."""
    dirs, files = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        keep = []
        for d in sorted(dirnames):
            if any(fnmatch.fnmatch(d, p) for p in patterns):
                dirs.append(str(rel / d))
            elif d not in SKIP_DIRS:
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            if any(fnmatch.fnmatch(f, p) for p in patterns):
                files.append(str(rel / f))
    return dirs, files


def cargo_target_paths(manifest: Path) -> list[str]:
    """Target source files cargo needs to exist to parse a manifest (cargo-chef's trick)."""
    try:
        data = tomllib.loads(manifest.read_text())
    except (tomllib.TOMLDecodeError, OSError):
        return []
    paths = ["src/main.rs", "src/lib.rs"]
    lib = data.get("lib")
    if isinstance(lib, dict) and "path" in lib:
        paths.append(lib["path"])
    for kind in ("bin", "example", "test", "bench"):
        for t in data.get(kind, []) or []:
            if isinstance(t, dict) and "path" in t:
                paths.append(t["path"])
    pkg = data.get("package")
    if isinstance(pkg, dict) and isinstance(pkg.get("build"), str):
        paths.append(pkg["build"])
    return paths


def manifest_tree(root: Path, eco: Eco, dest: Path) -> int:
    """Copy only dependency manifests of `eco` from root into dest; stub cargo targets empty."""
    n = 0
    for dirpath, _dirs, filenames in walk_project(root):
        rel = dirpath.relative_to(root)
        for f in filenames:
            if f in eco.manifests:
                (dest / rel).mkdir(parents=True, exist_ok=True)
                shutil.copy2(dirpath / f, dest / rel / f)
                n += 1
                if eco.name == "rust" and f == "Cargo.toml":
                    for p in cargo_target_paths(dirpath / f):
                        if (dirpath / p).is_file():
                            stub = dest / rel / p
                            stub.parent.mkdir(parents=True, exist_ok=True)
                            stub.touch()
    return n


MAX_MANIFEST = 64 * 1024 * 1024


def _regular(path: Path) -> bool:
    """True only for a regular file that is not a symlink (lstat, never follows links)."""
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def changed_manifests(root: Path, tree: Path, eco: Eco) -> list[str]:
    """Manifest/lockfile paths in tree that are new or differ from the project.

    The tree was writable inside the fetch VM, so anything in it may be hostile:
    symlinks (to files or via parent dirs) are never followed, only regular files
    are considered, and the project-side target must not be a symlink either.
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        d = Path(dirpath)
        dirnames[:] = sorted(n for n in dirnames if not (d / n).is_symlink() and n != "node_modules")
        for f in sorted(filenames):
            p = d / f
            if f not in eco.manifests or not _regular(p) or p.lstat().st_size > MAX_MANIFEST:
                continue
            rel = p.relative_to(tree)
            dst = root / rel
            if any((root / part).is_symlink() for part in [*reversed(rel.parents)][1:]) or dst.is_symlink():
                continue
            if not _regular(dst) or dst.read_bytes() != p.read_bytes():
                out.append(str(rel))
    return out


def copy_back(tree: Path, root: Path, rel: str) -> None:
    """Copy one vetted manifest without following a symlink swapped in meanwhile."""
    fd = os.open(tree / rel, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fsrc:
        data = fsrc.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise MvmError(f"{rel}: manifest too large")
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    tmp = (root / rel).with_name(f".{Path(rel).name}.mvm-tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, root / rel)
    finally:
        tmp.unlink(missing_ok=True)


def check_writable(root: Path, dirs: list[str]) -> list[str]:
    out = []
    for d in dirs:
        p = (root / d).resolve()
        if p == root or root not in p.parents:
            die(f"-w {d!r} must be a subdirectory of {root}")
        p.mkdir(parents=True, exist_ok=True)
        out.append(str(p.relative_to(root)))
    return out
