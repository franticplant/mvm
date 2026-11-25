"""ext4 cache images: creation, flock locking, commit-on-clean copies."""

from __future__ import annotations

import fcntl
import os
import re
import subprocess
from pathlib import Path

from . import core
from .core import die, find_sbin, now_iso, read_json, say, write_json_atomic
from .ecos import Cache


def cache_img(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        die(f"invalid cache name: {name!r}")
    return core.CACHE_ROOT / f"{name}.img"


def cache_lock(name: str) -> Path:
    return core.CACHE_ROOT / f"{name}.lock"


def cache_meta(name: str) -> Path:
    return core.CACHE_ROOT / f"{name}.meta.json"


def ensure_cache(c: Cache, project: Path | None = None) -> Path:
    core.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    img = cache_img(c.name)
    if not img.exists():
        say(f"creating cache {c.name} ({c.size}, sparse ext4)")
        tmp = img.with_name(img.name + ".new")
        subprocess.run(["truncate", "-s", c.size, str(tmp)], check=True)
        # ^orphan_file: avoids a harmless but noisy warning on read-only mounts in the guest.
        subprocess.run([find_sbin("mkfs.ext4"), "-q", "-F", "-O", "^orphan_file", str(tmp)], check=True)
        os.replace(tmp, img)
        meta = {"generation": 0, "created_at": now_iso()}
        if project:
            meta["project"] = str(project)
        write_json_atomic(cache_meta(c.name), meta)
    return img


def run_copies(name: str) -> list[Path]:
    return sorted(core.CACHE_ROOT.glob(f"{name}.img.run-*"))


class Locks:
    """flock per cache: shared for read-only, exclusive for writable. Sorted to avoid deadlocks."""

    def __init__(self, caches: list[Cache]):
        want: dict[str, bool] = {}
        for c in caches:
            want[c.name] = want.get(c.name, False) or c.rw
        self.want = want
        self.fds: list = []

    def __enter__(self):
        core.CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        for name in sorted(self.want):
            mode = fcntl.LOCK_EX if self.want[name] else fcntl.LOCK_SH
            fd = open(cache_lock(name), "a")
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
            except BlockingIOError:
                say(f"waiting for {'exclusive' if self.want[name] else 'shared'} lock on cache {name}")
                fcntl.flock(fd, mode)
            self.fds.append(fd)
        return self

    def __exit__(self, *exc):
        for fd in reversed(self.fds):
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                fd.close()
        return False


def make_run_copy(name: str, run_id: str) -> Path:
    """Caller holds the exclusive lock. Drop stale copies, then reflink-copy the image."""
    for stale in run_copies(name):
        stale.unlink(missing_ok=True)
    src = cache_img(name)
    dst = src.with_name(f"{src.name}.run-{run_id}")
    subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(src), str(dst)], check=True)
    return dst


def commit_copy(name: str, copy: Path, run_id: str) -> int:
    """Atomically replace the cache with the run's copy; return the new generation."""
    os.replace(copy, cache_img(name))
    meta = read_json(cache_meta(name), {})
    meta["generation"] = int(meta.get("generation", 0)) + 1
    meta["committed_at"] = now_iso()
    meta["committed_by"] = run_id
    write_json_atomic(cache_meta(name), meta)
    return meta["generation"]


def try_exclusive(name: str):
    fd = open(cache_lock(name), "a")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        fd.close()
        return None
