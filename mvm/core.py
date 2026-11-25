"""Paths, messages, JSON state, config and image pins."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

from .ecos import ECOS


HOME = Path.home()


CACHE_ROOT = Path(os.environ.get("MVM_CACHE_DIR", HOME / ".cache" / "mvm"))


STATE_ROOT = Path(os.environ.get("MVM_STATE_DIR", HOME / ".local" / "state" / "mvm"))


CONFIG_PATH = Path(os.environ.get("MVM_CONFIG", HOME / ".config" / "mvm" / "config.toml"))
LIB_DIR = Path(os.environ.get("MVM_LIB_DIR", HOME / ".local" / "lib" / "mvm"))


KEEP_RUNS = 200
EXIT_EGRESS_DENIED = 3     # fetch exited 0 but tried a denied host: held, not committed
EXIT_PROXY_FAILED = 4      # egress proxy died mid-run or its log was unreadable
EXIT_OBSERVER_FAILED = 5   # observer (enabled) died mid-run or its flows were unreadable


DEFAULT_MASK = [
    ".git", ".env", ".env.*", ".envrc", ".npmrc", ".netrc", ".pypirc",
    "*.pem", "*.key", "id_rsa*", "id_ecdsa*", "id_ed25519*",
]


# Directories never descended into when looking for masks or manifests.
SKIP_DIRS = {".git", "node_modules", "target", "vendor", ".venv", "__pycache__"}


class MvmError(Exception):
    pass


def die(msg: str, code: int = 2) -> None:
    print(f"mvm: {msg}", file=sys.stderr)
    sys.exit(code)


def say(msg: str) -> None:
    print(f"mvm: {msg}", file=sys.stderr)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def valid_allow_host(h) -> bool:
    """A DNS name with at least two labels; `*.` only in front of at least two labels
    (so *.github.com, never *.com); no IP literals."""
    if not isinstance(h, str):
        return False
    name = h[2:] if h.startswith("*.") else h
    labels = name.split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", lab) for lab in labels):
        return False
    return not all(lab.isdigit() for lab in labels)


def load_config() -> dict:
    """Read config.toml and reject wrong shapes (e.g. mask = ".env" would match per character)."""
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "rb") as f:
            cfg = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        die(f"{CONFIG_PATH}: {e}")
    unknown = set(cfg) - {"mask", "images", "memory", "allow", "observer"}
    if unknown:
        die(f"{CONFIG_PATH}: unknown keys {sorted(unknown)} (allowed: mask, images, memory, allow, observer)")
    obs = cfg.get("observer", {})
    if not isinstance(obs, dict) or set(obs) - {"enabled"} or not isinstance(obs.get("enabled", False), bool):
        die(f"{CONFIG_PATH}: [observer] takes only enabled = true|false")
    allow = cfg.get("allow", {})
    if not isinstance(allow, dict) or not all(
            k in ECOS and isinstance(v, list) and all(valid_allow_host(h) for h in v)
            for k, v in allow.items()):
        die(f"{CONFIG_PATH}: [allow] keys must be {sorted(ECOS)} with lists of host names")
    mask = cfg.get("mask", DEFAULT_MASK)
    if not isinstance(mask, list) or not all(isinstance(m, str) and m for m in mask):
        die(f"{CONFIG_PATH}: mask must be a list of non-empty strings")
    images = cfg.get("images", {})
    if not isinstance(images, dict) or not all(k in ECOS and isinstance(v, str) for k, v in images.items()):
        die(f"{CONFIG_PATH}: [images] keys must be {sorted(ECOS)} with string values")
    memory = cfg.get("memory", {})
    if not isinstance(memory, dict) or not all(
            k in (*ECOS, "run") and isinstance(v, str) and re.fullmatch(r"[0-9]+[kmgKMG]?", v)
            for k, v in memory.items()):
        die(f"{CONFIG_PATH}: [memory] keys must be {sorted((*ECOS, 'run'))} with sizes like \"4g\"")
    return cfg


def write_json_atomic(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def pins_path() -> Path:
    return STATE_ROOT / "pins.json"


def image_repo(tag: str) -> str:
    """Strip a :tag (not a registry :port) from an image reference."""
    ref = tag.split("@", 1)[0]
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    return ref[:colon] if colon > slash else ref


def podman_out(args: list[str]) -> str:
    return subprocess.run(["podman", *args], check=True, capture_output=True, text=True).stdout.strip()


def resolve_digest(tag: str, pull: bool) -> str:
    if pull or subprocess.run(["podman", "image", "exists", tag]).returncode != 0:
        say(f"pulling {tag}")
        subprocess.run(["podman", "pull", "-q", tag], check=True, stdout=subprocess.DEVNULL)
    digest = podman_out(["image", "inspect", "--format", "{{.Digest}}", tag])
    if not digest.startswith("sha256:"):
        raise MvmError(f"could not resolve digest for {tag}: {digest!r}")
    return f"{image_repo(tag)}@{digest}"


def pinned(tag: str) -> str:
    """Return tag pinned to a digest; pin on first use (trust on first use)."""
    if "@sha256:" in tag:
        return tag
    pins = read_json(pins_path(), {})
    if tag in pins:
        return pins[tag]["ref"]
    ref = resolve_digest(tag, pull=False)
    pins[tag] = {"ref": ref, "pinned_at": now_iso()}
    write_json_atomic(pins_path(), pins)
    say(f"pinned {tag} -> {ref}")
    return ref


def find_sbin(tool: str) -> str:
    for p in (f"/usr/sbin/{tool}", f"/sbin/{tool}", shutil.which(tool) or ""):
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    die(f"required tool not found: {tool}")
    return ""
