"""Ecosystem definitions (go, rust, node) and the caches each phase uses."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path



@dataclass
class Cache:
    name: str
    guest: str
    rw: bool
    size: str = "4G"


@dataclass
class Eco:
    name: str
    image: str
    memory: str
    detect: str
    manifests: list[str]
    fetch_cmd: list[str]
    env: dict[str, str]
    build_env: dict[str, str] = field(default_factory=dict)
    fetch_env: dict[str, str] = field(default_factory=dict)


ECOS: dict[str, Eco] = {
    "go": Eco(
        name="go",
        image="docker.io/library/golang:1.27-alpine",
        memory="2g",
        detect="go.mod",
        manifests=["go.mod", "go.sum", "go.work", "go.work.sum"],
        fetch_cmd=["go", "mod", "download"],
        # GOTOOLCHAIN=local: never download a newer Go toolchain (that is code that runs).
        # -buildvcs=false: .git is masked, so do not try to stamp VCS info.
        env={"CGO_ENABLED": "0", "GOMODCACHE": "/cache/go-mod", "GOCACHE": "/cache/go-build",
             "GOTOOLCHAIN": "local", "GOFLAGS": "-buildvcs=false"},
        build_env={"GOPROXY": "off"},
    ),
    "rust": Eco(
        name="rust",
        image="docker.io/library/rust:1.98-alpine",
        memory="4g",
        detect="Cargo.toml",
        manifests=["Cargo.toml", "Cargo.lock"],
        fetch_cmd=["cargo", "fetch"],
        env={"CARGO_TARGET_DIR": "/cache/target"},
        build_env={"CARGO_NET_OFFLINE": "true"},
    ),
    "node": Eco(
        name="node",
        image="docker.io/library/node:22-alpine",
        memory="2g",
        detect="package.json",
        manifests=["package.json", "package-lock.json", "npm-shrinkwrap.json"],
        # Install scripts never run with network; run them offline: mvm build node -- npm rebuild
        fetch_cmd=["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        env={"npm_config_cache": "/cache/npm", "npm_config_update_notifier": "false"},
        # Enforced for every fetch, including `mvm fetch node -- npm install x`.
        fetch_env={"npm_config_ignore_scripts": "true"},
        build_env={"npm_config_offline": "true"},
    ),
}


def project_cache_name(prefix: str, project: Path) -> str:
    h = hashlib.sha256(str(project).encode()).hexdigest()[:8]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", project.name)[:24] or "root"
    return f"{prefix}-{base}-{h}"


def eco_caches(eco: Eco, phase: str, project: Path) -> list[Cache]:
    fetch = phase == "fetch"
    if eco.name == "go":
        cs = [Cache("go-mod", "/cache/go-mod", fetch, "4G")]
        if not fetch:
            cs.append(Cache("go-build", "/cache/go-build", True, "8G"))
    elif eco.name == "rust":
        cs = [Cache("cargo-reg", "/usr/local/cargo/registry", fetch, "4G"),
              Cache("cargo-git", "/usr/local/cargo/git", fetch, "2G")]
        if not fetch:
            cs.append(Cache("cargo-target", "/cache/target", True, "8G"))
    else:
        # node_modules is per project; build keeps it writable for `npm rebuild`.
        cs = [Cache("npm", "/cache/npm", fetch, "4G"),
              Cache(project_cache_name("nm", project), "/src/node_modules", True, "4G")]
    return cs
