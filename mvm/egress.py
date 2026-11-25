"""Egress for fetch: a confined VM network plus one Smokescreen allowlist proxy per run.

The VM gets pasta networking whose only way out is TCP to one host-loopback port,
where a per-run Smokescreen (Stripe's egress proxy) enforces a hostname allowlist.
Proven with real krun runs: direct TCP, other host ports, DNS (UDP and TCP, any
resolver), ICMP, IPv6 and arbitrary UDP are all closed; the proxy resolves names.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from . import core

# Hosts each ecosystem's package manager needs; config [allow] adds more.
DEFAULT_ALLOW = {
    # proxy.golang.org serves module zips from storage.googleapis.com (seen in a real run).
    "go": ["proxy.golang.org", "sum.golang.org", "storage.googleapis.com"],
    "rust": ["index.crates.io", "static.crates.io"],
    "node": ["registry.npmjs.org"],
}
PROXY_IMAGE = "docker.io/library/alpine:3.24"
PROXY_PORT_IN_CONTAINER = 4750
READY_TIMEOUT = 15.0


def smokescreen_bin() -> Path:
    return core.LIB_DIR / "smokescreen"


def allowlist(cfg: dict, eco: str) -> list[str]:
    return sorted({*DEFAULT_ALLOW.get(eco, []), *cfg.get("allow", {}).get(eco, [])})


def vm_network_args(port: int) -> list[str]:
    """pasta: IPv4 only, outbound sockets bound to loopback, only <port> forwarded to
    the host, and its DNS forwarder pointed at an unroutable address (TEST-NET)."""
    return ["--dns=none",
            f"--network=pasta:-4,-o,127.0.0.1,--no-map-gw,-T,{port},--dns-host,192.0.2.1"]


def proxy_env(port: int) -> dict[str, str]:
    url = f"http://127.0.0.1:{port}"
    return {"HTTPS_PROXY": url, "HTTP_PROXY": url, "https_proxy": url, "http_proxy": url,
            "CARGO_HTTP_PROXY": url, "npm_config_https_proxy": url, "npm_config_proxy": url,
            "NO_PROXY": "", "no_proxy": ""}


def _quote(s: str) -> str:
    return json.dumps(s)          # a JSON string is a valid YAML double-quoted scalar


def acl_yaml(hosts: list[str], action: str) -> str:
    """Smokescreen v1 ACL. No client certs, so every request uses the default policy."""
    if action not in ("enforce", "report"):
        raise core.MvmError(f"bad egress action {action!r}")
    lines = ["version: v1", "services: []", "default:", "  project: mvm", f"  action: {action}"]
    if hosts:
        lines.append("  allowed_domains:")
        lines += [f"    - {_quote(h)}" for h in hosts]
    else:
        lines.append("  allowed_domains: []")
    return "\n".join(lines) + "\n"


CONFIG_YAML = "allow_missing_role: true\nacl_file: /cfg/acl.yaml\n"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _host(requested: str) -> str:
    """host[:port] -> host, lower-cased, trailing dot dropped (PROXY.golang.org. == proxy.golang.org)."""
    host = requested.rsplit(":", 1)[0] if requested.count(":") == 1 else requested
    return host.lower().rstrip(".")


def summarize(log_lines: list[str]) -> dict:
    """Per-host decisions and bytes from Smokescreen's JSON log.

    CANONICAL-PROXY-DECISION carries allow / enforce_would_deny (report mode) and
    CANONICAL-PROXY-CN-CLOSE carries bytes_in / bytes_out; they share an `id`.
    """
    decisions: dict[str, dict] = {}
    closes: dict[str, dict] = {}
    for line in log_lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict) or not d.get("requested_host"):
            continue
        if d.get("msg") == "CANONICAL-PROXY-DECISION":
            decisions[d.get("id") or str(len(decisions))] = d
        elif d.get("msg") == "CANONICAL-PROXY-CN-CLOSE":
            closes[d.get("id") or ""] = d
    allowed: dict[str, dict] = {}
    denied: dict[str, dict] = {}
    outside: set[str] = set()
    for cid, d in decisions.items():
        host = _host(d["requested_host"])
        bucket = allowed if d.get("allow") else denied
        e = bucket.setdefault(host, {"connections": 0, "bytes_in": 0, "bytes_out": 0})
        e["connections"] += 1
        c = closes.get(cid, {})
        for k in ("bytes_in", "bytes_out"):
            if isinstance(c.get(k), (int, float)):
                e[k] += int(c[k])
        if not d.get("allow"):
            e["reason"] = d.get("decision_reason", "")
        if d.get("enforce_would_deny") or not d.get("allow"):
            outside.add(host)
    return {"allowed": allowed, "denied": denied, "outside_allowlist": sorted(outside)}


def summary_line(s: dict) -> str:
    def size(n: int) -> str:
        for unit in ("B", "KiB", "MiB", "GiB"):
            if n < 1024 or unit == "GiB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return str(n)
    a, d = s["allowed"], s["denied"]
    parts = [f"{h} ({v['connections']}x, {size(v['bytes_in'])} in / {size(v['bytes_out'])} out)"
             for h, v in sorted(a.items())]
    out = "egress allowed: " + (", ".join(parts) if parts else "none")
    if d:
        out += "; DENIED: " + ", ".join(f"{h} ({v['connections']}x)" for h, v in sorted(d.items()))
    learned = [h for h in s.get("outside_allowlist", []) if h not in d]
    if learned:
        out += "; outside the allowlist (learn mode): " + ", ".join(learned)
    return out


class Proxy:
    """One Smokescreen container for one run, on a random host-loopback port."""

    def __init__(self, run_id: str, hosts: list[str], action: str):
        self.run_id = run_id
        self.hosts = hosts
        self.action = action
        self.name = f"mvm-proxy-{run_id}"
        self.port = 0
        self._dir: tempfile.TemporaryDirectory | None = None
        self.summary: dict = {"allowed": {}, "denied": {}}

    def __enter__(self) -> Proxy:
        binary = smokescreen_bin()
        if not binary.is_file():
            raise core.MvmError(f"egress proxy missing: {binary} (run `make smokescreen` in the mvm repo); "
                                "fetch refuses to run without it")
        image = core.pinned(PROXY_IMAGE)
        self._dir = tempfile.TemporaryDirectory(prefix="mvm-proxy-")
        cfg = Path(self._dir.name)
        (cfg / "acl.yaml").write_text(acl_yaml(self.hosts, self.action))
        (cfg / "config.yaml").write_text(CONFIG_YAML)
        self.port = free_port()
        argv = ["podman", "run", "-d", "--rm", "--name", self.name,
                "--label", f"mvm.run={self.run_id}", "--label", f"mvm.pid={os.getpid()}",
                "--read-only", "--cap-drop=all", "--security-opt", "no-new-privileges",
                "-p", f"127.0.0.1:{self.port}:{PROXY_PORT_IN_CONTAINER}",
                "-v", f"{binary}:/smokescreen:ro,z", "-v", f"{cfg}:/cfg:ro,z",
                image, "/smokescreen", "--config-file", "/cfg/config.yaml",
                # 0.0.0.0 is inside the container's own netns; the host side is published
                # only on 127.0.0.1 (the -p above), so nothing else can reach the proxy.
                "--listen-ip", "0.0.0.0",  # noqa: S104
                "--listen-port", str(PROXY_PORT_IN_CONTAINER)]
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)
        self._wait_ready()
        return self

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return
            except OSError:
                time.sleep(0.2)
        self._stop()
        raise core.MvmError(f"egress proxy did not start on 127.0.0.1:{self.port}")

    def _stop(self) -> list[str]:
        logs = subprocess.run(["podman", "logs", self.name], capture_output=True, text=True)
        subprocess.run(["podman", "stop", "-t", "2", self.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._dir:
            self._dir.cleanup()
        return (logs.stdout + logs.stderr).splitlines()

    def __exit__(self, *exc) -> bool:
        self.summary = summarize(self._stop())
        return False
