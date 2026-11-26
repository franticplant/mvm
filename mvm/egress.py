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
    # Image pulls (mvm pull / update / first use). Docker Hub: auth, registry, and blobs
    # from CloudFront (seen in a real run) or Cloudflare/R2 (Docker's published list; the
    # one R2 bucket by name, never *.r2: any bucket would do for exfiltration). GHCR:
    # registry and blobs. Other registries: [allow] pull = [...].
    "pull": ["auth.docker.io", "registry-1.docker.io", "production.cloudfront.docker.com",
             "production.cloudflare.docker.com",
             "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
             "ghcr.io", "pkg-containers.githubusercontent.com"],
}
# alpine 3.24 by digest, the base of the firewall image (`make smokescreen` brings it):
# by tag, a fresh machine would pull it through the very proxy it is about to run.
PROXY_IMAGE = "docker.io/library/alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395"
# Built by `make smokescreen` from the pinned alpine plus nftables; loads FIREWALL_SH.
FIREWALL_IMAGE = "localhost/mvm-egress-fw:1"
# Smokescreen allowlists host names but cannot restrict ports, so the proxy's own network
# namespace gets a kernel egress filter: only TCP 443 out, plus DNS to its resolver.
FIREWALL_SH = r"""set -eu
NS=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
# pasta gives the pod MTU 65520; at that size a packet capture (the observer) drops the
# oversized frames that carry the TLS ClientHello. 1500 keeps every frame parseable.
IF=$(awk -F: 'NR>2 {gsub(/ /,"",$1); if ($1 != "lo") {print $1; exit}}' /proc/net/dev)
ip link set dev "$IF" mtu 1500
nft -f - <<NFT
table inet mvm_egress {
  chain out {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr $NS meta l4proto { tcp, udp } th dport 53 accept
    # Defence in depth (Smokescreen refuses these too): never private, CGNAT/tailnet,
    # link-local, loopback or multicast destinations, whatever a name resolves to.
    ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 } reject
    ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } reject
    tcp dport 443 accept
    meta l4proto tcp reject with tcp reset
    reject
  }
}
NFT
nft list table inet mvm_egress | grep -q 'policy drop'
echo "MVM_IF=$IF"
echo MVM_EGRESS_FIREWALL_LOADED
"""
PROXY_PORT_IN_CONTAINER = 4750
READY_TIMEOUT = 15.0


def firewall_image_present() -> bool:
    return subprocess.run(["podman", "image", "exists", FIREWALL_IMAGE]).returncode == 0


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
    """host[:port] -> host, lower-cased, trailing dot dropped; [v6]:port -> v6."""
    host = requested
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.lower().rstrip(".") or "(unknown)"


def _port(requested: str) -> str:
    if requested.startswith("["):
        rest = requested.split("]", 1)[1] if "]" in requested else ""
        return rest[1:] if rest.startswith(":") else ""
    return requested.rsplit(":", 1)[1] if requested.count(":") == 1 else ""


def summarize(log_lines: list[str]) -> dict:
    """Per-host decisions and bytes from Smokescreen's JSON log.

    CANONICAL-PROXY-DECISION carries allow / enforce_would_deny / decision_reason;
    CANONICAL-PROXY-CN-CLOSE carries bytes_in / bytes_out; they share an `id`.
    Every decision counts (a list, never keyed), including ones without a host.
    `outside_allowlist` lists hosts the proxy let through only because of report
    (learn) mode; hosts refused by Smokescreen's IP rules are in `denied` instead.
    """
    decisions: list[dict] = []
    closes: dict[str, dict] = {}
    for line in log_lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict):
            continue
        if d.get("msg") == "CANONICAL-PROXY-DECISION" or ("allow" in d and d.get("msg") != "CANONICAL-PROXY-CN-CLOSE"):
            decisions.append(d)
        elif d.get("msg") == "CANONICAL-PROXY-CN-CLOSE" and d.get("id"):
            closes[d["id"]] = d
    allowed: dict[str, dict] = {}
    denied: dict[str, dict] = {}
    outside: set[str] = set()
    for d in decisions:
        requested = d.get("requested_host") or ""
        host = _host(requested)
        ok = bool(d.get("allow"))
        port = _port(requested)
        if ok and port not in ("", "443"):
            # Smokescreen's ACL is host-only; the pod's kernel filter blocks every port but 443.
            ok = False
            d = {**d, "decision_reason": f"port {port} blocked (443 only)"}
        e = (allowed if ok else denied).setdefault(host, {"connections": 0, "bytes_in": 0, "bytes_out": 0})
        e["connections"] += 1
        c = closes.get(d.get("id") or "", {})
        for k in ("bytes_in", "bytes_out"):
            if isinstance(c.get(k), (int, float)):
                e[k] += int(c[k])
        if not ok:
            e["reason"] = d.get("decision_reason", "")
        elif d.get("enforce_would_deny"):
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
    parts = [f"{h} ({v['connections']}x, {size(v.get('bytes_in', 0))} in / {size(v.get('bytes_out', 0))} out)"
             for h, v in sorted(a.items())]
    out = "egress allowed: " + (", ".join(parts) if parts else "none")
    if d:
        out += "; DENIED: " + ", ".join(f"{h} ({v['connections']}x)" for h, v in sorted(d.items()))
    learned = s.get("outside_allowlist", [])
    if learned:
        out += "; outside the allowlist (learn mode): " + ", ".join(learned)
    return out


class Proxy:
    """One proxy pod per run on a random host-loopback port: a one-shot NET_ADMIN
    container loads the port filter (FIREWALL_SH) into the pod's network namespace,
    then Smokescreen runs in the same pod with no capabilities at all."""

    def __init__(self, run_id: str, hosts: list[str], action: str):
        self.run_id = run_id
        self.hosts = hosts
        self.action = action
        self.name = f"mvm-proxy-{run_id}"
        self.port = 0
        self._dir: tempfile.TemporaryDirectory | None = None
        self.summary: dict = {"allowed": {}, "denied": {}}
        self.healthy = False                  # proxy still running and its log readable at the end
        self.iface = ""                       # the pod's capture interface (for the observer)

    def __enter__(self) -> Proxy:
        binary = smokescreen_bin()
        if not binary.is_file():
            raise core.MvmError(f"egress proxy missing: {binary} (run `make smokescreen` in the mvm repo); "
                                "fetch refuses to run without it")
        if not firewall_image_present():
            raise core.MvmError(f"egress firewall image missing: {FIREWALL_IMAGE} (run `make smokescreen` in "
                                "the mvm repo); fetch refuses to run without it")
        image = core.pinned(PROXY_IMAGE)
        self._dir = tempfile.TemporaryDirectory(prefix="mvm-proxy-")
        cfg = Path(self._dir.name)
        (cfg / "acl.yaml").write_text(acl_yaml(self.hosts, self.action))
        (cfg / "config.yaml").write_text(CONFIG_YAML)
        (cfg / "firewall.sh").write_text(FIREWALL_SH)
        self.port = free_port()
        try:
            self._start(binary, image, cfg)
        except BaseException:
            self._stop()                      # never leave a proxy or temp dir behind
            raise
        return self

    def _start(self, binary: Path, image: str, cfg: Path) -> None:
        labels = ["--label", f"mvm.run={self.run_id}", "--label", f"mvm.pid={os.getpid()}"]
        subprocess.run(["podman", "pod", "create", "--name", self.name, *labels,
                        "-p", f"127.0.0.1:{self.port}:{PROXY_PORT_IN_CONTAINER}"],
                       check=True, stdout=subprocess.DEVNULL)
        fw = subprocess.run(["podman", "run", "--rm", "--pull=never", "--pod", self.name, *labels,
                             "--cap-drop=all", "--cap-add=NET_ADMIN", "--read-only",
                             "-v", f"{cfg}/firewall.sh:/firewall.sh:ro,z",
                             FIREWALL_IMAGE, "sh", "/firewall.sh"],
                            capture_output=True, text=True)
        if fw.returncode != 0 or "MVM_EGRESS_FIREWALL_LOADED" not in fw.stdout:
            raise core.MvmError(f"egress port filter failed to load: {(fw.stderr or fw.stdout).strip()[:300]}")
        self.iface = next((ln[len("MVM_IF="):] for ln in fw.stdout.splitlines() if ln.startswith("MVM_IF=")), "")
        argv = ["podman", "run", "-d", "--pull=never", "--pod", self.name, "--name", f"{self.name}-smokescreen", *labels,
                "--read-only", "--cap-drop=all", "--security-opt", "no-new-privileges",
                "-v", f"{binary}:/smokescreen:ro,z", "-v", f"{cfg}:/cfg:ro,z",
                image, "/smokescreen", "--config-file", "/cfg/config.yaml",
                # 0.0.0.0 is inside the pod's own netns; the host side is published
                # only on 127.0.0.1 (pod create -p above), so nothing else can reach it.
                "--listen-ip", "0.0.0.0",  # noqa: S104
                "--listen-port", str(PROXY_PORT_IN_CONTAINER)]
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return
            except OSError:
                time.sleep(0.2)
        raise core.MvmError(f"egress proxy did not start on 127.0.0.1:{self.port}")

    def _stop(self) -> list[str]:
        sm = f"{self.name}-smokescreen"
        state = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.Running}}", sm],
                               capture_output=True, text=True)
        logs = subprocess.run(["podman", "logs", sm], capture_output=True, text=True)
        self.healthy = state.stdout.strip() == "true" and logs.returncode == 0
        subprocess.run(["podman", "pod", "rm", "-f", "-t", "2", self.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._dir:
            self._dir.cleanup()
            self._dir = None
        return (logs.stdout + logs.stderr).splitlines()

    def __exit__(self, *exc) -> bool:
        self.summary = summarize(self._stop())
        return False
