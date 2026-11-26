"""Egress for fetch: a confined VM network plus one Smokescreen allowlist proxy per run.

The VM gets pasta networking whose only way out is TCP to one host-loopback port,
where a per-run Smokescreen (Stripe's egress proxy) enforces a hostname allowlist.
Proven with real krun runs: direct TCP, other host ports, DNS (UDP and TCP, any
resolver), ICMP, IPv6 and arbitrary UDP are all closed; the proxy resolves names.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
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
    # mvm image build: OS package mirrors over HTTPS (443 only: a sources list on http://
    # fails; Debian's mirrors serve https). Others: [allow] image-build = [...].
    "image-build": ["dl-cdn.alpinelinux.org", "deb.debian.org", "security.debian.org"],
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
L7_PORT_IN_CONTAINER = 4751                  # l7proxy (pulls): the VM's entry, chained to Smokescreen
READY_TIMEOUT = 15.0


def firewall_image_present() -> bool:
    return subprocess.run(["podman", "image", "exists", FIREWALL_IMAGE]).returncode == 0


def l7proxy_bin() -> Path:
    return core.LIB_DIR / "l7proxy"


def l7_summary(lines: list[str]) -> dict:
    """l7proxy's JSON log -> {"requests", "denied": [{host, method, path, reason}], "pinned"}."""
    reqs, denied, pinned = 0, [], []
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict) or d.get("msg") != "L7":
            continue
        reqs += 1
        if d.get("allow") is not True:
            denied.append({k: str(d.get(k, "")) for k in ("host", "method", "path", "reason")})
        if d.get("pinned"):
            pinned.append(str(d["pinned"]))
    return {"requests": reqs, "denied": denied, "pinned": pinned}


def merge_l7(summary: dict, lines: list[str]) -> None:
    """An L7 refusal holds the run like a proxy denial (no [allow] line can fix it)."""
    l7 = l7_summary(lines)
    summary["l7"] = l7
    for d in l7["denied"]:
        e = summary["denied"].setdefault(d["host"] or "(unknown)", {"connections": 0, "bytes_in": 0, "bytes_out": 0})
        e["connections"] += 1
        e["reason"] = f"l7: {d['method']} {d['path']}: {d['reason']}"


def smokescreen_bin() -> Path:
    return core.LIB_DIR / "smokescreen"


def allowlist(cfg: dict, eco: str) -> list[str]:
    return sorted({*DEFAULT_ALLOW.get(eco, []), *cfg.get("allow", {}).get(eco, [])})


def vm_pasta(port: int) -> str:
    """pasta: IPv4 only, outbound sockets bound to loopback, only <port> forwarded to
    the host, and its DNS forwarder pointed at an unroutable address (TEST-NET)."""
    return f"pasta:-4,-o,127.0.0.1,--no-map-gw,-T,{port},--dns-host,192.0.2.1"


# pasta alone is not enough: its outbound sockets are bound to 127.0.0.1, and Linux lets
# a loopback-bound socket reach every *local* address, so a krun guest reached host
# listeners on 0.0.0.0 through the tailnet and bridge addresses (proven). The VM's pod is
# sealed: only its own loopback, where pasta's one -T port is the way to the proxy.
# (krun's TSI routes even the guest's own 127.0.0.1 sockets through this namespace, so
# all of lo is accepted.) Reject rather than drop: a dropped SYN leaves a TSI connect()
# waiting out the retries whatever the guest's timeout.
VM_SEAL_SH = r"""set -eu
nft -f - <<NFT
table inet mvm_vm_seal {
  chain out {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    meta l4proto tcp reject with tcp reset
    reject
  }
}
NFT
nft list table inet mvm_vm_seal | grep -q 'policy drop'
echo MVM_VM_SEALED
"""


def vm_pod_argv(name: str, port: int, labels: list[str]) -> list[str]:
    return ["podman", "pod", "create", "--name", name, *labels, "--dns=none", f"--network={vm_pasta(port)}"]


class VMPod:
    """The networked VM's own pod: pasta with only the proxy port forwarded, and its
    namespace sealed by a one-shot NET_ADMIN container (VM_SEAL_SH) before the VM starts.
    `run_args` join it (podman run); `build_args` join its namespace (podman build)."""

    def __init__(self, run_id: str, port: int):
        self.run_id, self.port = run_id, port
        self.name = f"mvm-vm-{run_id}"
        self.netns = ""

    def __enter__(self) -> VMPod:
        if not firewall_image_present():
            raise core.MvmError(f"egress firewall image missing: {FIREWALL_IMAGE} (run `make smokescreen` in "
                                "the mvm repo)")
        labels = ["--label", f"mvm.run={self.run_id}", "--label", f"mvm.pid={os.getpid()}"]
        try:
            r = subprocess.run(vm_pod_argv(self.name, self.port, labels), capture_output=True, text=True)
            if r.returncode != 0:
                raise core.MvmError(f"could not create the VM pod: {r.stderr.strip()}")
            with tempfile.TemporaryDirectory(prefix="mvm-vmseal-") as d:
                (Path(d) / "seal.sh").write_text(VM_SEAL_SH)
                fw = subprocess.run(["podman", "run", "--rm", "--pull=never", "--pod", self.name, *labels,
                                     "--cap-drop=all", "--cap-add=NET_ADMIN", "--read-only",
                                     "-v", f"{d}/seal.sh:/seal.sh:ro,z", FIREWALL_IMAGE, "sh", "/seal.sh"],
                                    capture_output=True, text=True)
            if fw.returncode != 0 or "MVM_VM_SEALED" not in fw.stdout:
                raise core.MvmError(f"could not seal the VM pod: {(fw.stderr or fw.stdout).strip()}")
            infra = subprocess.run(["podman", "pod", "inspect", "--format", "{{.InfraContainerID}}", self.name],
                                   capture_output=True, text=True).stdout.strip()
            pid = subprocess.run(["podman", "inspect", "--format", "{{.State.Pid}}", infra],
                                 capture_output=True, text=True).stdout.strip()
            if not pid.isdigit() or pid == "0":
                raise core.MvmError("the VM pod's network namespace is not running")
            self.netns = f"/proc/{pid}/ns/net"
        except BaseException:
            self.__exit__()
            raise
        return self

    def run_args(self) -> list[str]:
        return ["--pod", self.name]

    def build_args(self) -> list[str]:
        return ["--dns=none", f"--network=ns:{self.netns}"]

    def __exit__(self, *exc) -> None:
        subprocess.run(["podman", "pod", "rm", "-f", "-t", "0", self.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def parse_port(spec: str) -> tuple[int, int]:
    """-p HOST:CONT or 127.0.0.1:HOST:CONT -> (host, cont). Any other bind address is
    refused: published ports are host-loopback only."""
    parts = spec.split(":")
    if len(parts) == 3 and parts[0] == "127.0.0.1":
        parts = parts[1:]
    if len(parts) != 2 or not all(p.isascii() and p.isdigit() and 1 <= int(p) <= 65535 for p in parts):
        raise core.MvmError(f"bad port {spec!r}: give HOST:CONT (1-65535), published on 127.0.0.1 only")
    return int(parts[0]), int(parts[1])


def inbound_pod_argv(name: str, labels: list[str]) -> list[str]:
    """The workload's pod: --network=none, so its namespace has only loopback."""
    return ["podman", "pod", "create", "--name", name, *labels, "--network=none"]


def bridge_argv(pod: str, labels: list[str], sockdir: str, script: str, image: str, conts: list[int]) -> list[str]:
    """The pod-side bridge: no capabilities, read-only, only the socket dir writable."""
    return ["podman", "run", "-d", "--pull=never", "--pod", pod, "--name", f"{pod}-bridge", *labels,
            "--cap-drop=all", "--security-opt", "no-new-privileges", "--read-only",
            "-v", f"{sockdir}:/sock:z", "-v", f"{script}:/portbridge.py:ro,z",
            image, "python3", "-I", "-B", "/portbridge.py", "/sock", *[str(c) for c in conts]]


class InboundPod:
    """mvm run -p: the workload runs in a --network=none pod (loopback only, so it can open
    no connection to anything); inbound connections reach it through Unix sockets that a
    pod-side bridge forwards to 127.0.0.1:CONT, and mvm splices host 127.0.0.1:HOST to them."""

    def __init__(self, run_id: str, ports: list[tuple[int, int]]):
        self.run_id, self.ports = run_id, ports
        self.name = f"mvm-ports-{run_id}"
        self._dir: str | None = None
        self._listeners: list[socket.socket] = []

    def __enter__(self) -> InboundPod:
        from . import observer, portbridge
        if not observer.image_present():
            raise core.MvmError("the Python image for the port bridge is missing (run `make observer` in the "
                                "mvm repo); mvm run -p refuses to run without it")
        labels = ["--label", f"mvm.run={self.run_id}", "--label", f"mvm.pid={os.getpid()}"]
        try:
            self._dir = tempfile.mkdtemp(prefix="mvm-ports-")
            os.chmod(self._dir, 0o700)
            if len(os.path.join(self._dir, portbridge.sock_name(65535))) > 100:
                raise core.MvmError(f"temp dir path too long for a Unix socket: {self._dir} (set TMPDIR)")
            for host, _ in self.ports:          # bind first: a busy port fails before any pod exists
                ln = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ln.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    ln.bind(("127.0.0.1", host))
                except OSError as e:
                    ln.close()
                    raise core.MvmError(f"host port 127.0.0.1:{host}: {e.strerror}") from None
                ln.listen(64)
                self._listeners.append(ln)
            r = subprocess.run(inbound_pod_argv(self.name, labels), capture_output=True, text=True)
            if r.returncode != 0:
                raise core.MvmError(f"could not create the port pod: {r.stderr.strip()}")
            conts = sorted({c for _, c in self.ports})
            r = subprocess.run(bridge_argv(self.name, labels, self._dir, portbridge.__file__,
                                           observer.OBSERVER_IMAGE, conts),
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise core.MvmError(f"could not start the port bridge: {r.stderr.strip()}")
            socks = [Path(self._dir) / portbridge.sock_name(c) for c in conts]
            deadline = time.monotonic() + 15
            while not all(p.is_socket() for p in socks):
                if time.monotonic() > deadline:
                    raise core.MvmError("the port bridge did not come up")
                time.sleep(0.1)
            for ln, (_, cont) in zip(self._listeners, self.ports):
                path = str(Path(self._dir) / portbridge.sock_name(cont))

                def dial(path=path):
                    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        u.connect(path)
                    except OSError:
                        u.close()
                        raise
                    return u
                threading.Thread(target=portbridge.serve, args=(ln, dial), daemon=True).start()
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc) -> None:
        for ln in self._listeners:
            try:
                ln.shutdown(socket.SHUT_RDWR)  # wakes the accept() in the serving thread
            except OSError:
                pass
            ln.close()
        self._listeners = []
        subprocess.run(["podman", "pod", "rm", "-f", "-t", "0", self.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None


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

    def __init__(self, run_id: str, hosts: list[str], action: str, l7: dict | None = None):
        self.run_id = run_id
        # l7 = {"policy": {...}, "roots": Path}: put l7proxy in front of Smokescreen (pulls)
        self.l7 = l7
        self.ca_pem = b""                     # l7: the run's ephemeral CA certificate
        self._ca_dir: tempfile.TemporaryDirectory | None = None
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
        if self.l7 is not None:
            if not l7proxy_bin().is_file():
                self._dir.cleanup()
                raise core.MvmError(f"L7 proxy missing: {l7proxy_bin()} (run `make l7proxy` in the mvm repo)")
            (cfg / "l7rules.json").write_text(json.dumps(self.l7["policy"]))
            shutil.copyfile(self.l7["roots"], cfg / "roots.pem")
            self._ca_dir = tempfile.TemporaryDirectory(prefix="mvm-l7ca-")
            os.chmod(self._ca_dir.name, 0o700)
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
                        "-p", f"127.0.0.1:{self.port}:"
                        f"{L7_PORT_IN_CONTAINER if self.l7 is not None else PROXY_PORT_IN_CONTAINER}"],
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
        if self.l7 is not None:
            self._start_l7(cfg)
        self._wait_ready()

    def _start_l7(self, cfg: Path) -> None:
        labels = ["--label", f"mvm.run={self.run_id}", "--label", f"mvm.pid={os.getpid()}"]
        ca_dir = Path(self._ca_dir.name)
        subprocess.run(["podman", "run", "-d", "--pull=never", "--pod", self.name, "--name", f"{self.name}-l7", *labels,
                        "--read-only", "--cap-drop=all", "--security-opt", "no-new-privileges",
                        "-v", f"{l7proxy_bin()}:/l7proxy:ro,z", "-v", f"{cfg}:/cfg:ro,z", "-v", f"{ca_dir}:/ca:z",
                        core.pinned(PROXY_IMAGE), "/l7proxy", "-listen", f"0.0.0.0:{L7_PORT_IN_CONTAINER}",
                        "-upstream", f"127.0.0.1:{PROXY_PORT_IN_CONTAINER}", "-rules", "/cfg/l7rules.json",
                        "-roots", "/cfg/roots.pem", "-ca-out", "/ca/ca.crt"],
                       check=True, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            logs = subprocess.run(["podman", "logs", f"{self.name}-l7"], capture_output=True, text=True)
            if "L7-READY" in logs.stdout and (ca_dir / "ca.crt").is_file():
                self.ca_pem = (ca_dir / "ca.crt").read_bytes()
                if b"BEGIN CERTIFICATE" in self.ca_pem:
                    return
            time.sleep(0.1)
        raise core.MvmError(f"L7 proxy did not start: {(logs.stdout + logs.stderr).strip()[-300:]}")

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
        self.l7_lines: list[str] = []
        l7_ok = True
        if self.l7 is not None:
            # Read l7proxy, then stop it first: its idle upstream connections close, so
            # Smokescreen logs their bytes (CANONICAL-PROXY-CN-CLOSE) before it is read.
            l7 = f"{self.name}-l7"
            st7 = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.Running}}", l7],
                                 capture_output=True, text=True)
            subprocess.run(["podman", "stop", "-t", "2", l7], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            lg7 = subprocess.run(["podman", "logs", l7], capture_output=True, text=True)
            l7_ok = st7.stdout.strip() == "true" and lg7.returncode == 0
            self.l7_lines = lg7.stdout.splitlines()
            time.sleep(0.3)
        state = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.Running}}", sm],
                               capture_output=True, text=True)
        logs = subprocess.run(["podman", "logs", sm], capture_output=True, text=True)
        self.healthy = state.stdout.strip() == "true" and logs.returncode == 0 and l7_ok
        subprocess.run(["podman", "pod", "rm", "-f", "-t", "2", self.name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._dir:
            self._dir.cleanup()
            self._dir = None
        if self._ca_dir:
            self._ca_dir.cleanup()
            self._ca_dir = None
        return (logs.stdout + logs.stderr).splitlines()

    def __exit__(self, *exc) -> bool:
        self.summary = summarize(self._stop())
        if self.l7 is not None:
            merge_l7(self.summary, self.l7_lines)
        return False
