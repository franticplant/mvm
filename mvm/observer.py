"""Observer for fetch: mvm's own TLS ClientHello sensor (tlsobs.py) in the egress proxy pod.

It captures the pod's outbound leg, where the proxy relays the VM's own bytes, and
reports per connection to port 443 whether it starts with a TLS ClientHello, its SNI
and JA4, and the bytes each way. On by default (`[observer] enabled = false` in the
host config turns it off). It fails closed: a missing image refuses the run; a dead
sensor, unreadable output, kernel drops or too many flows mean nothing is committed
(exit 5). A connection that is not TLS, has no SNI, an SNI outside the allowlist, or a
reassembly fault holds the run (exit 3): the proxy only checks the CONNECT host, so this
is what catches SNI-level domain fronting and plaintext tunnelled to an allowed host
(fronting by the Host header inside encrypted TLS is invisible to it).

The sensor is stdlib Python in the official Python image (pinned by digest), with
tlsobs.py mounted read-only: nothing to build, nothing from nDPI. nDPI 5.0 is kept
only as a black-box oracle for the real tests (`make ndpi-oracle`).

Pod quirk (seen with nDPI, kept): pasta gives the pod MTU 65520; the firewall one-shot
sets 1500 so captured frames have ordinary sizes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import core, tlsobs

# Official Python image (3.13.18 alpine, 2026-11-05), pulled by `make observer`.
OBSERVER_IMAGE = ("docker.io/library/python@sha256:"
                  "d76f585fb0d5107dd47143da5e61554fd9cae656a30f3470f815cb8475769b6a")
SENSOR = Path(__file__).with_name("tlsobs.py")
READY_MARK = tlsobs.READY
READY_TIMEOUT = 15.0


def enabled(cfg: dict) -> bool:
    return bool(cfg.get("observer", {}).get("enabled", True))


def image_present() -> bool:
    return subprocess.run(["podman", "image", "exists", OBSERVER_IMAGE]).returncode == 0


def sidecar_argv(pod: str, name: str, run_id: str, iface: str, out: Path, pcap: bool = False) -> list[str]:
    """The sensor parses untrusted packets: raw capture only, nothing else."""
    return ["podman", "run", "-d", "--pod", pod, "--name", name,
            "--label", f"mvm.run={run_id}", "--label", f"mvm.pid={os.getpid()}",
            "--cap-drop=all", "--cap-add=NET_RAW", "--security-opt", "no-new-privileges",
            "--read-only", "--memory", "256m", "--pids-limit", "64",
            "--stop-signal", "SIGINT",            # the sensor writes its flows on SIGINT
            "-v", f"{SENSOR}:/obs/tlsobs.py:ro,z", "-v", f"{out}:/out:z", OBSERVER_IMAGE,
            "python3", "-I", "-B", "/obs/tlsobs.py", iface, "/out/flows.jsonl"] + (
                ["--pcap", "/out/cap.pcap"] if pcap else [])


def _matches(host: str, allow: list[str]) -> bool:
    """Smokescreen's semantics (acl.go hostMatchesGlob): `*.x` matches any subdomain of x
    at any depth, never x itself. An SNI with an empty label (".x", "a..x") never matches."""
    host = host.lower().rstrip(".")
    if not host or "" in host.split("."):
        return False
    for a in allow:
        a = a.lower().rstrip(".")
        if host == a or (a.startswith("*.") and host.endswith(a[1:])):
            return True
    return False


def _lines_ok(lines: list[str] | None) -> bool:
    """Every non-empty flow line is a JSON object (a truncated or corrupt line fails the run)."""
    for ln in lines or []:
        if ln.strip():
            try:
                if not isinstance(json.loads(ln), dict):
                    return False
            except ValueError:
                return False
    return True


def summarize(lines: list[str], allow: list[str]) -> dict:
    """The sensor's flow lines -> summary.

    `flows` keeps every flow (never keyed, so nothing is dropped); `outside_allowlist`
    lists SNIs not covered by the allowlist, "(no sni)" for TLS without one, "(non-tls)"
    for a connection that did not start with a ClientHello (e.g. plaintext HTTP sent
    through CONNECT to an allowed host), and "(fault: ...)" when reassembly saw
    conflicting retransmissions: only a cleanly parsed ClientHello carries a checked SNI.
    """
    flows = []
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict) or d.get("dst_port") != 443:
            continue
        flows.append({"sni": str(d.get("sni") or ""), "ja4": str(d.get("ja4") or ""), "dst": str(d.get("dst", "")),
                      "proto": str(d.get("proto", "")), "why": str(d.get("why") or ""),
                      "fault": str(d.get("fault") or ""),
                      "bytes_out": int(d.get("bytes_out", 0) or 0), "bytes_in": int(d.get("bytes_in", 0) or 0)})
    outside = set()
    for f in flows:
        if f["fault"]:
            outside.add(f"(fault: {f['fault']})")
        if f["proto"] != "TLS":
            outside.add("(non-tls)")
        elif not f["sni"] or not _matches(f["sni"], allow):
            outside.add(f["sni"] or "(no sni)")
    return {"flows": flows, "ja4": sorted({f["ja4"] for f in flows if f["ja4"]}), "outside_allowlist": sorted(outside)}


def unobserved(s: dict, proxy_summary: dict) -> int:
    """Connections the proxy dialed that the observer has no flow for. Every allowed
    CONNECT is one outbound TCP flow to port 443 (denied ones never dial), so fewer
    flows than connections means the capture missed some (e.g. drops under load)."""
    dialed = sum(int(v.get("connections", 0)) for v in proxy_summary.get("allowed", {}).values())
    return max(0, dialed - len(s["flows"]))


def summary_line(s: dict) -> str:
    snis = sorted({f["sni"] or "(no sni)" for f in s["flows"]})
    out = f"observer: {len(s['flows'])} TLS flow(s), SNI {', '.join(snis) or 'none'}; JA4 {', '.join(s['ja4']) or 'none'}"
    if s["outside_allowlist"]:
        out += "; SNI OUTSIDE THE ALLOWLIST: " + ", ".join(s["outside_allowlist"])
    return out


class Observer:
    """The TLS sensor in the proxy pod, started before the VM and stopped after it."""

    def __init__(self, run_id: str, pod: str, iface: str, allow: list[str]):
        self.run_id = run_id
        self.pod = pod
        self.iface = iface
        self.allow = allow
        self.name = f"{pod}-observer"
        self._dir: tempfile.TemporaryDirectory | None = None
        self.summary: dict = {"flows": [], "ja4": [], "outside_allowlist": []}
        self.healthy = False                  # ran the whole time, flow file read, nothing dropped
        self.stats: dict | None = None        # the sensor's STATS line (packets, drops, overflow)
        self.keep = os.environ.get("MVM_OBSERVER_PCAP", "")   # tests: keep pcap + flows here (nDPI oracle)

    def __enter__(self) -> Observer:
        if not image_present():
            raise core.MvmError(f"observer is enabled but its image is missing: {OBSERVER_IMAGE} "
                                "(run `make observer` in the mvm repo); fetch refuses to run without it")
        if not self.iface:
            raise core.MvmError("observer: the proxy pod reported no capture interface")
        self._dir = tempfile.TemporaryDirectory(prefix="mvm-observer-")
        out = Path(self._dir.name)
        os.chmod(out, 0o700)
        try:
            subprocess.run(sidecar_argv(self.pod, self.name, self.run_id, self.iface, out, bool(self.keep)),
                           check=True, stdout=subprocess.DEVNULL)
            self._wait_ready()
        except BaseException:
            self._cleanup()
            raise
        return self

    def _logs(self) -> str:
        r = subprocess.run(["podman", "logs", self.name], capture_output=True, text=True)
        return r.stdout + r.stderr

    def _running(self) -> bool:
        r = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.Running}}", self.name],
                           capture_output=True, text=True)
        return r.stdout.strip() == "true"

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT
        while time.monotonic() < deadline:
            if READY_MARK in self._logs():
                return
            if not self._running():
                break
            time.sleep(0.2)
        raise core.MvmError(f"observer did not start capturing: {self._logs().strip()[-300:]}")

    def _stop(self) -> list[str] | None:
        alive = self._running()
        subprocess.run(["podman", "stop", "-t", "10", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        code = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.ExitCode}}", self.name],
                              capture_output=True, text=True).stdout.strip()
        lines = None
        if self._dir:
            try:
                lines = (Path(self._dir.name) / "flows.jsonl").read_text().splitlines()
            except OSError:
                lines = None
            if self.keep:
                for n in ("flows.jsonl", "cap.pcap"):
                    if (Path(self._dir.name) / n).is_file():
                        shutil.copy(Path(self._dir.name) / n, Path(self.keep) / f"{self.run_id}-{n}")
        self.stats = None
        for ln in self._logs().splitlines():
            if ln.startswith(tlsobs.STATS):
                try:
                    self.stats = json.loads(ln[len(tlsobs.STATS):])
                except ValueError:
                    self.stats = None
        st = self.stats if isinstance(self.stats, dict) else {}
        # Fail closed on capture loss: the kernel dropped nothing, no flow was turned away,
        # no frame was unreadable, and every flow line is intact.
        stats_ok = all(type(st.get(k)) is int and st[k] == 0 for k in ("drops", "overflow", "unparsed"))
        self.healthy = alive and code == "0" and lines is not None and stats_ok and _lines_ok(lines)
        return lines

    def _cleanup(self) -> None:
        subprocess.run(["podman", "rm", "-f", "-t", "2", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self._dir:
            self._dir.cleanup()
            self._dir = None

    def __exit__(self, *exc) -> bool:
        try:
            lines = self._stop()
            self.summary = summarize(lines or [], self.allow)
        finally:
            self._cleanup()
        return False
