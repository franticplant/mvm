"""Observer for fetch: a passive nDPI (ndpiReader) sidecar in the egress proxy pod.

It captures the pod's outbound leg, where the proxy relays the VM's own TLS
ClientHello, and reports per flow the SNI, JA4 and bytes. Off by default; on with
`[observer] enabled = true` in the host config. When on, it fails closed: a missing
image refuses the run, and a dead observer or unreadable output means nothing is
committed. A TLS flow whose SNI is outside the allowlist (or has none) holds the run:
the proxy only sees the CONNECT host, so this is what catches domain fronting.

Proven with a real proxy pod: pasta gives the pod MTU 65520, and ndpiReader drops
frames over ~1514 B (the ClientHello among them) unless the firewall one-shot sets
MTU 1500 first. Then SNI, JA4 and goodput (equal to Smokescreen's byte counts) appear.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from . import core

# Built by `make observer`: nDPI 6.0 release tarball pinned by sha256, pinned Debian.
OBSERVER_IMAGE = "localhost/mvm-observer:1"
READY_MARK = "Capturing live traffic"
READY_TIMEOUT = 15.0


def enabled(cfg: dict) -> bool:
    return bool(cfg.get("observer", {}).get("enabled", False))


def image_present() -> bool:
    return subprocess.run(["podman", "image", "exists", OBSERVER_IMAGE]).returncode == 0


def sidecar_argv(pod: str, name: str, run_id: str, iface: str, out: Path) -> list[str]:
    """ndpiReader parses untrusted packets: raw capture only, nothing else."""
    return ["podman", "run", "-d", "--pod", pod, "--name", name,
            "--label", f"mvm.run={run_id}", "--label", f"mvm.pid={os.getpid()}",
            "--cap-drop=all", "--cap-add=NET_RAW", "--security-opt", "no-new-privileges",
            "--read-only", "--memory", "256m", "--pids-limit", "64",
            "--stop-signal", "SIGINT",            # ndpiReader writes its flows on SIGINT
            "-v", f"{out}:/out:z", OBSERVER_IMAGE,
            "-i", iface, "-k", "/out/flows.json", "-K", "json"]


def _matches(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allow:
        a = a.lower()
        if host == a or (a.startswith("*.") and fnmatch.fnmatchcase(host, a) and host.count(".") >= a.count(".")):
            return True
    return False


def summarize(lines: list[str], allow: list[str]) -> dict:
    """Outbound TLS flows (dst port 443) from ndpiReader's JSON flow lines.

    `flows` keeps every flow (never keyed, so nothing is dropped); `outside_allowlist`
    lists SNIs not covered by the allowlist, with "(no sni)" for a flow without one.
    """
    flows = []
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict) or d.get("dst_port") != 443:
            continue
        n = d.get("ndpi") if isinstance(d.get("ndpi"), dict) else {}
        tls = n.get("tls") if isinstance(n.get("tls"), dict) else {}
        x = d.get("xfer") if isinstance(d.get("xfer"), dict) else {}
        flows.append({"sni": n.get("hostname") or "", "ja4": tls.get("ja4", ""), "dst": d.get("dest_ip", ""),
                      "proto": n.get("proto", ""),
                      "bytes_out": int(x.get("src2dst_goodput_bytes", 0) or 0),
                      "bytes_in": int(x.get("dst2src_goodput_bytes", 0) or 0)})
    outside = sorted({f["sni"] or "(no sni)" for f in flows if not f["sni"] or not _matches(f["sni"], allow)})
    return {"flows": flows, "ja4": sorted({f["ja4"] for f in flows if f["ja4"]}), "outside_allowlist": outside}


def summary_line(s: dict) -> str:
    snis = sorted({f["sni"] or "(no sni)" for f in s["flows"]})
    out = f"observer: {len(s['flows'])} TLS flow(s), SNI {', '.join(snis) or 'none'}; JA4 {', '.join(s['ja4']) or 'none'}"
    if s["outside_allowlist"]:
        out += "; SNI OUTSIDE THE ALLOWLIST: " + ", ".join(s["outside_allowlist"])
    return out


class Observer:
    """ndpiReader in the proxy pod, started before the VM and stopped after it."""

    def __init__(self, run_id: str, pod: str, iface: str, allow: list[str]):
        self.run_id = run_id
        self.pod = pod
        self.iface = iface
        self.allow = allow
        self.name = f"{pod}-observer"
        self._dir: tempfile.TemporaryDirectory | None = None
        self.summary: dict = {"flows": [], "ja4": [], "outside_allowlist": []}
        self.healthy = False                  # ran the whole time and its flow file was read

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
            subprocess.run(sidecar_argv(self.pod, self.name, self.run_id, self.iface, out),
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
                lines = (Path(self._dir.name) / "flows.json").read_text().splitlines()
            except OSError:
                lines = None
        self.healthy = alive and code == "0" and lines is not None
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
