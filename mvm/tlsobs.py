"""mvm's TLS observer: a passive ClientHello sensor for the egress proxy pod (stdlib only).

Clean-room from RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN), RFC 8701 (GREASE)
and FoxIO's BSD-3 JA4 specification (JA4 TLS client only: never JA4+). Nothing here is
derived from nDPI; nDPI 5.0 serves only as a black-box oracle in the real tests.

Runs inside the proxy pod's network namespace with CAP_NET_RAW. An AF_PACKET socket sees
every frame of the pod's outbound interface. Per outbound TCP connection to port 443 it
reassembles the client's first bytes and reports whether they are a TLS ClientHello,
plus its SNI and JA4 and the stream bytes in each direction. It never blocks anything:
mvm holds the run afterwards (exit 3), or fails it (exit 5) when the capture was not
complete (kernel drops, too many flows, conflicting retransmissions).

Also imported by mvm (pure functions: `parse_client_hello`, `ja4`, `Flow`). As a script:
    python3 -I -B tlsobs.py IFACE OUT.jsonl [--pcap FILE]
prints READY when capturing; on SIGINT/SIGTERM writes one JSON line per flow to OUT and
prints one `STATS {...}` line, then exits 0.
"""

from __future__ import annotations

import hashlib
import json
import signal
import socket
import struct
import sys

READY = "mvm-tlsobs: capturing"
STATS = "mvm-tlsobs-stats "
PORT = 443
MAX_FLOWS = 4096
HELLO_CAP = 32 * 1024          # client bytes buffered per flow until the ClientHello is complete
PENDING_CAP = 64 * 1024        # out-of-order client bytes held per flow

# ---------------------------------------------------------------- ClientHello parsing

TLS_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
                0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}
EXT_SNI, EXT_ALPN, EXT_SIGALGS, EXT_VERSIONS = 0x0000, 0x0010, 0x000d, 0x002b


def is_grease(v: int) -> bool:
    """RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


class NeedMore(Exception):
    """The bytes so far are a valid prefix of a ClientHello; more are needed."""


class NotHello(Exception):
    """The bytes are not (or not a well-formed) TLS ClientHello."""


class _Reader:
    def __init__(self, data: bytes, what: str):
        self.d, self.i, self.what = data, 0, what

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise NotHello(f"{self.what}: truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def vec(self, lenbytes: int) -> bytes:
        n = int.from_bytes(self.take(lenbytes), "big")
        return self.take(n)

    def done(self) -> bool:
        return self.i == len(self.d)


def handshake_bytes(stream: bytes) -> bytes:
    """The first handshake message from the start of a client's TCP stream, joining the
    fragments of consecutive handshake records (a ClientHello may span records)."""
    if not stream:
        raise NeedMore
    if stream[0] != 0x16:
        raise NotHello(f"first byte 0x{stream[0]:02x} is not a TLS handshake record")
    hs, i = b"", 0
    while True:
        if len(stream) < i + 5:
            raise NeedMore
        ctype, ver, rlen = stream[i], struct.unpack(">H", stream[i + 1:i + 3])[0], struct.unpack(">H", stream[i + 3:i + 5])[0]
        if ctype != 0x16:
            raise NotHello(f"record type 0x{ctype:02x} before the ClientHello was complete")
        if ver >> 8 != 0x03 or rlen == 0 or rlen > 16384 + 256:
            raise NotHello("bad TLS record header")
        if len(stream) < i + 5 + rlen:
            raise NeedMore
        hs += stream[i + 5:i + 5 + rlen]
        i += 5 + rlen
        if len(hs) >= 4:
            if hs[0] != 0x01:
                raise NotHello(f"handshake type {hs[0]} is not ClientHello")
            need = 4 + int.from_bytes(hs[1:4], "big")
            if need > HELLO_CAP:
                raise NotHello("ClientHello larger than the cap")
            if len(hs) >= need:
                return hs[4:need]


def _u16s(v: bytes, what: str) -> list[int]:
    if len(v) % 2:
        raise NotHello(f"{what}: odd length")
    return list(struct.unpack(f">{len(v) // 2}H", v))


def parse_client_hello(body: bytes) -> dict:
    """ClientHello body (after the 4-byte handshake header) -> its fields, wire order kept."""
    r = _Reader(body, "ClientHello")
    legacy = r.u16()
    r.take(32)                                   # random
    r.vec(1)                                     # legacy_session_id
    cs = r.vec(2)
    if not cs:
        raise NotHello("no cipher_suites")
    ciphers = _u16s(cs, "cipher_suites")
    r.vec(1)                                     # legacy_compression_methods
    exts: list[int] = []
    sni, alpn, sigalgs, versions = None, [], [], []
    if not r.done():
        er = _Reader(r.vec(2), "extensions")
        if not r.done():
            raise NotHello("trailing bytes after extensions")
        while not er.done():
            etype, edata = er.u16(), er.vec(2)
            if etype in exts:                    # RFC 8446 4.2: a server may resolve duplicates differently
                raise NotHello(f"duplicate extension 0x{etype:04x}")
            exts.append(etype)
            x = _Reader(edata, f"extension 0x{etype:04x}")
            if etype == EXT_SNI and edata:
                lst = _Reader(x.vec(2), "server_name_list")
                while not lst.done():
                    kind, name = lst.u8(), lst.vec(2)
                    if kind == 0:
                        if sni is not None:      # RFC 6066 3: one host_name only
                            raise NotHello("more than one host_name in server_name")
                        sni = name.decode("ascii", "backslashreplace")
            elif etype == EXT_ALPN:
                lst = _Reader(x.vec(2), "alpn")
                while not lst.done():
                    alpn.append(lst.vec(1))
            elif etype == EXT_SIGALGS:
                sigalgs = _u16s(x.vec(2), "signature_algorithms")
            elif etype == EXT_VERSIONS:
                versions = _u16s(x.vec(1), "supported_versions")
            else:
                continue
            if not x.done():
                raise NotHello(f"trailing bytes in extension 0x{etype:04x}")
    return {"legacy_version": legacy, "ciphers": ciphers, "extensions": exts, "sni": sni,
            "alpn": alpn, "sigalgs": sigalgs, "versions": versions}


def _hash12(items: list[str]) -> str:
    return hashlib.sha256(",".join(items).encode()).hexdigest()[:12] if items else "000000000000"


def _alpn_chars(alpn: list[bytes]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first, last = alpn[0][0], alpn[0][-1]
    if chr(first).isascii() and chr(first).isalnum() and chr(last).isascii() and chr(last).isalnum():
        return chr(first) + chr(last)
    h = alpn[0].hex()
    return h[0] + h[-1]


def tls_version(h: dict) -> str:
    """Highest offered version, as in JA4 ("13", "12", ...; "00" unknown)."""
    versions = [v for v in h["versions"] if v in TLS_VERSIONS]      # drops GREASE and unknown drafts
    return TLS_VERSIONS.get(max(versions) if versions else h["legacy_version"], "00")


def ja4(h: dict, transport: str = "t") -> str:
    """JA4 (TLS client) per FoxIO's BSD-3 specification."""
    ver = tls_version(h)
    ciphers = [c for c in h["ciphers"] if not is_grease(c)]
    exts = [e for e in h["extensions"] if not is_grease(e)]
    a = (f"{transport}{ver}{'d' if EXT_SNI in exts else 'i'}"
         f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_chars(h['alpn'])}")
    b = _hash12(sorted(f"{c:04x}" for c in ciphers))
    ext_part = sorted(f"{e:04x}" for e in exts if e not in (EXT_SNI, EXT_ALPN))
    sig = [f"{s:04x}" for s in h["sigalgs"] if not is_grease(s)]
    c = "000000000000" if not ext_part else (
        hashlib.sha256((",".join(ext_part) + ("_" + ",".join(sig) if sig else "")).encode()).hexdigest()[:12])
    return f"{a}_{b}_{c}"


def classify(stream: bytes) -> dict | None:
    """Client stream prefix -> {"proto": "TLS", "sni", "ja4"} or {"proto": "non-TLS", "why"};
    None while more bytes are needed."""
    try:
        h = parse_client_hello(handshake_bytes(stream))
    except NeedMore:
        return None
    except NotHello as e:
        return {"proto": "non-TLS", "why": str(e)}
    return {"proto": "TLS", "sni": h["sni"] or "", "ja4": ja4(h),
            "alpn": h["alpn"][0].decode("ascii", "backslashreplace") if h["alpn"] else "",
            "tls_version": tls_version(h)}


# ---------------------------------------------------------------- TCP reassembly

def _rel(seq: int, base: int) -> int:
    return (seq - base) & 0xffffffff


SPLT_LEN = 20                                    # data packets kept per flow for the ETA sequence


class Flow:
    """One outbound TCP connection to port 443, keyed by its 4-tuple.

    Besides the ClientHello it keeps observe-only encrypted-traffic-analysis features
    (nothing is enforced on them): kernel timestamps of the first and last packet,
    packet counts each way, and SPLT, the first SPLT_LEN data-carrying packets as
    [signed payload length (+ out, - in), ms since the previous data packet (the first:
    since the SYN)]."""

    def __init__(self, dst: str, isn: int, ts: float = 0.0):
        self.dst, self.isn = dst, isn
        self.t_start = self.t_last = self.t_data = ts
        self.pkts_out = 1                         # the SYN
        self.pkts_in = 0
        self.splt: list[list] = []
        self.established = False
        self.server_isn: int | None = None
        self.buf = bytearray()                   # client bytes from offset 0, until classified
        self.pending: dict[int, bytes] = {}
        self.result: dict | None = None
        self.out_end = 0                         # highest client stream offset seen
        self.in_end = 0
        self.closed = False
        self.fault = ""                          # capture fault (conflicting overlap, cap)

    def client_data(self, seq: int, data: bytes) -> None:
        off = _rel(seq, (self.isn + 1) & 0xffffffff)
        if off > 0x7fffffff:                     # before the stream start (e.g. retransmitted SYN data)
            return
        self.out_end = max(self.out_end, off + len(data))
        if self.result is not None or not data:
            return
        self._add(off, data)
        self.result = classify(bytes(self.buf))
        if self.result is None and len(self.buf) >= HELLO_CAP:
            self.result = {"proto": "non-TLS", "why": "no complete ClientHello within the cap"}
        if self.result is not None:
            self.buf, self.pending = bytearray(), {}

    def _add(self, off: int, data: bytes) -> None:
        end = off + len(data)
        have = len(self.buf)
        if off < have:                           # overlap with bytes already assembled
            same = min(end, have) - off
            if self.buf[off:off + same] != data[:same]:
                self.fault = "conflicting retransmission"
            data, off = data[same:], have
        if not data:
            return
        if off == len(self.buf):
            self.buf += data
            while True:                          # drain out-of-order segments now contiguous
                ready = [o for o in self.pending if o <= len(self.buf)]
                if not ready:
                    break
                o = min(ready)
                seg = self.pending.pop(o)
                same = min(len(self.buf) - o, len(seg))
                if self.buf[o:o + same] != seg[:same]:
                    self.fault = "conflicting retransmission"
                self.buf += seg[same:]
        else:
            prev = self.pending.get(off)
            if prev is not None and prev[:len(data)] != data[:len(prev)]:
                self.fault = "conflicting retransmission"
            self.pending[off] = data if prev is None or len(data) > len(prev) else prev
            if sum(len(v) for v in self.pending.values()) > PENDING_CAP:
                self.fault = "too much out-of-order data"
                self.pending.clear()

    def server_data(self, seq: int, n: int) -> None:
        if self.server_isn is None:
            return
        off = _rel(seq, (self.server_isn + 1) & 0xffffffff)
        if off <= 0x7fffffff:
            self.in_end = max(self.in_end, off + n)

    def seen(self, ts: float, outgoing: bool, payload_len: int) -> None:
        """Count one packet of this flow (timestamps from the kernel ring)."""
        if outgoing:
            self.pkts_out += 1
        else:
            self.pkts_in += 1
        self.t_last = max(self.t_last, ts)
        if payload_len and len(self.splt) < SPLT_LEN:
            self.splt.append([payload_len if outgoing else -payload_len,
                              round(max(0.0, ts - self.t_data) * 1000, 3)])
            self.t_data = ts

    def record(self) -> dict:
        r = self.result or {"proto": "non-TLS", "why": "connection ended before a ClientHello"
                            if self.closed else "no ClientHello seen"}
        total = self.out_end + self.in_end
        return {"dst": self.dst, "dst_port": PORT, "proto": r["proto"], "sni": r.get("sni", ""),
                "ja4": r.get("ja4", ""), "why": r.get("why", ""), "fault": self.fault,
                "bytes_out": self.out_end, "bytes_in": self.in_end,
                "ts_start": self.t_start, "duration_ms": round((self.t_last - self.t_start) * 1000, 3),
                "pkts_out": self.pkts_out, "pkts_in": self.pkts_in,
                "data_ratio": round(self.out_end / total, 4) if total else None,
                "alpn": r.get("alpn", ""), "tls_version": r.get("tls_version", ""), "splt": self.splt}


class Tracker:
    """Frames in (direction known from the kernel), flows out."""

    def __init__(self):
        self.flows: dict[tuple, Flow] = {}
        self.all: list[Flow] = []                # every flow, in order: a reused port never hides one
        self.overflow = 0

    def packet(self, ip: bytes, outgoing: bool, ts: float = 0.0) -> None:
        t = _tcp(ip)
        if t is None:
            return
        src, dst, sport, dport, seq, flags, payload_len, payload = t
        if outgoing and dport == PORT:
            key = (src, sport, dst, dport)
            f = self.flows.get(key)
            if flags & 0x02 and not flags & 0x10:          # SYN: a new connection (or its retry)
                if f is None or f.isn != seq:            # same ISN: a retransmitted SYN
                    if len(self.all) >= MAX_FLOWS:
                        self.overflow += 1
                        return
                    self.flows[key] = Flow(dst, seq, ts)
                    self.all.append(self.flows[key])
                else:                                      # a retransmitted SYN
                    f.seen(ts, True, 0)
                return
            if f is None:
                return                                     # started before the capture: unobserved
            f.seen(ts, True, payload_len)
            if flags & 0x20 and f.result is None:
                f.fault = "TCP urgent data"               # never from Smokescreen's own stack
            if payload_len and payload is None:
                f.fault = "outbound payload not captured"
            elif payload:
                f.client_data(seq, payload)
            if flags & 0x05:                               # FIN or RST
                f.closed = True
        elif not outgoing and sport == PORT:
            f = self.flows.get((dst, dport, src, sport))
            if f is None:
                return
            f.seen(ts, False, payload_len)
            if flags & 0x12 == 0x12:                       # SYN-ACK
                f.established, f.server_isn = True, seq
                return
            f.server_data(seq, payload_len)
            if flags & 0x05:
                f.closed = True

    def records(self) -> list[dict]:
        """Established connections only: a SYN that was never answered carried no data."""
        return [f.record() for f in self.all if f.established]


UNPARSED = [0]                                  # IP frames we cannot read as TCP: fragments, IPv6 ext headers


def _tcp(ip: bytes):
    """IPv4/IPv6 + TCP headers -> (src, dst, sport, dport, seq, flags, payload_len, payload).
    payload is None when the frame was captured truncated (inbound frames are, on purpose)."""
    if len(ip) < 20:
        return None
    v = ip[0] >> 4
    if v == 4:
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6 or ihl < 20 or len(ip) < ihl + 20:
            return None
        if struct.unpack(">H", ip[6:8])[0] & 0x3fff:        # a fragment: Linux TCP sets DF, so never expected
            UNPARSED[0] += 1
            return None
        total = struct.unpack(">H", ip[2:4])[0] or len(ip)
        src, dst, off = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20]), ihl
    elif v == 6:
        if ip[6] in (0, 43, 44, 50, 51, 60):                 # extension headers: never from kernel TCP here
            UNPARSED[0] += 1
            return None
        if ip[6] != 6 or len(ip) < 60:
            return None
        total = 40 + struct.unpack(">H", ip[4:6])[0] if struct.unpack(">H", ip[4:6])[0] else len(ip)
        src, dst, off = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40]), 40
    else:
        return None
    sport, dport, seq = struct.unpack(">HHI", ip[off:off + 8])
    doff = (ip[off + 12] >> 4) * 4
    flags = ip[off + 13]
    start = off + doff
    if doff < 20 or start > total:
        return None
    plen = max(0, total - start)
    payload = ip[start:total] if len(ip) >= total else None
    return src, dst, sport, dport, seq, flags, plen, payload


# ---------------------------------------------------------------- capture (script mode)

ETH_P_ALL, SOL_PACKET, PACKET_STATISTICS, SO_ATTACH_FILTER = 0x0003, 263, 6, 26
PACKET_OUTGOING = 4
SKF_AD_PKTTYPE = 0xfffff000 + 4


def _attach_filter(s: socket.socket) -> None:
    """Classic BPF: whole outgoing frames, only the first 192 bytes of incoming ones (headers
    are enough to count a download's bytes), so big downloads copy little."""
    import ctypes
    prog = [(0x20, 0, 0, SKF_AD_PKTTYPE),                  # ld  pkttype
            (0x15, 0, 1, PACKET_OUTGOING),                  # jeq #OUTGOING
            (0x06, 0, 0, 262144),                           # ret whole frame
            (0x06, 0, 0, 192)]                              # ret headers only
    insns = b"".join(struct.pack("=HBBI", *i) for i in prog)
    buf = ctypes.create_string_buffer(insns)
    fprog = struct.pack("=HxxI", len(prog), ctypes.addressof(buf)) if struct.calcsize("P") == 4 else \
        struct.pack("=HxxxxxxQ", len(prog), ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)        # the kernel copies the program


class Pcap:
    """Minimal pcap writer (LINKTYPE_RAW: IP packets), for the nDPI oracle in real tests."""

    def __init__(self, path: str):
        self.f = open(path, "wb")
        self.f.write(struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101))

    def write(self, ts: float, ip: bytes, orig_len: int) -> None:
        self.f.write(struct.pack("=IIII", int(ts), int(ts % 1 * 1e6), len(ip), orig_len) + ip)


PACKET_VERSION, PACKET_RX_RING, TPACKET_V3 = 10, 5, 2
TP_STATUS_USER = 1
RING_BLOCK, RING_BLOCKS = 1 << 20, 64          # 64 MiB ring: not limited by net.core.rmem_max


def _ring(s: socket.socket):
    """A TPACKET_V3 receive ring: the kernel writes frames (truncated by the BPF program)
    straight into it, so a burst of large downloads cannot overflow a socket buffer."""
    import mmap
    s.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
    frame = 2048
    req = struct.pack("=IIIIIII", RING_BLOCK, RING_BLOCKS, frame, RING_BLOCK * RING_BLOCKS // frame,
                      20, 0, 0)                 # retire a partly filled block after 20 ms
    s.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
    return mmap.mmap(s.fileno(), RING_BLOCK * RING_BLOCKS, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)


def _blocks(ring, start: int):
    """Yield (block_index, [(ip_bytes, outgoing, kernel_timestamp)]) for every block the kernel handed over,
    starting at `start`, and give each block back after its frames are read."""
    i = start
    while True:
        base = i * RING_BLOCK
        status, num, first = struct.unpack_from("=III", ring, base + 8)
        if not status & TP_STATUS_USER:
            return
        frames, off = [], base + first
        for _ in range(num):
            nxt, sec, nsec, snap, _len, _st, mac, net = struct.unpack_from("=IIIIIIHH", ring, off)
            pkttype = ring[off + 48 + 10]                       # sockaddr_ll.sll_pkttype
            frames.append((ring[off + net:off + mac + snap], pkttype == PACKET_OUTGOING, sec + nsec / 1e9))
            off += nxt
        struct.pack_into("=I", ring, base + 8, 0)               # TP_STATUS_KERNEL: give it back
        i = (i + 1) % RING_BLOCKS
        yield i, frames


def capture(iface: str, out: str, pcap: str | None = None) -> int:
    import select
    import time
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)    # protocol 0: receives nothing until bound
    _attach_filter(s)
    ring = _ring(s)
    s.bind((iface, ETH_P_ALL))
    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    tr, packets, drops, nxt = Tracker(), 0, 0, 0
    pw = Pcap(pcap) if pcap else None
    print(f"{READY} on {iface}", flush=True)

    def drain() -> int:
        nonlocal nxt, packets
        seen = 0
        for following, frames in _blocks(ring, nxt):
            seen += len(frames)
            nxt = following                     # resume here next time
            for ip, outgoing, ts in frames:
                if not ip or ip[0] >> 4 not in (4, 6):
                    continue
                packets += 1
                tr.packet(ip, outgoing, ts)
                if pw and outgoing:
                    pw.write(ts, ip, len(ip))
        return seen

    while not stop:
        try:
            select.select([s], [], [], 0.2)
        except InterruptedError:
            pass
        drain()
    drain()
    for _ in range(10):                         # the last, partly filled block retires after 20 ms
        time.sleep(0.05)
        if not drain():
            break
    st = s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 12)   # tpacket_stats_v3
    drops += struct.unpack("=III", st)[1]
    with open(out, "w") as f:
        for r in tr.records():
            f.write(json.dumps(r) + "\n")
    if pw:
        pw.f.close()
    print(STATS + json.dumps({"packets": packets, "drops": drops, "overflow": tr.overflow, "unparsed": UNPARSED[0],
                              "faults": sum(1 for f in tr.all if f.fault)}), flush=True)
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    pc = None
    if "--pcap" in a:
        i = a.index("--pcap")
        pc = a[i + 1]
        del a[i:i + 2]
    if len(a) != 2:
        sys.exit("usage: tlsobs.py IFACE OUT.jsonl [--pcap FILE]")
    sys.exit(capture(a[0], a[1], pc))
