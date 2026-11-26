"""mvm run -p: inbound-only port bridge (stdlib only).

The workload's pod has --network=none: only loopback exists there, so nothing in it can
open a connection anywhere. Inbound connections cross in through Unix sockets:

  host 127.0.0.1:HOST  --(mvm, on the host)-->  DIR/p<CONT>.sock
  DIR/p<CONT>.sock     --(sidecar, in the pod)-->  127.0.0.1:CONT  (the microVM)

The sidecar runs this file (`python3 -I -B portbridge.py SOCKDIR CONT...`); the host
side imports it. Each side only accepts and dials one fixed target: the workload can
answer, never initiate, because nothing listens towards the host for it.
"""

from __future__ import annotations

import os
import socket
import sys
import threading

READY = "MVM-BRIDGE-READY"


def sock_name(cont: int) -> str:
    return f"p{cont}.sock"


def splice(a: socket.socket, b: socket.socket) -> None:
    """Copy both ways until both directions end (half-close kept), then close both."""
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()
    a.close()
    b.close()


def serve(listener: socket.socket, dial) -> None:
    """Accept forever; for each connection dial the one target and splice."""
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return                     # listener closed: stop
        threading.Thread(target=_one, args=(conn, dial), daemon=True).start()


def _one(conn: socket.socket, dial) -> None:
    try:
        up = dial()
    except OSError:
        conn.close()                   # nothing listening yet: refuse this one
        return
    splice(conn, up)


def pod_side(sockdir: str, ports: list[int]) -> None:
    """In the pod: one Unix socket per container port, each forwarding to 127.0.0.1:port."""
    threads = []
    for cont in ports:
        path = os.path.join(sockdir, sock_name(cont))
        if os.path.lexists(path):
            os.unlink(path)
        ln = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ln.bind(path)
        ln.listen(64)

        def dial(cont=cont):
            return socket.create_connection(("127.0.0.1", cont), timeout=10)
        t = threading.Thread(target=serve, args=(ln, dial), daemon=True)
        t.start()
        threads.append(t)
    print(READY, flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    pod_side(sys.argv[1], [int(p) for p in sys.argv[2:]])
