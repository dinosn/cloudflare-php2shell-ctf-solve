"""Raw HTTP/1.1 transport.

Why not ``http.client``: the class needs

* chunked multipart bodies that can be streamed from a generator without ever
  materialising the body in memory,
* the ability to see an *early* response (a front that answers before the
  upload finishes) and to keep the partial response,
* exact control over the request line and headers for the 12 encoding
  variants,
* per-request byte and time accounting for the ledger.

The parser is deliberately forgiving: a OOM bailout can truncate a response at
any point, and that truncation is itself a signal.
"""
from __future__ import annotations

import re
import select
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

from .doctrine import NEUTRAL_UA, Doctrine, HardStop, utc_iso


class TransportError(Exception):
    """A transport-level failure that ends the phase for this host.

    Deliberately *not* an ``OSError``: the probe helpers catch ``OSError`` to
    record a dead exchange and carry on probing, which is right for a target
    that answers badly and wrong for a host that never answered at all. A
    transport failure is not target behaviour, so it must reach the phase
    runner, which records it as the host result and closes the ledger instead
    of dying with an uncaught traceback (RUN-2: 14 hosts exited rc=1 with no
    JSON document and an unfinished campaign).
    """

    def __init__(
        self,
        kind: str,
        detail: str,
        *,
        host: str = "",
        port: int = 0,
    ) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail
        self.host = host
        self.port = port

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "host": self.host,
            "port": self.port,
        }


def classify_transport_error(exc: BaseException) -> str:
    """Name the transport failure class the operator has to act on."""
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(
        exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
    ):
        return "reset"
    return "transport"


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    raw: bytes = b""
    elapsed: float = 0.0
    outcome: str = "ok"          # ok | net | dropped | hang
    error: str = ""
    at: str = ""
    sent: int = 0
    early: bool = False
    ttfb: float = 0.0
    note: str = ""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def dead(self) -> bool:
        return self.outcome in ("net", "dropped", "hang") or self.status >= 500

    def status_line(self) -> bytes:
        return self.raw.split(b"\r\n", 1)[0]


class Target:
    """A parsed http(s) URL plus its Host header."""

    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"not an http(s) URL: {url!r}")
        self.url = url
        self.tls = parsed.scheme == "https"
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.tls else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        header_host = self.host if ":" not in self.host else f"[{self.host}]"
        if self.port != (443 if self.tls else 80):
            header_host += f":{self.port}"
        self.host_header = header_host
        self.authority = f"{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.url


def dechunk(raw: bytes) -> bytes:
    """Best-effort dechunking; returns the input when it is not chunked."""
    out = bytearray()
    pos = 0
    while pos < len(raw):
        end = raw.find(b"\r\n", pos)
        if end < 0:
            out.extend(raw[pos:])
            break
        size_text = raw[pos:end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            out.extend(raw[pos:])
            break
        pos = end + 2
        if size == 0:
            break
        out.extend(raw[pos:pos + size])
        pos += size + 2
    return bytes(out)


class HttpClient:
    """One target, one doctrine, one ledger."""

    def __init__(
        self,
        target: Target,
        doctrine: Doctrine,
        *,
        ledger=None,
        read_cap: int = 1 << 20,
        user_agent: str = NEUTRAL_UA,
        insecure: bool = False,
        tls_max: str = "auto",
    ) -> None:
        self.target = target
        self.doctrine = doctrine
        self.ledger = ledger
        self.read_cap = read_cap
        self.user_agent = user_agent
        self.insecure = insecure
        self.tls_max = tls_max or "auto"
        self.requests: list[Response] = []

    def tls_context(self) -> ssl.SSLContext:
        """The client TLS context, honouring the measured version ceiling.

        A front can drop one TLS+HTTP/1.1 shape while serving another: the
        RUN-5 target answered TLS 1.2 + HTTP/1.1 in 0.36 s but blackholed
        TLS 1.3 + HTTP/1.1 (request sent, no response, 12 s timeout) while
        still accepting TLS 1.3 + h2. A silent drop is a transport fact, not
        a target verdict, so the ceiling is an operator knob, not a guess.
        """
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        ceiling = str(self.tls_max).lower()
        try:
            if ceiling in ("1.2", "tls1.2", "12"):
                context.maximum_version = ssl.TLSVersion.TLSv1_2
            elif ceiling in ("1.3", "tls1.3", "13"):
                context.minimum_version = ssl.TLSVersion.TLSv1_3
        except (ValueError, AttributeError):
            # A platform without the enum keeps its default; the caller sees
            # the negotiation in the transport failure instead of a crash.
            pass
        return context

    # -- connection --------------------------------------------------------
    def _connect(self, timeout: Optional[float] = None) -> socket.socket:
        timeout = timeout or self.doctrine.timeout
        last: Optional[OSError] = None
        for _ in range(6):
            sock: Optional[socket.socket] = None
            try:
                sock = socket.create_connection(
                    (self.target.host, self.target.port), timeout
                )
                if self.target.tls:
                    sock = self.tls_context().wrap_socket(
                        sock, server_hostname=self.target.host
                    )
                sock.settimeout(timeout)
                return sock
            except OSError as exc:
                last = exc
                # A failed handshake leaves the raw TCP socket open when
                # wrap_socket raised: close it, or six attempts leak six fds.
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                time.sleep(0.2)
        raise TransportError(
            classify_transport_error(last) if last else "transport",
            repr(last) if last else "connect failed",
            host=self.target.host,
            port=self.target.port,
        ) from last

    def open_socket(self, timeout: Optional[float] = None) -> socket.socket:
        return self._connect(timeout)

    # -- request construction ---------------------------------------------
    @staticmethod
    def build_head(
        method: str,
        path: str,
        host_header: str,
        *,
        headers: Optional[dict] = None,
        content_length: Optional[int] = None,
        chunked: bool = False,
        connection: str = "close",
        user_agent: str = NEUTRAL_UA,
    ) -> bytes:
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
        sent_names = set()
        if headers:
            for name, value in headers.items():
                lines.append(f"{name}: {value}")
                sent_names.add(name.lower())
        if "user-agent" not in sent_names:
            lines.append(f"User-Agent: {user_agent}")
        if "accept" not in sent_names:
            lines.append("Accept: */*")
        if "accept-encoding" not in sent_names:
            lines.append("Accept-Encoding: identity")
        if chunked:
            lines.append("Transfer-Encoding: chunked")
        elif content_length is not None:
            lines.append(f"Content-Length: {content_length}")
        lines.append(f"Connection: {connection}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")

    def _consume(
        self, response: Response, started: float, note: str, method: str = "GET"
    ) -> Response:
        response.elapsed = time.monotonic() - started
        response.at = utc_iso()
        response.note = note
        self.requests.append(response)
        if self.ledger is not None:
            try:
                self.ledger.record(
                    method=method,
                    path=self.target.path,
                    status=response.status,
                    sent=response.sent,
                    received=len(response.raw),
                    elapsed=response.elapsed,
                    note=note,
                )
            except Exception:  # ledger must never break a probe
                pass
        self.doctrine.note_status(response.status, response.headers, response.body)
        return response

    # -- read --------------------------------------------------------------
    def _read_response(
        self,
        sock: socket.socket,
        read_cap: int,
        *,
        stop: Optional[threading.Event] = None,
        started: Optional[float] = None,
    ) -> tuple[bytes, bool, float]:
        """Read one response; return (raw, early, time-to-first-byte)."""
        buf = bytearray()
        early = False
        first: Optional[float] = None
        try:
            while b"\r\n\r\n" not in buf and len(buf) < read_cap:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                if first is None:
                    first = time.monotonic()
                buf.extend(chunk)
        except OSError:
            return bytes(buf), early, (first - started if first and started else 0.0)
        head, sep, body = bytes(buf).partition(b"\r\n\r\n")
        if not sep:
            return bytes(buf), early, (first - started if first and started else 0.0)
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name:
                headers[name.strip().lower()] = value.strip()
        out = bytearray(body)
        try:
            if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
                while not bytes(out).endswith(b"0\r\n\r\n") and len(out) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    out.extend(chunk)
            elif b"content-length" in headers:
                try:
                    need = int(headers[b"content-length"])
                except ValueError:
                    need = 0
                while len(out) < need and len(out) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    out.extend(chunk)
        except OSError:
            pass
        return (
            head + b"\r\n\r\n" + bytes(out),
            early,
            (first - started if first and started else 0.0),
        )

    @staticmethod
    def parse(raw: bytes) -> tuple[int, dict, bytes]:
        head, _, body = raw.partition(b"\r\n\r\n")
        status = 0
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        if match:
            status = int(match.group(1))
        headers = {}
        cookies = []
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name and not name.startswith(b" "):
                key = name.strip().lower().decode("latin1")
                text = value.strip().decode("latin1", "replace")
                if key == "set-cookie":
                    cookies.append(text)
                    headers[key] = "\n".join(cookies)
                else:
                    headers[key] = text
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = dechunk(body)
        return status, headers, body

    # -- simple requests ---------------------------------------------------
    def get(
        self,
        path: Optional[str] = None,
        *,
        timeout: Optional[float] = None,
        read_cap: Optional[int] = None,
        headers: Optional[dict] = None,
        note: str = "",
    ) -> Response:
        path = path or self.target.path
        read_cap = read_cap or self.read_cap
        if self.ledger is not None:
            self.ledger.spend(note)
        self.doctrine.wait()
        self.doctrine.note_request()
        started = time.monotonic()
        response = Response()
        response.at = utc_iso()
        sock = None
        try:
            sock = self._connect(timeout)
            head = self.build_head(
                "GET",
                path,
                self.target.host_header,
                headers=headers,
                connection="close",
                user_agent=self.user_agent,
            )
            sock.sendall(head)
            raw, _, ttfb = self._read_response(sock, read_cap, started=started)
            response.raw = raw
            response.ttfb = ttfb
            response.sent = len(head)
            response.status, response.headers, response.body = self.parse(raw)
            response.outcome = "ok" if raw else "dropped"
        except HardStop:
            raise
        except OSError as exc:
            response.outcome = "net"
            response.error = repr(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return self._consume(response, started, note or "GET", "GET")

    def post(
        self,
        body: bytes | Iterable[bytes],
        *,
        headers: dict,
        chunked: bool = False,
        path: Optional[str] = None,
        timeout: Optional[float] = None,
        read_cap: Optional[int] = None,
        connection: str = "close",
        note: str = "",
        delay_between: float = 0.0,
    ) -> Response:
        """POST a bytes body or an iterable of wire blocks.

        With ``chunked`` the iterable must already carry chunk framing (use
        :func:`chunk_stream`); without it, the iterable is concatenated and a
        Content-Length is computed when the total is cheap to know.

        The whole exchange runs on the calling thread. An earlier version read
        the response from a second thread while this thread was still sending,
        which is safe for a plain socket and undefined for TLS: both calls go
        through one OpenSSL ``SSL*``, so a front that answers mid-body could
        take the process down with a silent SIGSEGV. Early answers are instead
        detected by polling readability between body blocks (see
        :meth:`_peer_answered`), and the answer is read once the send stops.
        """
        path = path or self.target.path
        read_cap = read_cap or self.read_cap
        if self.ledger is not None:
            self.ledger.spend(note)
        self.doctrine.wait()
        self.doctrine.note_request()
        started = time.monotonic()
        response = Response()
        response.at = utc_iso()
        sock: Optional[socket.socket] = None
        sender_error = None
        if isinstance(body, str):
            body = body.encode("latin1")
        if isinstance(body, (bytes, bytearray)):
            if chunked:
                # A bytes body with chunked=True is unframed user data; wrap
                # it. Iterables are assumed to be already framed by the caller
                # (chunk_stream), which is how the streaming ladders send.
                blocks: Iterator[bytes] = chunk_stream([bytes(body)])
                length: Optional[int] = None
            else:
                blocks = iter([bytes(body)])
                length = len(body)
        else:
            if chunked:
                blocks = iter(body)
                length = None
            else:
                joined = b"".join(body)
                blocks = iter([joined])
                length = len(joined)
        head = self.build_head(
            "POST",
            path,
            self.target.host_header,
            headers=headers,
            content_length=length,
            chunked=chunked,
            connection=connection,
            user_agent=self.user_agent,
        )
        sent = [len(head)]
        early_stop = False
        try:
            sock = self._connect(timeout)
            sock.sendall(head)
            first_block = True
            for block in blocks:
                if not first_block and self._peer_answered(sock):
                    # The front answered (or closed) before the body finished.
                    # Stop sending: continuing would be noise, and on an
                    # aborting stage the connection is already gone. The
                    # answer itself is read below, on this thread.
                    early_stop = True
                    break
                first_block = False
                if block:
                    sock.sendall(block)
                    sent[0] += len(block)
                if delay_between:
                    time.sleep(delay_between)
        except OSError as exc:
            sender_error = exc
        if early_stop and chunked and sock is not None:
            # A body cut before its terminating chunk never finishes, so the
            # front waits for the rest and the probe records a stall instead of
            # the refusal it actually got. Complete the framing even when the
            # peer spoke first; a closed peer turns this into an EPIPE that the
            # read below already handles.
            try:
                sock.sendall(b"0\r\n\r\n")
                sent[0] += 5
            except OSError:
                pass
        if sock is not None:
            # Read whatever the peer wrote, including the answer that arrived
            # before the send broke: the read is bounded by the socket timeout.
            raw, _, ttfb = self._read_response(sock, read_cap, started=started)
            response.raw = raw
            response.ttfb = ttfb
            try:
                sock.close()
            except OSError:
                pass
        response.sent = sent[0]
        if not response.raw and sender_error is not None:
            response.outcome = "dropped"
            response.error = repr(sender_error)
        elif not response.raw:
            response.outcome = "hang"
        else:
            response.outcome = "ok"
        if response.raw:
            response.status, response.headers, response.body = self.parse(
                response.raw
            )
        response.early = early_stop
        return self._consume(response, started, note or "POST", "POST")

    @staticmethod
    def _peer_answered(sock: socket.socket, *, tls: Optional[bool] = None) -> bool:
        """True when the peer has sent application data since the last block.

        A ``Content-Length``/chunked request that is still being sent has no
        answer to give yet, so readable-before-finished means the front is
        aborting or redirecting early. Polling keeps the check on the sending
        thread, which is what makes the TLS path safe.

        On TLS, socket readability is **not** an answer: OpenSSL's
        post-handshake records (session tickets, key updates) make ``select``
        fire while ``SSLSocket.pending()`` is still zero, and breaking the send
        there truncates a chunked body before its terminating chunk. The front
        then waits for the rest of the body, and the probe records a stall for
        a framing it accepts (live: a 2 KB chunked probe hung 180 s this way,
        while the same bytes in one ``sendall`` answered in 0.34 s). Only
        decrypted application data counts; a real early answer whose connection
        dies still surfaces as an ``EPIPE`` on the next block.
        """
        if tls is None:
            tls = isinstance(sock, ssl.SSLSocket)
        try:
            if tls:
                return bool(sock.pending())  # type: ignore[attr-defined]
            return bool(select.select([sock], [], [], 0)[0])
        except (OSError, ValueError):
            # closed under us: let the next send raise, or the read see EOF
            return True


    def exchange(
        self,
        head: bytes,
        body: bytes,
        *,
        read_cap: Optional[int] = None,
        timeout: Optional[float] = None,
        note: str = "",
    ) -> Response:
        """Send pre-built request bytes and read one response.

        A method's measured request shape sometimes *is* the contract: the
        heap geometry a chain depends on moves with the exact header set and
        body layout, so a shape cannot always be rebuilt through
        :meth:`post`.  This keeps the transport honest about that without
        exposing the socket.
        """
        read_cap = read_cap or self.read_cap
        if self.ledger is not None:
            self.ledger.spend(note)
        self.doctrine.wait()
        self.doctrine.note_request()
        started = time.monotonic()
        response = Response()
        response.at = utc_iso()
        sock = None
        try:
            sock = self._connect(timeout)
            sock.sendall(head)
            sock.sendall(body)
            raw, early, ttfb = self._read_response(sock, read_cap, started=started)
            response.raw = raw
            response.early = early
            response.ttfb = ttfb
            response.sent = len(head) + len(body)
            response.status, response.headers, response.body = self.parse(raw)
            response.outcome = "ok" if raw else "dropped"
        except HardStop:
            raise
        except OSError as exc:
            response.outcome = "net"
            response.error = repr(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return self._consume(response, started, note or "EXCHANGE", "POST")


def chunk_stream(blocks: Iterable[bytes]) -> Iterator[bytes]:
    """Wrap wire blocks in HTTP chunk framing."""
    for block in blocks:
        if not block:
            continue
        yield f"{len(block):X}\r\n".encode() + block + b"\r\n"
    yield b"0\r\n\r\n"


def multipart_frames(
    parts: Iterable[tuple],
    boundary: bytes,
    *,
    crlf_headers: bool = True,
    closing: bool = True,
) -> Iterator[bytes]:
    """Yield multipart frames.

    ``parts`` items are ``(name, data[, filename[, extra_headers]])`` where
    ``data`` may be bytes or a zero-argument callable returning an iterable of
    bytes. ``extra_headers`` is raw wire text inserted into the part header
    block (the header amplifier uses this).
    """
    eol = b"\r\n" if crlf_headers else b"\n"
    for part in parts:
        name = part[0]
        data = part[1]
        filename = part[2] if len(part) > 2 else None
        extra = part[3] if len(part) > 3 else None
        head = b"--" + boundary + eol
        head += b'Content-Disposition: form-data; name="' + str(name).encode() + b'"'
        if filename is not None:
            head += b'; filename="' + str(filename).encode() + b'"'
            head += eol + b"Content-Type: application/octet-stream"
        yield head + eol
        if extra:
            if callable(extra):
                yield from extra()
            else:
                yield extra
            yield eol
        else:
            yield eol
        if callable(data):
            yield from data()
        else:
            yield data
        yield eol
    if closing:
        yield b"--" + boundary + b"--" + eol


def body_length(parts: Iterable[tuple], boundary: bytes) -> int:
    total = 0
    for block in multipart_frames(parts, boundary):
        total += len(block)
    return total


def multipart_body(parts, boundary: bytes) -> bytes:
    return b"".join(multipart_frames(parts, boundary))
