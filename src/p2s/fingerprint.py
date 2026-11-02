"""Version and banner fingerprinting — a remediation flag, never a verdict.

Rules encoded here:

* the fixed line for the 2026-10-21 security release is 8.2.35 / 8.3.36 /
  8.4.27 / 8.5.12; a version below its branch's line is ``vulnerable``,
  at/above is ``patched``, an unsupported branch is ``eol``,
* a two-component banner (``PHP/8.5``) has no patch level and is a blind
  spot: report ``blind_spot``, do not guess,
* ``expose_php=Off`` (no ``X-Powered-By``) is ``no_signal``, not "patched",
* banner state never decides the route; the behavioural crash matrix does.
  Distro/vendor backports can carry the fix under a stale banner, and a
  build can be changed under a fixed one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?")

# branch -> (fixed patch level)
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
SUPPORTED_BRANCHES = set(FIXED_VERSIONS)

CACHE_MARKERS = (
    "age",
    "via",
    "x-cache",
    "x-cache-status",
    "x-cache-hits",
    "cf-cache-status",
    "x-grace",
    "x-served-by",
    "x-proxy-cache",
    "x-varnish",
    "x-fastly-request-id",
)


@dataclass
class Banner:
    status: int = 0
    server: str = ""
    powered_by: str = ""          # full X-Powered-By string, verbatim
    version: Optional[tuple] = None
    version_text: str = ""
    version_state: str = "unknown"      # vulnerable|patched|eol|unknown|blind_spot|no_signal
    version_reason: str = ""
    two_component: bool = False
    expose_php_off: bool = False
    cache_markers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body_len: int = 0
    sapi_hint: str = "unknown"          # mod_php|fpm_or_cgi|unknown
    front: str = ""                     # apache|nginx|litespeed|other|unknown
    anomalous_session_id: bool = False
    tls: bool = False

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "server": self.server,
            "powered_by": self.powered_by,
            "version": ".".join(str(p) for p in self.version) if self.version else "",
            "version_text": self.version_text,
            "version_state": self.version_state,
            "version_reason": self.version_reason,
            "two_component": self.two_component,
            "expose_php_off": self.expose_php_off,
            "cache_markers": self.cache_markers,
            "set_cookies": self.set_cookies,
            "body_len": self.body_len,
            "sapi_hint": self.sapi_hint,
            "front": self.front,
            "anomalous_session_id": self.anomalous_session_id,
            "tls": self.tls,
        }


def version_state(version: Optional[tuple]) -> tuple[str, str]:
    if not version:
        return "no_signal", "no parsable PHP version in any banner"
    if len(version) < 3:
        return (
            "blind_spot",
            "two-component banner has no patch level; the parser fix line "
            "cannot be applied to it",
        )
    branch = version[:2]
    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        if branch < (8, 2):
            return (
                "eol",
                f"PHP {'.'.join(map(str, version))} is out of support; only "
                "unofficial backports carry the parser fix",
            )
        return (
            "unknown",
            f"PHP {'.'.join(map(str, version))}: branch has no fixed release in "
            "the map",
        )
    fixed_tuple = branch + (fixed,)
    if version < fixed_tuple:
        return (
            "vulnerable",
            f"PHP {'.'.join(map(str, version))} < fixed "
            f"{'.'.join(map(str, fixed_tuple))}",
        )
    return (
        "patched",
        f"PHP {'.'.join(map(str, version))} >= fixed "
        f"{'.'.join(map(str, fixed_tuple))}",
    )


def parse_version(text: str) -> tuple[Optional[tuple], bool]:
    """Return (version tuple, two_component)."""
    match = VERSION_PATTERN.search(text or "")
    if not match:
        return None, False
    major, minor, patch = match.group(1), match.group(2), match.group(3)
    if patch is None:
        return (int(major), int(minor)), True
    return (int(major), int(minor), int(patch)), False


def sapi_hint(server: str, powered_by: str, *, front: str = "") -> str:
    """Classify the PHP execution model from headers only.

    This is the coarse first pass; ``precheck.sapi`` refines it with keep-alive
    and behavioural probes. The decisive structural fact: mod_php cannot run
    inside nginx or LiteSpeed, so a non-Apache front means the PHP worker is
    FPM/CGI behind it.
    """
    server_l = (server or "").lower()
    powered = bool(powered_by)
    if "litespeed" in server_l or "openlitespeed" in server_l:
        return "fpm_or_cgi"
    if "nginx" in server_l:
        return "fpm_or_cgi"
    if "apache" in server_l or "httpd" in server_l:
        return "mod_php" if powered else "fpm_or_cgi"
    if front and front not in ("apache", "unknown"):
        return "fpm_or_cgi"
    return "mod_php" if powered else "unknown"


def front_kind(server: str) -> str:
    server_l = (server or "").lower()
    if "litespeed" in server_l or "openlitespeed" in server_l:
        return "litespeed"
    if "nginx" in server_l:
        return "nginx"
    if "apache" in server_l or "httpd" in server_l:
        return "apache"
    if "cloudflare" in server_l:
        return "cloudflare"
    if "microsoft-iis" in server_l:
        return "iis"
    return "other" if server_l else "unknown"


def analyse(response, *, tls: bool = False) -> Banner:
    """Build a :class:`Banner` from one root GET response."""
    banner = Banner(status=response.status, tls=tls)
    banner.server = response.header("server")
    banner.powered_by = response.header("x-powered-by")
    banner.body_len = len(response.body or b"")
    version, two = parse_version(
        banner.powered_by or response.text[:4096]
    )
    banner.version = version
    banner.two_component = two
    banner.version_text = (
        ".".join(str(p) for p in version) if version else ""
    )
    state, reason = version_state(version)
    banner.version_state = state
    banner.version_reason = reason
    banner.expose_php_off = not bool(banner.powered_by)
    banner.cache_markers = {
        name: response.header(name)
        for name in CACHE_MARKERS
        if response.header(name)
    }
    for cookie in response.headers.get("set-cookie", "").replace("\n", ",").split(","):
        if cookie.strip():
            banner.set_cookies.append(cookie.strip()[:200])
    banner.front = front_kind(banner.server)
    banner.sapi_hint = sapi_hint(banner.server, banner.powered_by, front=banner.front)
    banner.anomalous_session_id = anomalous_phpsessid(banner.set_cookies)
    return banner


def anomalous_phpsessid(set_cookies: list) -> bool:
    """The freed-memory reflection shape: an oversized/non-charset SID."""
    for cookie in set_cookies:
        if "phpsessid=" not in cookie.lower():
            continue
        value = cookie.split("=", 1)[1].split(";", 1)[0]
        if len(value) > 128:
            return True
        if value and not re.fullmatch(r"[A-Za-z0-9_,-]+", value):
            return True
    return False


def parse_session_id(set_cookies: list) -> str:
    for cookie in set_cookies:
        lowered = cookie.lower()
        if "phpsessid=" not in lowered:
            continue
        start = lowered.index("phpsessid=") + len("phpsessid=")
        return cookie[start:].split(";", 1)[0].strip()
    return ""
