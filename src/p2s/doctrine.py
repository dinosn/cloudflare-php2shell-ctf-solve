"""Engagement doctrine: pacing, backoff, hard stops, clean-traffic ordering.

The rules encoded here are the ones the program learned the hard way:

* one request per ``pace`` seconds on a remote host (six by default); a
  loopback lab target runs without the remote pause so a ladder is practical,
* a storm of 403/429/503 responses pauses the campaign for two minutes; two
  such pauses end the campaign rather than escalating into the challenge,
* a bot challenge is a hard stop with explicit resume criteria: continuing
  only deepens the block and is never a "measurement",
* probes are ordered storm-risk-last: banners and session probes first, the
  body-ceiling and memory ladders after them, the pool ramp last, so the
  precheck itself does not create the 413/502 storm that arms a challenge,
* no persistence on the target beyond the explicit proof artefact.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# A neutral desktop UA. The tool is not a browser and does not pretend to be
# a specific one; it simply avoids the empty/curl default that several WAFs
# score as a scanner.
NEUTRAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

THROTTLE_STATUSES = {403, 429, 503}
# Death classification anchors (measured): a real parser OOM answers in
# 0.03-3.9 s (ttfb 0.004-0.05 s); a per-part/front artefact holds for a
# constant ~17-18 s. These thresholds come from the calibration reference and
# the campaign record.
FAST_DEATH_SECONDS = 5.0
SLOW_ARTIFACT_SECONDS = 12.0
# Markers that mean "an interstitial answered, not the application". Cloudflare
# is the common case; the generic strings cover the other challenge vendors.
CHALLENGE_HEADERS = ("cf-ray", "cf-mitigated", "x-datadome", "x-sucuri-id")
CHALLENGE_BODY_MARKERS = (
    b"just a moment",
    b"cf-challenge",
    b"attention required",
    b"captcha-delivery",
    b"_incapsula_resource",
    b"enable javascript and cookies to continue",
)
CHALLENGE_COOKIE_MARKERS = ("__cf_bm", "datadome", "incap_ses", "visid_incap")


class HardStop(RuntimeError):
    """A doctrine stop: the campaign must park, not retry."""

    def __init__(self, reason: str, *, marker: str = "", resume: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.marker = marker
        self.resume = resume

    def as_dict(self) -> dict:
        return {
            "active": True,
            "reason": self.reason,
            "marker": self.marker,
            "resume_criteria": self.resume
            or (
                "challenge must clear on its own; re-run precheck after 24 h and "
                "confirm a neutral GET returns application content, not an "
                "interstitial"
            ),
        }


@dataclass
class Doctrine:
    """Pacing + throttle state for one target."""

    pace: float = 6.0
    backoff_seconds: float = 120.0
    max_backoffs: int = 2
    loopback: bool = False
    timeout: float = 20.0
    authorized: bool = False
    started: float = field(default_factory=time.monotonic, init=False)
    last_request: float = field(default=0.0, init=False)
    requests: int = field(default=0, init=False)
    throttle_window: list = field(default_factory=list, init=False)
    backoffs: int = field(default=0, init=False)
    challenge: Optional[HardStop] = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.loopback and self.pace == 6.0:
            # Loopback is the lab, not a third party. The remote default stays
            # six seconds; the operator can still set --pacing explicitly.
            self.pace = 0.2

    # -- pacing ------------------------------------------------------------
    def wait(self) -> None:
        if self.pace <= 0 or not self.last_request:
            return
        target = self.last_request + self.pace
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def note_request(self) -> None:
        self.requests += 1
        self.last_request = time.monotonic()

    # -- throttle / challenge ---------------------------------------------
    def note_status(self, status: int, headers: dict, body: bytes) -> None:
        if self._is_challenge(status, headers, body):
            if self.challenge is None:
                self.challenge = HardStop(
                    "bot challenge active",
                    marker=self._challenge_marker(headers, body),
                )
            raise self.challenge
        if self._is_throttle(status, headers, body):
            now = time.monotonic()
            self.throttle_window = [
                t for t in self.throttle_window if now - t <= 120.0
            ]
            self.throttle_window.append(now)
            if len(self.throttle_window) >= 3 and self.backoff_seconds > 0:
                self.backoffs += 1
                self.throttle_window.clear()
                if self.backoffs > self.max_backoffs:
                    raise HardStop(
                        "throttle storm persisted through the backoff budget",
                        marker=f"consecutive statuses {status}",
                        resume="re-run after the edge stops throttling; do not "
                        "raise request volume",
                    )
                time.sleep(self.backoff_seconds)

    @staticmethod
    def _is_throttle(status: int, headers: dict, body: bytes) -> bool:
        """Rate limiting, not a deterministic filter.

        A 403 from a WAF rule or a LiteSpeed multipart rule is a decision the
        campaign should record, not a reason to sleep two minutes; only 429/503
        (or a 403 that explicitly signals rate limiting) enters the backoff.
        """
        if status in (429, 503):
            return True
        if status != 403:
            return False
        if headers.get("retry-after"):
            return True
        lowered = (body or b"").lower()
        return any(
            marker in lowered
            for marker in (b"rate limit", b"too many requests", b"slow down")
        )

    @staticmethod
    def _is_challenge(status: int, headers: dict, body: bytes) -> bool:
        if status not in (403, 429, 503):
            return False
        for name in CHALLENGE_HEADERS:
            if name in headers:
                return True
        cookie = headers.get("set-cookie", "").lower()
        for marker in CHALLENGE_COOKIE_MARKERS:
            if marker in cookie:
                return True
        lowered = (body or b"").lower()
        return any(marker in lowered for marker in CHALLENGE_BODY_MARKERS)

    @staticmethod
    def _challenge_marker(headers: dict, body: bytes) -> str:
        for name in CHALLENGE_HEADERS:
            if name in headers:
                return f"header:{name}"
        cookie = headers.get("set-cookie", "").lower()
        for marker in CHALLENGE_COOKIE_MARKERS:
            if marker in cookie:
                return f"cookie:{marker}"
        lowered = (body or b"").lower()
        for marker in CHALLENGE_BODY_MARKERS:
            if marker in lowered:
                return f"body:{marker.decode('ascii', 'replace')}"
        return "unclassified-interstitial"


# Clean-traffic-start order. Lower runs first. The body-ceiling, memory and
# pool probes come last because they are the ones that can trip a front into
# a challenge; the chain starts only after they have settled.
PRECHECK_ORDER = (
    "banner",
    "sapi",
    "session_surface",
    "app_surface",
    "waf_shapes",
    "body_ceiling",
    "post_max",
    "ml_bracket",
    "nested_oracle",
    "patched_build",
    "unserialize_surface",
    "pool_width",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(moment: Optional[datetime] = None) -> str:
    moment = moment or utc_now()
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost") or host.startswith("127.")


def resolve_loopback(host: str) -> bool:
    """Resolve a hostname and decide whether every address is loopback."""
    if is_loopback(host):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(
        info[4][0] in ("127.0.0.1", "::1") or info[4][0].startswith("127.")
        for info in infos
    )
