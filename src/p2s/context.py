"""Shared execution context for precheck, calibration and chain methods."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .doctrine import Doctrine
from .fingerprint import Banner
from .http import HttpClient, Target


@dataclass
class Context:
    target: Target
    http: HttpClient
    doctrine: Doctrine
    ledger: object = None          # ledger.Ledger | None
    options: dict = field(default_factory=dict)
    banner: Optional[Banner] = None
    signals: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)
    route: object = None           # routing.Route | None
    profile: dict = field(default_factory=dict)
    dry_run: bool = False
    proof: bytes = b""
    proof_source: str = ""
    request_count: int = 0

    # -- convenience -------------------------------------------------------
    @property
    def version_text(self) -> str:
        return self.banner.version_text if self.banner else ""

    def note(self, key: str, value) -> None:
        self.signals[key] = value

    def option(self, key: str, default=None):
        return self.options.get(key, default)

    def spent(self) -> int:
        return self.request_count

    def record_requests(self, before: int) -> None:
        self.request_count += max(0, len(self.http.requests) - before)

    def as_dict(self) -> dict:
        return {
            "target": str(self.target),
            "banner": self.banner.as_dict() if self.banner else None,
            "signals": self.signals,
            "checks": self.checks,
            "profile": self.profile,
            "requests": len(self.http.requests),
        }
