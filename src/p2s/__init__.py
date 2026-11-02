"""Consolidated php2shell end-to-end tool.

One entrypoint (``php2shell_e2e.py``) drives four phases over a registry of
methods:

    precheck  -> classify the target (version/SAPI/front/memory/session/pool)
    route     -> turn the precheck verdict into a chain class
    calibrate -> derive the per-target numbers the chain needs
    chain     -> execute the weapon bank and collect the proof

Everything is standard-library only. Every request carries a UTC timestamp and
is charged to a per-host ledger. Targets are limited to loopback unless
``--allow-remote`` is passed together with an authorized scope.
"""

__version__ = "1.0.6"
