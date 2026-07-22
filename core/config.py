"""
config.py — the port layout, fixed in one place.

WHY THIS FILE EXISTS
====================
The slot→port mapping must be identical on every machine that ever runs this
project: this server today, a rebuilt server tomorrow, a second node next
month. If it drifts, the core config in your panel silently points at the
wrong ports and traffic dies.

So the layout is derived from constants here, not from whatever happened to
be in the registry when it was first created:

    SOCKS   slot N  ->  SOCKS_BASE_PORT + N        (20000, 20001, …)
    Inbound slot N  ->  INBOUND_BASE_PORT + N      (10000, 10001, …)

Copy this file to a new server and the layout comes with it. Nothing is
generated, nothing is random, nothing depends on order of operations.

CHANGING THESE VALUES
---------------------
Only do it on a fresh install, or you will invalidate the core config that
your panel already has. If you must change them on a live system:

    1. edit here (or set PEPECORE_SOCKS_BASE / PEPECORE_INBOUND_BASE)
    2. pepectl ports resync      -> rewrites the registry to match
    3. pepectl bind …            -> re-wires the panel to the new ports

Environment variables win over the defaults, which is handy when running two
instances on one box:

    PEPECORE_SOCKS_BASE=21000 PEPECORE_INBOUND_BASE=11000 pepectl status
"""

import os

# --- the layout ------------------------------------------------------

SOCKS_BASE_PORT = int(os.environ.get("PEPECORE_SOCKS_BASE", 20000))
INBOUND_BASE_PORT = int(os.environ.get("PEPECORE_INBOUND_BASE", 10000))

# Hard ceiling on slots. Keeps the two ranges from ever colliding and stops
# a typo from trying to reserve 50,000 ports.
MAX_SLOTS = int(os.environ.get("PEPECORE_MAX_SLOTS", 256))

# --- derived ---------------------------------------------------------

def socks_port(slot_index: int) -> int:
    """The permanent SOCKS5 port for a slot. Same answer on every machine."""
    return SOCKS_BASE_PORT + slot_index


def inbound_port(slot_index: int) -> int:
    """The permanent Xray inbound port for a slot."""
    return INBOUND_BASE_PORT + slot_index


def outbound_tag(slot_index: int) -> str:
    return f"PS-Out-{slot_index:03d}"


def inbound_tag(slot_index: int) -> str:
    return f"PS-In-{slot_index:03d}"


def validate() -> None:
    """Fail loudly at import time rather than mysteriously at runtime."""
    if MAX_SLOTS < 1:
        raise ValueError("PEPECORE_MAX_SLOTS must be at least 1")

    socks_range = range(SOCKS_BASE_PORT, SOCKS_BASE_PORT + MAX_SLOTS)
    inbound_range = range(INBOUND_BASE_PORT, INBOUND_BASE_PORT + MAX_SLOTS)

    if set(socks_range) & set(inbound_range):
        raise ValueError(
            f"Port ranges overlap: SOCKS {socks_range.start}-{socks_range.stop - 1} "
            f"collides with inbound {inbound_range.start}-{inbound_range.stop - 1}. "
            f"Move one of the bases further apart."
        )

    for name, base in (("SOCKS", SOCKS_BASE_PORT), ("inbound", INBOUND_BASE_PORT)):
        if base < 1024:
            raise ValueError(f"{name} base port {base} is in the privileged range")
        if base + MAX_SLOTS > 65535:
            raise ValueError(f"{name} range would run past port 65535")


def summary() -> str:
    return (
        f"SOCKS   {SOCKS_BASE_PORT}–{SOCKS_BASE_PORT + MAX_SLOTS - 1}\n"
        f"Inbound {INBOUND_BASE_PORT}–{INBOUND_BASE_PORT + MAX_SLOTS - 1}\n"
        f"Max slots: {MAX_SLOTS}"
    )


validate()
