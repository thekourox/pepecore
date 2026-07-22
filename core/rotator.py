"""
rotator.py — periodic reshuffling of slots across keys.

WHAT PROBLEM THIS SOLVES
========================
Symptom: random locations drop every hour or two, and only replacing the
private key brings them back.

Cause: one WireGuard keypair connected to many servers at once. The provider
treats that as a single identity in N places and starts culling the extra
sessions. Which ones get culled looks random, which is why it presents as
"some locations died again".

Two things fix it, and this module does the second:

  1. Enough keys that no single one carries too many tunnels.
     -> registry.key_load() reports this; the UI nags you about it.

  2. Periodically reshuffle which key serves which slot, so no keypair
     holds the same long-lived set of sessions indefinitely.
     -> this module.

Note that several keypairs can live on ONE Surfshark account — generate
them in the account's WireGuard section. You do not need extra accounts.

WHAT THIS DOES NOT DO
---------------------
It does not log into Surfshark, generate keys, or register public keys.
That would mean storing your account password on this server and driving
undocumented endpoints, and the automated register/delete pattern is itself
a good way to get an account flagged. Keys go in by hand, once.
"""

import logging
import threading
import time
from typing import Dict, Optional

from . import engine, registry

log = logging.getLogger("pepecore.rotator")

DEFAULT_INTERVAL_HOURS = 3
MIN_INTERVAL_HOURS = 1
STAGGER = 0.6           # seconds between tunnel restarts


class Rotator:
    """
    Rotates the key→slot assignment on a schedule.

    Each cycle shifts every slot to the next key in the pool (a rotation by
    one), then restarts the affected tunnels. Ports, tags, pins and UUIDs
    are untouched, so the panel is never involved and users keep their
    configs — exactly like a manual `key rotate`, just automatic.
    """

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.state: Dict = {
            "enabled": False,
            "interval_hours": DEFAULT_INTERVAL_HOURS,
            "last_run": None,
            "next_run": None,
            "cycles": 0,
            "last_result": None,
        }

    # -------------------------------------------------- control

    def configure(self, enabled: bool, interval_hours: float) -> Dict:
        interval_hours = max(MIN_INTERVAL_HOURS, float(interval_hours))
        self.state["enabled"] = bool(enabled)
        self.state["interval_hours"] = interval_hours
        _persist(self.state)

        if enabled:
            self.start()
            self._wake.set()        # recompute the schedule now
        else:
            self.state["next_run"] = None

        log.info("Rotator %s (every %sh)",
                 "enabled" if enabled else "disabled", interval_hours)
        return self.status()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="rotator")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def status(self) -> Dict:
        load = registry.key_load()
        s = dict(self.state)
        s["key_load"] = load
        # A rotation only helps if there is more than one key to rotate between.
        s["effective"] = load["keys_present"] > 1
        return s

    # -------------------------------------------------- the work

    def rotate_now(self) -> Dict:
        """
        Shift every occupied slot one position along the key pool.

        With keys [A, B, C]: slots on A move to B, B to C, C back to A.
        Nothing else about the slot changes.
        """
        import datetime

        reg = registry.load()
        idents = reg["identities"]
        live = [s for s in reg["slots"] if s.get("endpoint") and s.get("enabled", True)]

        if len(idents) < 2:
            result = {
                "rotated": 0,
                "skipped": "Only one key present — rotation would be a no-op. "
                           "Add more keypairs (several can live on one account).",
            }
            self.state["last_result"] = result
            return result

        if not live:
            result = {"rotated": 0, "skipped": "No active slots."}
            self.state["last_result"] = result
            return result

        order = [i["id"] for i in idents]
        pos = {kid: n for n, kid in enumerate(order)}

        moved = 0
        for slot in live:
            current = slot.get("identity_id")
            nxt = order[(pos.get(current, -1) + 1) % len(order)] if current in pos else order[0]
            registry.update_slot(slot["index"], identity_id=nxt)
            moved += 1

        # Restart so the new key actually takes effect.
        restarted = 0
        for slot in live:
            if engine.start_slot(slot["index"], quiet=True):
                restarted += 1
            time.sleep(STAGGER)

        now = datetime.datetime.now()
        self.state["last_run"] = now.isoformat(timespec="seconds")
        self.state["cycles"] += 1
        result = {
            "rotated": moved,
            "restarted": restarted,
            "keys_in_pool": len(order),
            "panel_touched": False,
        }
        self.state["last_result"] = result
        _persist(self.state)

        log.info("Rotation complete: %s slots across %s keys (%s back up)",
                 moved, len(order), restarted)
        return result

    # -------------------------------------------------- loop

    def _loop(self) -> None:
        import datetime

        while not self._stop.is_set():
            if not self.state["enabled"]:
                self._wake.wait(60)
                self._wake.clear()
                continue

            interval = self.state["interval_hours"] * 3600
            nxt = datetime.datetime.now() + datetime.timedelta(seconds=interval)
            self.state["next_run"] = nxt.isoformat(timespec="seconds")

            # Wake early if the schedule changes underneath us.
            self._wake.wait(interval)
            if self._wake.is_set():
                self._wake.clear()
                continue
            if self._stop.is_set() or not self.state["enabled"]:
                continue

            try:
                self.rotate_now()
            except Exception as e:      # noqa: BLE001 - never kill the loop
                log.error("Rotation failed: %s", e)


# ---------------------------------------------------------------- persistence

def _persist(state: Dict) -> None:
    """Keep the schedule across restarts."""
    try:
        reg = registry.load()
        reg["rotator"] = {
            "enabled": state["enabled"],
            "interval_hours": state["interval_hours"],
            "cycles": state["cycles"],
            "last_run": state["last_run"],
        }
        registry.save(reg)
    except Exception as e:      # noqa: BLE001
        log.warning("Could not persist rotator state: %s", e)


def _restore(rot: "Rotator") -> None:
    saved = registry.load().get("rotator")
    if not saved:
        return
    rot.state["enabled"] = saved.get("enabled", False)
    rot.state["interval_hours"] = saved.get("interval_hours", DEFAULT_INTERVAL_HOURS)
    rot.state["cycles"] = saved.get("cycles", 0)
    rot.state["last_run"] = saved.get("last_run")
    if rot.state["enabled"]:
        rot.start()
        log.info("Rotator resumed (every %sh)", rot.state["interval_hours"])


rotator = Rotator()
