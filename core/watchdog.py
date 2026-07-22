"""
watchdog.py — Keeps slots healthy without ever contacting the panel.

When a Surfshark server goes bad the watchdog swaps in a different server
for the same country and restarts the tunnel. The slot's port and tags are
untouched, so Xray keeps routing to the same place and users never notice.

Under the old design this class of failure needed a human to re-inject.
"""

import logging
import threading
import time
from typing import Dict

from . import engine, registry

log = logging.getLogger("pepecore.watchdog")

CHECK_INTERVAL = 120        # seconds between sweeps
FAILS_BEFORE_SWAP = 2       # consecutive failures before we replace the server
BOOT_GRACE = 90             # let handshakes settle after startup
SWAP_GAP = 1.5              # pause between swaps, avoids rate limiting


class Watchdog:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self.stats: Dict = {"cycles": 0, "swaps": 0, "restarts": 0,
                            "repatriated": 0, "displaced": 0, "last_run": None}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="watchdog")
        self._thread.start()
        log.info("Watchdog started (interval=%ss)", CHECK_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        self._stop.wait(BOOT_GRACE)

        while not self._stop.is_set():
            try:
                self._sweep()
            except Exception as e:      # noqa: BLE001 - never let the loop die
                log.error("Sweep failed: %s", e)
            self._stop.wait(CHECK_INTERVAL)

    def _sweep(self) -> None:
        import datetime

        slots = registry.occupied_slots()
        if not slots:
            return

        alive = swapped = restarted = repatriated = 0

        for slot in slots:
            idx = slot["index"]

            if engine.probe(slot["port"], timeout=4.0):
                alive += 1
                registry.update_slot(
                    idx, fail_streak=0, last_health="up",
                    last_health_at=datetime.datetime.now().isoformat(timespec="seconds"),
                )
                # Healthy — but is it in the right country? A slot that fell
                # back to a neighbour during an outage gets pulled home as
                # soon as its own country has a working server again.
                if self._repatriate(slot):
                    repatriated += 1
                continue

            streak = slot.get("fail_streak", 0) + 1
            registry.update_slot(
                idx, fail_streak=streak, last_health="down",
                last_health_at=datetime.datetime.now().isoformat(timespec="seconds"),
            )

            if streak < FAILS_BEFORE_SWAP:
                continue

            # Replace with another server. Preference order: same country,
            # then a neighbour, then anything — a dead slot helps nobody.
            # The pin is never cleared, so a slot parked on a neighbour gets
            # pulled home automatically once its own country recovers.
            target_country = engine.slot_country(slot)
            target_location = engine.slot_location(slot)
            candidates = engine.failover_candidates(
                target_country, slot.get("endpoint", ""), target_location)

            if candidates:
                import random
                tier = candidates[0][1]
                pool = [c for c, t in candidates if t == tier]
                pick = random.choice(pool)

                if tier in ("same-city", "same-country"):
                    log.info("slot %s down x%s -> %s / %s (%s)",
                             idx, streak, pick["country"], pick["location"], tier)
                else:
                    log.warning(
                        "slot %s: no working %s server, falling back to %s (%s)",
                        idx, target_country, pick["country"], tier,
                    )

                engine.assign_server(
                    idx, pick["endpoint"], pick["publicKey"],
                    country=pick["country"], country_code=pick["countryCode"],
                    location=pick["location"], force=True,
                )
                swapped += 1
            else:
                log.info("slot %s down x%s -> plain restart (no alternative)", idx, streak)
                engine.start_slot(idx, quiet=True)
                restarted += 1

            time.sleep(SWAP_GAP)

        self.stats["cycles"] += 1
        self.stats["swaps"] += swapped
        self.stats["restarts"] += restarted
        self.stats["repatriated"] += repatriated
        self.stats["displaced"] = self._count_displaced()
        self.stats["last_run"] = datetime.datetime.now().isoformat(timespec="seconds")

        if swapped or restarted or repatriated:
            log.info("Sweep: %s alive, %s swapped, %s restarted, %s brought home",
                     alive, swapped, restarted, repatriated)

    # ------------------------------------------------------------------
    def _repatriate(self, slot: dict) -> bool:
        """
        If this slot is pinned to country X but currently exiting through
        country Y (because X was down when it failed over), try to move it
        back. Only acts when a same-country server is actually reachable,
        so it will not flap between a dead home and a working neighbour.
        """
        pinned = slot.get("locked_country")
        pinned_city = slot.get("locked_location")
        current = slot.get("country")
        current_city = slot.get("location")
        if not pinned or not current:
            return False

        home_country = registry.norm(pinned) == registry.norm(current)
        home_city = (not pinned_city) or registry.norm(pinned_city) == registry.norm(current_city)
        if home_country and home_city:
            return False        # already exactly where it belongs

        # Only same-city servers count as "home" when a city is pinned.
        home = engine.alternatives_for(pinned, "", pinned_city or "")
        if pinned_city:
            home = [c for c in home
                    if registry.norm(c["location"]) == registry.norm(pinned_city)]
        if not home:
            return False        # home is still unreachable

        import random
        pick = random.choice(home)
        log.info("slot %s: %s is reachable again, bringing it home from %s / %s",
                 slot["index"], registry.slot_label(slot), current, current_city)
        engine.assign_server(
            slot["index"], pick["endpoint"], pick["publicKey"],
            country=pick["country"], country_code=pick["countryCode"],
            location=pick["location"], force=True,
        )
        time.sleep(SWAP_GAP)
        return True

    def _count_displaced(self) -> int:
        """How many slots are currently exiting from the wrong country."""
        n = 0
        for s in registry.occupied_slots():
            pinned, current = s.get("locked_country"), s.get("country")
            if not pinned or not current:
                continue
            if registry.norm(pinned) != registry.norm(current):
                n += 1
            elif s.get("locked_location") and \
                    registry.norm(s["locked_location"]) != registry.norm(s.get("location")):
                n += 1          # right country, wrong city
        return n


watchdog = Watchdog()
