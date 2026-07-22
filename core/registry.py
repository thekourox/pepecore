"""
registry.py — The stable contract between the WireGuard engine and any panel.

THE CENTRAL IDEA OF THE REWRITE
================================
A "slot" is a permanent, numbered SOCKS5 endpoint on 127.0.0.1.

    slot 0  ->  127.0.0.1:20000
    slot 1  ->  127.0.0.1:20001
    slot 2  ->  127.0.0.1:20002
    ...

The slot NEVER changes. The port NEVER changes. The Xray outbound that points
at that port NEVER changes.

What lives BEHIND the slot (which private key, which Surfshark server, which
country) is free to change at any moment. The engine swaps it live and the
panel never finds out, because from Xray's perspective 127.0.0.1:20003 is
still 127.0.0.1:20003.

CONSEQUENCE
-----------
Changing the Surfshark private key = rewrite N config files, restart N
processes. Zero panel API calls. Zero inbound rebuilds. Zero UUID churn.
Users' subscription links keep working through the whole operation.

The registry below is the single source of truth for that mapping. It is a
plain JSON file so you can read it, diff it, back it up, and edit it by hand
in an emergency.
"""

import json
import math
import os
import threading
from typing import Dict, List, Optional, Any

from . import config

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
REGISTRY_FILE = os.path.join(DATA_DIR, "registry.json")

os.makedirs(DATA_DIR, exist_ok=True)

# Ports come from config.py, never from stored state — see resync_ports().
BASE_SOCKS_PORT = config.SOCKS_BASE_PORT

_lock = threading.RLock()


def _default_registry() -> Dict[str, Any]:
    return {
        "version": 3,
        "base_port": config.SOCKS_BASE_PORT,
        "inbound_base_port": config.INBOUND_BASE_PORT,
        # Identity pool: the WireGuard credentials. Swapping these is the
        # operation that used to require a full re-inject.
        "identities": [],          # [{"id","private_key","address","label"}]
        "users": [],               # [{"username","password"}]
        # Slots: the permanent port assignments.
        "slots": [],               # see _blank_slot()
        # Panel binding is recorded for reference only. The engine never
        # calls the panel; this is here so you can see what was wired up.
        "panel_binding": {
            "bound": False,
            "core_id": None,
            "host": None,
            "bound_at": None,
            "slot_count": 0,
        },
    }


def _blank_slot(index: int, base_port: int = 0) -> Dict[str, Any]:
    # Every field below is computed from config.py, so the same slot index
    # yields the same port and tags on any machine, forever.
    return {
        "index": index,
        "port": config.socks_port(index),
        "inbound_port": config.inbound_port(index),
        "outbound_tag": config.outbound_tag(index),
        "inbound_tag": config.inbound_tag(index),
        # locked_country: once set, this slot serves ONLY this country.
        # Key rotations, server swaps and watchdog failovers all stay inside
        # it. Changing it is a deliberate, separate operation because it
        # silently relocates every user on this slot's inbound.
        "locked_country": None,
        "locked_country_code": None,
        # --- everything below is hot-swappable within the locked country ---
        "identity_id": None,
        "endpoint": None,
        "public_key": None,
        "country": None,
        "country_code": None,
        "location": None,
        "enabled": True,
        "last_health": None,
        "last_health_at": None,
        "fail_streak": 0,
    }


def load() -> Dict[str, Any]:
    with _lock:
        if not os.path.exists(REGISTRY_FILE):
            reg = _default_registry()
            _write_unlocked(reg)
            return reg
        try:
            with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                reg = json.load(f)
        except (OSError, json.JSONDecodeError):
            return _default_registry()

        # Forward-compat: fill in any missing top-level keys.
        base = _default_registry()
        for k, v in base.items():
            reg.setdefault(k, v)

        # Enforce the canonical port layout on every read. This is what makes
        # a registry portable between servers.
        if _apply_port_layout(reg):
            _write_unlocked(reg)
        return reg


def _write_unlocked(reg: Dict[str, Any]) -> None:
    tmp = REGISTRY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, REGISTRY_FILE)   # atomic; never leaves a half-written file


def save(reg: Dict[str, Any]) -> None:
    with _lock:
        _write_unlocked(reg)


# ----------------------------------------------------------------------
# Slot allocation
# ----------------------------------------------------------------------

def ensure_slots(count: int) -> Dict[str, Any]:
    """
    Grow the slot table to `count` slots. Existing slots are NEVER renumbered
    or repurposed — that is the whole point. Growing is safe; the panel only
    ever needs re-binding if the count increases.
    """
    with _lock:
        reg = load()
        if count > config.MAX_SLOTS:
            raise ValueError(
                f"Requested {count} slots but MAX_SLOTS is {config.MAX_SLOTS}. "
                f"Raise PEPECORE_MAX_SLOTS if you really need more."
            )
        current = len(reg["slots"])
        for i in range(current, count):
            reg["slots"].append(_blank_slot(i))
        _apply_port_layout(reg)
        save(reg)
        return reg


def _apply_port_layout(reg: Dict[str, Any]) -> int:
    """
    Force every slot's ports and tags to match config.py.

    Called on every load, so a registry copied from another machine — or one
    written before the base ports were changed — is corrected automatically
    instead of quietly serving the wrong layout. Returns how many slots were
    out of line.
    """
    fixed = 0
    for s in reg.get("slots", []):
        i = s["index"]
        want = {
            "port": config.socks_port(i),
            "inbound_port": config.inbound_port(i),
            "outbound_tag": config.outbound_tag(i),
            "inbound_tag": config.inbound_tag(i),
        }
        if any(s.get(k) != v for k, v in want.items()):
            s.update(want)
            fixed += 1
    reg["base_port"] = config.SOCKS_BASE_PORT
    reg["inbound_base_port"] = config.INBOUND_BASE_PORT
    return fixed


def resync_ports() -> Dict[str, Any]:
    """
    Explicitly re-derive the whole port layout from config.py.

    Use after changing the base ports, or on a server you have just restored
    a registry backup onto. Returns a report of what moved.
    """
    with _lock:
        reg = load()
        before = [(s["index"], s.get("port"), s.get("inbound_port")) for s in reg["slots"]]
        fixed = _apply_port_layout(reg)
        save(reg)
        after = [(s["index"], s.get("port"), s.get("inbound_port")) for s in reg["slots"]]
        return {
            "slots_corrected": fixed,
            "changes": [
                {"slot": b[0], "socks": [b[1], a[1]], "inbound": [b[2], a[2]]}
                for b, a in zip(before, after) if b != a
            ],
            "layout": config.summary(),
        }


def get_slot(index: int) -> Optional[Dict[str, Any]]:
    reg = load()
    for s in reg["slots"]:
        if s["index"] == index:
            return s
    return None


def update_slot(index: int, **fields) -> Optional[Dict[str, Any]]:
    """
    Patch a single slot's mutable fields and persist.

    Note that `locked_country` is NOT patchable here — it is part of the
    contract, like the port. Use lock_country() / unlock_country() so that
    relocating a slot is always a conscious act.
    """
    with _lock:
        reg = load()
        for s in reg["slots"]:
            if s["index"] == index:
                # Guard the immutable contract fields.
                for immutable in ("index", "port", "inbound_port",
                                  "outbound_tag", "inbound_tag",
                                  "locked_country", "locked_country_code"):
                    fields.pop(immutable, None)
                s.update(fields)
                save(reg)
                return s
        return None


def lock_country(index: int, country: str, country_code: str = "") -> Optional[Dict[str, Any]]:
    """
    Pin a slot to a country. From here on the engine and the watchdog will
    refuse to place any other country's server on this port.
    """
    with _lock:
        reg = load()
        for s in reg["slots"]:
            if s["index"] == index:
                s["locked_country"] = country
                s["locked_country_code"] = country_code
                save(reg)
                return s
        return None


def unlock_country(index: int) -> Optional[Dict[str, Any]]:
    """Deliberately release the pin so the slot can be re-homed."""
    with _lock:
        reg = load()
        for s in reg["slots"]:
            if s["index"] == index:
                s["locked_country"] = None
                s["locked_country_code"] = None
                save(reg)
                return s
        return None


def country_matches(slot: Dict[str, Any], country: str) -> bool:
    """Loose comparison — 'United States' vs 'UnitedStates' vs 'united states'."""
    locked = slot.get("locked_country")
    if not locked:
        return True          # unpinned slots accept anything
    norm = lambda x: (x or "").replace(" ", "").replace("-", "").lower()
    return norm(locked) == norm(country)


def occupied_slots() -> List[Dict[str, Any]]:
    """Slots that actually have a server assigned (i.e. should be running)."""
    return [s for s in load()["slots"] if s.get("endpoint") and s.get("enabled")]


# ----------------------------------------------------------------------
# Identity pool  (the private keys)
# ----------------------------------------------------------------------

def add_identities_bulk(entries: List[Dict[str, str]], default_address: str = "10.14.0.2/16") -> Dict[str, Any]:
    """
    Import many keypairs at once.

    At 140 locations you need roughly 28 keys, and adding those one at a time
    through a form is miserable. Duplicate private keys are skipped rather
    than creating two identities that would share sessions — which is the
    very thing the per-key limit exists to prevent.
    """
    import uuid as _uuid
    with _lock:
        reg = load()
        existing = {i["private_key"] for i in reg["identities"]}
        added, skipped = [], []

        for n, e in enumerate(entries, 1):
            pk = (e.get("private_key") or "").strip()
            if not pk:
                continue
            if pk in existing:
                skipped.append(pk[:8] + "…")
                continue

            ident = {
                "id": _uuid.uuid4().hex[:8],
                "private_key": pk,
                "address": (e.get("address") or default_address).strip(),
                "label": (e.get("label") or "").strip() or f"key-{len(reg['identities']) + 1}",
            }
            reg["identities"].append(ident)
            existing.add(pk)
            added.append({"id": ident["id"], "label": ident["label"]})

        save(reg)
        return {"added": added, "added_count": len(added),
                "skipped_duplicates": len(skipped), "total_keys": len(reg["identities"])}


def parse_key_blob(blob: str, default_address: str = "10.14.0.2/16") -> List[Dict[str, str]]:
    """
    Accept keys pasted in whatever shape they come out of the account page.

    Handles one key per line, `label: key`, `key,address`, and full
    [Interface] config blocks — so you can paste raw exports without
    reformatting them by hand.
    """
    import re as _re

    entries: List[Dict[str, str]] = []

    # Full WireGuard config blocks
    if "[Interface]" in blob:
        for block in _re.split(r"(?=\[Interface\])", blob):
            if "[Interface]" not in block:
                continue
            pk = _re.search(r"PrivateKey\s*=\s*(\S+)", block)
            addr = _re.search(r"Address\s*=\s*(\S+)", block)
            if pk:
                entries.append({
                    "private_key": pk.group(1),
                    "address": addr.group(1) if addr else default_address,
                    "label": "",
                })
        return entries

    for raw in blob.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        label = ""
        address = default_address

        # "label: key" or "label = key"
        m = _re.match(r"^([\w\- ]+)\s*[:=]\s*(\S+)$", line)
        if m and len(m.group(2)) > 20:
            label, line = m.group(1).strip(), m.group(2)

        # "key,address" or "key address"
        parts = _re.split(r"[,\s]+", line)
        if len(parts) >= 2 and "/" in parts[1]:
            line, address = parts[0], parts[1]
        else:
            line = parts[0]

        if len(line) >= 40:      # a base64 WireGuard key is 44 chars
            entries.append({"private_key": line, "address": address, "label": label})

    return entries


def add_identity(private_key: str, address: str, label: str = "") -> Dict[str, Any]:
    import uuid
    with _lock:
        reg = load()
        ident = {
            "id": uuid.uuid4().hex[:8],
            "private_key": private_key.strip(),
            "address": address.strip(),
            "label": label or f"key-{len(reg['identities']) + 1}",
        }
        reg["identities"].append(ident)
        save(reg)
        return ident


def replace_identity(identity_id: str, private_key: str, address: str) -> bool:
    """
    Swap the credentials behind an existing identity, keeping its ID.

    Because slots reference identities BY ID, every slot using this identity
    picks up the new key automatically. No slot is reassigned, so no port
    moves, so the panel stays untouched.
    """
    with _lock:
        reg = load()
        for ident in reg["identities"]:
            if ident["id"] == identity_id:
                ident["private_key"] = private_key.strip()
                ident["address"] = address.strip()
                save(reg)
                return True
        return False


def remove_identity(identity_id: str) -> bool:
    with _lock:
        reg = load()
        before = len(reg["identities"])
        reg["identities"] = [i for i in reg["identities"] if i["id"] != identity_id]
        for s in reg["slots"]:
            if s.get("identity_id") == identity_id:
                s["identity_id"] = None
        save(reg)
        return len(reg["identities"]) < before


def get_identity(identity_id: str) -> Optional[Dict[str, Any]]:
    for i in load()["identities"]:
        if i["id"] == identity_id:
            return i
    return None


def identities() -> List[Dict[str, Any]]:
    return load()["identities"]


def rebalance_identities() -> Dict[str, Any]:
    """
    Spread the occupied slots evenly across the available identities.
    Slots keep their ports; only which key they use changes.
    """
    with _lock:
        reg = load()
        idents = reg["identities"]
        if not idents:
            return reg
        live = [s for s in reg["slots"] if s.get("endpoint")]
        for i, s in enumerate(live):
            s["identity_id"] = idents[i % len(idents)]["id"]
        save(reg)
        return reg


# How many simultaneous tunnels one Surfshark keypair can carry before the
# provider starts dropping sessions. Surfshark does not publish a number;
# this is a conservative working limit. Raise it via PEPECORE_MAX_SLOTS_PER_KEY
# if your experience differs.
MAX_SLOTS_PER_KEY = int(os.environ.get("PEPECORE_MAX_SLOTS_PER_KEY", 5))


def key_load() -> Dict[str, Any]:
    """
    How many live tunnels sit on each key, and whether that is too many.

    Overloading one keypair across many servers is the usual cause of
    "random locations drop every hour or two and only a new key fixes it":
    the provider sees one identity connected from N places at once and
    starts culling the extra sessions. More keys, fewer tunnels each, is
    the fix — and several keys can live on a single account.
    """
    reg = load()
    idents = reg["identities"]
    live = [s for s in reg["slots"] if s.get("endpoint")]

    per_key: Dict[str, List[int]] = {i["id"]: [] for i in idents}
    orphans = []
    for s in live:
        kid = s.get("identity_id")
        if kid in per_key:
            per_key[kid].append(s["index"])
        else:
            orphans.append(s["index"])

    rows = []
    for i in idents:
        slots = per_key[i["id"]]
        rows.append({
            "id": i["id"],
            "label": i["label"],
            "slot_count": len(slots),
            "slots": slots,
            "overloaded": len(slots) > MAX_SLOTS_PER_KEY,
        })

    total_live = len(live)
    keys_needed = max(1, math.ceil(total_live / MAX_SLOTS_PER_KEY)) if total_live else 0

    return {
        "limit_per_key": MAX_SLOTS_PER_KEY,
        "keys": rows,
        "orphan_slots": orphans,
        "total_live_slots": total_live,
        "keys_present": len(idents),
        "keys_needed": keys_needed,
        "healthy": (
            bool(idents)
            and not orphans
            and all(not r["overloaded"] for r in rows)
        ),
    }


# ----------------------------------------------------------------------
# Panel binding record
# ----------------------------------------------------------------------

def mark_bound(core_id: str, host: str, slot_count: int) -> None:
    import datetime
    with _lock:
        reg = load()
        reg["panel_binding"] = {
            "bound": True,
            "core_id": str(core_id),
            "host": host,
            "bound_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "slot_count": slot_count,
        }
        save(reg)


def binding() -> Dict[str, Any]:
    return load()["panel_binding"]


# ----------------------------------------------------------------------
# Users / Authentication
# ----------------------------------------------------------------------

def add_user(username: str, password: str) -> None:
    with _lock:
        reg = load()
        for u in reg.setdefault("users", []):
            if u["username"] == username:
                u["password"] = password
                save(reg)
                return
        reg["users"].append({"username": username, "password": password})
        save(reg)

def remove_user(username: str) -> bool:
    with _lock:
        reg = load()
        users = reg.setdefault("users", [])
        before = len(users)
        reg["users"] = [u for u in users if u["username"] != username]
        save(reg)
        return len(reg["users"]) < before

def get_users() -> List[Dict[str, str]]:
    return load().setdefault("users", [])

def check_user(username: str, password: str) -> bool:
    for u in load().setdefault("users", []):
        if u["username"] == username and u["password"] == password:
            return True
    return False
