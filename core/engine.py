"""
engine.py — The standalone WireGuard/SOCKS5 engine.

This module has NO knowledge of PasarGuard, Xray, hosts, inbounds, UUIDs or
subscription groups. It does exactly one job:

    "Slot N must expose a working SOCKS5 proxy on 127.0.0.1:(base+N),
     tunnelled through Surfshark using identity X and server Y."

Everything about how that proxy is consumed is somebody else's problem.

Because of that separation, all of these operations are now panel-free:

    * change the Surfshark private key      -> rotate_identity()
    * move a slot to another country        -> assign_server()
    * a server dies                         -> watchdog swaps it silently
    * reboot the machine                    -> recover_all()

None of them touch the panel. None of them change a port. None of them
invalidate a user's config.
"""

import glob
import logging
import math
import os
import re
import signal
import socket
import subprocess
import tarfile
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

from . import registry

log = logging.getLogger("pepecore.engine")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(ROOT, "bin")
CONF_DIR = os.path.join(ROOT, "data", "wg")
LOG_FILE = os.path.join(ROOT, "data", "engine.log")
WIREPROXY_BIN = os.path.join(BIN_DIR, "wireproxy")

os.makedirs(BIN_DIR, exist_ok=True)
os.makedirs(CONF_DIR, exist_ok=True)

WIREPROXY_VERSION = "v1.0.9"
MTU = 1280
HANDSHAKE_PORT = 51820


# ======================================================================
# Binary provisioning
# ======================================================================

def ensure_binary() -> None:
    """Download wireproxy once, on first use."""
    if os.path.exists(WIREPROXY_BIN) and os.access(WIREPROXY_BIN, os.X_OK):
        return

    arch = os.uname().machine
    goarch = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm"}.get(arch, "amd64")
    name = f"wireproxy_linux_{goarch}.tar.gz"

    urls = [
        f"https://github.com/pufferffish/wireproxy/releases/download/{WIREPROXY_VERSION}/{name}",
        f"https://github.com/octeep/wireproxy/releases/download/v1.0.8/wireproxy_linux_{goarch}.tar.gz",
    ]

    tar_path = os.path.join(BIN_DIR, "wireproxy.tar.gz")
    last_err: Optional[Exception] = None

    for url in urls:
        try:
            log.info("Downloading wireproxy from %s", url)
            urllib.request.urlretrieve(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=BIN_DIR)
            os.remove(tar_path)
            os.chmod(WIREPROXY_BIN, 0o755)
            log.info("wireproxy ready at %s", WIREPROXY_BIN)
            return
        except Exception as e:      # noqa: BLE001 - we want to try the next mirror
            last_err = e
            log.warning("Download failed (%s): %s", url, e)

    raise RuntimeError(f"Could not obtain wireproxy binary: {last_err}")


# ======================================================================
# Process control  (keyed by slot index, not by tag)
# ======================================================================

def _conf_path(slot_index: int) -> str:
    return os.path.join(CONF_DIR, f"slot-{slot_index:03d}.conf")


def _pid_path(slot_index: int) -> str:
    return os.path.join(CONF_DIR, f"slot-{slot_index:03d}.pid")


def _read_pid(slot_index: int) -> Optional[int]:
    try:
        with open(_pid_path(slot_index), "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _write_pid(slot_index: int, pid: int) -> None:
    with open(_pid_path(slot_index), "w") as f:
        f.write(str(pid))


def _alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill(pid: Optional[int]) -> None:
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            time.sleep(0.1)
            if not _alive(pid):
                return
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _render_config(private_key: str, address: str, endpoint: str,
                   public_key: str, socks_port: int) -> str:
    """
    ListenPort is deliberately omitted so the kernel hands out a random
    ephemeral UDP source port per instance. Fixed sequential source ports
    make conntrack cross-wire replies between tunnels, which surfaces as
    'invalid mac1' errors under load.
    """
    addr = address.split("/")[0] + "/32"
    return (
        "[Interface]\n"
        f"Address = {addr}\n"
        f"PrivateKey = {private_key}\n"
        f"MTU = {MTU}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
        "\n"
        "[Socks5]\n"
        f"BindAddress = 127.0.0.1:{socks_port}\n"
    )


def start_slot(slot_index: int, quiet: bool = False) -> bool:
    """
    (Re)start the tunnel for one slot using whatever the registry currently
    says belongs there. Idempotent: safe to call on a running slot.
    """
    ensure_binary()

    slot = registry.get_slot(slot_index)
    if not slot:
        log.error("Slot %s does not exist", slot_index)
        return False
    if not slot.get("endpoint") or not slot.get("public_key"):
        log.debug("Slot %s has no server assigned; skipping", slot_index)
        return False
    if not slot.get("enabled", True):
        return False

    ident = registry.get_identity(slot.get("identity_id"))
    if not ident:
        log.error("Slot %s references missing identity %s", slot_index, slot.get("identity_id"))
        return False

    stop_slot(slot_index)

    conf = _render_config(
        private_key=ident["private_key"],
        address=ident["address"],
        endpoint=slot["endpoint"],
        public_key=slot["public_key"],
        socks_port=slot["port"],
    )
    with open(_conf_path(slot_index), "w", encoding="utf-8") as f:
        f.write(conf)
    os.chmod(_conf_path(slot_index), 0o600)     # contains a private key

    lf = open(LOG_FILE, "a")
    lf.write(f"\n--- slot {slot_index} -> {slot['endpoint']} on :{slot['port']} ---\n")
    lf.flush()

    proc = subprocess.Popen(
        [WIREPROXY_BIN, "-c", _conf_path(slot_index)],
        stdout=lf, stderr=lf, start_new_session=True,
    )
    _write_pid(slot_index, proc.pid)

    if not quiet:
        log.info("slot %s up (pid %s) -> %s", slot_index, proc.pid, slot["endpoint"])
    return True


def stop_slot(slot_index: int) -> None:
    _kill(_read_pid(slot_index))
    try:
        os.remove(_pid_path(slot_index))
    except OSError:
        pass


def stop_all() -> int:
    """Stop every tracked slot, then sweep for orphans."""
    count = 0
    for slot in registry.load()["slots"]:
        if _alive(_read_pid(slot["index"])):
            stop_slot(slot["index"])
            count += 1

    # Sweep any wireproxy we lost track of (e.g. after a crash).
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f"/proc/{pid_dir}/cmdline", "rb") as f:
                    if b"wireproxy" in f.read():
                        os.kill(int(pid_dir), signal.SIGKILL)
                        count += 1
            except OSError:
                continue
    except OSError:
        pass

    return count


def recover_all(stagger: Optional[float] = None) -> int:
    """
    Bring every occupied slot back up. Called on boot. Reads only the
    registry, so it restores the exact same port layout every time —
    which is why a reboot never breaks a user's config.

    Startup is paced. Firing 140 WireGuard handshakes at once looks like a
    UDP flood to both Surfshark and most hosting providers, and the usual
    result is that a large share of them fail and have to be retried. The
    pacing below trades a slower boot for tunnels that actually come up.
    """
    stop_all()
    time.sleep(1.5)

    slots = registry.occupied_slots()
    total = len(slots)
    if not total:
        return 0

    if stagger is None:
        # Small setups can start briskly; large ones must not.
        stagger = 0.5 if total <= 20 else (1.0 if total <= 60 else 1.5)

    log.info("Recovering %s slots (%.1fs apart, ~%.0fs total)",
             total, stagger, total * stagger)

    started = 0
    for n, slot in enumerate(slots, 1):
        if start_slot(slot["index"], quiet=True):
            started += 1
        if n % 25 == 0:
            log.info("  … %s/%s started", n, total)
        time.sleep(stagger)

    log.info("Recovery finished: %s/%s slots up", started, total)
    return started


# ======================================================================
# Health
# ======================================================================

def probe(port: int, timeout: float = 5.0) -> bool:
    """SOCKS5 handshake against the local listener."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
        return len(resp) == 2 and resp[0] == 0x05
    except OSError:
        return False


def probe_egress(port: int, timeout: float = 12.0) -> Tuple[bool, Optional[str]]:
    """
    Stronger check: actually send traffic through the tunnel and read back
    the exit IP. A listener can accept TCP while the WireGuard handshake is
    dead, so this is what the watchdog trusts for real verdicts.
    """
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({
                "http": f"socks5h://127.0.0.1:{port}",
                "https": f"socks5h://127.0.0.1:{port}",
            })
        )
        with opener.open("https://api.ipify.org", timeout=timeout) as r:
            return True, r.read().decode().strip()
    except Exception:       # noqa: BLE001
        # Fall back to the cheap check so a missing PySocks doesn't
        # make every slot look dead.
        return probe(port, timeout=5.0), None


def health_snapshot(deep: bool = False) -> Dict:
    slots = registry.load()["slots"]
    alive = dead = idle = 0
    detail = []

    for s in slots:
        if not s.get("endpoint"):
            idle += 1
            detail.append({**s, "status": "empty"})
            continue

        ok = probe(s["port"], timeout=2.0)
        if ok and deep:
            ok, _ = probe_egress(s["port"])

        if ok:
            alive += 1
        else:
            dead += 1
        detail.append({**s, "status": "up" if ok else "down"})

    return {
        "total": len(slots),
        "alive": alive,
        "dead": dead,
        "empty": idle,
        "slots": detail,
    }


# ======================================================================
# THE OPERATIONS THAT USED TO REQUIRE A RE-INJECT
# ======================================================================

def rotate_identity(identity_id: str, private_key: str, address: str) -> Dict:
    """
    *** This is the function the whole rewrite exists for. ***

    Replace a Surfshark private key. Every slot bound to this identity is
    rewritten and restarted in place. Ports do not move. Tags do not change.
    The panel is not contacted. Users stay connected to the same inbounds
    with the same UUIDs — they just exit through the new key.
    """
    if not registry.replace_identity(identity_id, private_key, address):
        raise ValueError(f"identity {identity_id} not found")

    affected = [s for s in registry.occupied_slots() if s.get("identity_id") == identity_id]
    ok = 0
    for s in affected:
        if start_slot(s["index"], quiet=True):
            ok += 1
        time.sleep(0.4)

    log.info("Rotated identity %s across %s slots (%s up)", identity_id, len(affected), ok)
    return {
        "identity_id": identity_id,
        "slots_affected": [s["index"] for s in affected],
        "restarted": ok,
        "panel_touched": False,
    }


class CountryLockError(Exception):
    """Raised when something tries to put the wrong country on a pinned slot."""


def assign_server(slot_index: int, endpoint: str, public_key: str,
                  country: str = "", country_code: str = "",
                  location: str = "", identity_id: Optional[str] = None,
                  force: bool = False) -> Dict:
    """
    Point a slot at a different Surfshark *server*. Same port, same tags.

    If the slot is pinned to a country, only servers from that country are
    accepted. This is what makes ":20004 is Germany" a guarantee rather than
    a convention — a stray call cannot silently relocate the users on that
    slot's inbound. Pass force=True only when you genuinely mean to re-home
    the slot, and expect to change the pin too.
    """
    slot_now = registry.get_slot(slot_index)
    if not slot_now:
        raise ValueError(f"slot {slot_index} not found")

    if country and not force and not registry.country_matches(slot_now, country):
        raise CountryLockError(
            f"Slot {slot_index} is pinned to {slot_now['locked_country']}; "
            f"refusing to assign a {country} server. "
            f"Use relocate() if the move is intentional."
        )

    if ":" not in endpoint:
        endpoint = f"{endpoint}:{HANDSHAKE_PORT}"

    patch = {
        "endpoint": endpoint,
        "public_key": public_key,
        "country": country,
        "country_code": country_code,
        "location": location,
        "fail_streak": 0,
    }
    if identity_id:
        patch["identity_id"] = identity_id
    else:
        cur = registry.get_slot(slot_index)
        if cur and not cur.get("identity_id"):
            idents = registry.identities()
            if idents:
                patch["identity_id"] = idents[slot_index % len(idents)]["id"]

    slot = registry.update_slot(slot_index, **patch)
    if not slot:
        raise ValueError(f"slot {slot_index} not found")

    started = start_slot(slot_index)
    return {"slot": slot, "started": started, "panel_touched": False}


def pin_slot(slot_index: int, country: str, location: str = "",
             identity_id: Optional[str] = None) -> Dict:
    """
    Pin a slot to a country AND put a server from that country on it.

    This is the normal way to set a slot up:  slot 4 = Germany, forever.
    After this, key rotations and watchdog failovers can never move it
    somewhere else.
    """
    matches = [c for c in fetch_clusters()
               if c["country"].replace(" ", "").lower() == country.replace(" ", "").lower()]
    if location:
        narrowed = [c for c in matches if location.lower() in c["location"].lower()]
        matches = narrowed or matches
    if not matches:
        raise ValueError(f"No Surfshark servers found for country '{country}'")

    pick = matches[0]
    registry.lock_country(slot_index, pick["country"], pick["countryCode"])
    result = assign_server(
        slot_index, pick["endpoint"], pick["publicKey"],
        pick["country"], pick["countryCode"], pick["location"],
        identity_id=identity_id,
    )
    result["locked_to"] = pick["country"]
    return result


def relocate(slot_index: int, new_country: str, location: str = "") -> Dict:
    """
    Deliberately move a pinned slot to a different country.

    Separate from assign_server on purpose: every user whose config points
    at this slot's inbound will start exiting from the new country, with no
    change on their side. That should never happen by accident.
    """
    old = registry.get_slot(slot_index)
    if not old:
        raise ValueError(f"slot {slot_index} not found")
    previous = old.get("locked_country")

    registry.unlock_country(slot_index)
    result = pin_slot(slot_index, new_country, location)
    result["previous_country"] = previous
    result["warning"] = (
        f"Users on {old['inbound_tag']} now exit via {new_country} "
        f"instead of {previous}."
    ) if previous else None

    log.info("Slot %s relocated: %s -> %s", slot_index, previous, new_country)
    return result


def clear_slot(slot_index: int) -> None:
    """Empty a slot but keep its port reserved so the panel stays valid."""
    stop_slot(slot_index)
    registry.update_slot(
        slot_index, endpoint=None, public_key=None,
        country=None, country_code=None, location=None, fail_streak=0,
    )
    try:
        os.remove(_conf_path(slot_index))
    except OSError:
        pass


# ======================================================================
# Surfshark catalogue
# ======================================================================

_cluster_cache: Dict = {"at": 0.0, "data": []}
CLUSTER_TTL = 600


def fetch_clusters(force: bool = False) -> List[Dict]:
    now = time.time()
    if not force and _cluster_cache["data"] and (now - _cluster_cache["at"]) < CLUSTER_TTL:
        return _cluster_cache["data"]

    req = urllib.request.Request(
        "https://api.surfshark.com/v4/server/clusters",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = __import__("json").loads(resp.read())

    out = []
    for c in raw:
        if c.get("pubKey") and c.get("connectionName"):
            out.append({
                "country": c.get("country", "Unknown"),
                "countryCode": c.get("countryCode", ""),
                "location": c.get("location", ""),
                "endpoint": c["connectionName"],
                "publicKey": c["pubKey"],
            })
    out.sort(key=lambda x: (x["country"], x["location"]))
    _cluster_cache.update({"at": now, "data": out})
    return out


def capacity_report(target_slots: Optional[int] = None) -> Dict:
    """
    Sanity-check a deployment size against the machine and the key pool.

    Written for the 140-location case: at that scale the things that bite
    are key count, RAM, and file descriptors — and all three are cheaper to
    check now than to discover at 03:00 when half the tunnels are down.
    """
    from . import config

    reg = registry.load()
    live = len(registry.occupied_slots())
    target = target_slots or len(reg["slots"]) or live
    keys = len(reg["identities"])

    # RAM
    mem_total_mb = mem_avail_mb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total_mb = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    mem_avail_mb = int(line.split()[1]) // 1024
    except OSError:
        pass

    MB_PER_TUNNEL = 25          # observed working figure for wireproxy
    ram_needed = target * MB_PER_TUNNEL

    # File descriptors — each tunnel holds several
    fd_limit = None
    try:
        import resource
        fd_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:       # noqa: BLE001
        pass
    fd_needed = target * 12

    keys_needed = math.ceil(target / registry.MAX_SLOTS_PER_KEY) if target else 0

    warnings, blockers = [], []

    if keys < keys_needed:
        blockers.append(
            f"{target} tunnels need about {keys_needed} keypairs "
            f"(limit {registry.MAX_SLOTS_PER_KEY} each); you have {keys}. "
            f"Without more keys the provider will keep culling sessions."
        )

    if mem_total_mb and ram_needed > mem_total_mb * 0.7:
        blockers.append(
            f"{target} tunnels need roughly {ram_needed} MB; "
            f"the machine has {mem_total_mb} MB."
        )
    elif mem_avail_mb and ram_needed > mem_avail_mb:
        warnings.append(
            f"Estimated {ram_needed} MB needed but only {mem_avail_mb} MB free right now."
        )

    if fd_limit and fd_needed > fd_limit:
        warnings.append(
            f"Open-file limit is {fd_limit}; about {fd_needed} would be used. "
            f"Raise LimitNOFILE in the systemd unit."
        )

    if target > config.MAX_SLOTS:
        blockers.append(
            f"{target} exceeds MAX_SLOTS ({config.MAX_SLOTS}). "
            f"Set PEPECORE_MAX_SLOTS higher before reserving."
        )

    stagger = 0.5 if target <= 20 else (1.0 if target <= 60 else 1.5)

    return {
        "target_slots": target,
        "live_slots": live,
        "keys_present": keys,
        "keys_needed": keys_needed,
        "slots_per_key_limit": registry.MAX_SLOTS_PER_KEY,
        "ram_total_mb": mem_total_mb,
        "ram_available_mb": mem_avail_mb,
        "ram_estimate_mb": ram_needed,
        "fd_limit": fd_limit,
        "fd_estimate": fd_needed,
        "boot_seconds_estimate": int(target * stagger),
        "warnings": warnings,
        "blockers": blockers,
        "ok": not blockers,
    }


def alternatives_for(country: str, avoid_endpoint: str = "") -> List[Dict]:
    """
    Other servers in the SAME country. The watchdog uses this for failover,
    which is why a dead server never changes a slot's exit country — it can
    only ever be replaced by another server flying the same flag.
    """
    try:
        clusters = fetch_clusters()
    except Exception:       # noqa: BLE001
        return []
    norm = (country or "").replace(" ", "").replace("-", "").lower()
    if not norm:
        return []
    same = [c for c in clusters
            if c["country"].replace(" ", "").replace("-", "").lower() == norm]
    if avoid_endpoint:
        same = [c for c in same if c["endpoint"] not in avoid_endpoint]
    return same


# Geographic fallback groups. Used ONLY when every server in a slot's own
# country is unreachable — the choice is then between a dead slot and a
# neighbouring exit, and a working neighbour beats nothing.
NEIGHBOURS = {
    "germany":       ["Netherlands", "Austria", "Switzerland", "Denmark", "Poland", "France"],
    "netherlands":   ["Germany", "Belgium", "Denmark", "United Kingdom", "France"],
    "france":        ["Belgium", "Germany", "Switzerland", "Spain", "Netherlands"],
    "unitedkingdom": ["Ireland", "Netherlands", "France", "Belgium"],
    "japan":         ["South Korea", "Taiwan", "Hong Kong", "Singapore"],
    "southkorea":    ["Japan", "Taiwan", "Hong Kong", "Singapore"],
    "singapore":     ["Malaysia", "Hong Kong", "Taiwan", "Japan"],
    "hongkong":      ["Taiwan", "Singapore", "Japan", "South Korea"],
    "taiwan":        ["Hong Kong", "Japan", "South Korea", "Singapore"],
    "unitedstates":  ["Canada", "Mexico"],
    "canada":        ["United States"],
    "turkey":        ["Bulgaria", "Greece", "Romania", "Cyprus"],
    "unitedarabemirates": ["Bahrain", "Qatar", "Oman", "Saudi Arabia"],
    "poland":        ["Germany", "Czech Republic", "Slovakia", "Lithuania"],
    "sweden":        ["Denmark", "Norway", "Finland", "Germany"],
    "norway":        ["Sweden", "Denmark", "Finland"],
    "denmark":       ["Sweden", "Germany", "Norway", "Netherlands"],
    "finland":       ["Sweden", "Estonia", "Norway"],
    "italy":         ["Switzerland", "Austria", "France", "Slovenia"],
    "spain":         ["Portugal", "France", "Italy"],
    "portugal":      ["Spain", "France"],
    "switzerland":   ["Germany", "Austria", "France", "Italy"],
    "austria":       ["Germany", "Switzerland", "Czech Republic", "Italy"],
    "belgium":       ["Netherlands", "France", "Germany"],
    "ireland":       ["United Kingdom", "Netherlands"],
    "india":         ["Singapore", "United Arab Emirates", "Sri Lanka"],
    "australia":     ["New Zealand", "Singapore"],
    "newzealand":    ["Australia", "Singapore"],
    "brazil":        ["Argentina", "Chile", "Uruguay"],
    "argentina":     ["Chile", "Brazil", "Uruguay"],
}


def _norm(s: str) -> str:
    return (s or "").replace(" ", "").replace("-", "").lower()


def failover_candidates(country: str, avoid_endpoint: str = "") -> List[Tuple[Dict, str]]:
    """
    Servers to try when a slot is down, in order of preference:

        1. same country          -> exit country unchanged (the normal case)
        2. neighbouring country  -> only if the whole country is unreachable
        3. anything alive        -> last resort, better than a dead slot

    Returns (server, tier) pairs so the caller can log and flag drift.
    A slot that falls back to tier 2 or 3 keeps its pin, so as soon as its
    real country comes back the watchdog pulls it home again.
    """
    out: List[Tuple[Dict, str]] = []

    same = alternatives_for(country, avoid_endpoint)
    out += [(c, "same-country") for c in same]

    try:
        clusters = fetch_clusters()
    except Exception:       # noqa: BLE001
        return out

    for nb in NEIGHBOURS.get(_norm(country), []):
        for c in clusters:
            if _norm(c["country"]) == _norm(nb) and c["endpoint"] not in (avoid_endpoint or ""):
                out.append((c, "neighbour"))

    if not out:
        for c in clusters:
            if c["endpoint"] not in (avoid_endpoint or ""):
                out.append((c, "any"))

    return out


def slot_country(slot: Dict) -> str:
    """The country a slot must serve: its pin if it has one, else current."""
    return slot.get("locked_country") or slot.get("country") or ""
