#!/usr/bin/env python3
"""
pepectl — command line control for PepeCore.

The point of this tool: the operations you actually perform week to week
never need the web panel, so they're available straight from SSH.

    # swap a Surfshark private key across every tunnel using it
    ./pepectl.py key rotate <identity-id> --key <NEW_PRIVATE_KEY>

    # see what's up
    ./pepectl.py status

    # move slot 4 to Japan
    ./pepectl.py slot set 4 --country Japan

None of the above contacts PasarGuard. `pepectl.py bind` is the only
command that does, and you run it once.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import engine, registry     # noqa: E402
from core.rotator import rotator      # noqa: E402

G, Y, R, B, D, X = "\033[92m", "\033[93m", "\033[91m", "\033[94m", "\033[2m", "\033[0m"


def _ok(m):   print(f"{G}✓{X} {m}")
def _warn(m): print(f"{Y}!{X} {m}")
def _err(m):  print(f"{R}✗{X} {m}")
def _head(m): print(f"\n{B}{m}{X}\n" + "─" * 62)


# ---------------------------------------------------------------- status

def cmd_status(args):
    snap = engine.health_snapshot(deep=args.deep)
    reg = registry.load()

    _head("PepeCore Status")
    print(f"  Slots     : {snap['total']}  "
          f"({G}{snap['alive']} up{X}, {R}{snap['dead']} down{X}, {D}{snap['empty']} empty{X})")

    b = reg["panel_binding"]
    if b["bound"]:
        print(f"  Panel     : bound to core {b['core_id']} on {b['bound_at']}")
        print(f"  {D}Key/server changes since then required zero panel calls.{X}")
    else:
        print(f"  Panel     : {Y}not bound yet{X} — run `pepectl.py bind`")

    _head("Identities (WireGuard keys)")
    if not reg["identities"]:
        _warn("none — add one with `pepectl.py key add --key <KEY>`")
    for i in reg["identities"]:
        used = sum(1 for s in reg["slots"] if s.get("identity_id") == i["id"])
        preview = i["private_key"][:8] + "…" + i["private_key"][-4:]
        print(f"  {i['id']}  {i['label']:<14} {preview}  {D}{i['address']}  "
              f"used by {used} slot(s){X}")

    _head("Slots   (🔒 = country pinned to this port)")
    for s in snap["slots"]:
        if s["status"] == "empty":
            print(f"  {D}[{s['index']:03d}] :{s['port']}  — empty —{X}")
            continue
        mark = f"{G}UP  {X}" if s["status"] == "up" else f"{R}DOWN{X}"
        locked = s.get("locked_country")
        pin = "🔒" if locked else "  "
        loc = s.get("location") or ""
        where = (locked or s.get("country") or "?") + (f" / {loc}" if loc else "")
        drift = ""
        if locked and s.get("country") and \
                locked.replace(" ", "").lower() != s["country"].replace(" ", "").lower():
            drift = f" {R}⚠ serving {s['country']}{X}"
        print(f"  [{s['index']:03d}] :{s['port']}  {mark} {pin} {where:<26} "
              f"{D}{s.get('endpoint', '')}{X}{drift}")
    print()


# ------------------------------------------------------------ identities

def cmd_key_add(args):
    ident = registry.add_identity(args.key, args.address, args.label or "")
    _ok(f"Added identity {ident['id']} ({ident['label']})")
    print(f"  {D}Assign it to slots with `pepectl.py key rebalance`.{X}")


def cmd_key_rotate(args):
    """The headline command."""
    ident = registry.get_identity(args.identity_id)
    if not ident:
        _err(f"No identity '{args.identity_id}'. Run `pepectl.py status` to list them.")
        sys.exit(1)

    affected = [s for s in registry.occupied_slots() if s.get("identity_id") == args.identity_id]
    print(f"\nRotating key for {B}{ident['label']}{X} ({args.identity_id})")
    print(f"  affects {len(affected)} tunnel(s): "
          f"{', '.join(str(s['index']) for s in affected) or '(none)'}")
    print(f"  {D}ports unchanged · tags unchanged · panel not contacted{X}\n")

    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    address = args.address or ident["address"]
    result = engine.rotate_identity(args.identity_id, args.key, address)

    _ok(f"Rotated. {result['restarted']}/{len(affected)} tunnels back up.")
    print(f"  {D}No inbounds rebuilt. No UUIDs changed. "
          f"User subscriptions unaffected.{X}")
    if result["restarted"] < len(affected):
        _warn("Some tunnels didn't come up immediately — "
              "the watchdog will retry within 2 minutes.")


def cmd_key_remove(args):
    if registry.remove_identity(args.identity_id):
        _ok(f"Removed {args.identity_id}")
    else:
        _err("Not found")


def cmd_key_import(args):
    """Bulk-import keys from a file or stdin."""
    if args.file == "-":
        blob = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8") as f:
            blob = f.read()

    entries = registry.parse_key_blob(blob, args.address)
    if not entries:
        _err("No WireGuard keys found in that file.")
        sys.exit(1)

    r = registry.add_identities_bulk(entries, args.address)
    _ok(f"Imported {r['added_count']} keys (total now {r['total_keys']})")
    if r["skipped_duplicates"]:
        _warn(f"{r['skipped_duplicates']} duplicate(s) skipped")
    registry.rebalance_identities()
    print(f"  {D}Keys spread across slots. Run `pepectl key load` to verify.{X}")


def cmd_capacity(args):
    r = engine.capacity_report(args.slots or None)
    _head(f"Capacity check for {r['target_slots']} slots")
    print(f"  keys        : {r['keys_present']} present, ~{r['keys_needed']} needed "
          f"({r['slots_per_key_limit']} tunnels each)")
    if r["ram_total_mb"]:
        print(f"  RAM         : ~{r['ram_estimate_mb']} MB needed, "
              f"{r['ram_total_mb']} MB total, {r['ram_available_mb']} MB free")
    if r["fd_limit"]:
        print(f"  open files  : ~{r['fd_estimate']} needed, limit {r['fd_limit']}")
    print(f"  boot time   : ~{r['boot_seconds_estimate']}s to bring all tunnels up")

    if r["blockers"]:
        print()
        for b in r["blockers"]:
            _err(b)
    for w in r["warnings"]:
        _warn(w)
    if r["ok"] and not r["warnings"]:
        print()
        _ok("This size looks workable on this machine.")


def cmd_key_load(args):
    kl = registry.key_load()
    _head("Key load")
    print(f"  live tunnels {kl['total_live_slots']}   keys {kl['keys_present']}   "
          f"recommended {kl['keys_needed']}   limit/key {kl['limit_per_key']}\n")
    for r in kl["keys"]:
        flag = f"{R}OVERLOADED{X}" if r["overloaded"] else f"{G}ok{X}"
        print(f"  {r['label']:<14} {r['slot_count']:>3} tunnels   {flag}")
    if kl["orphan_slots"]:
        _warn(f"slots with no key: {kl['orphan_slots']}")

    if not kl["healthy"]:
        print()
        _warn("One keypair is serving too many servers at once.")
        print(f"""  This is the usual cause of locations dropping at random every
  hour or two, fixed only by replacing the key: the provider sees
  one identity connected from many places and culls the extras.

  Generate ~{kl['keys_needed']} keypairs in your Surfshark account's WireGuard
  section (several keys can live on ONE account), add them with
  `pepectl key add`, then run `pepectl key rebalance`.""")


def cmd_rotate_status(args):
    st = rotator.status()
    _head("Scheduled key rotation")
    print(f"  status      : {'on, every %sh' % st['interval_hours'] if st['enabled'] else 'off'}")
    print(f"  cycles run  : {st['cycles']}")
    print(f"  last run    : {st['last_run'] or '—'}")
    print(f"  next run    : {st['next_run'] or '—'}")
    if st["enabled"] and not st["effective"]:
        _warn("Only one key in the pool — each cycle is a no-op.")


def cmd_rotate_set(args):
    st = rotator.configure(not args.off, args.hours)
    if args.off:
        _ok("Scheduled rotation disabled.")
    else:
        _ok(f"Scheduled rotation on — every {st['interval_hours']}h")
        if not st["effective"]:
            _warn("Only one key present; add more keypairs or this does nothing.")


def cmd_rotate_now(args):
    r = rotator.rotate_now()
    if r.get("skipped"):
        _warn(r["skipped"])
    else:
        _ok(f"{r['rotated']} slots moved across {r['keys_in_pool']} keys "
            f"({r['restarted']} back up). Panel untouched.")


def cmd_key_rebalance(args):
    registry.rebalance_identities()
    n = sum(1 for s in registry.occupied_slots() if engine.start_slot(s["index"], quiet=True))
    _ok(f"Rebalanced and restarted {n} tunnels. Panel untouched.")


# ----------------------------------------------------------------- slots

def cmd_slots_ensure(args):
    reg = registry.ensure_slots(args.count)
    _ok(f"{len(reg['slots'])} slots reserved "
        f"(ports {reg['base_port']}–{reg['base_port'] + len(reg['slots']) - 1})")
    if reg["panel_binding"]["bound"] and args.count > reg["panel_binding"]["slot_count"]:
        _warn("Slot count grew — re-run `bind` to wire the new ports into the panel. "
              "Existing slots keep their config.")


def cmd_slot_pin(args):
    """Pin a slot to a country permanently."""
    try:
        res = engine.pin_slot(args.index, args.country, args.location)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)

    s = res["slot"]
    _ok(f"Slot {args.index} pinned to {res['locked_to']} "
        f"({s.get('location') or s['endpoint']})")
    print(f"  {D}Port :{s['port']} now serves {res['locked_to']} permanently.")
    print(f"  Key rotations and server failures cannot change this.{X}")


def cmd_slot_relocate(args):
    slot = registry.get_slot(args.index)
    if not slot:
        _err(f"No slot {args.index}")
        sys.exit(1)

    prev = slot.get("locked_country") or slot.get("country") or "(unset)"
    print(f"\n{Y}This moves slot {args.index} from {prev} to {args.country}.{X}")
    print(f"  Users on {slot['inbound_tag']} will start exiting from "
          f"{args.country} with no change on their side.\n")
    if not args.yes:
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    res = engine.relocate(args.index, args.country, args.location)
    _ok(f"Slot {args.index}: {prev} → {res['locked_to']}")
    print(f"  {D}Port unchanged. Panel not contacted.{X}")


def cmd_slot_clear(args):
    engine.clear_slot(args.index)
    _ok(f"Slot {args.index} cleared; port stays reserved.")


def cmd_slot_fill(args):
    """Auto-fill empty slots with the fastest spread of countries."""
    import time
    servers = engine.fetch_clusters()
    reg = registry.load()
    empty = [s for s in reg["slots"] if not s.get("endpoint")]
    if not empty:
        _warn("No empty slots. Use `slots ensure <n>` to add more.")
        return
    if not reg["identities"]:
        _err("Add a WireGuard key first: `pepectl.py key add --key <KEY>`")
        sys.exit(1)

    # One server per country, for maximum geographic spread.
    seen, pool = set(), []
    for s in servers:
        if s["country"] not in seen:
            seen.add(s["country"])
            pool.append(s)

    n = min(len(empty), len(pool), args.count or len(empty))
    for i in range(n):
        slot, srv = empty[i], pool[i]
        # Pin as we go: each slot gets one country and keeps it.
        registry.lock_country(slot["index"], srv["country"], srv["countryCode"])
        engine.assign_server(
            slot["index"], srv["endpoint"], srv["publicKey"],
            srv["country"], srv["countryCode"], srv["location"],
        )
        print(f"  [{slot['index']:03d}] :{slot['port']} → {srv['country']} {D}(pinned){X}")
        time.sleep(0.5)
    _ok(f"Filled and pinned {n} slots. Panel not contacted.")
    print(f"  {D}Each port now serves one fixed country. "
          f"Use `slot relocate` if you ever need to change one.{X}")


# ------------------------------------------------------------- lifecycle

def cmd_ports_show(args):
    from core import config
    _head("Port layout (identical on every machine)")
    print("  " + config.summary().replace("\n", "\n  "))
    print(f"\n  {D}Derived from core/config.py. Copy that file to a new server")
    print(f"  and the layout comes with it.{X}\n")

    reg = registry.load()
    for s in reg["slots"]:
        tag = s.get("locked_country") or s.get("country") or "—"
        print(f"  slot {s['index']:03d}   SOCKS :{s['port']}   "
              f"inbound :{s['inbound_port']}   {D}{tag}{X}")
    if not reg["slots"]:
        print(f"  {D}(no slots reserved yet){X}")
    print()


def cmd_ports_resync(args):
    """Force the registry back in line with config.py."""
    report = registry.resync_ports()
    if not report["slots_corrected"]:
        _ok("Ports already match config.py — nothing to do.")
        return

    _warn(f"{report['slots_corrected']} slot(s) had the wrong ports; corrected:")
    for c in report["changes"]:
        print(f"    slot {c['slot']:03d}  SOCKS {c['socks'][0]}→{c['socks'][1]}   "
              f"inbound {c['inbound'][0]}→{c['inbound'][1]}")
    print(f"\n  {Y}Next: restart the engine, then re-run `bind` so the panel")
    print(f"  points at the corrected ports.{X}")


def cmd_recover(args):
    _ok(f"{engine.recover_all()} tunnels restarted on their original ports.")


def cmd_stop(args):
    _ok(f"Stopped {engine.stop_all()} processes.")


def cmd_servers(args):
    servers = engine.fetch_clusters(force=True)
    if args.country:
        servers = [s for s in servers if args.country.lower() in s["country"].lower()]
    _head(f"Surfshark servers ({len(servers)})")
    for s in servers[:args.limit]:
        print(f"  {s['country']:<24} {s['location']:<20} {D}{s['endpoint']}{X}")


# ------------------------------------------------------------------ bind

def cmd_bind(args):
    import asyncio
    from core.panel import PanelClient

    print(f"\n{Y}This is the only command that talks to the panel.{X}")
    print(f"{D}Run it once now; key and country changes afterwards won't need it.{X}\n")

    client = PanelClient(args.host, args.token)

    async def run():
        if not args.template_host_id:
            hosts = await client.hosts()
            _head("Available template hosts")
            for h in hosts:
                print(f"  {h['id']:<6} {h['remark']:<34} {D}{h['inbound_tag']}{X}")
            print("\nRe-run with --template-host-id <id>")
            return None
        return await client.bind(args.core_id, args.template_host_id,
                                 args.slot_count, args.node_ip)

    result = asyncio.run(run())
    if result:
        _ok(f"Bound {result['slots_bound']} slots "
            f"({result['hosts_created']} new, {result['hosts_reused']} reused)")
        print(f"  {D}{result['note']}{X}")


# ------------------------------------------------------------------ auth

def cmd_auth_add(args):
    registry.add_user(args.username, args.password)
    _ok(f"User '{args.username}' added/updated.")

def cmd_auth_list(args):
    users = registry.get_users()
    if not users:
        _warn("No users configured. The web panel is currently unprotected.")
        return
    _head("Authentication")
    for u in users:
        print(f"  User: {G}{u['username']:<14}{X} Pass: {Y}{u['password']}{X}")
    print()

def cmd_auth_remove(args):
    if registry.remove_user(args.username):
        _ok(f"User '{args.username}' removed.")
    else:
        _err(f"User '{args.username}' not found.")


# ------------------------------------------------------------------ main

def main():
    p = argparse.ArgumentParser(prog="pepectl", description="PepeCore control")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="show engine and slot health")
    s.add_argument("--deep", action="store_true", help="verify real egress per tunnel")
    s.set_defaults(func=cmd_status)

    # key
    k = sub.add_parser("key", help="manage WireGuard identities").add_subparsers(
        dest="sub", required=True)

    ka = k.add_parser("add")
    ka.add_argument("--key", required=True)
    ka.add_argument("--address", default="10.14.0.2/16")
    ka.add_argument("--label", default="")
    ka.set_defaults(func=cmd_key_add)

    kr = k.add_parser("rotate", help="replace a private key in place (no panel call)")
    kr.add_argument("identity_id")
    kr.add_argument("--key", required=True)
    kr.add_argument("--address", default=None)
    kr.add_argument("-y", "--yes", action="store_true")
    kr.set_defaults(func=cmd_key_rotate)

    kd = k.add_parser("remove")
    kd.add_argument("identity_id")
    kd.set_defaults(func=cmd_key_remove)

    kb = k.add_parser("rebalance")
    kb.set_defaults(func=cmd_key_rebalance)

    kl = k.add_parser("load", help="show per-key tunnel counts and warnings")
    kl.set_defaults(func=cmd_key_load)

    ki = k.add_parser("import", help="bulk-import keys from a file (or - for stdin)")
    ki.add_argument("file")
    ki.add_argument("--address", default="10.14.0.2/16")
    ki.set_defaults(func=cmd_key_import)

    # rotation
    rt = sub.add_parser("rotate", help="scheduled key rotation"
                        ).add_subparsers(dest="sub", required=True)
    rt.add_parser("status").set_defaults(func=cmd_rotate_status)
    rs = rt.add_parser("set", help="enable/disable and set the interval")
    rs.add_argument("--hours", type=float, default=3)
    rs.add_argument("--off", action="store_true")
    rs.set_defaults(func=cmd_rotate_set)
    rt.add_parser("now", help="rotate immediately").set_defaults(func=cmd_rotate_now)

    # slots
    sl = sub.add_parser("slots").add_subparsers(dest="sub", required=True)
    se = sl.add_parser("ensure")
    se.add_argument("count", type=int)
    se.set_defaults(func=cmd_slots_ensure)

    sf = sl.add_parser("fill", help="auto-assign servers to empty slots")
    sf.add_argument("--count", type=int, default=0)
    sf.set_defaults(func=cmd_slot_fill)

    sm = sub.add_parser("slot").add_subparsers(dest="sub", required=True)

    sp = sm.add_parser("pin", help="pin a slot to a country permanently")
    sp.add_argument("index", type=int)
    sp.add_argument("--country", required=True)
    sp.add_argument("--location", default="")
    sp.set_defaults(func=cmd_slot_pin)

    sr = sm.add_parser("relocate", help="deliberately move a pinned slot elsewhere")
    sr.add_argument("index", type=int)
    sr.add_argument("--country", required=True)
    sr.add_argument("--location", default="")
    sr.add_argument("-y", "--yes", action="store_true")
    sr.set_defaults(func=cmd_slot_relocate)

    sc = sm.add_parser("clear")
    sc.add_argument("index", type=int)
    sc.set_defaults(func=cmd_slot_clear)

    cap = sub.add_parser("capacity", help="check a deployment size against this machine")
    cap.add_argument("--slots", type=int, default=0)
    cap.set_defaults(func=cmd_capacity)

    # ports
    pt = sub.add_parser("ports", help="inspect / fix the fixed port layout"
                        ).add_subparsers(dest="sub", required=True)
    pt.add_parser("show").set_defaults(func=cmd_ports_show)
    pt.add_parser("resync", help="force registry back in line with config.py"
                  ).set_defaults(func=cmd_ports_resync)

    # lifecycle
    sub.add_parser("recover").set_defaults(func=cmd_recover)
    sub.add_parser("stop").set_defaults(func=cmd_stop)

    sv = sub.add_parser("servers")
    sv.add_argument("--country", default="")
    sv.add_argument("--limit", type=int, default=50)
    sv.set_defaults(func=cmd_servers)

    b = sub.add_parser("bind", help="ONE-TIME panel wiring")
    b.add_argument("--host", required=True)
    b.add_argument("--token", required=True)
    b.add_argument("--core-id", required=True)
    b.add_argument("--template-host-id", default="")
    b.add_argument("--slot-count", type=int, default=15)
    b.add_argument("--node-ip", default="127.0.0.1")
    b.set_defaults(func=cmd_bind)

    # auth
    au = sub.add_parser("auth", help="manage web panel authentication").add_subparsers(dest="sub", required=True)
    aua = au.add_parser("add", help="add or update a user")
    aua.add_argument("username")
    aua.add_argument("password")
    aua.set_defaults(func=cmd_auth_add)
    
    aul = au.add_parser("list", help="list all users and passwords")
    aul.set_defaults(func=cmd_auth_list)

    aur = au.add_parser("remove", help="remove a user")
    aur.add_argument("username")
    aur.set_defaults(func=cmd_auth_remove)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
