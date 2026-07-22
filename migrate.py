#!/usr/bin/env python3
"""
migrate.py — import an existing pepeshark v1 install into PepeCore v2.

Reads the old wireproxy_configs/*.conf files, extracts the keys and server
assignments, and lays them out on the new permanent slot grid.

    python3 migrate.py --from /root/pepepanel/pepeshark

This only writes the local registry. It does not touch the panel. After the
import you still need to run `pepectl bind` once, because the old config's
port numbers were arbitrary and are being replaced by the fixed grid.

Your old install is left untouched — nothing is deleted.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import registry     # noqa: E402


def parse_conf(path):
    out = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if "=" not in line or line.startswith(("[", "#")):
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", required=True,
                    help="path to the old pepeshark directory")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    conf_dir = os.path.join(args.src, "wireproxy_configs")
    if not os.path.isdir(conf_dir):
        print(f"No wireproxy_configs found in {args.src}")
        sys.exit(1)

    confs = sorted(f for f in os.listdir(conf_dir) if f.endswith(".conf"))
    if not confs:
        print("No .conf files to import.")
        sys.exit(0)

    print(f"Found {len(confs)} old tunnel configs.\n")

    # Group by private key -> one identity per distinct key.
    by_key = {}
    entries = []

    for name in confs:
        c = parse_conf(os.path.join(conf_dir, name))
        pk = c.get("PrivateKey")
        if not pk:
            continue
        addr = c.get("Address", "10.14.0.2/16")
        endpoint = c.get("Endpoint", "")
        pubkey = c.get("PublicKey", "")

        tag = os.path.splitext(name)[0]
        m = re.match(r"(?:B-Out|SurfOut)-([A-Za-z]+)-", tag)
        country = m.group(1) if m else ""

        by_key.setdefault((pk, addr), [])
        entries.append({
            "key": (pk, addr), "endpoint": endpoint,
            "public_key": pubkey, "country": country, "old_tag": tag,
        })

    print(f"Distinct private keys: {len(by_key)}")
    print(f"Tunnels to place     : {len(entries)}\n")

    if args.dry_run:
        for i, e in enumerate(entries):
            print(f"  slot {i:03d} :{20000+i}  {e['country']:<18} {e['endpoint']}")
        print("\n(dry run — nothing written)")
        return

    # Create identities
    key_ids = {}
    for n, (pk, addr) in enumerate(by_key, 1):
        ident = registry.add_identity(pk, addr, f"imported-{n}")
        key_ids[(pk, addr)] = ident["id"]
        print(f"  identity {ident['id']}  ({pk[:8]}…)")

    # Lay out on the permanent grid
    registry.ensure_slots(len(entries))
    for i, e in enumerate(entries):
        registry.update_slot(
            i,
            identity_id=key_ids[e["key"]],
            endpoint=e["endpoint"],
            public_key=e["public_key"],
            country=e["country"],
        )

    print(f"\nImported {len(entries)} tunnels onto slots 0–{len(entries)-1} "
          f"(ports 20000–{20000+len(entries)-1}).")
    print("""
Next steps:
  1. pepectl status                  — confirm the layout looks right
  2. systemctl restart pepecore      — bring the tunnels up
  3. pepectl bind --host … --token … --core-id … --slot-count %d
                                     — one-time re-wire of the panel

The bind step replaces the old B-In-/B-Out- tags with the fixed PS-In-/PS-Out-
grid. Users on old hosts will need the new subscription links once; after that
you never have to re-inject again.
""" % len(entries))


if __name__ == "__main__":
    main()
