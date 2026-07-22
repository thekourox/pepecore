"""
panel.py — The ONLY module in this project that knows PasarGuard exists.

Everything panel-specific is quarantined here. Delete this file and the
engine still runs perfectly; you would just have to wire the SOCKS ports
into Xray by hand.

THE ONE-TIME BIND
=================
`bind()` is a setup operation, not an operational one. You run it once,
when you first stand the node up or when you want MORE slots than you
currently have. It writes into the core config:

    inbound  PS-In-000   port 10000   ->  outbound PS-Out-000 -> 127.0.0.1:20000
    inbound  PS-In-001   port 10001   ->  outbound PS-Out-001 -> 127.0.0.1:20001
    ...

Note what is NOT in there: no country, no server, no key, no endpoint.
The panel is bound to *ports*, and ports are permanent.

After that, the day-to-day work all happens in engine.py:

    change the key         -> engine.rotate_identity()    no panel call
    change countries       -> engine.assign_server()      no panel call
    server dies            -> watchdog swaps it           no panel call
    reboot                 -> engine.recover_all()        no panel call

You only ever come back here to grow the slot count.
"""

import copy
import logging
import re
import uuid
from typing import Dict, List, Optional

import httpx

from . import config, registry

log = logging.getLogger("pepecore.panel")

TIMEOUT = 120.0

# Tags we own. Anything matching these prefixes is ours to manage; anything
# else in the core config is left strictly alone.
IN_PREFIX = "PS-In-"
OUT_PREFIX = "PS-Out-"

# Legacy prefixes from the previous architecture, cleaned up on bind.
LEGACY_IN = ("Surf-", "B-In-")
LEGACY_OUT = ("SurfOut-", "B-Out-")

# Port layout lives in config.py so it is identical on every machine.
BASE_INBOUND_PORT = config.INBOUND_BASE_PORT


def flag_emoji(country_code: str) -> str:
    """
    Two-letter country code -> regional indicator pair, e.g. 'DE' -> 🇩🇪.
    Returns "" for anything that isn't a plausible code.
    """
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


def host_remark(country: str, location: str = "", country_code: str = "") -> str:
    """
    Build the host label users see in their subscription:

        Germany - Berlin 🇩🇪
        Japan 🇯🇵                (when the city adds nothing)

    The city is omitted when it just repeats the country name, which is how
    Surfshark lists single-city countries.
    """
    country = (country or "").strip()
    location = (location or "").strip()
    flag = flag_emoji(country_code)

    part = f" - {location}" if location and location != country else ""
    return f"{country}{part} {flag}".strip()


def slot_remark(slot: Dict) -> str:
    """The remark for a slot, preferring its pin over its current server."""
    return host_remark(
        slot.get("locked_country") or slot.get("country") or "",
        slot.get("locked_location") or slot.get("location") or "",
        slot.get("locked_country_code") or slot.get("country_code") or "",
    ) or f"Slot {slot['index']:03d}"


class PanelClient:
    def __init__(self, host: str, token: str):
        self.host = host.rstrip("/")
        self.token = token.replace("Bearer ", "").strip()

    @property
    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    async def _get(self, client: httpx.AsyncClient, path: str):
        r = await client.get(f"{self.host}{path}", headers=self._headers, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()

    # ---------------- read-only helpers ----------------

    async def cores(self) -> List[Dict]:
        async with httpx.AsyncClient() as c:
            data = await self._get(c, "/api/cores/simple")
            return [{"id": str(x["id"]), "name": x["name"]} for x in data.get("cores", [])]

    async def hosts(self) -> List[Dict]:
        async with httpx.AsyncClient() as c:
            data = await self._get(c, "/api/hosts")
            return [
                {"id": str(h["id"]), "remark": h.get("remark", ""),
                 "port": h.get("port"), "inbound_tag": h.get("inbound_tag", "")}
                for h in data
            ]

    async def core_config(self, core_id: str) -> Dict:
        async with httpx.AsyncClient() as c:
            return await self._get(c, f"/api/core/{core_id}")

    # ---------------- the one-time bind ----------------

    async def bind(self, core_id: str, template_host_id: str,
                   slot_count: int, node_ip: str = "127.0.0.1") -> Dict:
        """
        Create `slot_count` inbound/outbound/routing triples wired to the
        engine's permanent SOCKS ports.

        Idempotent. Re-running with a larger slot_count adds only the new
        slots; existing ones keep their ports, tags and UUIDs, so existing
        subscriptions survive untouched.
        """
        registry.ensure_slots(slot_count)
        reg = registry.load()
        slots = reg["slots"][:slot_count]

        async with httpx.AsyncClient() as client:
            core_data = await self._get(client, f"/api/core/{core_id}")
            cfg = core_data["config"]
            cfg.setdefault("inbounds", [])
            cfg.setdefault("outbounds", [])
            cfg.setdefault("routing", {}).setdefault("rules", [])

            template_host = await self._get(client, f"/api/host/{template_host_id}")
            tpl_tag = template_host.get("inbound_tag")
            if not tpl_tag:
                raise ValueError("Template host has no inbound_tag")

            template_inbound = next(
                (i for i in cfg["inbounds"] if i.get("tag") == tpl_tag), None
            )
            if not template_inbound:
                raise ValueError(f"Template inbound '{tpl_tag}' not found in core config")

            # Remove anything left over from the OLD architecture.
            cfg["inbounds"] = [
                i for i in cfg["inbounds"]
                if not i.get("tag", "").startswith(LEGACY_IN)
            ]
            cfg["outbounds"] = [
                o for o in cfg["outbounds"]
                if not o.get("tag", "").startswith(LEGACY_OUT)
            ]
            cfg["routing"]["rules"] = [
                r for r in cfg["routing"]["rules"]
                if not _rule_matches_prefixes(r, LEGACY_IN, LEGACY_OUT)
            ]

            # Preserve UUIDs of slots we've already bound before, so that
            # re-binding never invalidates a live subscription.
            existing_hosts = await self._get(client, "/api/hosts")
            known: Dict[str, Dict] = {
                h.get("inbound_tag"): h
                for h in existing_hosts
                if h.get("inbound_tag", "").startswith(IN_PREFIX)
            }

            new_host_payloads = []
            host_updates = []

            for slot in slots:
                in_tag = slot["inbound_tag"]
                out_tag = slot["outbound_tag"]
                # Both ports come from config.py, so re-binding on a rebuilt
                # server reproduces the exact same layout.
                inbound_port = slot["inbound_port"]

                prior = known.get(in_tag)
                if prior:
                    # Keep the UUID so live subscriptions stay valid.
                    slot_uuid = prior.get("uuid") or str(uuid.uuid4())
                    is_new = False
                else:
                    slot_uuid = str(uuid.uuid4())
                    is_new = True

                # --- inbound (cloned from the template) ---
                inbound = copy.deepcopy(template_inbound)
                inbound["tag"] = in_tag
                inbound["port"] = inbound_port
                clients = inbound.get("settings", {}).get("clients")
                if clients:
                    client_entry = copy.deepcopy(clients[0])
                    client_entry["id"] = slot_uuid
                    client_entry["email"] = f"{in_tag}@pepecore"
                    inbound["settings"]["clients"] = [client_entry]

                cfg["inbounds"] = [i for i in cfg["inbounds"] if i.get("tag") != in_tag]
                cfg["inbounds"].append(inbound)

                # --- outbound: points at the PERMANENT engine port ---
                cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != out_tag]
                cfg["outbounds"].append({
                    "tag": out_tag,
                    "protocol": "socks",
                    "settings": {
                        "servers": [{"address": node_ip, "port": slot["port"]}]
                    },
                })

                # --- routing ---
                cfg["routing"]["rules"] = [
                    r for r in cfg["routing"]["rules"] if r.get("outboundTag") != out_tag
                ]
                cfg["routing"]["rules"].insert(0, {
                    "type": "field",
                    "inboundTag": [in_tag],
                    "outboundTag": out_tag,
                })

                if is_new:
                    payload = copy.deepcopy(template_host)
                    for k in ("id", "created_at", "updated_at"):
                        payload.pop(k, None)
                    payload["uuid"] = slot_uuid
                    payload["remark"] = slot_remark(slot)
                    payload["inbound_tag"] = in_tag
                    payload["port"] = inbound_port
                    new_host_payloads.append(payload)
                else:
                    # Existing host: refresh the label if the slot has since
                    # been pinned or relocated. The UUID is untouched, so
                    # current subscriptions keep working — only the name the
                    # user sees changes.
                    want = slot_remark(slot)
                    if prior.get("remark") != want or prior.get("port") != inbound_port:
                        updated = copy.deepcopy(prior)
                        updated["remark"] = want
                        updated["port"] = inbound_port
                        host_updates.append(updated)

            # Push config first so the tags exist before hosts reference them.
            core_data["config"] = cfg
            r = await client.put(
                f"{self.host}/api/core/{core_id}?restart_nodes=false",
                headers=self._headers, json=core_data, timeout=TIMEOUT,
            )
            if not r.is_success:
                raise RuntimeError(f"Core update rejected: {r.text}")

            created = 0
            for payload in new_host_payloads:
                hr = await client.post(
                    f"{self.host}/api/host/", headers=self._headers,
                    json=payload, timeout=TIMEOUT,
                )
                if hr.is_success:
                    created += 1
                else:
                    log.warning("Host create failed: %s", hr.text)

            relabelled = 0
            for payload in host_updates:
                ur = await client.put(
                    f"{self.host}/api/host/{payload['id']}", headers=self._headers,
                    json=payload, timeout=TIMEOUT,
                )
                if ur.is_success:
                    relabelled += 1
                else:
                    log.warning("Host relabel failed: %s", ur.text)

            # Single restart at the end.
            await client.put(
                f"{self.host}/api/core/{core_id}?restart_nodes=true",
                headers=self._headers, json=core_data, timeout=TIMEOUT,
            )

        registry.mark_bound(core_id, self.host, slot_count)
        log.info("Bound %s slots to core %s (%s new, %s relabelled)",
                 slot_count, core_id, created, relabelled)

        return {
            "slots_bound": slot_count,
            "hosts_created": created,
            "hosts_relabelled": relabelled,
            "hosts_reused": slot_count - created,
            "note": "Ports are now fixed. Key and server changes no longer touch the panel.",
        }

    async def relabel_hosts(self) -> Dict:
        """
        Bring host labels back in line with the slots' pinned countries.

        Cheaper than a full bind and touches nothing else: no config push,
        no restart, no UUID changes.
        """
        slots_by_tag = {s["inbound_tag"]: s for s in registry.load()["slots"]}

        async with httpx.AsyncClient() as client:
            hosts = await self._get(client, "/api/hosts")
            updated, unchanged = 0, 0

            for h in hosts:
                tag = h.get("inbound_tag", "")
                if not tag.startswith(IN_PREFIX):
                    continue
                slot = slots_by_tag.get(tag)
                if not slot:
                    continue

                want = slot_remark(slot)
                if h.get("remark") == want:
                    unchanged += 1
                    continue

                h["remark"] = want
                r = await client.put(
                    f"{self.host}/api/host/{h['id']}", headers=self._headers,
                    json=h, timeout=TIMEOUT,
                )
                if r.is_success:
                    updated += 1
                else:
                    log.warning("Relabel failed for %s: %s", tag, r.text)

        return {"relabelled": updated, "already_correct": unchanged}

    async def set_enabled(self, enabled: bool) -> Dict:
        """Enable/disable our hosts without deleting anything."""
        async with httpx.AsyncClient() as client:
            hosts = await self._get(client, "/api/hosts")
            n = 0
            for h in hosts:
                if h.get("inbound_tag", "").startswith(IN_PREFIX):
                    h["enable"] = enabled
                    await client.put(
                        f"{self.host}/api/host/{h['id']}", headers=self._headers,
                        json=h, timeout=TIMEOUT,
                    )
                    n += 1
        return {"updated": n, "enabled": enabled}

    async def unbind(self, core_id: str) -> Dict:
        """Remove everything this project created. Other configs untouched."""
        async with httpx.AsyncClient() as client:
            hosts = await self._get(client, "/api/hosts")
            removed = 0
            for h in hosts:
                if h.get("inbound_tag", "").startswith((IN_PREFIX,) + LEGACY_IN):
                    await client.delete(
                        f"{self.host}/api/host/{h['id']}",
                        headers=self._headers, timeout=TIMEOUT,
                    )
                    removed += 1

            core_data = await self._get(client, f"/api/core/{core_id}")
            cfg = core_data["config"]
            prefixes_in = (IN_PREFIX,) + LEGACY_IN
            prefixes_out = (OUT_PREFIX,) + LEGACY_OUT

            cfg["inbounds"] = [
                i for i in cfg.get("inbounds", [])
                if not i.get("tag", "").startswith(prefixes_in)
            ]
            cfg["outbounds"] = [
                o for o in cfg.get("outbounds", [])
                if not o.get("tag", "").startswith(prefixes_out)
            ]
            if "routing" in cfg and "rules" in cfg["routing"]:
                cfg["routing"]["rules"] = [
                    r for r in cfg["routing"]["rules"]
                    if not _rule_matches_prefixes(r, prefixes_in, prefixes_out)
                ]

            core_data["config"] = cfg
            await client.put(
                f"{self.host}/api/core/{core_id}?restart_nodes=true",
                headers=self._headers, json=core_data, timeout=TIMEOUT,
            )

        return {"hosts_removed": removed}


def _rule_matches_prefixes(rule: Dict, in_prefixes, out_prefixes) -> bool:
    inbound = rule.get("inboundTag")
    if isinstance(inbound, list) and any(
        isinstance(t, str) and t.startswith(tuple(in_prefixes)) for t in inbound
    ):
        return True
    outbound = rule.get("outboundTag")
    if isinstance(outbound, str) and outbound.startswith(tuple(out_prefixes)):
        return True
    return False
