"""
app.py — HTTP surface for PepeCore.

Route layout mirrors the architecture, deliberately:

    /api/engine/*    Never contacts the panel. Keys, servers, slots, health.
    /api/panel/*     Contacts the panel. Only used at bind/unbind time.

If you never call anything under /api/panel/ after the initial bind, that
is the system working as designed.
"""

import logging
import os
import threading
from typing import List, Optional

import secrets
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from contextlib import asynccontextmanager

from core import engine, registry
from core.panel import PanelClient
from core.rotator import rotator, _restore as _restore_rotator
from core.watchdog import watchdog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("pepecore")

ROOT = os.path.dirname(os.path.abspath(__file__))


@asynccontextmanager
async def lifespan(app: FastAPI):
    def boot():
        try:
            engine.recover_all()
        except Exception as e:      # noqa: BLE001
            log.error("Boot recovery failed: %s", e)

    threading.Thread(target=boot, daemon=True).start()
    watchdog.start()
    _restore_rotator(rotator)
    yield
    rotator.stop()
    watchdog.stop()
    engine.stop_all()


app = FastAPI(title="PepeCore", version="2.0.0", lifespan=lifespan)

os.makedirs(os.path.join(ROOT, "static"), exist_ok=True)
os.makedirs(os.path.join(ROOT, "templates"), exist_ok=True)
app.mount("/static", StaticFiles(directory=os.path.join(ROOT, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(ROOT, "templates"))

SESSIONS = {}

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/"):
        users = registry.get_users()
        if users:
            auth = request.headers.get("Authorization")
            if not auth:
                return JSONResponse(status_code=401, content={"detail": "Missing Authorization header"})
            token = auth.replace("Bearer ", "").strip()
            if token not in SESSIONS:
                return JSONResponse(status_code=401, content={"detail": "Invalid or expired session token"})
    return await call_next(request)


# ======================================================================
# Models
# ======================================================================

class IdentityIn(BaseModel):
    private_key: str
    address: str = "10.14.0.2/16"
    label: str = ""


class IdentityRotate(BaseModel):
    private_key: str
    address: str


class ServerAssign(BaseModel):
    endpoint: str
    public_key: str
    country: str = ""
    country_code: str = ""
    location: str = ""
    identity_id: Optional[str] = None


class BulkKeyImport(BaseModel):
    blob: str
    default_address: str = "10.14.0.2/16"


class RotatorConfig(BaseModel):
    enabled: bool
    interval_hours: float = Field(ge=1, le=168, default=3)


class PinRequest(BaseModel):
    country: str
    location: str = ""
    identity_id: Optional[str] = None


class SlotsEnsure(BaseModel):
    count: int = Field(ge=1, le=256)


class BindRequest(BaseModel):
    core_id: str
    template_host_id: str
    slot_count: int = Field(ge=1, le=256)
    node_ip: str = "127.0.0.1"


class ToggleRequest(BaseModel):
    enable: bool


def _panel(x_panel_token: Optional[str], host: Optional[str]) -> PanelClient:
    if not x_panel_token or not host:
        raise HTTPException(401, "Missing panel credentials (X-Panel-Token + X-Panel-Host)")
    return PanelClient(host, x_panel_token)


# ======================================================================
# UI
# ======================================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# ======================================================================
# AUTH ROUTES
# ======================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def auth_login(req: LoginRequest):
    if not registry.check_user(req.username, req.password):
        raise HTTPException(401, "Invalid username or password")
    token = secrets.token_hex(32)
    SESSIONS[token] = req.username
    return {"token": token}

@app.get("/api/auth/me")
def auth_me(authorization: str = Header(None)):
    if not registry.get_users():
        return {"username": "admin (unsecured)", "setup_required": True}
    if not authorization:
        raise HTTPException(401, "Not authenticated")
    token = authorization.replace("Bearer ", "").strip()
    if token not in SESSIONS:
        raise HTTPException(401, "Invalid token")
    return {"username": SESSIONS[token]}

@app.post("/api/auth/logout")
def auth_logout(authorization: str = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        SESSIONS.pop(token, None)
    return {"logged_out": True}


# ======================================================================
# ENGINE ROUTES — none of these touch the panel
# ======================================================================

@app.get("/api/engine/status")
def engine_status(deep: bool = False):
    snap = engine.health_snapshot(deep=deep)
    reg = registry.load()
    return {
        **snap,
        "identities": [
            {"id": i["id"], "label": i["label"], "address": i["address"],
             "key_preview": i["private_key"][:6] + "…" + i["private_key"][-4:]}
            for i in reg["identities"]
        ],
        "binding": reg["panel_binding"],
        "watchdog": watchdog.stats,
    }


@app.get("/api/engine/slots")
def list_slots():
    return registry.load()["slots"]


@app.post("/api/engine/slots/ensure")
def ensure_slots(req: SlotsEnsure):
    reg = registry.ensure_slots(req.count)
    return {
        "total_slots": len(reg["slots"]),
        "note": "Existing slots keep their ports. Re-bind the panel only if the count grew.",
    }


@app.get("/api/engine/identities")
def get_identities():
    return [
        {"id": i["id"], "label": i["label"], "address": i["address"],
         "key_preview": i["private_key"][:6] + "…" + i["private_key"][-4:]}
        for i in registry.identities()
    ]


@app.post("/api/engine/identities")
def create_identity(req: IdentityIn):
    ident = registry.add_identity(req.private_key, req.address, req.label)
    return {"id": ident["id"], "label": ident["label"]}


@app.put("/api/engine/identities/{identity_id}")
def rotate_identity(identity_id: str, req: IdentityRotate):
    """
    *** THE KEY ROTATION ENDPOINT ***

    Swap a Surfshark private key. Affected tunnels restart on the same
    ports. The panel is never called; no inbound is rebuilt; no user
    subscription changes.
    """
    try:
        return engine.rotate_identity(identity_id, req.private_key, req.address)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.delete("/api/engine/identities/{identity_id}")
def delete_identity(identity_id: str):
    if not registry.remove_identity(identity_id):
        raise HTTPException(404, "identity not found")
    return {"deleted": identity_id}


@app.post("/api/engine/identities/rebalance")
def rebalance():
    registry.rebalance_identities()
    restarted = sum(
        1 for s in registry.occupied_slots() if engine.start_slot(s["index"], quiet=True)
    )
    return {"restarted": restarted, "panel_touched": False}


@app.put("/api/engine/slots/{slot_index}/server")
def assign_server(slot_index: int, req: ServerAssign):
    """
    Swap the server on a slot. Rejected if the slot is pinned to a different
    country — use /pin or /relocate for that.
    """
    try:
        return engine.assign_server(
            slot_index, req.endpoint, req.public_key,
            req.country, req.country_code, req.location, req.identity_id,
        )
    except engine.CountryLockError as e:
        raise HTTPException(409, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.post("/api/engine/slots/{slot_index}/pin")
def pin_slot(slot_index: int, req: PinRequest):
    """
    Pin this port to a country permanently. Key rotations and watchdog
    failovers can no longer move it elsewhere.
    """
    try:
        return engine.pin_slot(slot_index, req.country, req.location, req.identity_id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/engine/slots/{slot_index}/relocate")
def relocate_slot(slot_index: int, req: PinRequest):
    """
    Deliberately re-home a pinned slot. Everyone on this slot's inbound
    starts exiting from the new country.
    """
    try:
        return engine.relocate(slot_index, req.country, req.location)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/engine/slots/autofill")
def autofill_slots(req: AutoFillRequest):
    """
    Fill every empty slot with a different country, pinning as it goes.
    This is the one-click setup path — the web equivalent of `slots fill`.
    """
    import time
    reg = registry.load()
    if not reg["identities"]:
        raise HTTPException(400, "Add a WireGuard key first.")

    empty = [s for s in reg["slots"] if not s.get("endpoint")]
    if not empty:
        return {"filled": 0, "message": "No empty slots. Reserve more first."}

    try:
        servers = engine.fetch_clusters()
    except Exception as e:      # noqa: BLE001
        raise HTTPException(502, f"Surfshark API unreachable: {e}")

    # Countries already pinned elsewhere are skipped, so autofill never
    # produces two slots serving the same country.
    taken = {
        (s.get("locked_country") or "").replace(" ", "").lower()
        for s in reg["slots"] if s.get("locked_country")
    }
    pool, seen = [], set()
    for s in servers:
        key = s["country"].replace(" ", "").lower()
        if key not in seen and key not in taken:
            seen.add(key)
            pool.append(s)

    n = min(len(empty), len(pool), req.count or len(empty))
    filled = []
    for i in range(n):
        slot, srv = empty[i], pool[i]
        try:
            if req.pin:
                registry.lock_country(slot["index"], srv["country"], srv["countryCode"])
            engine.assign_server(
                slot["index"], srv["endpoint"], srv["publicKey"],
                srv["country"], srv["countryCode"], srv["location"], force=True,
            )
            filled.append({"slot": slot["index"], "port": slot["port"],
                           "country": srv["country"]})
        except Exception as e:      # noqa: BLE001
            log.warning("autofill slot %s failed: %s", slot["index"], e)
        time.sleep(0.4)

    return {"filled": len(filled), "slots": filled, "panel_touched": False}


@app.get("/api/engine/keyload")
def key_load():
    """
    Per-key tunnel counts, plus whether any key is carrying too many.

    Overloading one keypair is the usual reason locations drop at random
    and only a new key revives them.
    """
    return registry.key_load()


@app.post("/api/engine/identities/bulk")
def import_keys_bulk(req: BulkKeyImport):
    """
    Paste many keypairs at once. Accepts plain lines, `label: key`,
    `key,address`, or full [Interface] config blocks.
    """
    entries = registry.parse_key_blob(req.blob, req.default_address)
    if not entries:
        raise HTTPException(400, "No WireGuard keys found in that text.")
    result = registry.add_identities_bulk(entries, req.default_address)
    registry.rebalance_identities()
    return result


@app.get("/api/engine/capacity")
def capacity(target: int = 0):
    """Check a deployment size against RAM, keys and file descriptors."""
    return engine.capacity_report(target or None)


@app.get("/api/engine/rotator")
def rotator_status():
    return rotator.status()


@app.post("/api/engine/rotator")
def rotator_configure(req: RotatorConfig):
    """Turn scheduled key rotation on/off and set the interval."""
    return rotator.configure(req.enabled, req.interval_hours)


@app.post("/api/engine/rotator/run")
def rotator_run_now():
    """Rotate immediately, without waiting for the schedule."""
    return rotator.rotate_now()


@app.get("/api/engine/ports")
def port_layout():
    """The fixed port map — same answer on every machine."""
    from core import config
    return {
        "socks_base": config.SOCKS_BASE_PORT,
        "inbound_base": config.INBOUND_BASE_PORT,
        "max_slots": config.MAX_SLOTS,
        "slots": [
            {"index": s["index"], "socks_port": s["port"],
             "inbound_port": s["inbound_port"],
             "inbound_tag": s["inbound_tag"],
             "country": s.get("locked_country") or s.get("country")}
            for s in registry.load()["slots"]
        ],
    }


@app.post("/api/engine/ports/resync")
def resync_ports():
    """Force the registry back in line with config.py."""
    report = registry.resync_ports()
    if report["slots_corrected"]:
        engine.recover_all()
    return report


@app.post("/api/engine/recover")
def recover():
    return {"started": engine.recover_all()}


@app.post("/api/engine/stop")
def stop_engine():
    return {"stopped": engine.stop_all()}


@app.get("/api/engine/surfshark/servers")
def surfshark_servers(force: bool = False):
    try:
        return engine.fetch_clusters(force=force)
    except Exception as e:      # noqa: BLE001
        raise HTTPException(502, f"Surfshark API unreachable: {e}")


@app.get("/api/engine/logs")
def engine_logs(lines: int = 300):
    path = os.path.join(ROOT, "data", "engine.log")
    if not os.path.exists(path):
        return {"logs": "No logs yet."}
    with open(path, "r", errors="replace") as f:
        return {"logs": "".join(f.readlines()[-lines:])}


# ======================================================================
# PANEL ROUTES — setup only
# ======================================================================

@app.get("/api/panel/cores")
async def panel_cores(x_panel_token: str = Header(None),
                      x_panel_host: str = Header(None)):
    try:
        return await _panel(x_panel_token, x_panel_host).cores()
    except HTTPException:
        raise
    except Exception as e:      # noqa: BLE001
        raise HTTPException(502, f"Panel error: {e}")


@app.get("/api/panel/hosts")
async def panel_hosts(x_panel_token: str = Header(None),
                      x_panel_host: str = Header(None)):
    try:
        return await _panel(x_panel_token, x_panel_host).hosts()
    except HTTPException:
        raise
    except Exception as e:      # noqa: BLE001
        raise HTTPException(502, f"Panel error: {e}")


@app.post("/api/panel/bind")
async def panel_bind(req: BindRequest,
                     x_panel_token: str = Header(None),
                     x_panel_host: str = Header(None)):
    """
    One-time wiring of slot ports into the core config.

    Run this once. After it succeeds you can rotate keys and change
    countries indefinitely without ever calling it again.
    """
    try:
        return await _panel(x_panel_token, x_panel_host).bind(
            req.core_id, req.template_host_id, req.slot_count, req.node_ip
        )
    except HTTPException:
        raise
    except Exception as e:      # noqa: BLE001
        raise HTTPException(500, f"Bind failed: {e}")


@app.post("/api/panel/toggle")
async def panel_toggle(req: ToggleRequest,
                       x_panel_token: str = Header(None),
                       x_panel_host: str = Header(None)):
    try:
        return await _panel(x_panel_token, x_panel_host).set_enabled(req.enable)
    except HTTPException:
        raise
    except Exception as e:      # noqa: BLE001
        raise HTTPException(500, str(e))


@app.delete("/api/panel/bind/{core_id}")
async def panel_unbind(core_id: str,
                       x_panel_token: str = Header(None),
                       x_panel_host: str = Header(None)):
    try:
        return await _panel(x_panel_token, x_panel_host).unbind(core_id)
    except HTTPException:
        raise
    except Exception as e:      # noqa: BLE001
        raise HTTPException(500, str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8088)
