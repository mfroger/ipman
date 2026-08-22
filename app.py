import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

load_dotenv()
UNIFI_URL = os.getenv("UNIFI_URL", "https://192.168.1.1").rstrip("/")
API_KEY = os.getenv("UNIFI_API_KEY")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_FILE = os.path.join(DATA_DIR, "ipman.db")
IPS_FILE = os.path.join(BASE_DIR, "ips.txt")

app = FastAPI(title="IPMan")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
requests.packages.urllib3.disable_warnings()


class IPUpdate(BaseModel):
    ip: str
    fixed: bool = False
    description: str = ""
    model: str = ""


class IPDelete(BaseModel):
    ip: str


def db():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    return c


def load_old_ips():
    if not os.path.exists(IPS_FILE):
        return []
    result = []
    with open(IPS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ip = ipaddress.ip_address(line)
                if ip.version == 4:
                    result.append(str(ip))
            except ValueError:
                pass
    return result


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS ip_metadata (
            ip TEXT PRIMARY KEY,
            fixed INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            mac TEXT NOT NULL DEFAULT ''
        )""")
        columns = {r[1] for r in c.execute("PRAGMA table_info(ip_metadata)")}
        if "mac" not in columns:
            c.execute("ALTER TABLE ip_metadata ADD COLUMN mac TEXT NOT NULL DEFAULT ''")

        c.execute("""CREATE TABLE IF NOT EXISTS inventory_cache (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload TEXT NOT NULL DEFAULT '[]',
            synced_at TEXT NOT NULL DEFAULT ''
        )""")

        if c.execute("SELECT COUNT(*) FROM ip_metadata").fetchone()[0] == 0:
            for ip in load_old_ips():
                c.execute("INSERT OR IGNORE INTO ip_metadata(ip,fixed) VALUES(?,1)", (ip,))
        c.commit()


def metadata():
    with db() as c:
        rows = c.execute("SELECT * FROM ip_metadata").fetchall()
    by_ip = {}
    by_mac = {}
    for r in rows:
        item = {
            "ip": r["ip"],
            "fixed": bool(r["fixed"]),
            "description": r["description"],
            "model_override": r["model"],
            "mac": (r["mac"] or "").lower(),
        }
        by_ip[item["ip"]] = item
        if item["mac"]:
            by_mac[item["mac"]] = item
    return by_ip, by_mac


def api_get(path, params=None):
    if not API_KEY:
        raise RuntimeError("UNIFI_API_KEY n'est pas défini")
    r = requests.get(
        f"{UNIFI_URL}/proxy/network/integration{path}",
        headers={"X-API-Key": API_KEY, "Accept": "application/json"},
        params=params,
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_all(endpoint):
    result, offset, limit = [], 0, 200
    while True:
        data = api_get(endpoint, {"offset": offset, "limit": limit})
        items = data.get("data", [])
        result.extend(items)
        if not items or len(result) >= data.get("totalCount", len(result)):
            break
        offset += limit
    return result


def vlan(ip):
    try:
        p = ip.split(".")
        return int(p[2]) if len(p) == 4 and p[:2] == ["192", "168"] else None
    except ValueError:
        return None


def ip_sort(row):
    try:
        return tuple(map(int, row["ip"].split(".")))
    except Exception:
        return (999, 999, 999, 999)


def apply_metadata(rows):
    by_ip, by_mac = metadata()
    seen_ips = set()
    result = []

    for row in rows:
        ip = row.get("ip")
        mac = (row.get("mac") or "").lower()
        if not ip:
            continue

        m = by_mac.get(mac) if mac else None
        if m is None:
            m = by_ip.get(ip)

        if m:
            row["fixed"] = m["fixed"]
            row["description"] = m["description"]
            row["model"] = m["model_override"] or row.get("model", "")
            # The MAC is the stable identity. If UniFi changed the IP,
            # move the metadata record to the new IP automatically.
            if mac and m["mac"] == mac and m["ip"] != ip:
                with db() as c:
                    existing = c.execute("SELECT ip FROM ip_metadata WHERE ip=?", (ip,)).fetchone()
                    if not existing:
                        c.execute("UPDATE ip_metadata SET ip=? WHERE ip=?", (ip, m["ip"]))
                        c.commit()
        else:
            row["fixed"] = False
            row["description"] = ""

        seen_ips.add(ip)
        result.append(row)

    # IPs created manually in IPMan and not currently visible in UniFi.
    by_ip, _ = metadata()
    for ip, m in by_ip.items():
        if ip in seen_ips:
            continue
        result.append({
            "ip": ip,
            "type": "IPMAN",
            "name": "",
            "mac": m["mac"],
            "model": m["model_override"],
            "state": "OFFLINE",
            "site": "",
            "vlan": vlan(ip),
            "fixed": m["fixed"],
            "description": m["description"],
        })

    return sorted(result, key=ip_sort)


def fetch_inventory_from_unifi():
    result = []
    for site in api_get("/v1/sites").get("data", []):
        sid, sname = site["id"], site.get("name", site["id"])
        devices = get_all(f"/v1/sites/{sid}/devices")
        clients = get_all(f"/v1/sites/{sid}/clients")
        device_macs = {d.get("macAddress", "").lower() for d in devices}

        for d in devices:
            ip = d.get("ipAddress")
            if not ip:
                continue
            result.append({
                "ip": ip,
                "type": "UNIFI",
                "name": d.get("name", ""),
                "mac": d.get("macAddress", ""),
                "model": d.get("model", ""),
                "state": d.get("state", ""),
                "site": sname,
                "vlan": vlan(ip),
            })

        for client in clients:
            ip = client.get("ipAddress")
            if not ip or client.get("macAddress", "").lower() in device_macs:
                continue
            result.append({
                "ip": ip,
                "type": "CLIENT",
                "name": client.get("name", ""),
                "mac": client.get("macAddress", ""),
                "model": "",
                "state": "ONLINE",
                "site": sname,
                "vlan": vlan(ip),
            })
    return result


def save_cache(rows):
    with db() as c:
        c.execute(
            "INSERT INTO inventory_cache(id,payload,synced_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,synced_at=excluded.synced_at",
            (json.dumps(rows, ensure_ascii=False), datetime.now(timezone.utc).isoformat()),
        )
        c.commit()


def cached_inventory():
    with db() as c:
        row = c.execute("SELECT payload FROM inventory_cache WHERE id=1").fetchone()
    if not row:
        return []
    try:
        return json.loads(row["payload"])
    except (TypeError, json.JSONDecodeError):
        return []


def sync_inventory():
    rows = fetch_inventory_from_unifi()
    # Match existing metadata by MAC and move IPs when UniFi reports a new one.
    apply_metadata(rows)
    # Reload metadata after any MAC-based IP moves, then cache the raw UniFi data.
    save_cache(rows)
    return apply_metadata(rows)


def inventory():
    return apply_metadata(cached_inventory())


@app.on_event("startup")
def startup():
    init_db()
    if not cached_inventory():
        try:
            sync_inventory()
        except Exception:
            pass


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    error, rows = None, []
    try:
        rows = inventory()
    except Exception as e:
        error = str(e)
    fixed = [r for r in rows if r["fixed"]]
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"rows": rows, "fixed_rows": fixed, "fixed_count": len(fixed), "error": error},
    )


@app.post("/api/sync")
def manual_sync():
    try:
        rows = sync_inventory()
        fixed = sum(1 for r in rows if r["fixed"])
        return {"success": True, "count": len(rows), "fixed": fixed}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/ip")
def update_ip(payload: IPUpdate):
    try:
        address = ipaddress.ip_address(payload.ip.strip())
        if address.version != 4:
            raise ValueError("Seules les IPv4 sont supportées")
        ip = str(address)
        with db() as c:
            old = c.execute("SELECT mac FROM ip_metadata WHERE ip=?", (ip,)).fetchone()
            mac = old["mac"] if old else ""
            c.execute(
                "INSERT INTO ip_metadata(ip,fixed,description,model,mac) VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET fixed=excluded.fixed,description=excluded.description,model=excluded.model",
                (ip, int(payload.fixed), payload.description.strip(), payload.model.strip(), mac),
            )
            c.commit()
        return {"success": True, "ip": ip}
    except ValueError as e:
        return {"success": False, "error": str(e)}


@app.delete("/api/ip")
def delete_ip(payload: IPDelete):
    try:
        address = ipaddress.ip_address(payload.ip.strip())
        if address.version != 4:
            raise ValueError("Seules les IPv4 sont supportées")
        ip = str(address)
        with db() as c:
            c.execute("DELETE FROM ip_metadata WHERE ip = ?", (ip,))
            c.commit()
        return {"success": True, "ip": ip}
    except ValueError as e:
        return {"success": False, "error": str(e)}


@app.post("/api/fixed-ips")
def update_fixed_ips(payload: dict):
    try:
        ips = set()
        for raw in payload.get("ips", []):
            if not raw.strip():
                continue
            address = ipaddress.ip_address(raw.strip())
            if address.version != 4:
                raise ValueError(f"IPv4 uniquement : {raw}")
            ips.add(str(address))
        with db() as c:
            for ip in ips:
                c.execute("INSERT INTO ip_metadata(ip,fixed) VALUES(?,1) ON CONFLICT(ip) DO UPDATE SET fixed=1", (ip,))
            if ips:
                c.execute("UPDATE ip_metadata SET fixed=0 WHERE ip NOT IN ({})".format(",".join("?" * len(ips))), tuple(ips))
            else:
                c.execute("UPDATE ip_metadata SET fixed=0")
            c.commit()
        return {"success": True, "ips": sorted(ips, key=lambda x: tuple(map(int, x.split("."))))}
    except ValueError as e:
        return {"success": False, "error": str(e)}
