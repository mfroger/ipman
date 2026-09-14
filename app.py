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
from peewee import BooleanField, CharField, DateTimeField, IntegerField, Model, PostgresqlDatabase, TextField
from pydantic import BaseModel

load_dotenv()

UNIFI_URL = os.getenv("UNIFI_URL", "https://10.44.1.1").rstrip("/")
API_KEY = os.getenv("UNIFI_API_KEY")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LEGACY_DB_FILE = os.path.join(DATA_DIR, "ipman.db")
IPS_FILE = os.path.join(BASE_DIR, "ips.txt")

# PostgreSQL configuration. Secrets must come from the environment.
POSTGRES_DB = os.getenv("POSTGRES_DB", "ipam")
POSTGRES_USER = os.getenv("POSTGRES_USER", "mickael")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "database.mickyhome.casa")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))

if not POSTGRES_PASSWORD:
    raise RuntimeError("POSTGRES_PASSWORD n'est pas défini")

pg_db = PostgresqlDatabase(
    POSTGRES_DB,
    user=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    host=POSTGRES_HOST,
    port=POSTGRES_PORT,
)


class IPMetadata(Model):
    ip = CharField(primary_key=True, max_length=45)
    fixed = BooleanField(default=False)
    description = TextField(default="")
    model = TextField(default="")
    mac = CharField(max_length=32, default="")
    type = CharField(max_length=20, default="")

    class Meta:
        database = pg_db
        table_name = "ip_metadata"


class InventoryCache(Model):
    id = IntegerField(primary_key=True)
    payload = TextField(default="[]")
    synced_at = DateTimeField(null=True)

    class Meta:
        database = pg_db
        table_name = "inventory_cache"


app = FastAPI(title="IPMan")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
requests.packages.urllib3.disable_warnings()


class IPUpdate(BaseModel):
    ip: str
    fixed: bool = False
    description: str = ""
    model: str = ""
    type: str = ""


class IPDelete(BaseModel):
    ip: str


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
                address = ipaddress.ip_address(line)
                if address.version == 4:
                    result.append(str(address))
            except ValueError:
                pass
    return result


def migrate_legacy_sqlite():
    """Import the old SQLite metadata once, if it exists and PostgreSQL is empty."""
    try:
        if not os.path.exists(LEGACY_DB_FILE) or IPMetadata.select().exists():
            return

        sqlite_conn = sqlite3.connect(LEGACY_DB_FILE)
        sqlite_conn.row_factory = sqlite3.Row
        try:
            rows = sqlite_conn.execute("SELECT * FROM ip_metadata").fetchall()
        finally:
            sqlite_conn.close()

        with pg_db.atomic():
            for row in rows:
                IPMetadata.insert(
                    ip=row["ip"],
                    fixed=bool(row["fixed"]),
                    description=row["description"] or "",
                    model=row["model"] or "",
                    mac=(row["mac"] or "").lower(),
                    type=(row["type"] or "").upper(),
                ).on_conflict_ignore().execute()

        print(f"Migrated {len(rows)} IP metadata records from SQLite to PostgreSQL")
    except Exception as e:
        print(f"SQLite migration skipped: {e}")


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    pg_db.connect(reuse_if_open=True)
    pg_db.create_tables([IPMetadata, InventoryCache], safe=True)
    migrate_legacy_sqlite()

    if not IPMetadata.select().exists():
        with pg_db.atomic():
            for ip in load_old_ips():
                IPMetadata.insert(ip=ip, fixed=True).on_conflict_ignore().execute()


def metadata():
    with pg_db.connection_context():
        rows = list(IPMetadata.select())

    by_ip, by_mac = {}, {}
    for r in rows:
        item = {
            "ip": r.ip,
            "fixed": bool(r.fixed),
            "description": r.description or "",
            "model_override": r.model or "",
            "mac": (r.mac or "").lower(),
            "type_override": (r.type or "").upper(),
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
            return result
        offset += limit


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
    for original in rows:
        row = dict(original)
        ip = row.get("ip")
        mac = (row.get("mac") or "").lower()
        if not ip:
            continue

        m = by_mac.get(mac) if mac else None
        if m is None:
            m = by_ip.get(ip)

        if m:
            # A UniFi reservation and an IPMan manual fixed flag are both fixed.
            row["fixed"] = bool(m["fixed"] or row.get("unifi_fixed", False))
            row["description"] = m["description"]
            row["model"] = m["model_override"] or row.get("model", "")
            row["type"] = m["type_override"] or row.get("type", "")

            with pg_db.connection_context():
                if mac and m["mac"] != mac:
                    IPMetadata.update(mac=mac).where(
                        (IPMetadata.ip == m["ip"]) & ((IPMetadata.mac == "") | IPMetadata.mac.is_null())
                    ).execute()

                if mac and m["mac"] == mac and m["ip"] != ip:
                    if IPMetadata.get_or_none(IPMetadata.ip == ip) is None:
                        IPMetadata.update(ip=ip).where(IPMetadata.ip == m["ip"]).execute()
        else:
            row["fixed"] = bool(row.get("unifi_fixed", False))
            row["description"] = ""

        row.setdefault("vlan", vlan(ip))
        row.setdefault("vlan_name", "")
        row.setdefault("site", "")
        row.setdefault("state", "")
        row.setdefault("id", "")
        row.setdefault("uplink_id", "")
        seen_ips.add(ip)
        result.append(row)

    by_ip, _ = metadata()
    for ip, m in by_ip.items():
        if ip in seen_ips:
            continue
        result.append(
            {
                "ip": ip,
                "type": m["type_override"] or "IPMAN",
                "name": "",
                "mac": m["mac"],
                "model": m["model_override"],
                "state": "OFFLINE",
                "site": "",
                "vlan": vlan(ip),
                "vlan_name": "",
                "fixed": m["fixed"],
                "description": m["description"],
                "id": "",
                "uplink_id": "",
            }
        )

    return sorted(result, key=ip_sort)


def fetch_inventory_from_unifi():
    result = []
    for site in api_get("/v1/sites").get("data", []):
        sid, sname = site["id"], site.get("name", site["id"])
        devices = get_all(f"/v1/sites/{sid}/devices")
        clients = get_all(f"/v1/sites/{sid}/clients")
        try:
            networks = get_all(f"/v1/sites/{sid}/networks")
        except Exception:
            networks = []

        network_names = {n.get("vlanId"): n.get("name", "") for n in networks if n.get("vlanId") is not None}
        device_macs = {d.get("macAddress", "").lower() for d in devices}

        for d in devices:
            ip = d.get("ipAddress")
            if not ip:
                continue
            v = vlan(ip)
            result.append(
                {
                    "ip": ip,
                    "type": "UNIFI",
                    "name": d.get("name", ""),
                    "mac": d.get("macAddress", ""),
                    "model": d.get("model", ""),
                    "state": d.get("state", ""),
                    "site": sname,
                    "vlan": v,
                    "vlan_name": network_names.get(v, ""),
                    "id": d.get("id", ""),
                    "uplink_id": d.get("uplinkDeviceId", ""),
                    "unifi_fixed": False,
                }
            )

        for client in clients:
            # Depending on UniFi Network version, these fields may be exposed as
            # fixedIp/fixed_ip and useFixedIp/use_fixedip. The official Integration
            # API documentation does not currently guarantee them, so we support all
            # observed variants without relying on the private API.
            fixed_ip = (
                client.get("fixedIp")
                or client.get("fixed_ip")
                or client.get("fixedIP")
            )
            use_fixed = bool(
                client.get("useFixedIp")
                or client.get("use_fixedip")
                or client.get("useFixedIP")
            )
            ip = fixed_ip if use_fixed and fixed_ip else client.get("ipAddress")
            mac = client.get("macAddress", "")
            if not ip or mac.lower() in device_macs:
                continue
            v = vlan(ip)
            result.append(
                {
                    "ip": ip,
                    "type": "CLIENT",
                    "name": client.get("name", ""),
                    "mac": mac,
                    "model": "",
                    "state": "ONLINE",
                    "site": sname,
                    "vlan": v,
                    "vlan_name": network_names.get(v, ""),
                    "id": client.get("id", ""),
                    "uplink_id": client.get("uplinkDeviceId", ""),
                    "unifi_fixed": use_fixed and bool(fixed_ip),
                }
            )
    return result


def save_cache(rows):
    payload = json.dumps(rows, ensure_ascii=False)
    synced_at = datetime.now(timezone.utc)
    with pg_db.connection_context():
        InventoryCache.insert(id=1, payload=payload, synced_at=synced_at).on_conflict(
            conflict_target=[InventoryCache.id],
            update={InventoryCache.payload: payload, InventoryCache.synced_at: synced_at},
        ).execute()


def cached_inventory():
    with pg_db.connection_context():
        row = InventoryCache.get_or_none(InventoryCache.id == 1)
    if not row:
        return []
    try:
        return json.loads(row.payload)
    except (TypeError, json.JSONDecodeError):
        return []


def sync_inventory():
    rows = fetch_inventory_from_unifi()
    rows = apply_metadata(rows)
    save_cache(rows)
    return rows


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
        return {"success": True, "count": len(rows), "fixed": sum(1 for r in rows if r["fixed"])}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/inventory")
def inventory_api():
    rows = inventory()
    return {"rows": rows}


@app.post("/api/ip")
def update_ip(payload: IPUpdate):
    try:
        address = ipaddress.ip_address(payload.ip.strip())
        if address.version != 4:
            raise ValueError("Seules les IPv4 sont supportées")
        ip = str(address)
        ip_type = payload.type.strip().upper() or "IPMAN"
        if ip_type not in {"UNIFI", "CLIENT", "IPMAN"}:
            raise ValueError("Type invalide")

        with pg_db.connection_context():
            old = IPMetadata.get_or_none(IPMetadata.ip == ip)
            mac = old.mac if old else ""
            (
                IPMetadata.insert(
                    ip=ip,
                    fixed=payload.fixed,
                    description=payload.description.strip(),
                    model=payload.model.strip(),
                    mac=mac,
                    type=ip_type,
                )
                .on_conflict(
                    conflict_target=[IPMetadata.ip],
                    update={
                        IPMetadata.fixed: payload.fixed,
                        IPMetadata.description: payload.description.strip(),
                        IPMetadata.model: payload.model.strip(),
                        IPMetadata.type: ip_type,
                    },
                )
                .execute()
            )
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
        with pg_db.connection_context():
            IPMetadata.delete().where(IPMetadata.ip == ip).execute()
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

        with pg_db.atomic():
            for ip in ips:
                IPMetadata.insert(ip=ip, fixed=True).on_conflict(
                    conflict_target=[IPMetadata.ip],
                    update={IPMetadata.fixed: True},
                ).execute()

            if ips:
                IPMetadata.update(fixed=False).where(~IPMetadata.ip.in_(ips)).execute()
            else:
                IPMetadata.update(fixed=False).execute()

        return {"success": True, "ips": sorted(ips, key=lambda x: tuple(map(int, x.split("."))))}
    except ValueError as e:
        return {"success": False, "error": str(e)}
