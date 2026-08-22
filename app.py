import base64
import ipaddress
import os
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

UNIFI_URL = os.getenv("UNIFI_URL", "https://192.168.1.1").rstrip("/")
API_KEY = os.getenv("UNIFI_API_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IPS_FILE = os.path.join(BASE_DIR, "ips.txt")

# GitHub sync configuration.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = "mfroger/ipman"
GITHUB_BRANCH = "main"
GITHUB_FILE = "ips.txt"

app = FastAPI(title="IPMan")

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "static")),
    name="static",
)

requests.packages.urllib3.disable_warnings()


class FixedIPsPayload(BaseModel):
    ips: list[str]
    push_github: bool = True


# ============================================================
# UNIFI API
# ============================================================

def api_get(path: str, params: dict | None = None) -> dict:
    if not API_KEY:
        raise RuntimeError("UNIFI_API_KEY n'est pas défini")

    response = requests.get(
        f"{UNIFI_URL}/proxy/network/integration{path}",
        headers={
            "X-API-Key": API_KEY,
            "Accept": "application/json",
        },
        params=params,
        verify=False,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def get_all(endpoint: str) -> list[dict[str, Any]]:
    results = []
    offset = 0
    limit = 200

    while True:
        data = api_get(endpoint, {"offset": offset, "limit": limit})
        items = data.get("data", [])
        results.extend(items)

        total = data.get("totalCount", len(results))
        if not items or len(results) >= total:
            break

        offset += limit

    return results


def get_sites():
    return api_get("/v1/sites").get("data", [])


# ============================================================
# FIXED IPS
# ============================================================

def normalize_ips(ips: list[str]) -> list[str]:
    """Validate IPv4 addresses, remove duplicates and sort them."""
    normalized = set()

    for raw_ip in ips:
        ip = raw_ip.strip()
        if not ip:
            continue

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"IP invalide : {ip}")

        if address.version != 4:
            raise ValueError(f"Seules les IPv4 sont supportées : {ip}")

        normalized.add(str(address))

    return sorted(
        normalized,
        key=lambda value: tuple(int(part) for part in value.split(".")),
    )


def load_fixed_ips() -> set[str]:
    if not os.path.exists(IPS_FILE):
        return set()

    ips = set()

    with open(IPS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.add(line)

    return ips


def write_fixed_ips(ips: list[str]) -> None:
    content = "# IP fixes\n# Une IP par ligne\n# Les lignes commençant par # sont ignorées\n\n"
    content += "\n".join(ips)
    content += "\n"

    with open(IPS_FILE, "w", encoding="utf-8") as f:
        f.write(content)


def push_ips_to_github(ips: list[str]) -> str:
    """Commit ips.txt to GitHub using the repository Contents API."""
    if not GITHUB_TOKEN:
        raise RuntimeError(
            "GITHUB_TOKEN n'est pas défini. Les IP ont été sauvegardées localement."
        )

    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}"

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.get(
        api_url,
        headers=headers,
        params={"ref": GITHUB_BRANCH},
        timeout=15,
    )
    response.raise_for_status()

    current = response.json()
    current_sha = current.get("sha")

    content = "# IP fixes\n# Une IP par ligne\n# Les lignes commençant par # sont ignorées\n\n"
    content += "\n".join(ips)
    content += "\n"

    payload = {
        "message": "Update fixed IPs from IPMan",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": GITHUB_BRANCH,
    }

    if current_sha:
        payload["sha"] = current_sha

    response = requests.put(
        api_url,
        headers=headers,
        json=payload,
        timeout=15,
    )
    response.raise_for_status()

    return response.json().get("commit", {}).get("html_url", "")


# ============================================================
# VLAN
# ============================================================

def get_vlan(ip: str) -> int | None:
    try:
        parts = ip.split(".")

        if len(parts) != 4:
            return None

        if parts[0] != "192" or parts[1] != "168":
            return None

        return int(parts[2])

    except (ValueError, IndexError):
        return None


# ============================================================
# INVENTORY
# ============================================================

def ip_sort(row):
    try:
        return tuple(int(x) for x in row.get("ip", "").split("."))
    except Exception:
        return (999, 999, 999, 999)


def get_inventory():
    rows = []

    for site in get_sites():
        site_id = site["id"]
        site_name = site.get("name", site_id)

        devices = get_all(f"/v1/sites/{site_id}/devices")
        clients = get_all(f"/v1/sites/{site_id}/clients")

        device_macs = {
            d.get("macAddress", "").lower()
            for d in devices
            if d.get("macAddress")
        }

        for device in devices:
            ip = device.get("ipAddress")
            if not ip:
                continue

            rows.append({
                "ip": ip,
                "type": "UNIFI",
                "name": device.get("name", ""),
                "mac": device.get("macAddress", ""),
                "model": device.get("model", ""),
                "state": device.get("state", ""),
                "site": site_name,
                "vlan": get_vlan(ip),
            })

        for client in clients:
            ip = client.get("ipAddress")
            if not ip:
                continue

            mac = client.get("macAddress", "").lower()
            if mac in device_macs:
                continue

            rows.append({
                "ip": ip,
                "type": "CLIENT",
                "name": client.get("name", ""),
                "mac": client.get("macAddress", ""),
                "model": "",
                "state": "ONLINE",
                "site": site_name,
                "vlan": get_vlan(ip),
            })

    rows.sort(key=ip_sort)
    return rows


# ============================================================
# ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    error = None
    rows = []

    try:
        rows = get_inventory()
    except Exception as e:
        error = str(e)

    fixed_ips = load_fixed_ips()

    for row in rows:
        row["fixed"] = row["ip"] in fixed_ips

    fixed_rows = [row for row in rows if row["fixed"]]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "rows": rows,
            "fixed_rows": fixed_rows,
            "fixed_ips": sorted(
                fixed_ips,
                key=lambda value: tuple(int(x) for x in value.split(".")),
            ),
            "github_configured": bool(GITHUB_TOKEN),
            "error": error,
        },
    )


@app.post("/api/fixed-ips")
def update_fixed_ips(payload: FixedIPsPayload):
    try:
        ips = normalize_ips(payload.ips)
        write_fixed_ips(ips)

        github_url = None
        github_error = None

        if payload.push_github:
            try:
                github_url = push_ips_to_github(ips)
            except Exception as e:
                github_error = str(e)

        return {
            "success": True,
            "ips": ips,
            "count": len(ips),
            "github_pushed": github_url is not None,
            "github_url": github_url,
            "github_error": github_error,
        }

    except ValueError as e:
        return {
            "success": False,
            "error": str(e),
        }
