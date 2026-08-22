import os
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

load_dotenv()

UNIFI_URL = os.getenv(
    "UNIFI_URL",
    "https://192.168.1.1"
).rstrip("/")

API_KEY = os.getenv("UNIFI_API_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IPS_FILE = os.path.join(BASE_DIR, "ips.txt")


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(title="IPMan")

templates = Jinja2Templates(
    directory=os.path.join(BASE_DIR, "templates")
)

app.mount(
    "/static",
    StaticFiles(
        directory=os.path.join(BASE_DIR, "static")
    ),
    name="static",
)


# ============================================================
# SSL
# ============================================================

requests.packages.urllib3.disable_warnings()


# ============================================================
# UNIFI API
# ============================================================

def api_get(
    path: str,
    params: dict | None = None
) -> dict:

    if not API_KEY:
        raise RuntimeError(
            "UNIFI_API_KEY n'est pas défini"
        )

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


# ============================================================
# PAGINATION
# ============================================================

def get_all(
    endpoint: str
) -> list[dict[str, Any]]:

    results = []

    offset = 0
    limit = 200

    while True:

        data = api_get(
            endpoint,
            {
                "offset": offset,
                "limit": limit,
            }
        )

        items = data.get(
            "data",
            []
        )

        results.extend(items)

        total = data.get(
            "totalCount",
            len(results)
        )

        if not items:
            break

        if len(results) >= total:
            break

        offset += limit

    return results


# ============================================================
# SITES
# ============================================================

def get_sites():

    data = api_get(
        "/v1/sites"
    )

    return data.get(
        "data",
        []
    )


# ============================================================
# FIXED IPS
# ============================================================

def load_fixed_ips() -> set[str]:

    if not os.path.exists(IPS_FILE):
        return set()

    ips = set()

    with open(
        IPS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            ips.add(line)

    return ips


# ============================================================
# VLAN
# ============================================================

def get_vlan(ip: str) -> int | None:
    """
    Déduit automatiquement le VLAN depuis l'IP.

    Exemple :

        192.168.1.120   -> VLAN 1
        192.168.20.11   -> VLAN 20
        192.168.40.245  -> VLAN 40
        192.168.50.10   -> VLAN 50
        192.168.70.160  -> VLAN 70
    """

    try:

        parts = ip.split(".")

        if len(parts) != 4:
            return None

        if parts[0] != "192":
            return None

        if parts[1] != "168":
            return None

        return int(parts[2])

    except (
        ValueError,
        IndexError
    ):

        return None


# ============================================================
# IP SORT
# ============================================================

def ip_sort(row):

    ip = row.get(
        "ip",
        ""
    )

    try:

        return tuple(
            int(x)
            for x in ip.split(".")
        )

    except Exception:

        return (
            999,
            999,
            999,
            999
        )


# ============================================================
# INVENTORY
# ============================================================

def get_inventory():

    rows = []

    sites = get_sites()

    for site in sites:

        site_id = site["id"]

        site_name = site.get(
            "name",
            site_id
        )

        # ----------------------------------------------------
        # DEVICES UNIFI
        # ----------------------------------------------------

        devices = get_all(
            f"/v1/sites/{site_id}/devices"
        )

        # ----------------------------------------------------
        # CLIENTS
        # ----------------------------------------------------

        clients = get_all(
            f"/v1/sites/{site_id}/clients"
        )

        # MAC des devices UniFi
        #
        # Permet d'éviter de présenter deux fois un device
        # si UniFi le retourne également comme client.
        # ----------------------------------------------------

        device_macs = {
            d.get(
                "macAddress",
                ""
            ).lower()

            for d in devices

            if d.get("macAddress")
        }

        # ====================================================
        # DEVICES
        # ====================================================

        for device in devices:

            ip = device.get(
                "ipAddress"
            )

            if not ip:
                continue

            vlan = get_vlan(ip)

            rows.append({

                "ip": ip,

                "type": "UNIFI",

                "name": device.get(
                    "name",
                    ""
                ),

                "mac": device.get(
                    "macAddress",
                    ""
                ),

                "model": device.get(
                    "model",
                    ""
                ),

                "state": device.get(
                    "state",
                    ""
                ),

                "site": site_name,

                "vlan": vlan,

            })

        # ====================================================
        # CLIENTS
        # ====================================================

        for client in clients:

            ip = client.get(
                "ipAddress"
            )

            if not ip:
                continue

            mac = client.get(
                "macAddress",
                ""
            ).lower()

            # Ne pas afficher deux fois un device UniFi
            if mac in device_macs:
                continue

            vlan = get_vlan(ip)

            rows.append({

                "ip": ip,

                "type": "CLIENT",

                "name": client.get(
                    "name",
                    ""
                ),

                "mac": client.get(
                    "macAddress",
                    ""
                ),

                "model": "",

                "state": "ONLINE",

                "site": site_name,

                "vlan": vlan,

            })

    rows.sort(
        key=ip_sort
    )

    return rows


# ============================================================
# ROUTE PRINCIPALE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def index(
    request: Request
):

    error = None

    rows = []

    try:

        rows = get_inventory()

    except Exception as e:

        error = str(e)

    # --------------------------------------------------------
    # IP FIXES
    # --------------------------------------------------------

    fixed_ips = load_fixed_ips()

    # --------------------------------------------------------
    # Marque les IP fixes
    # --------------------------------------------------------

    for row in rows:

        row["fixed"] = (
            row["ip"] in fixed_ips
        )

    # --------------------------------------------------------
    # IP FIXES uniquement
    # --------------------------------------------------------

    fixed_rows = [
        row
        for row in rows
        if row["fixed"]
    ]

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return templates.TemplateResponse(

        request=request,

        name="index.html",

        context={

            "rows": rows,

            "fixed_rows": fixed_rows,

            "fixed_ips": fixed_ips,

            "error": error,

        }
    )