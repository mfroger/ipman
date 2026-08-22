# IPMan FastAPI

Petite interface web FastAPI pour afficher l'inventaire UniFi.

## Fonctionnalités

- Tous les devices UniFi + clients
- Onglet `Toutes les IP`
- Onglet `IP Fixed`
- Liste des IP fixes dans `ips.txt`
- Recherche instantanée dans les tableaux
- Détection automatique du type `UNIFI` / `CLIENT`
- Pas de base de données

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configurer les variables :

```bash
export UNIFI_URL="https://192.168.1.1"
export UNIFI_API_KEY="TA_CLE"
```

Puis :

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Ouvrir :

http://localhost:8000

## IP fixes

Modifier simplement `ips.txt`.

Une IP par ligne :

```text
192.168.1.122
192.168.1.145
192.168.1.252
...
```

Les commentaires commençant par `#` sont ignorés.
# ipman
