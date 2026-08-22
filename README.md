# IPMan FastAPI

Petite interface web FastAPI pour afficher l'inventaire UniFi.

## Fonctionnalités

- Tous les devices UniFi + clients
- Onglet `Toutes les IP`
- Onglet `IP Fixed`
- VLAN déduit automatiquement depuis `192.168.<VLAN>.x`
- Code couleur par VLAN
- Recherche instantanée
- Édition de `ips.txt` directement depuis l'interface
- Sauvegarde locale de la liste d'IP fixes
- Push automatique de `ips.txt` vers GitHub
- Pas de base de données

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Créer un fichier `.env` local :

```env
UNIFI_URL=https://192.168.1.1
UNIFI_API_KEY=TA_CLE_UNIFI

# Optionnel : permet le bouton "Enregistrer + GitHub"
GITHUB_TOKEN=TA_CLE_GITHUB
GITHUB_REPO=mfroger/ipman
GITHUB_BRANCH=main
GITHUB_FILE=ips.txt
```

Le token GitHub doit avoir la permission fine-grained `Contents: Read and write` sur le dépôt.

Puis :

```bash
uvicorn app:app --host 127.0.0.1 --port 8765
```

Ouvrir :

http://127.0.0.1:8765

## Gestion des IP fixes

Dans l'onglet `IP Fixed`, la zone d'édition permet de modifier directement la liste.

Une IP par ligne :

```text
192.168.1.122
192.168.1.145
192.168.40.245
192.168.70.160
```

Les IP sont validées comme IPv4, dédoublonnées et triées automatiquement.

### Enregistrer

Écrit uniquement `ips.txt` localement.

### Enregistrer + GitHub

Écrit `ips.txt` localement puis met à jour le fichier `ips.txt` sur GitHub avec un commit.

Si GitHub n'est pas configuré ou si le push échoue, la sauvegarde locale est conservée et l'interface affiche l'erreur.

## Sécurité

Ne jamais committer `.env`, un token GitHub ou une clé UniFi dans le dépôt.

L'interface de modification doit idéalement rester accessible uniquement depuis le réseau de confiance tant qu'aucune authentification n'est ajoutée.
