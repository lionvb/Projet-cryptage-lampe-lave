import asyncio
import json
import base64

import httpx
import websockets

from src.encrypt_decrypt.encrypt_decrypt import (
    chiffrer_RSA,
    dechiffrer_RSA,
    chiffrement_AES,
    dechiffrement_AES,
)
from src.encrypt_decrypt.key_generator import (
    extraire_cle_aes,
    generer_cles_rsa,
    seed_vers_grands_entiers,
)


BASE_HTTP = "http://localhost:8000"
BASE_WS = "ws://localhost:8000"


def set_username():
    username=input("\nQuelle est votre username ? : ")
    return username

def enregistrer(username: str) -> None:
    """Inscrit un username via POST /register. Idempotent (409 toléré)."""
    with httpx.Client() as client:
        r = client.post(f"{BASE_HTTP}/register", json={"username": username})
        if r.status_code not in (201, 409):
            r.raise_for_status()


def obtenir_seed() -> str:
    """Récupère une seed d'entropie de 64 octets en hexadécimal via GET /seed."""
    r = httpx.get(f"{BASE_HTTP}/seed", timeout=5.0)
    r.raise_for_status()
    return r.json()["seed"]


def publier_cle(username: str, cle_publique: dict) -> None:
    """Publie la clé publique RSA d'un utilisateur via POST /publickey."""
    payload = {
        "username": username,
        "n": cle_publique["n"],
        "e": cle_publique["e"],
    }
    with httpx.Client() as client:
        r = client.post(f"{BASE_HTTP}/publickey", json=payload)
        if r.status_code != 201:
            r.raise_for_status()


def recuperer_cle(destinataire: str) -> dict:
    """Récupère la clé publique RSA d'un autre utilisateur via GET /publickey/{username}."""
    r = httpx.get(f"{BASE_HTTP}/publickey/{destinataire}", timeout=5.0)
    r.raise_for_status()
    data = r.json()
    return {"n": data["n"], "e": data["e"]}

def initialiser_session(username: str) -> tuple[dict, dict]:
    """
    Phase d'initialisation locale commune à tous les clients :
    inscription, obtention d'une seed, dérivation de la paire RSA,
    publication de la clé publique sur le serveur.

    Retourne (cle_publique, cle_privee), chacune au format
    {"n": int, "e": int} ou {"n": int, "d": int}.
    """
    enregistrer(username)
    seed_bytes = bytes.fromhex(obtenir_seed())
    nb1, nb2, _ = seed_vers_grands_entiers(seed_bytes)
    cle_publique, cle_privee = generer_cles_rsa(nb1, nb2)
    publier_cle(username, cle_publique)
    return cle_publique, cle_privee


def generer_cle_aes_session() -> bytes:
    """
    Génère une clé AES-256 de session, dérivée d'une seed serveur.

    À n'appeler que côté initiateur de la WebSocket. Le récepteur ne
    génère pas de clé locale : il récupère celle de l'initiateur via
    le message aes_key au début de la session.
    """
    seed_bytes = bytes.fromhex(obtenir_seed())
    _, _, nb3 = seed_vers_grands_entiers(seed_bytes)
    return extraire_cle_aes(nb3)

async def ouvrir_websocket(username: str) -> None:
    """
    Ouvre la WebSocket de chat et la maintient ouverte jusqu'à fermeture
    (côté serveur via close-frame, ou côté utilisateur via Ctrl+C).

    Sous-étape 2 : on se contente de la connexion. Aucun message n'est
    envoyé ; les messages reçus sont loggés mais pas traités.
    """
    url = f"{BASE_WS}/chat?user={username}"
    print(f"\nConnexion à {url} ...")
    async with websockets.connect(url) as ws:
        print(f"Connecté en tant que {username}. Ctrl+C pour quitter.")
        async for message in ws:
            print(f"[reçu] {message}")
    # Une fois le `async with` sorti, la WS est fermée des deux côtés.
    print(f"Connexion fermée — code={ws.close_code} reason={ws.close_reason!r}")

async def envoyer_cle_aes(ws, destinataire: str, cle_aes: bytes) -> None:
    """
    Côté initiateur : récupère la clé publique RSA du destinataire,
    chiffre la clé AES de session avec, encode le résultat en base64,
    et envoie le tout sur la WS via un message :
        {"type": "aes_key", "to": <destinataire>, "payload": <base64>}
    """
    pub_dest = recuperer_cle(destinataire)
    aes_chiffree = chiffrer_RSA(cle_aes, pub_dest)
    payload_b64 = base64.b64encode(aes_chiffree).decode("ascii")

    message = {
        "type": "aes_key",
        "to": destinataire,
        "payload": payload_b64,
    }
    await ws.send(json.dumps(message))
    print(f"Clé AES envoyée (chiffrée RSA) à {destinataire}.")

async def main_client() -> None:
    """Orchestration interactive du client."""
    username = input("\nUsername : ").strip()
    if not username:
        print("Username vide, abandon.")
        return

    pub, priv = initialiser_session(username)
    print(f"\nSession initialisée pour {username}.")

    await ouvrir_websocket(username)

async def main_client() -> None:
    """Orchestration interactive du client."""
    username = input("\nUsername : ").strip()
    if not username:
        print("Username vide, abandon.")
        return

    pub, priv = initialiser_session(username)
    print(f"\nSession initialisée pour {username}.")

    # Choix du rôle
    reponse = input("\nÊtes-vous l'initiateur de la session ? (o/n) : ").strip().lower()
    est_initiateur = reponse.startswith("o")

    destinataire = None
    cle_aes = None
    if est_initiateur:
        destinataire = input("Username du destinataire : ").strip()
        cle_aes = generer_cle_aes_session()
        print(f"\nClé AES de session générée (32 octets).")

    # Connexion WS et handshake
    url = f"{BASE_WS}/chat?user={username}"
    print(f"\nConnexion à {url} ...")
    try:
        async with websockets.connect(url) as ws:
            print(f"Connecté en tant que {username}.")

            if est_initiateur:
                await envoyer_cle_aes(ws, destinataire, cle_aes)

            print("\nEn écoute. Ctrl+C pour quitter.\n")
            async for raw in ws:
                # Pour l'instant on log le brut. Le traitement du
                # message `aes_key` côté récepteur arrive à l'étape suivante.
                print(f"[reçu] {raw}")
    except websockets.exceptions.ConnectionClosed as e:
        print(f"\nFermée — code={e.code} reason={e.reason!r}")