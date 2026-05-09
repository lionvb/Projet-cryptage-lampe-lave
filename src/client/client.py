import asyncio
import json

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

if __name__ == "__main__":
    
    user1 = input("\nUsername user1 : ")
    pub1, priv1 = initialiser_session(user1)
    print(f"\nuser1 ({user1}) initialisé. n: {str(pub1['n'])[:10]}...")

    user2 = input("\nUsername user2 : ")
    pub2, priv2 = initialiser_session(user2)
    print(f"\nuser2 ({user2}) initialisé. n: {str(pub2['n'])[:10]}...")

    # Simulation du handshake AES (user2 = initiateur)
    pub_destinataire = recuperer_cle(user1)
    cle_aes = generer_cle_aes_session()
    aes_chiffree = chiffrer_RSA(cle_aes, pub_destinataire)
    aes_recue = dechiffrer_RSA(aes_chiffree, priv1)
    print(f"\nHandshake AES : {'OK' if aes_recue == cle_aes else 'KO'}")