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
    #========== Création user1 ==========
    user1=set_username()
    print(f"\n========== Création du profil de {user1} ==========")
    enregistrer(user1)
    print(f"\nProfil de {user1} enregistré.")

    #========== Clé rsa user1 ==========
    print(f"\n========== Clé RSA {user1} ==========")
    pub_rsa1, priv_rsa1 = create_rsa_keys(user1)
    print(f"\nClé publique rsa de {user1} : \n- n {str(pub_rsa1['n'])[:10]}... \n- e {pub_rsa1['e']}")

    #========== Création user2 ==========
    user2=set_username()
    print(f"\n========== Création de profil de {user2} ==========")
    enregistrer(user2)
    print(f"\nProfil de {user2} enregistré.")

    #========== Clé rsa user2 ==========
    print(f"\n========== Clé RSA {user2} ==========")
    pub_rsa2, priv_rsa2 = create_rsa_keys(user2)
    print(f"\nClé publique rsa de {user2} : \n- n {str(pub_rsa2['n'])[:10]}... \n- e {pub_rsa2['e']}")

    #========== Récupération de la clé publique de user1 par user2 =========
    print(f"\n= Récupération de la clé publique de {user1} par {user2} =")
    destinataire_pub_key = dict(zip(("n", "e"), récuperer_clés(user1)))
    print(f"\nClé RSA publique de {user1} récupérée par {user2}.")

    #========== Création de la clé aes par user2 ==========
    print(f"\n========== Création de la clé AES par {user2} ==========")
    aes = create_aes_key()
    print(f"\nclé AES crée par {user2} :\n {aes[:10]}...")

    #========== Chiffrement de la clé aes par user2 pour user1 ==========
    print(f"\n=== Chiffrement de la clé AES par {user2} pour {user1} ===")
    aes_key_crypted=chiffrer_RSA(aes,destinataire_pub_key)
    print(f"\nClé AES chiffrée en RSA par {user2} avec la clé_publique de {user1} : {aes_key_crypted[:5]}...")
    
    #========== Récéption de la clé aes chiffrée de user2 par user1 ==========
    aes_key_decrypted=dechiffrer_RSA(aes_key_crypted,priv_rsa1)
    print(f"\nTest du déchiffrement de la clé AES reçu par {user1} :")  
    if aes_key_crypted == aes :
        print("OK")
    else :
        print("KO")
