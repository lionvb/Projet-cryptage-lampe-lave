import asyncio
import json

from src.encrypt_decrypt.key_generator import generer_cles_rsa,extraire_cle_aes,seed_vers_grands_entiers

import httpx
import websockets


BASE_HTTP = "http://localhost:8000"
BASE_WS = "ws://localhost:8000"




def set_username():
    username=input("Quelle est votre username ? : ")
    return username

def enregistrer(username: str) -> None:
    """Inscrit un username via POST /register, idempotent."""
    with httpx.Client() as client:
        r = client.post(f"{BASE_HTTP}/register", json={"username": username})
        if r.status_code not in (201, 409):
            r.raise_for_status()

def seed() -> str:
    """Récupère la seed via GET /seed."""
    reponse=httpx.get(f"{BASE_HTTP}/seed",timeout=5.0)
    reponse.raise_for_status()
    return reponse.json()["seed"]

def publier_clés(username,cle_pub):
    with httpx.Client() as client:
        r = client.post(f"{BASE_HTTP}/publickey", json={"username": username,"n":cle_pub["n"],"e":cle_pub["e"]})
        if r.status_code !=201:
            r.raise_for_status()

if __name__ == "__main__":
    user1=set_username()
    enregistrer(user1)
    seed_user1=seed()
    nb1,nb2,nb3=seed_vers_grands_entiers(bytes.fromhex(seed_user1))
    cle_pub,cle_priv=generer_cles_rsa(nb1,nb2)
    aes_key=extraire_cle_aes(nb3)
    publier_clés(user1,cle_pub)