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
            
def récuperer_clés(destinataire:str) -> tuple[int, int]:
    """Récupère la seed via GET /seed."""
    reponse=httpx.get(f"{BASE_HTTP}/publickey/{destinataire}",timeout=5.0)
    reponse.raise_for_status()
    return reponse.json()["n"],reponse.json()["e"]

def create_rsa_keys(username: str) -> tuple:
    seed_hex=seed()
    nb1,nb2,nb3 = seed_vers_grands_entiers(bytes.fromhex(seed_hex))
    pub_key, priv_key = generer_cles_rsa(nb1, nb2)
    publier_clés(username, pub_key)
    return pub_key, priv_key

def create_aes_key() -> bytes:
    seed_hex=seed()
    nb3 = seed_vers_grands_entiers(bytes.fromhex(seed_hex))[2]
    aes_key = extraire_cle_aes(nb3)
    return aes_key

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
