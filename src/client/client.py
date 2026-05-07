import asyncio
import json

from src.encrypt_decrypt.key_generator import generer_cles_rsa,extraire_cle_aes,seed_vers_grands_entiers
from src.encrypt_decrypt.encrypt_decrypt import *
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
            
def récuperer_clés(destinataire:str) -> str:
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
    user1=set_username()
    enregistrer(user1)
    rsa = create_rsa_keys(user1)
    pub_rsa, priv_rsa = create_rsa_keys(user1)
    print(f"rsa keys {user1} : \n- n {str(pub_rsa['n'])[:10]}... \n- e {pub_rsa['e']}")

    print("\nSecond User :")
    user2=set_username()
    enregistrer(user2)

    destinataire_pub_key = dict(zip(("n", "e"), récuperer_clés(user1)))
    print(f"Clé RSA publique reçu par {user2} crée par {user1}: \n- n {str(destinataire_pub_key['n'])[:10]}... \n- e {destinataire_pub_key['e']}")

    aes = create_aes_key()
    print(f"\naes key de {user2} : {aes[:10]}...")

    aes_key_crypted=chiffrer_RSA(aes,destinataire_pub_key)
    print(f"Clé aes de {user2} chiffré RSA avec la clé_publique de {user1} : {aes_key_crypted[:5]}...")
    
    #Reste à voir l'envoi de la clé aescrypté pour que l'user 1 la décrypte
    aes_key_decrypted=dechiffrer_RSA(aes_key_crypted,priv_rsa)
    print(f"\nTest du déchiffrement de la clé AES de {user2} reçu par {user1} : {aes_key_decrypted[:10]}...")
    
