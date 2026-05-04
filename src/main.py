import sys
import os

from chiffrement_dechiffrement.rsa_cles   import generer_cles_rsa,seed_vers_grands_entiers
from chiffrement_dechiffrement.cryptage   import chiffrer
from chiffrement_dechiffrement.decryptage import dechiffrer
from number_generator.setup import images_to_bytes

PHOTO_PATH = os.path.join("docs", "Pictures")
INPUT_FILE  = os.path.join("docs", "message.txt")
ENCRYPTED_FILE   = os.path.join("docs", "message_chiffre.txt")
DECRYPTED_FILE   = os.path.join("docs", "message_dechiffre.txt")


def lire_fichier(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def ecrire_fichier(path: str, contenu: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(contenu)


if __name__ == "__main__":
    # Génération des clés RSA
    raw_bytes = images_to_bytes(PHOTO_PATH)
    nombre_1, nombre_2 = seed_vers_grands_entiers(raw_bytes)
    cle_pub, cle_priv = generer_cles_rsa(nombre_1, nombre_2)

    # 1. Lecture du fichier source
    texte_original = lire_fichier(INPUT_FILE)
    print(f"Message original :\n{texte_original}\n")

    # 2. Chiffrement → écriture
    message_chiffre = chiffrer(texte_original, cle_pub)
    ecrire_fichier(ENCRYPTED_FILE, message_chiffre.hex())
    print(f"Fichier chiffré écrit : {ENCRYPTED_FILE}\n")

    # 3. Déchiffrement → écriture
    message_chiffre_bytes = bytes.fromhex(lire_fichier(ENCRYPTED_FILE))
    message_dechiffre = dechiffrer(message_chiffre_bytes, cle_priv)
    ecrire_fichier(DECRYPTED_FILE, message_dechiffre)
    print(f"Fichier déchiffré écrit : {DECRYPTED_FILE}\n")

    # 4. Vérification
    if texte_original == message_dechiffre:
        print("Succès ✅")
    else:
        print("Échec ❌")