import sys
import os

from chiffrement_dechiffrement.rsa_cles   import generer_cles_rsa
from chiffrement_dechiffrement.cryptage   import chiffrer
from chiffrement_dechiffrement.decryptage import dechiffrer
from number_generator.setup import images_to_bytes, bytes_to_grands_entiers

PHOTO_PATH = os.path.join("docs", "Pictures")

if __name__ == "__main__":
    # A remplacer par le generateur
    raw_bytes = images_to_bytes(PHOTO_PATH)
    nombre_1, nombre_2 = bytes_to_grands_entiers(raw_bytes)

    # 1. Génération des clés RSA
    cle_pub, cle_priv = generer_cles_rsa(nombre_1, nombre_2)

    # 2. Chiffrement
    texte_original = "J'ai un secret à vous réveler mais chuuuttt"
    print(f"Message original : {texte_original}\n")

    message_chiffre = chiffrer(texte_original, cle_pub)
    print(f"Message chiffré (hex) : {message_chiffre}...\n")

    # 3. Déchiffrement
    message_dechiffre = dechiffrer(message_chiffre, cle_priv)
    print(f"Message déchiffré : {message_dechiffre}\n")

    # 4. Vérification
    if texte_original == message_dechiffre:
        print("Succès")
    else:
        print("Echec")