import sys
import os

from chiffrement_dechiffrement.rsa_cles   import generer_cles_rsa
from chiffrement_dechiffrement.cryptage   import chiffrer
from chiffrement_dechiffrement.decryptage import dechiffrer

if __name__ == "__main__":
    # A remplacer par le generateur
    nombre_1 = int(9426861206042897866691649560399289814634872072151098307165809898495902470614278983979314325730129566996069367595781295614820185427285694087126854627)  
    nombre_2 = int(8714052839765081726485920163847291653902740183475029384756102938475601827364501928374650192837465019283746501928374650192837465019283746501928374651)

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