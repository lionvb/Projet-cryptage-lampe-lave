import os
import time
import cv2
import numpy as np
from matplotlib import pyplot as plt
from random import randint
import hashlib

from chiffrement_dechiffrement.rsa_cles   import generer_cles_rsa,seed_vers_grands_entiers
from chiffrement_dechiffrement.cryptage   import chiffrer
from chiffrement_dechiffrement.decryptage import dechiffrer
from number_generator.setup               import images_to_bytes, bytes_to_grands_entiers

FRAMES_DIR = os.path.join("docs", "Pictures")
INPUT_FILE      = os.path.join("docs", "message.txt")
ENCRYPTED_FILE  = os.path.join("docs", "message_chiffre.txt")
DECRYPTED_FILE  = os.path.join("docs", "message_dechiffre.txt")
SEPARATEUR      = "─" * 60

# ─── UTILITAIRES D'AFFICHAGE ────────────────────────────────────────────────

def titre(texte: str):
    print(f"\n{SEPARATEUR}")
    print(f"  {texte}")
    print(SEPARATEUR)

def etape(numero: int, texte: str):
    print(f"\n  [{numero}] {texte}")

def ok(texte: str):
    print(f"      ✔  {texte}")

def ko(texte: str):
    print(f"      ✘  {texte}")

def afficher_extrait(label: str, valeur, longueur: int = 60):
    s = str(valeur)
    extrait = s[:longueur] + ("..." if len(s) > longueur else "")
    print(f"      {label} : {extrait}")

def lire_fichier(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def ecrire_fichier(path: str, contenu: str):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(contenu)

# ─── ÉTAPE 0 — Visualisation des frames ─────────────────────────────────────

def afficher_pipeline_images(frames_dir: str):
    titre("ÉTAPE 0 — Source d'entropie : les frames de la lampe à lave")

    extensions_valides = (".jpg", ".jpeg", ".png", ".bmp")
    chemins = sorted([
        os.path.join(frames_dir, f)
        for f in os.listdir(frames_dir)
        if f.lower().endswith(extensions_valides)
    ])

    nb = len(chemins)
    ok(f"Nombre de frames trouvées : {nb}")

    fig, axes = plt.subplots(1, nb, figsize=(4 * nb, 4))
    if nb == 1:
        axes = [axes]

    for i, chemin in enumerate(chemins):
        image = cv2.imread(chemin, cv2.IMREAD_GRAYSCALE)
        image_50x50 = cv2.resize(image, (50, 50))
        axes[i].imshow(image_50x50, cmap="gray")
        axes[i].set_title(f"Frame {i+1}\n50×50")
        axes[i].axis("off")

    fig.suptitle("Frames → source d'aléa (1 sélectionnée aléatoirement)", fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.show()

# ─── ÉTAPE 1 — Génération des grands entiers ────────────────────────────────

def demo_generation_entiers(frames_dir: str) -> tuple[int, int]:
    titre("ÉTAPE 1 — Frames → hash SHA-512 aléatoire → deux grands entiers")

    t0       = time.perf_counter()
    raw_bytes = images_to_bytes(frames_dir)
    nb1, nb2 = seed_vers_grands_entiers(raw_bytes)
    duree    = time.perf_counter() - t0

    ok(f"Hash sélectionné       : 64 bytes (SHA-512 d'une frame tirée au sort)")
    ok(f"Re-hash SHA-512        : 64 bytes → coupé en 2 × 32 bytes")
    afficher_extrait("Entier 1", nb1)
    afficher_extrait("Entier 2", nb2)
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return nb1, nb2

# ─── ÉTAPE 2 — Génération des clés RSA ──────────────────────────────────────

def demo_generation_cles(nb1: int, nb2: int) -> tuple[dict, dict]:
    titre("ÉTAPE 2 — Grands entiers → nombres premiers → clés RSA")

    t0                = time.perf_counter()
    cle_pub, cle_priv = generer_cles_rsa(nb1, nb2)
    duree             = time.perf_counter() - t0

    n_bits = cle_pub["n"].bit_length()
    ok(f"Module RSA n           : {n_bits} bits")
    ok(f"Exposant public  e     : {cle_pub['e']}  (2¹⁶ + 1, standard)")
    afficher_extrait("Module n (extrait)", cle_pub["n"])
    afficher_extrait("Exposant privé d ", cle_priv["d"])
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return cle_pub, cle_priv

# ─── ÉTAPE 3 — Chiffrement ──────────────────────────────────────────────────

def demo_chiffrement(input_file: str, cle_pub: dict) -> bytes:
    titre("ÉTAPE 3 — Lecture du fichier et chiffrement RSA-OAEP")

    texte_original = lire_fichier(input_file)
    print(f"\n      Fichier source     : {input_file}")
    print(f"      Taille             : {len(texte_original.encode('utf-8'))} bytes\n")

    t0              = time.perf_counter()
    message_chiffre = chiffrer(texte_original, cle_pub)
    duree           = time.perf_counter() - t0

    ecrire_fichier(ENCRYPTED_FILE, message_chiffre.hex())
    ok(f"Taille chiffrée        : {len(message_chiffre)} bytes")
    ok(f"Fichier écrit          : {ENCRYPTED_FILE}")
    afficher_extrait("Chiffré (hex)    ", message_chiffre.hex())
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return message_chiffre

# ─── ÉTAPE 4 — Déchiffrement et vérification ────────────────────────────────

def demo_dechiffrement(message_chiffre: bytes, cle_priv: dict, input_file: str):
    titre("ÉTAPE 4 — Déchiffrement et vérification")

    t0                = time.perf_counter()
    message_chiffre_bytes = bytes.fromhex(lire_fichier(ENCRYPTED_FILE))
    message_dechiffre = dechiffrer(message_chiffre_bytes, cle_priv)
    duree             = time.perf_counter() - t0

    ecrire_fichier(DECRYPTED_FILE, message_dechiffre)
    ok(f"Fichier écrit          : {DECRYPTED_FILE}")
    print(f"\n      Message déchiffré  : {message_dechiffre}")
    ok(f"Durée                  : {duree*1000:.1f} ms\n")

    texte_original = lire_fichier(input_file)
    print(SEPARATEUR)
    if texte_original == message_dechiffre:
        print("  ✔  SUCCÈS — Le message déchiffré est identique à l'original.")
    else:
        print("  ✘  ÉCHEC  — Les messages diffèrent.")
    print(SEPARATEUR)

# ─── POINT D'ENTRÉE ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    titre("POC — Chiffrement RSA par source d'entropie visuelle")
    print(f"  Dossier frames : {FRAMES_DIR}")
    print(f"  Fichier source : {INPUT_FILE}")

    afficher_pipeline_images(FRAMES_DIR)
    nb1, nb2          = demo_generation_entiers(FRAMES_DIR)
    cle_pub, cle_priv = demo_generation_cles(nb1, nb2)
    message_chiffre   = demo_chiffrement(INPUT_FILE, cle_pub)
    demo_dechiffrement(message_chiffre, cle_priv, INPUT_FILE)