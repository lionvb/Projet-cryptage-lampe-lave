import os
import time
import cv2
import numpy as np
from matplotlib import pyplot as plt

from chiffrement_dechiffrement.rsa_cles   import generer_cles_rsa
from chiffrement_dechiffrement.cryptage   import chiffrer
from chiffrement_dechiffrement.decryptage import dechiffrer
from number_generator.setup               import image_to_bytes, bytes_to_grands_entiers

PHOTO_PATH  = os.path.join("docs", "photo_lava_lamp.jpg")
MESSAGE     = "J'ai un secret à vous révéler mais chuuuttt"
SEPARATEUR  = "─" * 60

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
    """Affiche les n premiers caractères d'une valeur avec '...' si tronquée."""
    s = str(valeur)
    extrait = s[:longueur] + ("..." if len(s) > longueur else "")
    print(f"      {label} : {extrait}")

# ─── ÉTAPE 0 — Visualisation de l'image source ──────────────────────────────

def afficher_pipeline_image(photo_path: str):
    titre("ÉTAPE 0 — Source d'entropie : la lampe à lave")

    image        = cv2.imread(photo_path, cv2.IMREAD_GRAYSCALE)
    image_cropped = image[50:image.shape[0]-50, 390:image.shape[1]-390]
    image_50x50  = cv2.resize(image_cropped, (50, 50))

    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    fig.suptitle("Pipeline image → source d'aléa", fontsize=13, fontweight="bold")

    axes[0].imshow(image,          cmap="gray")
    axes[0].set_title("Originale")
    axes[0].axis("off")

    axes[1].imshow(image_cropped,  cmap="gray")
    axes[1].set_title("Rognée")
    axes[1].axis("off")

    axes[2].imshow(image_50x50,    cmap="gray")
    axes[2].set_title("50×50 → Clé")
    axes[2].axis("off")

    plt.tight_layout()
    plt.show()

    ok(f"Image chargée          : {image.shape[1]}×{image.shape[0]} px")
    ok(f"Après rognage          : {image_cropped.shape[1]}×{image_cropped.shape[0]} px")
    ok(f"Après réduction        : 50×50 px  →  2 500 bytes bruts")

# ─── ÉTAPE 1 — Génération des grands entiers ────────────────────────────────

def demo_generation_entiers(photo_path: str) -> tuple[int, int]:
    titre("ÉTAPE 1 — Bytes bruts → deux grands entiers (SHA-512)")

    t0        = time.perf_counter()
    raw_bytes = image_to_bytes(photo_path)
    nb1, nb2  = bytes_to_grands_entiers(raw_bytes)
    duree     = time.perf_counter() - t0

    ok(f"Bytes bruts extraits   : {len(raw_bytes)} bytes")
    ok(f"Hash SHA-512           : 64 bytes → coupé en 2 × 32 bytes")
    afficher_extrait("Entier 1", nb1)
    afficher_extrait("Entier 2", nb2)
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return nb1, nb2

# ─── ÉTAPE 2 — Génération des clés RSA ──────────────────────────────────────

def demo_generation_cles(nb1: int, nb2: int) -> tuple[dict, dict]:
    titre("ÉTAPE 2 — Grands entiers → nombres premiers → clés RSA")

    t0               = time.perf_counter()
    cle_pub, cle_priv = generer_cles_rsa(nb1, nb2)
    duree            = time.perf_counter() - t0

    n_bits = cle_pub["n"].bit_length()
    ok(f"Module RSA n           : {n_bits} bits")
    ok(f"Exposant public  e     : {cle_pub['e']}  (2¹⁶ + 1, standard)")
    afficher_extrait("Module n (extrait)", cle_pub["n"])
    afficher_extrait("Exposant privé d ", cle_priv["d"])
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return cle_pub, cle_priv

# ─── ÉTAPE 3 — Chiffrement ──────────────────────────────────────────────────

def demo_chiffrement(message: str, cle_pub: dict) -> bytes:
    titre("ÉTAPE 3 — Chiffrement RSA-OAEP")

    print(f"\n      Message original   : {message}")
    print(f"      Taille             : {len(message.encode('utf-8'))} bytes\n")

    t0              = time.perf_counter()
    message_chiffre = chiffrer(message, cle_pub)
    duree           = time.perf_counter() - t0

    ok(f"Taille chiffrée        : {len(message_chiffre)} bytes")
    afficher_extrait("Chiffré (hex)    ", message_chiffre.hex())
    ok(f"Durée                  : {duree*1000:.1f} ms")

    return message_chiffre

# ─── ÉTAPE 4 — Déchiffrement et vérification ────────────────────────────────

def demo_dechiffrement(message_chiffre: bytes, cle_priv: dict, message_original: str):
    titre("ÉTAPE 4 — Déchiffrement et vérification")

    t0                = time.perf_counter()
    message_dechiffre = dechiffrer(message_chiffre, cle_priv)
    duree             = time.perf_counter() - t0

    print(f"\n      Message déchiffré  : {message_dechiffre}")
    ok(f"Durée                  : {duree*1000:.1f} ms\n")

    print(SEPARATEUR)
    if message_original == message_dechiffre:
        print("  ✔  SUCCÈS — Le message déchiffré est identique à l'original.")
    else:
        print("  ✘  ÉCHEC  — Les messages diffèrent.")
    print(SEPARATEUR)

# ─── POINT D'ENTRÉE ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    titre("POC — Chiffrement RSA par source d'entropie visuelle")
    print(f"  Image source : {PHOTO_PATH}")
    print(f"  Message      : {MESSAGE}")

    afficher_pipeline_image(PHOTO_PATH)
    nb1, nb2           = demo_generation_entiers(PHOTO_PATH)
    cle_pub, cle_priv  = demo_generation_cles(nb1, nb2)
    message_chiffre    = demo_chiffrement(MESSAGE, cle_pub)
    demo_dechiffrement(message_chiffre, cle_priv, MESSAGE)