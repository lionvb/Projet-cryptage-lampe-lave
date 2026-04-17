import cv2
import numpy as np
import hashlib
from matplotlib import pyplot as plt 
import os
from random import randint

def images_to_bytes(frames_dir: str) -> bytes:
    extensions_valides = (".jpg", ".jpeg", ".png", ".bmp")
    chemins = sorted([
        os.path.join(frames_dir, f)
        for f in os.listdir(frames_dir)
        if f.lower().endswith(extensions_valides)
    ])

    if not chemins:
        raise ValueError(f"Aucune image trouvée dans : {frames_dir}")

    hashs_frames = []
    for chemin in chemins:
        image = cv2.imread(chemin, cv2.IMREAD_GRAYSCALE)
        if image is None:
            raise ValueError(f"Impossible de lire l'image : {chemin}")

        image_50x50  = cv2.resize(image, (50, 50))
        raw_bytes    = image_50x50.flatten().tobytes()
        hash_frame   = hashlib.sha512(raw_bytes).digest()
        hashs_frames.append(hash_frame)
    hash_final = hashs_frames[randint(0, len(hashs_frames)-1)]
    return hash_final

def bytes_to_grands_entiers(raw_bytes: bytes) -> tuple[int, int]:
    """
    Convertit des bytes bruts (issus d'une image) en deux grands entiers
    utilisables comme source d'aléa pour la génération de clés RSA.
    """
    # SHA-512 → 64 bytes bien distribués
    hash_bytes = hashlib.sha512(raw_bytes).digest()

    # Split en deux moitiés de 32 bytes
    moitie_1 = hash_bytes[:32]
    moitie_2 = hash_bytes[32:]

    # Conversion bytes → entier (big-endian : octet de poids fort en premier)
    entier_1 = int.from_bytes(moitie_1, byteorder='big')
    entier_2 = int.from_bytes(moitie_2, byteorder='big')

    return entier_1, entier_2


"""
Diagramme pour visualiser la pipeline :

[matrice 50x50]
    ↓ flatten()
[2500 valeurs en ligne]
    ↓ tobytes()
[2500 octets bruts]
    ↓ sha256()
[32 octets] = la clé de chiffrement

"""