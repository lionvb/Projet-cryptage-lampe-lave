import numpy as np
import hashlib
from matplotlib import pyplot as plt 
import cv2
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