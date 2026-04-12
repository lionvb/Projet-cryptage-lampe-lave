import cv2
import numpy as np
import hashlib
from matplotlib import pyplot as plt 

def image_to_bytes(PHOTO_PATH: str) -> bytes :
    # Chargement de l'image en n&b
    image = cv2.imread(PHOTO_PATH, cv2.IMREAD_GRAYSCALE)

    # Rognage de l'image (isoler la lampe)
    image_cropped = image[50:image.shape[0]-50, 390:image.shape[1]-390]

    # Réduire la taille de l'image (réduire la résolution)
    image_50x50 = cv2.resize(image_cropped, (50, 50))

    # Génération de la clé depuis les pixels
    raw_bytes = image_50x50.flatten().tobytes()     # formatage de la data pour hashlib : Matrice 50*50 -> Vecteur de 2500 bytes

    return raw_bytes

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
--pas utilisé--
    ↓ sha256()
[32 octets] = la clé de chiffrement

"""