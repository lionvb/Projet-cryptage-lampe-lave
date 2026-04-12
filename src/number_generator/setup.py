import cv2
import numpy as np
import hashlib
from matplotlib import pyplot as plt 

# Chargement de l'image en n&b
image = cv2.imread("docs/photo_lava_lamp.jpg", cv2.IMREAD_GRAYSCALE)

# Rognage de l'image (isoler la lampe)
image_cropped = image[50:image.shape[0]-50, 390:image.shape[1]-390]

# Réduire la taille de l'image (réduire la résolution)
image_50x50 = cv2.resize(image_cropped, (50, 50))

# Génération de la clé depuis les pixels
raw_bytes = image_50x50.flatten().tobytes()     # formatage de la data pour hashlib : Matrice 50*50 -> Vecteur de 2500 bytes
key = hashlib.sha256(raw_bytes).digest()        # Création de la clé

print(f"Taille matrice : {image_50x50.shape}")  # (50, 50)
print(f"Nombre de pixels : {image_50x50.size}") # 2500
print(f"Clé SHA-256 : {key.hex()}")             # 64 chars hex

# Visualisation des étapes
fig, axes = plt.subplots(1, 3, figsize=(12, 4))
axes[0].imshow(image,         cmap="gray"), axes[0].set_title("Originale"),    axes[0].axis("off")
axes[1].imshow(image_cropped, cmap="gray"), axes[1].set_title("Rognée"),       axes[1].axis("off")
axes[2].imshow(image_50x50,   cmap="gray"), axes[2].set_title("50x50 → Clé"), axes[2].axis("off")
plt.tight_layout()
plt.show()


"""
Diagramme pour visualiser la pipeline :

[matrice 50x50]
    ↓ flatten()
[2500 valeurs en ligne]
    ↓ tobytes()
[2500 octets bruts]
    ↓ sha256()
[32 octets] = ta clé de chiffrement

"""