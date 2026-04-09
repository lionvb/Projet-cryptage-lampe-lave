# Chargement des bibliothèques
import cv2
import numpy as np
from matplotlib import pyplot as plt 

# Chargement de l'image en n&b
image = cv2.imread("docs\photo_lava_lamp.jpg", cv2.IMREAD_GRAYSCALE)

# Rognage de l'image en 220x900 (isoler la lampe)
image_cropped = image[50:image.shape[0]-50, 390:image.shape[1] - 390]

# Réduire la taille de l'image (qualité)
image_50x50 = cv2.resize(image, (50, 50))

# Print de la matrice
# print(image_cropped)

# Visualisation de l'image
visu = image
plt.imshow(visu, cmap="gray"), plt.axis("off")
plt.show()