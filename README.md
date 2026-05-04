# 🌋 Crypto Lava Lamp

> Chiffrement RSA dont l'entropie est générée à partir d'une source visuelle aléatoire,
> inspiré de [LavaRand](https://blog.cloudflare.com/lavarand-in-production-the-nitty-gritty-technical-details/) de Cloudflare.

---

## Sommaire

- [Contexte](#contexte)
- [Installation](#installation)
- [V1  Preuve de concept](#v1--preuve-de-concept)
- [V2  Multi-images et chiffrement de fichier](#v2--multi-images-et-chiffrement-de-fichier)
- [Documentation](#documentation)

---

## Contexte

La sécurité de RSA repose entièrement sur l'imprévisibilité des nombres premiers `p` et `q`. Si ces nombres sont prévisibles, toute la sécurité s'effondre.

Cloudflare résout ce problème avec **LavaRand** : un mur de lampes à lave filmé en continu. Le chaos thermique produit une entropie physiquement imprévisible, utilisée pour seeder leur générateur de nombres aléatoires.

Ce projet reproduit ce principe en Python.

---

## Installation

**Prérequis :** Python 3.8+

```bash
git clone https://github.com/lionvb/Projet-cryptage-lampe-lave.git
cd Projet-cryptage-lampe-lave
pip install -r requirements.txt
```

---

## V1 Preuve de concept

L'objectif de cette version est de faire fonctionner la pipeline de bout en bout avec le minimum de complexité.

### Contraintes

- Source d'entropie : **une photo statique** de lampe à lave
- Images traitées en **noir et blanc**
- Le message chiffré est un **string** (pas de fichier)
- Stockage **local**
- Scripting entièrement en **Python**

### Architecture

```
Projet-cryptage-lampe-lave/
├── docs/
│   ├── Cryptologie.md          # Explication du chiffrement RSA
│   ├── Notes_V1.md             # Décisions d'architecture de la V1
│   └── photo_lava_lamp.jpg     # Source d'entropie
├── src/
│   ├── main.py                 # Point d'entrée
│   ├── poc.py                  # Démo visuelle étape par étape
│   ├── number_generator/
│   │   └── setup.py            # Image → bytes bruts → 2 grands entiers
│   └── chiffrement_dechiffrement/
│       ├── rsa_cles.py         # Miller-Rabin + génération des clés RSA
│       ├── cryptage.py         # Chiffrement RSA + padding OAEP
│       └── decryptage.py       # Déchiffrement RSA + retrait du padding
├── requirements.txt
└── README.md
```

### Pipeline

```
photo_lava_lamp.jpg
    ↓ image_to_bytes()              rognage + réduction 50×50 + flatten
2 500 bytes bruts
    ↓ bytes_to_grands_entiers()     SHA-512 → split 2 × 32 o → 2 entiers (256 bits)
nombre_1, nombre_2
    ↓ prochain_premier()            Miller-Rabin + recherche linéaire
p, q  (~256 bits)
    ↓ generer_cles_rsa()            n=p×q, φ(n), e=65537, d=e⁻¹ mod φ(n)
clé publique (n,e)  /  clé privée (n,d)     [module ~512 bits]
    ↓ chiffrer() / dechiffrer()
message chiffré → message en clair  (affiché en console)
```

### Utilisation

```bash
cd src

# Pipeline complète
python main.py

# Démo visuelle avec matplotlib
python poc.py
```

---

## V2 Multi-images et chiffrement de fichier

La V2 renforce l'entropie en passant d'une photo fixe à plusieurs captures d'écran d'une vidéo, et chiffre désormais un fichier `.txt` complet.

### Ce qui change

- **Entropie** : N frames d'une vidéo → une frame tirée aléatoirement parmi leurs hashs SHA-512
- **Seed** : le hash de la frame sert de graine, dérivée en 2 × 512 bits par *domain separation* (`RSA_P` / `RSA_Q`)
- **Clés RSA** : module ~1023 bits (contre ~512 bits en V1)
- **Données** : chiffrement d'un fichier `.txt`, résultat écrit dans un autre fichier `.txt`

### Contraintes

- Source d'entropie : **captures d'écran** d'une vidéo de lampe à lave (`docs/Pictures/`)
- L'image est une **seed** pour dériver les clés, pas la clé elle-même
- Images en **noir et blanc**
- Données chiffrées : **fichier `.txt`**
- Stockage **local**

### Architecture

```
Projet-cryptage-lampe-lave/
├── docs/
│   ├── Cryptologie.md
│   ├── Notes_V1.md
│   ├── Notes_V2.md             # Décisions d'architecture de la V2
│   ├── message.txt             # Fichier source à chiffrer
│   ├── message_chiffre.txt     # Produit par main.py
│   ├── message_dechiffre.txt   # Produit par main.py
│   └── Pictures/               # Frames de la vidéo lampe à lave
│       ├── lavalamp_1.png
│       └── ...
├── src/
│   ├── main.py
│   ├── number_generator/
│   │   └── setup.py            # N images → seed SHA-512 aléatoire
│   └── chiffrement_dechiffrement/
│       ├── rsa_cles.py         # + seed_vers_grands_entiers()
│       ├── cryptage.py
│       └── decryptage.py
├── requirements.txt
└── README.md
```

### Pipeline

```
docs/Pictures/  (N frames)
    ↓ images_to_bytes()             SHA-512 de chaque frame → 1 hash tiré aléatoirement
seed  (64 octets)
    ↓ seed_vers_grands_entiers()    SHA-512(seed + "RSA_P/Q" + compteur)
nombre_1, nombre_2  (512 bits chacun)
    ↓ prochain_premier()            Miller-Rabin + recherche linéaire
p, q  (~512 bits)
    ↓ generer_cles_rsa()            n=p×q, φ(n), e=65537, d=e⁻¹ mod φ(n)
clé publique (n,e)  /  clé privée (n,d)     [module ~1023 bits]
    ↓ chiffrer() / dechiffrer()
message_chiffre.txt  →  message_dechiffre.txt
```

### Utilisation

Placer le texte à chiffrer dans `docs/message.txt`, puis :

```bash
cd src
python main.py
```
##### Exemple de sortie :
```
Message original :
Bonjour, ceci est mon message secret...

Fichier chiffré écrit   : docs/message_chiffre.txt
Fichier déchiffré écrit : docs/message_dechiffre.txt

Succès ✅
```

---

## Documentation

| Fichier | Contenu |
|---------|---------|
| [`docs/Cryptologie.md`](docs/Cryptologie.md) | Chiffrement RSA : fonctionnement, preuves mathématiques, padding OAEP, sécurité |
| [`docs/Notes_V1.md`](docs/Notes_V1.md) | Contraintes et décisions de la V1 |
| [`docs/Notes_V2.md`](docs/Notes_V2.md) | Contraintes et décisions de la V2 |