# 🌋 Crypto Lava Lamp

> Chiffrement RSA dont l'entropie est générée à partir d'une source visuelle aléatoire inspiré de [LavaRand](https://blog.cloudflare.com/lavarand-in-production-the-nitty-gritty-technical-details/) de Cloudflare.

---

## Sommaire

- [Contexte](#contexte)
- [V1  Preuve de concept](#v1--preuve-de-concept)
- [Architecture](#architecture)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Pipeline](#pipeline)
- [Documentation](#documentation)

---

## Contexte

La sécurité d'un chiffrement RSA repose entièrement sur l'imprévisibilité des nombres premiers `p` et `q` utilisés pour générer les clés. Si ces nombres sont prévisibles, toute la sécurité s'effondre.

Cloudflare résout ce problème avec **LavaRand** : un mur de lampes à lave filmé en continu. Le chaos thermique et visuel des lampes produit une source d'entropie physiquement imprévisible, utilisée pour seeder leur générateur de nombres aléatoires.

Ce projet reproduit ce principe : une **image de lampe à lave** est transformée en grands entiers aléatoires, qui servent de base à la génération d'une paire de clés RSA, puis au chiffrement et déchiffrement de messages.

---

## V1 — Preuve de concept

Cette première version est volontairement simplifiée. L'objectif est de faire fonctionner l'ensemble de la pipeline de bout en bout.

**Contraintes de la V1 :**

- La source d'entropie est une **photo statique** de lampe à lave (stockée localement)
- Les images sont traitées en **noir et blanc** pour simplifier l'extraction des pixels
- Le stockage des données est **local**
- Les messages chiffrés sont du **texte simple**
- Le scripting est entièrement en **Python**

---

## Architecture

```
Projet-cryptage-lampe-lave/
│
├── docs/
│   ├── Cryptologie.md          # Explication du chiffrement RSA utilisé
│   ├── Notes_V1.md             # Contraintes et décisions de la V1
│   └── photo_lava_lamp.jpg     # Source d'entropie de la V1
│
├── src/
│   ├── main.py                 # Point d'entrée principal
│   ├── poc.py                  # Démo visuelle complète étape par étape
│   │
│   ├── number_generator/
│   │   └── setup.py            # Image → bytes → grands entiers (SHA-512)
│   │
│   └── chiffrement_dechiffrement/
│       ├── __init__.py
│       ├── rsa_cles.py         # Primalité (Miller-Rabin) + génération des clés RSA
│       ├── cryptage.py         # Chiffrement RSA + padding OAEP
│       └── decryptage.py       # Déchiffrement RSA + retrait du padding OAEP
│
├── requirements.txt
└── README.md
```

### Rôle de chaque module

| Fichier | Responsabilité |
|---------|----------------|
| `number_generator/setup.py` | Charge l'image, la rogne, la réduit en 50×50 px, extrait les bytes bruts, applique SHA-512 pour produire deux grands entiers |
| `rsa_cles.py` | Test de primalité (Miller-Rabin), recherche du prochain premier, calcul de `n`, `φ(n)`, `e`, `d` |
| `cryptage.py` | Chiffrement `c = mᵉ mod n` avec padding OAEP (sel aléatoire + masquage MGF/SHA-256) |
| `decryptage.py` | Déchiffrement `m = cᵈ mod n` avec retrait du padding et validation des données |
| `main.py` | Orchestre les modules, point d'entrée minimaliste |
| `poc.py` | Démo complète avec visualisation matplotlib des étapes de la pipeline |

---

## Installation

**Prérequis :** Python 3.8+

Cloner le dépôt et installer les dépendances :

```bash
git clone https://github.com/lionvb/Projet-cryptage-lampe-lave.git
cd Projet-cryptage-lampe-lave
pip install -r requirements.txt
```

**Dépendances :**

```
opencv-python
numpy
matplotlib
```

---

## Utilisation

Tous les scripts se lancent **depuis le dossier `src/`** :

```bash
cd src
```

### Exécution principale

```bash
python main.py
```

Chiffre et déchiffre un message de test en utilisant la photo de lampe à lave comme source d'entropie.

**Exemple de sortie :**

```
[CLÉ] p → 256 bits : 94268612060428978666916495603...
[CLÉ] q → 256 bits : 87140528397650817264859201638...
[CLÉ] Module n → 512 bits

Message original   : J'ai un secret à vous réveler mais chuuuttt
Message chiffré    : 3f8a2c...
Message déchiffré  : J'ai un secret à vous réveler mais chuuuttt

Succès
```

### Démo visuelle (POC)

```bash
python poc.py
```

Affiche chaque étape de la pipeline avec les durées d'exécution et une visualisation matplotlib de la transformation de l'image.

```
──────────────────────────────────────────────────────────
  ÉTAPE 0 — Source d'entropie : la lampe à lave
──────────────────────────────────────────────────────────
  [1] ÉTAPE 1 — Bytes bruts → deux grands entiers (SHA-512)
  [2] ÉTAPE 2 — Grands entiers → nombres premiers → clés RSA
  [3] ÉTAPE 3 — Chiffrement RSA-OAEP
  [4] ÉTAPE 4 — Déchiffrement et vérification
```

---

## Pipeline

```
docs/photo_lava_lamp.jpg
         │
         │  image_to_bytes()          → rognage + réduction 50×50 + flatten
         ▼
  2 500 bytes bruts
         │
         │  bytes_to_grands_entiers() → SHA-512 → 2 × 32 bytes → 2 entiers
         ▼
  nombre_1, nombre_2  (256 bits chacun)
         │
         │  prochain_premier()        → Miller-Rabin + recherche linéaire
         ▼
  p, q  (nombres premiers)
         │
         │  generer_cles_rsa()        → n = p×q, φ(n), e=65537, d=e⁻¹ mod φ(n)
         ▼
  clé publique (n, e)   clé privée (n, d)
         │                     │
         │  chiffrer()         │  dechiffrer()
         │  c = mᵉ mod n       │  m = cᵈ mod n
         ▼                     ▼
  message chiffré   →   message en clair
```

---

## Documentation

- [`docs/Cryptologie.md`](docs/Cryptologie.md) — Explication complète du chiffrement RSA : symétrique vs asymétrique, génération des clés, preuve mathématique, padding OAEP, lien avec le projet, recommandations de sécurité.
- [`docs/Notes_V1.md`](docs/Notes_V1.md) — Contraintes et décisions d'architecture de la V1.