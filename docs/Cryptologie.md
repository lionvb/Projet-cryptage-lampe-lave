# Cryptologie — Chiffrement RSA

## Sommaire
1. [Chiffrement symétrique vs asymétrique](#1-chiffrement-symétrique-vs-asymétrique)
2. [Principe du chiffrement RSA](#2-principe-du-chiffrement-rsa)
3. [Génération des clés](#3-génération-des-clés)
4. [Chiffrement et déchiffrement](#4-chiffrement-et-déchiffrement)
5. [Padding OAEP](#5-padding-oaep)

---

## 1. Chiffrement symétrique vs asymétrique

### Chiffrement symétrique

Dans un chiffrement symétrique, la **même clé** sert à la fois à chiffrer et à déchiffrer. Les deux parties doivent donc se mettre d'accord sur cette clé **avant** de communiquer, ce qui pose un problème : comment transmettre cette clé de façon sécurisée ?

```
Alice ──[clé secrète]──► message chiffré ──► Bob
Bob   ──[clé secrète]──► message en clair
```


### Chiffrement asymétrique

Le chiffrement asymétrique repose sur une **paire de clés** mathématiquement liées :

- La **clé publique** : connue de tous, sert à **chiffrer**
- La **clé privée** : gardée secrète, sert à **déchiffrer**

Ce que la clé publique chiffre, seule la clé privée correspondante peut le déchiffrer — et vice versa.

```
                 Clé publique d'Alice
                        │
Bob ──[message]──►  Chiffrement  ──► message chiffré ──► Alice
                                                            │
                                                    Clé privée d'Alice
                                                            │
                                                     Déchiffrement
                                                            │
                                                     message en clair
```



Le chiffrement asymétrique résout le problème de l'échange de clé : Alice peut publier librement sa clé publique. N'importe qui peut s'en servir pour lui envoyer un message que seule elle pourra lire.

La clé privée peut également servir à **signer** un message : Alice chiffre une empreinte du message avec sa clé privée. N'importe qui peut vérifier la signature en la déchiffrant avec la clé publique d'Alice.


---

## 2. Principe du chiffrement RSA

RSA (1977) est le chiffrement asymétrique le plus répandu. Sa sécurité repose sur la **difficulté de factoriser** un grand nombre entier.

Le principe est le suivant : il est très facile de multiplier deux grands nombres premiers `p` et `q` pour obtenir `n = p × q`, mais il est **extrêmement difficile** de retrouver `p` et `q` en ne connaissant que `n`.

### Pourquoi des nombres premiers ?

Les nombres premiers sont des entiers divisibles uniquement par 1 et par eux-mêmes. Ils sont au cœur de RSA car :

- Leur produit `n = p × q` a des propriétés arithmétiques exploitables (indicatrice d'Euler)
- La factorisation de `n` est le seul moyen connu de casser RSA
- Pour `p` et `q` de 512 bits chacun, `n` fait 1024 bits — le factoriser prendrait des milliers d'années avec les ordinateurs actuels

---

## 3. Génération des clés


**1. Choisir deux grands nombres premiers `p` et `q`**

Ces nombres doivent être :
- **grands** (512 bits minimum chacun pour une sécurité correcte)
- **différents** (`p ≠ q`, sinon `n = p²` est factorisable trivialement)
- **secrets** (ils ne doivent jamais être divulgués)

**2. Calculer le module de chiffrement `n`**

```
n = p × q
```

`n` est la partie **publique** du module RSA. Sa taille (en bits) définit la robustesse de la clé.

**3. Calculer l'indicatrice d'Euler `φ(n)`**

```
φ(n) = (p − 1) × (q − 1)
```

`φ(n)` compte combien d'entiers entre 1 et `n` sont premiers avec `n`. Cette valeur est **secrète** (la connaître revient à connaître `p` et `q`).

**4. Choisir l'exposant public `e`**

On choisit un entier `e` tel que :
- `1 < e < φ(n)`
- `pgcd(e, φ(n)) = 1`  (e est premier avec φ(n))

En pratique, on utilise presque toujours :

```
e = 65537  (= 2¹⁶ + 1)
```

Ce choix est un standard industriel : 65537 est premier, petit (donc rapide à calculer), et sa forme binaire `1 0000 0000 0000 0001` minimise les opérations lors de l'exponentiation modulaire.

**5. Calculer l'exposant privé `d`**

```
d = e⁻¹ mod φ(n)
```

Autrement dit, `d` est l'**inverse modulaire** de `e` modulo `φ(n)`, c'est-à-dire l'entier tel que :

```
e × d ≡ 1  (mod φ(n))
```

`d` se calcule efficacement grâce à l'**algorithme d'Euclide étendu**.

### Résumé des clés

| Clé | Composantes | Visibilité |
|-----|-------------|------------|
| **Clé publique** | `(n, e)` | Partagée librement |
| **Clé privée** | `(n, d)` | Gardée secrète |

---

## 4. Chiffrement et déchiffrement

### Chiffrement (avec la clé publique)

Pour chiffrer un message `m` (représenté comme un entier tel que `0 ≤ m < n`) :

```
c = mᵉ mod n
```

`c` est le **message chiffré** (aussi appelé cryptogramme).

### Déchiffrement (avec la clé privée)

Pour retrouver le message original à partir de `c` :

```
m = cᵈ mod n
```

### Pourquoi ça fonctionne ?

La preuve repose sur le **théorème d'Euler** : si `pgcd(m, n) = 1`, alors

```
m ^ φ(n) ≡ 1  (mod n)
```

Puisque `e × d ≡ 1 (mod φ(n))`, on a `e × d = 1 + k × φ(n)` pour un certain entier `k`. Donc :

```
cᵈ = (mᵉ)ᵈ = m^(e×d) = m^(1 + k×φ(n)) = m × (m^φ(n))ᵏ ≡ m × 1ᵏ ≡ m  (mod n)
```

On retrouve bien `m`.

---

## 5. Padding OAEP

### Problème du RSA brut

Le RSA tel que décrit ci-dessus présente des vulnérabilités si on l'applique directement sur le message :

- **Déterminisme** : chiffrer deux fois le même message donne le même résultat — un attaquant peut deviner le contenu en comparant des chiffrés
- **Malléabilité** : si `c = mᵉ mod n`, alors `(2ᵉ × c) mod n` est le chiffré de `2m` — un attaquant peut manipuler le chiffré sans connaître le message
- **Attaque de Bleichenbacher** : sur certains formats de padding, un oracle de déchiffrement permet de retrouver le message

### Solution : OAEP

Le **padding OAEP** (Optimal Asymmetric Encryption Padding) transforme le message avant chiffrement en y ajoutant un sel aléatoire et un masquage croisé.

Structure du bloc avant chiffrement :

```
┌────────┬──────────────────┬─────────────────┬──────────────────┬──────────┐
│  0x00  │  sel masqué      │  longueur msg   │  message masqué  │  zéros   │
│  (1 o) │   (32 octets)    │   (4 octets)    │   (L octets)     │  (reste) │
└────────┴──────────────────┴─────────────────┴──────────────────┴──────────┘
```

Le masquage fonctionne par XOR via une **MGF** (Mask Generation Function) basée sur SHA-256 :

```
msg_masqué = message  ⊕  MGF(sel)
sel_masqué = sel      ⊕  MGF(msg_masqué)
```

Ce masquage croisé garantit :
- Chaque chiffrement d'un même message donne un résultat **différent** (grâce au sel aléatoire)
- On ne peut pas retrouver l'un sans l'autre
- Le déchiffrement est l'opération strictement inverse

L'**octet `0x00` en tête** est crucial : il garantit que l'entier `m` représenté par le bloc vérifie `m < n`, condition nécessaire au bon fonctionnement de RSA. Sans lui, `m ≥ n` environ une fois sur deux, ce qui corrompt silencieusement le déchiffrement.