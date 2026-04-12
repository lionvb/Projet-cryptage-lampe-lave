"""
Déchiffrement RSA avec retrait du padding OAEP.

Il est le symétrique de cryptage.py : il attend exactement les bytes produits par chiffrer() et reconstruit le texte original.
Garanties de sécurité :
- Le message chiffré entrant est validé (taille, domaine RSA).
- La longueur L extraite du padding est bornée avant utilisation (prévient les boucles infinies si la clé est incorrecte).
- Les erreurs de déchiffrement retournent des ValueError explicites.
"""
import hashlib

# FONCTION INTERNE — Mask Generation Function (MGF1 / SHA-256)

def _mgf(graine: bytes, longueur: int) -> bytes:
    """
    Génère un masque pseudo-aléatoire de `longueur` octets à partir d'une `graine`, en utilisant SHA-256.

    Paramètres
    graine   : source du masque
    longueur : nombre d'octets à produire

    Retourne
    bytes de longueur exactement `longueur`
    """
    masque = b""
    for i in range((longueur + 31) // 32):
        masque += hashlib.sha256(graine + i.to_bytes(4, "big")).digest()
    return masque[:longueur]


# FONCTION PUBLIQUE — Déchiffrement

def dechiffrer(message_chiffre: bytes, cle_privee: dict) -> str:
    n, d = cle_privee["n"], cle_privee["d"]
    k    = (n.bit_length() + 7) // 8

    # Lire le préfixe : nombre de blocs
    nb_blocs = int.from_bytes(message_chiffre[:4], "big")
    blocs_chiffres = [
        message_chiffre[4 + i * k : 4 + (i + 1) * k]
        for i in range(nb_blocs)
    ]

    blocs_dechiffres = []
    for bloc_chiffre in blocs_chiffres:

        # Validation
        if len(bloc_chiffre) != k:
            raise ValueError(f"Bloc invalide : {len(bloc_chiffre)} octets reçus, {k} attendus.")
        c = int.from_bytes(bloc_chiffre, "big")
        if c >= n:
            raise ValueError("Bloc invalide : valeur hors du domaine RSA (c >= n).")

        # RSA inverse : m = c^d mod n
        m    = pow(c, d, n)
        bloc = m.to_bytes(k, "big")

        # Retrait du padding OAEP
        sel_masque = bloc[1:33]
        L          = int.from_bytes(bloc[33:37], "big")
        capacite_max = k - 37
        if L > capacite_max:
            raise ValueError(f"Longueur récupérée ({L}) incohérente (max : {capacite_max}).")

        msg_masque = bloc[37 : 37 + L]
        sel        = bytes(a ^ b for a, b in zip(sel_masque, _mgf(msg_masque, 32)))
        msg_b      = bytes(a ^ b for a, b in zip(msg_masque, _mgf(sel, L)))
        blocs_dechiffres.append(msg_b)

    # Reconstruction du message complet
    try:
        return b"".join(blocs_dechiffres).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Impossible de décoder en UTF-8 : données corrompues ou mauvaise clé privée.")