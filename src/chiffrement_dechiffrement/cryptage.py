"""
Chiffrement RSA avec padding OAEP.

Le padding OAEP (Optimal Asymmetric Encryption Padding) est utilisé pour protéger contre les attaques classiques sur le RSA brut
"""

import hashlib
import os

# FONCTION INTERNE — Mask Generation Function (MGF1 / SHA-256)
def _mgf(graine: bytes, longueur: int) -> bytes:
    """
    Génère un masque pseudo-aléatoire de `longueur` octets à partir d'une `graine`, en utilisant SHA-256.
    """
    masque = b""
    for i in range((longueur + 31) // 32):
        masque += hashlib.sha256(graine + i.to_bytes(4, "big")).digest()
    return masque[:longueur]


# FONCTION PUBLIQUE — Chiffrement

def chiffrer(message: str, cle_publique: dict) -> bytes:
    """
    Chiffre un message texte avec la clé publique RSA.
    Paramètres
    message      : texte en clair (str, encodé en UTF-8)
    cle_publique : dict contenant :
                     'n' → module RSA (int)
                     'e' → exposant public (int, typiquement 65537)
    Retourne
    bytes : message chiffré, de longueur k = ceil(n.bit_length() / 8)
    """
    n, e  = cle_publique["n"], cle_publique["e"]
    k     = (n.bit_length() + 7) // 8      # taille du module en octets
    msg_b = message.encode("utf-8")
    L     = len(msg_b)
    capacite_max = k - 37
    if L > capacite_max:
        raise ValueError(f"Message trop long : {L} octets fournis, maximum {capacite_max} octets pour une clé de {n.bit_length()} bits."
        )

    # Construction du padding OAEP

    # 1. Sel aléatoire (32 octets) différent à chaque appel, ce qui garantit que deux chiffrements du même message donnent deux résultats différents.
    sel = os.urandom(32)

    # 2. Masquer le message : msg_masque = msg ⊕ MGF(sel)
    msg_masque = bytes(a ^ b for a, b in zip(msg_b, _mgf(sel, L)))

    # 3. Masquer le sel : sel_masque = sel ⊕ MGF(msg_masque)
    # Le masquage croisé rend impossible de retrouver l'un sans l'autre.
    sel_masque = bytes(a ^ b for a, b in zip(sel, _mgf(msg_masque, 32)))

    # 4. Assembler le bloc final
    # 0x00 | sel_masqué | longueur(4) | msg_masqué | zéros de rembourrage
    bloc = b"\x00" + sel_masque + L.to_bytes(4, "big") + msg_masque
    bloc = bloc.ljust(k, b"\x00")

    # RSA : c = m^e mod n
    # L'octet 0x00 garantit m < 2^((k-1)×8) < n → RSA fonctionne correctement.
    m = int.from_bytes(bloc, "big")
    c = pow(m, e, n)

    return c.to_bytes(k, "big")