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
    n, e  = cle_publique["n"], cle_publique["e"]
    k     = (n.bit_length() + 7) // 8
    msg_b = message.encode("utf-8")
    capacite_max = k - 37

    if capacite_max <= 0:
        raise ValueError(f"Clé trop courte : {n.bit_length()} bits. Minimum requis : ~300 bits.")

    # Découpage en blocs
    blocs = [msg_b[i:i + capacite_max] for i in range(0, len(msg_b), capacite_max)]

    blocs_chiffres = []
    for bloc_msg in blocs:
        L   = len(bloc_msg)
        sel = os.urandom(32)

        msg_masque = bytes(a ^ b for a, b in zip(bloc_msg, _mgf(sel, L)))
        sel_masque = bytes(a ^ b for a, b in zip(sel, _mgf(msg_masque, 32)))

        bloc = b"\x00" + sel_masque + L.to_bytes(4, "big") + msg_masque
        bloc = bloc.ljust(k, b"\x00")

        m = int.from_bytes(bloc, "big")
        c = pow(m, e, n)
        blocs_chiffres.append(c.to_bytes(k, "big"))

    # Préfixe : nombre de blocs (4 bytes) pour que le déchiffrement sache combien itérer
    return len(blocs_chiffres).to_bytes(4, "big") + b"".join(blocs_chiffres)