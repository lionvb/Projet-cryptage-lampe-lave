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
    """
    Déchiffre un message chiffré par chiffrer() avec la clé privée RSA.
    Paramètres :
    message_chiffre : bytes produits par cryptage.chiffrer()
    cle_privee      : dict contenant :
                        'n' → module RSA (int)
                        'd' → exposant privé (int)
    Retourne
    str : le texte en clair d'origine
    """
    n, d = cle_privee["n"], cle_privee["d"]
    k    = (n.bit_length() + 7) // 8       # taille du module en octets

    # Validation de l'entrée

    if len(message_chiffre) != k:
        raise ValueError(f"Message chiffré invalide : {len(message_chiffre)} octets reçus, {k} attendus (taille du module).")
    c = int.from_bytes(message_chiffre, "big")
    if c >= n:
        raise ValueError("Message chiffré invalide : la valeur est hors du domaine RSA (c >= n).")

    # RSA inverse : m = c^d mod n 
    m    = pow(c, d, n)
    bloc = m.to_bytes(k, "big")            # reconstruction du bloc en k octets

    # Retrait du padding OAEP
    # Le bloc a la structure suivante (cf. cryptage.py) :
    # [0] = 0x00 de garde  →  ignoré
    # [1:33]  = sel masqué          (32 octets)
    # [33:37] = longueur L en clair (4 octets, big-endian)
    # [37:37+L] = message masqué    (L octets)
    # [37+L:] = zéros de rembourrage

    sel_masque = bloc[1:33]

    # Valider L AVANT d'appeler _mgf — clé critique pour éviter les
    # boucles infinies si la clé est incorrecte ou les données corrompues.
    L = int.from_bytes(bloc[33:37], "big")
    capacite_max = k - 37
    if L > capacite_max:
        raise ValueError(f"Déchiffrement invalide : longueur récupérée ({L}) incohérente (max attendu : {capacite_max}). Vérifiez que la bonne clé privée est utilisée.")

    msg_masque = bloc[37 : 37 + L]

    # Retrouver le sel : sel = sel_masque ⊕ MGF(msg_masque)
    sel = bytes(a ^ b for a, b in zip(sel_masque, _mgf(msg_masque, 32)))

    # Retrouver le message : msg = msg_masque ⊕ MGF(sel)
    msg_b = bytes(a ^ b for a, b in zip(msg_masque, _mgf(sel, L)))

    #  Décodage UTF-8
    try:
        return msg_b.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Impossible de décoder le message en UTF-8 : "
            "données corrompues ou clé privée incorrecte."
        )