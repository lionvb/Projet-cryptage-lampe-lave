"""
Génération des nombres premiers et des clés RSA.
"""
import math

# TEST DE PRIMALITÉ — Miller-Rabin
def est_premier(n: int) -> bool:
    """
    Test de primalité déterministe Miller-Rabin.
    Utilise des témoins fixes qui couvrent sans faux positif tous les entiers jusqu'à 3.3 × 10²⁴.
    """
    if n < 2:
        return False

    petits_premiers = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    # Cas trivial : n est l'un des petits témoins
    if n in petits_premiers:
        return True

    # Divisibilité rapide par les petits premiers
    if any(n % p == 0 for p in petits_premiers):
        return False

    # Décomposer n - 1 = 2^r × d (avec d impair)
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test de Miller-Rabin avec chaque témoin
    for a in petits_premiers:
        if a >= n:
            continue

        x = pow(a, d, n)            # a^d mod n

        if x in (1, n - 1):
            continue                # témoin "passé", continuer

        for _ in range(r - 1):
            x = pow(x, 2, n)       # x² mod n
            if x == n - 1:
                break
        else:
            return False            # n est n'est pas premier avec certitude

    return True                     # n est (très probablement) premier

# RECHERCHE DU PROCHAIN NOMBRE PREMIER

def prochain_premier(n: int) -> int:
    """
    Transforme un nombre aléatoire quelconque (issu de la source
    d'entropie externe) en un nombre premier utilisable pour RSA.
    """
    candidat = abs(n) | 1       # valeur absolue et forcer impair (avec | opérateur OU binaire)
    while not est_premier(candidat):
        candidat += 2
    return candidat

# GÉNÉRATION DE LA PAIRE DE CLÉS RSA

def generer_cles_rsa(nb_alea_1: int,nb_alea_2: int) -> tuple:
    """
    Génère une paire de clés RSA à partir de deux grands entiers aléatoires.

    Paramètres :
    nb_alea_1 : grand entier aléatoire
    nb_alea_2 : grand entier aléatoire différent du premier

    Retourne
    cle_publique : dict { 'n': int, 'e': int }
    cle_privee   : dict { 'n': int, 'd': int }

    Schéma RSA : 
    n    = p × q             module public  (connu de tous)
    φ(n) = (p−1)(q−1)        indicatrice d'Euler  (secret)
    e    = 65537             exposant public  (standard)
    d    = e⁻¹ mod φ(n)      exposant privé  (secret absolu)
    """
    # Étape 1 : Construire deux grands nombres premiers à partir des aléas
    p = prochain_premier(nb_alea_1)
    q = prochain_premier(nb_alea_2)

    # p et q doivent être différents (sinon n = p² est factorisable facilement)
    if p == q:
        q = prochain_premier(q + 2)

    # Étape 2 : Module RSA et indicatrice d'Euler
    n     = p * q
    phi_n = (p - 1) * (q - 1)

    # Étape 3 : Exposant public e = 65537 (= 2¹⁶ + 1 : petit, premier, standard)
    e = 65537
    if math.gcd(e, phi_n) != 1:
        raise ValueError("e=65537 n'est pas copremier avec φ(n).Changez les nombres aléatoires sources.")

    # Étape 4 : Exposant privé d = e⁻¹ mod φ(n) 
    d = pow(e, -1, phi_n)

    cle_publique = {"n": n, "e": e}
    cle_privee   = {"n": n, "d": d}
    return cle_publique, cle_privee