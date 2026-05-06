"""
Serveur FastAPI — V3 du projet lava_entropy.

Étape 1 : squelette minimal.
Permet uniquement de valider que la stack ASGI tourne.

Lancement depuis la racine du projet :
    uvicorn src.server.server:app --reload
"""

import os

from fastapi import FastAPI, HTTPException, WebSocket, status
from pydantic import BaseModel, Field

from src.server.number_generator.setup import images_to_bytes

app = FastAPI(title="lava_entropy — serveur V3")

# Ensemble des usernames enregistrés via POST /register.
utilisateurs: set[str] = set()

# Clés publiques RSA des utilisateurs
cles_publiques: dict[str, dict] = {}

# Connexions WebSocket actives : 
connexions: dict[str, WebSocket] = {}


# ---------------------------------------------------------------------------
# Schémas Pydantic
# ---------------------------------------------------------------------------
# Pydantic valide automatiquement les corps de requête/réponse et alimente
# la doc Swagger générée par FastAPI sur /docs.

class DemandeInscription(BaseModel):
    """Corps de requête de POST /register."""
    username: str = Field(min_length=1, max_length=32)


class ReponseInscription(BaseModel):
    """Réponse de POST /register."""
    username: str
    status: str


class ReponseSeed(BaseModel):
    """Réponse de GET /seed : seed d'entropie en hexadécimal."""
    seed: str

class DemandeCleePublique(BaseModel):
    """Corps de requête de POST /publickey."""
    username: str = Field(min_length=1, max_length=32)
    n: int = Field(gt=0)
    e: int = Field(gt=0)


class ReponseCleePublique(BaseModel):
    """Réponse de POST /publickey."""
    username: str
    status: str

class CleePublique(BaseModel):
    """Réponse de GET /publickey/{username} : clé publique RSA d'un utilisateur."""
    username: str
    n: int
    e: int

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def racine():
    """Endpoint de santé : vérifie simplement que le serveur répond."""
    return {"status": "ok"}


@app.post(
    "/register",
    response_model=ReponseInscription,
    status_code=status.HTTP_201_CREATED,
)
def inscrire(demande: DemandeInscription) -> ReponseInscription:
    """
    Enregistre un nouvel utilisateur.

    - 201 Created : username libre, inscription effectuée.
    - 409 Conflict : username déjà pris.
    - 422 Unprocessable Entity : validation Pydantic échouée (auto par FastAPI).
    """
    if demande.username in utilisateurs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{demande.username}' déjà utilisé.",
        )

    utilisateurs.add(demande.username)
    return ReponseInscription(username=demande.username, status="registered")

PHOTO_PATH = os.path.join(os.path.dirname(__file__), "Pictures")
@app.get("/seed", response_model=ReponseSeed)
def obtenir_seed() -> ReponseSeed:
    """
    Renvoie une seed d'entropie de 64 octets (512 bits) en hexadécimal.
    """
    # Génération des clés RSA
    seed = images_to_bytes(PHOTO_PATH).hex()
    return ReponseSeed(seed=seed)

@app.post(
    "/publickey",
    response_model=ReponseCleePublique,
    status_code=status.HTTP_201_CREATED,
)
def publier_cle_publique(demande: DemandeCleePublique) -> ReponseCleePublique:
    """
    Publie la clé publique RSA d'un utilisateur déjà enregistré.

    - 201 Created : clé publiée (écrase la précédente si elle existait,
      pour permettre la rotation à chaque nouvelle session).
    - 404 Not Found : username inconnu (l'utilisateur doit d'abord
      passer par POST /register).
    - 422 Unprocessable Entity : validation Pydantic échouée
      (auto par FastAPI, par exemple si n ou e sont absents ou ≤ 0).
    """
    if demande.username not in utilisateurs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Username '{demande.username}' non enregistré.",
        )

    cles_publiques[demande.username] = {"n": demande.n, "e": demande.e}
    return ReponseCleePublique(username=demande.username, status="key_published")

@app.get(
    "/publickey/{username}",
    response_model=CleePublique,
)
def recuperer_cle_publique(username: str) -> CleePublique:
    """
    Récupère la clé publique RSA d'un utilisateur.

    - 200 OK : la clé est renvoyée.
    - 404 Not Found : aucune clé publiée pour ce username
      (soit il n'existe pas, soit il ne s'est pas encore enregistré
      côté /publickey).
    """
    if username not in cles_publiques:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Aucune clé publique trouvée pour '{username}'.",
        )

    cle = cles_publiques[username]
    return CleePublique(username=username, n=cle["n"], e=cle["e"])