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


@app.get("/seed", response_model=ReponseSeed)

def obtenir_seed() -> ReponseSeed:
    """
    Renvoie une seed d'entropie de 64 octets (512 bits) en hexadécimal.
    AFAIRE : remplacer os.urandom par la génération d'entropie physique
    """
    seed = os.urandom(64).hex()
    return ReponseSeed(seed=seed)
