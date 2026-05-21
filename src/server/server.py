"""
Serveur FastAPI — V3 du projet lava_entropy.

Lancement en localhost      : >> uvicorn src.server.server:app --reload
Lancement en réseau local   : >> uvicorn src.server.server:app --host 0.0.0.0 --port 8000
"""
import json
import threading

import cv2
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from src.server.number_generator.setup import images_to_bytes


async def envoyer_erreur(ws: WebSocket, raison: str, to: str | None = None) -> None:
    """Envoie un message d'erreur structuré à un client WS."""
    payload = {"type": "error", "reason": raison}
    if to is not None:
        payload["to"] = to
    await ws.send_text(json.dumps(payload))


app = FastAPI(title="lava_entropy — serveur V3")

utilisateurs:   set[str]            = set()
cles_publiques: dict[str, dict]     = {}
connexions:     dict[str, WebSocket] = {}

# Garde la dernière frame capturée pour l'affichage continu
_derniere_frame = None
_lock_frame = threading.Lock()


# ── Schémas Pydantic ─────────────────────────────────────────────────────────

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


# ── Affichage de la frame sur le serveur ─────────────────────────────────────

def _afficher_frame(frame, username: str) -> None:
    """
    Affiche la frame capturée dans une fenêtre OpenCV sur l'écran du serveur.

    L'affichage est délégué à un thread séparé pour ne pas bloquer
    la réponse HTTP (cv2.waitKey est bloquant).

    La fenêtre se ferme automatiquement après 3 secondes, ou immédiatement
    si l'utilisateur appuie sur une touche.
    """
    def _show():
        titre = f"Seed capturée — demande de : {username}"
        cv2.imshow(titre, frame)
        cv2.waitKey(3000)   # 3 secondes puis fermeture automatique
        cv2.destroyWindow(titre)

    thread = threading.Thread(target=_show, daemon=True)
    thread.start()


# ── Capture webcam + seed ─────────────────────────────────────────────────────

def capturer_photo_webcam(username: str) -> bytes:
    """
    Capture une frame depuis la webcam du serveur.

    - Affiche la frame dans une fenêtre OpenCV (3 s) pour que l'opérateur
      du serveur voie quelle image a servi à générer la seed.
    - Retourne le hash SHA-512 (64 octets) produit par images_to_bytes().

    Lève HTTP 503 si la webcam est indisponible ou ne répond pas.
    """
    global _derniere_frame

    camera = cv2.VideoCapture(0)
    if not camera.isOpened():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webcam indisponible.",
        )
    try:
        ok, frame = camera.read()
        if not ok or frame is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Impossible de lire un frame depuis la webcam.",
            )

        # Sauvegarder la frame et l'afficher sur l'écran du serveur
        with _lock_frame:
            _derniere_frame = frame.copy()

        _afficher_frame(frame, username)

        # Générer la seed depuis la frame
        return images_to_bytes(frame)

    finally:
        camera.release()

@app.get("/seed", response_model=ReponseSeed)
def obtenir_seed(user: str = "inconnu") -> ReponseSeed:
    """
    Capture une photo via la webcam du serveur et renvoie la seed en hex.

    Passer le paramètre ?user=<username> pour identifier la demande
    dans la fenêtre d'affichage.

    Exemple : GET /seed?user=alice
    """
    seed = capturer_photo_webcam(username=user).hex()
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

@app.websocket("/chat")
async def chat(websocket: WebSocket):
    """
    WebSocket du chat chiffré (étape 4b — connexion + routage).

    Le client doit fournir son username via la query string :
        ws://localhost:8000/chat?user=alice

    Format des messages JSON acceptés (client -> serveur) :
    - {"type": "aes_key", "to": "<username>", "payload": "<b64>"}
        Handshake initial : clé AES de session chiffrée RSA pour le destinataire.
    - {"type": "message", "to": "<username>", "nonce": "<b64>", "ciphertext": "<b64>", "tag": "<b64>"}
        Message chiffré AES-GCM.

    Le serveur enrichit le message d'un champ `from` (et retire `to`)
    avant de le transmettre au destinataire. Si le destinataire est offline
    ou si le message est mal formé, un message d'erreur est renvoyé à
    l'expéditeur sans rompre la connexion.
    """
    username = websocket.query_params.get("user")
    await websocket.accept()

    if not username:
        await websocket.close(code=1008, reason="username_manquant")
        return
    if username not in utilisateurs:
        await websocket.close(code=1008, reason="username_inconnu")
        return
    if username in connexions:
        await websocket.close(code=1008, reason="deja_connecte")
        return

    connexions[username] = websocket
    try:
        while True:
            raw = await websocket.receive_text()

            # Parsing JSON
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await envoyer_erreur(websocket, "json_invalide")
                continue
            if not isinstance(message, dict):
                await envoyer_erreur(websocket, "format_invalide")
                continue

            # Validation : type connu
            type_msg = message.get("type")
            if type_msg not in ("aes_key", "message"):
                await envoyer_erreur(websocket, "type_inconnu")
                continue

            # Validation : destinataire renseigné
            destinataire = message.get("to")
            if not isinstance(destinataire, str) or not destinataire:
                await envoyer_erreur(websocket, "to_manquant")
                continue

            # Vérification : destinataire connecté ?
            ws_dest = connexions.get(destinataire)
            if ws_dest is None:
                await envoyer_erreur(websocket, "recipient_offline", to=destinataire)
                continue

            # Routage : on remplace `to` par `from` (le destinataire sait
            # déjà qu'il est `to`, ce qui l'intéresse c'est l'expéditeur).
            message_relaye = {k: v for k, v in message.items() if k != "to"}
            message_relaye["from"] = username

            await ws_dest.send_text(json.dumps(message_relaye))

    except WebSocketDisconnect:
        pass
    finally:
        connexions.pop(username, None)