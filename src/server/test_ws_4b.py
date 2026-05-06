"""
Tests manuels de l'étape 4b — routage des messages sur WS /chat.

À lancer pendant que `uvicorn` tourne :
    python test_ws_4b.py

Prérequis :
    pip install websockets httpx
"""

import asyncio
import json

import httpx
import websockets

BASE_HTTP = "http://localhost:8000"
BASE_WS = "ws://localhost:8000"


async def enregistrer(username: str) -> None:
    """Inscrit un username via POST /register, idempotent."""
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{BASE_HTTP}/register", json={"username": username})
        if r.status_code not in (201, 409):
            r.raise_for_status()


async def lire_message(ws, timeout: float = 0.5):
    """Lit un message JSON dans la WS, ou None si rien n'arrive avant `timeout` secondes."""
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        return json.loads(raw)
    except asyncio.TimeoutError:
        return None


def verifier(label: str, recu, attendu) -> None:
    """Affiche un OK/KO selon que le message reçu correspond à l'attendu."""
    if recu == attendu:
        print(f"  [OK] {label}")
    else:
        print(f"  [KO] {label}")
        print(f"       attendu : {attendu}")
        print(f"       reçu    : {recu}")


async def main() -> None:
    await enregistrer("alice")
    await enregistrer("bob")

    async with (
        websockets.connect(f"{BASE_WS}/chat?user=alice") as alice,
        websockets.connect(f"{BASE_WS}/chat?user=bob") as bob,
    ):
        # ----------------------------------------------------------------
        print("\n--- 1. aes_key valide alice -> bob ---")
        await alice.send(json.dumps({
            "type": "aes_key", "to": "bob", "payload": "AAAA=="
        }))
        verifier(
            "bob reçoit le aes_key avec from=alice",
            await lire_message(bob),
            {"type": "aes_key", "from": "alice", "payload": "AAAA=="},
        )

        # ----------------------------------------------------------------
        print("\n--- 2. message valide alice -> bob ---")
        await alice.send(json.dumps({
            "type": "message", "to": "bob",
            "nonce": "BBBB==", "ciphertext": "CCCC==", "tag": "DDDD==",
        }))
        verifier(
            "bob reçoit le message chiffré avec from=alice",
            await lire_message(bob),
            {
                "type": "message", "from": "alice",
                "nonce": "BBBB==", "ciphertext": "CCCC==", "tag": "DDDD==",
            },
        )

        # ----------------------------------------------------------------
        print("\n--- 3. message vers destinataire non connecté ---")
        await alice.send(json.dumps({
            "type": "message", "to": "charlie",
            "nonce": "x", "ciphertext": "y", "tag": "z",
        }))
        verifier(
            "alice reçoit recipient_offline",
            await lire_message(alice),
            {"type": "error", "reason": "recipient_offline", "to": "charlie"},
        )

        # ----------------------------------------------------------------
        print("\n--- 4. JSON invalide ---")
        await alice.send("pas du tout du json")
        verifier(
            "alice reçoit json_invalide",
            await lire_message(alice),
            {"type": "error", "reason": "json_invalide"},
        )

        # ----------------------------------------------------------------
        print("\n--- 5. type de message inconnu ---")
        await alice.send(json.dumps({"type": "salut", "to": "bob"}))
        verifier(
            "alice reçoit type_inconnu",
            await lire_message(alice),
            {"type": "error", "reason": "type_inconnu"},
        )

        # ----------------------------------------------------------------
        print("\n--- 6. champ to manquant ---")
        await alice.send(json.dumps({"type": "message"}))
        verifier(
            "alice reçoit to_manquant",
            await lire_message(alice),
            {"type": "error", "reason": "to_manquant"},
        )

        # ----------------------------------------------------------------
        print("\n--- 7. la connexion d'alice survit aux erreurs ---")
        await alice.send(json.dumps({
            "type": "message", "to": "bob",
            "nonce": "1", "ciphertext": "2", "tag": "3",
        }))
        verifier(
            "bob reçoit toujours après les erreurs",
            await lire_message(bob),
            {
                "type": "message", "from": "alice",
                "nonce": "1", "ciphertext": "2", "tag": "3",
            },
        )


if __name__ == "__main__":
    asyncio.run(main())