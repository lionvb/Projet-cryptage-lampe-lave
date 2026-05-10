# V3

Cette troisième version est plus complète que la précédente : elle intègre plus de features.

## Contraintes

La troisième version du projet a pour but de réaliser un chat crypté. Deux utilisateurs pourrons donc échanger via un chat sécurisé par notre techno lavalamp. Un serveur servira d'oracle d'entropie, relais des messages et registre de clé publiques. 


## Architecture

1. Serveur central :
- génération de l'entropie
- registre de clés publiques
- relais des messages chiffrés

2. Machine client :
- création des clés 
- chiffrement et déchiffrement des messages

## Pipeline

Phase 1 — Génération des clés (au démarrage) 
        Le client contacte le serveur pour récupérer de l'entropie lavalamp via GET /entropy 
        L'entropie reçue sert de seed pour générer une paire de clés RSA (via le module existant) 
        La clé publique est déposée sur le serveur via POST /register/{username} 

Phase 2 — Établissement de la session chiffrée 
        Alice récupère la clé publique RSA de Bob via GET /pubkey/bob 
        Alice génère une clé AES-256 (clé de session) et la chiffre avec la clé publique RSA de Bob 
        Alice envoie la clé AES chiffrée à Bob via le serveur (POST /session/bob) 
        Bob déchiffre la clé AES avec sa clé privée RSA — le canal est établi 

Phase 3 — Échange de messages 
        Chaque message est chiffré avec AES-GCM (clé partagée) avant envoi 
        Le serveur relaye les messages chiffrés via WebSocket sans pouvoir les lire 
        Le destinataire déchiffre et affiche le message dans son terminal 
