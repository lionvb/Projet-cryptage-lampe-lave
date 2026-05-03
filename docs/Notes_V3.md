# V3

Cette troisième version est plus complète que la précédente : elle intègre plus de features.

## Contraintes

La troisième version du projet a pour but de réaliser un chat crypté. Il restera à déterminer les deux appareils utilisés pour le chat (deux PC, un serveur...). 

## Recherches

Nous ne savons pas encore comment implémenter cette fonctionnalité. Par conséquent, des recherches en amont devront être mises en place avant toute modification des scripts, de l'architecture, ou de la pipeline. 

Ainsi, les parties suivantes de ce document seront modifiées a posteriori. 

## Architecture

L'architecture de la première version du projet sera principalement constituée de 4 scripts :

1. Un script `setup.py` : chargé de générer 2 grands nombres à partir de la photo publique. 
2. Un script `rsa_cles.py` : chargé de générer les clés RSA à partir des 2 grands nombres.
3. Un script `cryptage.py` : chargé de crypter de la donnée à partir de la clé publique du destinataire.
4. Un script `décryptage.py` : charge de décrypter un message reçu à partir de la clé privée. 
5. Un script `main.py` : chargé d'exécuter tous les scripts depuis la racine + gestion des interruptions lors du changement de clés.

## Pipeline

Diagramme pour visualiser la pipeline de main.py :

```
image lava lamp
        ↓ image_to_bytes()
bytes brutes
        ↓ bytes_to_grands_entiers()
grands entiers (entropy seed)
        ↓ generer_cles_rsa()
clé RSA
        ↓ chiffrer()
message chiffé
        ↓ dechiffrer()
message déchiffré
```
