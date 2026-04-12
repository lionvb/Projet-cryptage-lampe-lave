# V1

## Contraintes

La première version du projet sera la version la plus simplifiée : le but étant de faire fonctionner avant de faire beau, nous commencerons avec les contraintes suivantes (volontairement les plus simples possibles) : 

1. La source d'entropie sera une photo de lampe à lave téléchargée en ligne.
2. Le scriptage sera réalisé en Python.
3. Le stockage de la data sera fait en local sur nos machines.
4. Les images seront en noir et blanc pour réduire la taille des clés.
5. Les données cryptées seront simplement du texte.

## Architecture

L'architecture de la première version du projet sera principalement constituée de 4 scripts :

1. Un script `setup.py` : chargé de créer les clés privées et publiques à partir de la photo publique. 
2. Un script `cryptage.py` : chargé de crypter de la donnée à partir de la clé publique du destinataire.
3. Un script `décryptage.py` : charge de décrypter un message reçu à partir de la clé privée. 
4. UN script `main.py` : chargé d'exécuter tous les scripts depuis la racine + gestion des interruptions lors du changement de clés.

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
