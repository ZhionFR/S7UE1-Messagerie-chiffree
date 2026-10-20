# S7UE1-Messagerie-chiffree

Ce repo contient du projet de cryptographie d'octobre 2026.

# Cahier des charges

## Description
Alice et Bob communiquent de manière chiffrée
Eve voit les paquets mais ne peut pas lire les messages

## Processus
Bob génère sa paire de clés RSA et publie la clé publique

Alice génère une clé AES et HMAC (aléatoire)
Alice chiffre les deux clés en RSA-OAEP avec la clé de Bob
Alice chiffre le message en AES-256-CBC avec un IV neuf
Alice calcule le HMAC-SHA256 de l'IV + message chiffré

Alice transmets à Bob {clés chiffrées, IV, message chiffré, HMAC}

Bob déchiffre les clés avec sa clé privée
Bob vérifier le HMAC et rejette le paquet s'il est faux
Bob déchiffre le message

## Specs
- RSA transporte les clés
- AES chiffre le message
- HMAC pour l'intégrité
- Python3 + librairie `cryptography`

## Architecture

messagerie/
- crypto_utils.py
- rsa_utils.py
- messenger.py
- main.py
- README.md

### Fichiers
crypto_utils.py
- aes_cbc_encrypt(plaintext, aes_key) -> (iv, ciphertext)
- aes_cbc_decrypt(iv, ciphertext, aes_key) -> plaintext
- compute_hmac(hmac_key, data) -> 32 octets
- verify_hmac(hmac_key, data, mac) -> bool

rsa_utils.py
- generer_paire_rsa() -> (private_key, public_key)
- rsa_chiffrer_cle(cles, rsa_public_key) -> bytes
- rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key) -> bytes

messenger.py
- send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac} (en hex)
- recieve_message(packet, rsa_private_key) -> plaintext
- -> exception si le message est faux

main.py
- Déroule toute la séquence décrite dans [[Processus]]

# Documentation du projet

## Doc: crypto_utils

**aes_cbc_encrypt(plaintext, aes_key):**

Chiffre un str en AES-256-CBC (IV aléatoire de 16 octets, padding PKCS7). Retourne (iv, ciphertext).
-> À noter que la taille de l'iv est toujours 16 même avec une clé de 32 (AES256) car les blocs AES font TOUS 128 bits indépendament de la clé.

**aes_cbc_decrypt(iv, ciphertext, aes_key):**

Déchiffre, retire le padding et décode en UTF-8. Une seule erreur (Err04) pour padding ou UTF-8 invalide.
-> même erreur volontairement car 255/256 cas seront une erreur de padding

**compute_hmac(hmac_key, data):**

Calcule un HMAC-SHA256 (32 octets).

**verify_hmac(hmac_key, data, mac):**

Vérifie un MAC en temps constant. Retourne True ou False.
-> temps constant natif dans la librairie `cryptography` donc pas besoin de l'implémenter en plus

### TEMP : TO DELETE
**encrypt_then_mac(plaintext, aes_key, hmac_key):**

Chiffre puis calcule le MAC sur iv || ciphertext. Retourne iv || ciphertext || mac.
-> sera remplacé par des fonctions de messenger.py (mais sert aussi de prototype)

**verify_then_decrypt(blob, aes_key, hmac_key):**

Contrôle la taille, vérifie le MAC avant tout déchiffrement, puis déchiffre.
-> sera remplacé par des fonctions de messenger.py (mais sert aussi de prototype)


## Doc: rsa_utils

**generer_paire_rsa():**

Génère une paire RSA 3072 bits (exposant 65537). Retourne (private_key, public_key).

**rsa_chiffrer_cle(cles, rsa_public_key):**

Chiffre les clés (typiquement aes_key || hmac_key, 64 octets) avec OAEP-SHA256. Taille max 318 octets.
-> Les octets obligatoires sont : 1 (0x00) + hLen (seed) + hLen (lHash) + 1 (0x01) = 2·hLen + 2
-> Donc mLen_max = k - 2·hLen - 2; Pour RSA 3072 bits, SHA-256 :
```
k = 3072 / 8 = 384 octets
hLen = 32
mLen_max = 384 − 64 − 2 = 318 octets
```

**rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key):**

Déchiffre avec la clé privée. Une seule erreur (Err03) pour toute cause d’échec


## Doc: messenger

**send_message(plaintext, rsa_public_key):**

Chiffre plaintext pour le destinataire détenteur de la clé privée associée à rsa_public_key.
Desc : 
- Tire aes_key et hmac_key (32 octets chacune, os.urandom), nouvelles à chaque message.
- Chiffre le message : iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key).
- Calcule hmac = HMAC-SHA256(hmac_key, iv || ciphertext).
- Chiffre aes_key || hmac_key (64 octets) avec RSA-OAEP.
Out: Dictionnaire de chaines en hex
