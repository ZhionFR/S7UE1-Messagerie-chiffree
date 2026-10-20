# S7UE1-Messagerie-chiffree

Ce repo contient du projet de cryptographie d'octobre 2026.

- [Cahier des charges](#cahier-des-charges)
  - [Description](#description)
  - [Processus](#processus)
  - [Specs](#specs)
  - [Architecture](#architecture)
    - [Fichiers](#fichiers)
- [Documentation du projet](#documentation-du-projet)
  - [Doc: crypto_utils](#doc-crypto_utils)
    - [aes_cbc_encrypt](#aes_cbc_encrypt)
    - [aes_cbc_decrypt](#aes_cbc_decrypt)
    - [compute_hmac](#compute_hmac)
    - [verify_hmac](#verify_hmac)
  - [Doc: rsa_utils](#doc-rsa_utils)
    - [generer_paire_rsa](#generer_paire_rsa)
    - [rsa_chiffrer_cle](#rsa_chiffrer_cle)
    - [rsa_dechiffrer_cle](#rsa_dechiffrer_cle)
  - [Doc: messenger](#doc-messenger)
    - [send_message](#send_message)
    - [receive_message](#receive_message)
- [Tests & erreurs](#tests--erreurs)
    - [Tests](#tests)
    - [Codes d'erreurs](#codes-derreur)


# Cahier des charges

## Description

Alice et Bob communiquent de manière chiffrée.

Eve voit les paquets mais ne peut pas lire les messages.

## Processus

Bob génère sa paire de clés RSA et publie la clé publique.

Alice :

1. Génère une clé AES et HMAC (aléatoire)
2. Chiffre les deux clés en RSA-OAEP avec la clé de Bob
3. Chiffre le message en AES-256-CBC avec un IV neuf
4. Calcule le HMAC-SHA256 de l'IV + message chiffré
5. Transmet à Bob {clés chiffrées, IV, message chiffré, HMAC}

Bob :

1. Déchiffre les clés avec sa clé privée
2. Vérifie le HMAC et rejette le paquet s'il est faux
3. Déchiffre le message

## Specs

- RSA transporte les clés
- AES chiffre le message
- HMAC pour l'intégrité
- Python3 + librairie `cryptography`

## Architecture

```
messagerie/
├── crypto_utils.py
├── rsa_utils.py
├── messenger.py
├── main.py
└── README.md
```

### Fichiers

**`crypto_utils.py`**

- `aes_cbc_encrypt(plaintext, aes_key) -> (iv, ciphertext)`
- `aes_cbc_decrypt(iv, ciphertext, aes_key) -> plaintext`
- `compute_hmac(hmac_key, data) -> 32 octets`
- `verify_hmac(hmac_key, data, mac) -> bool`

**`rsa_utils.py`**

- `generer_paire_rsa() -> (private_key, public_key)`
- `rsa_chiffrer_cle(cles, rsa_public_key) -> bytes`
- `rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key) -> bytes`

**`messenger.py`**

- `send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac}` (en hex)
- `receive_message(packet, rsa_private_key) -> plaintext`
- Lève une exception si le message est faux

**`main.py`**

- Déroule toute la séquence décrite dans [Processus](#processus)

# Documentation du projet

## Doc: crypto_utils

#### aes_cbc_encrypt

`aes_cbc_encrypt(plaintext, aes_key)`

Chiffre un str en AES-256-CBC (IV aléatoire de 16 octets, padding PKCS7). Retourne `(iv, ciphertext)`.

> À noter que la taille de l'IV est toujours 16 même avec une clé de 32 (AES-256) car les blocs AES font TOUS 128 bits indépendamment de la clé.

#### aes_cbc_decrypt

`aes_cbc_decrypt(iv, ciphertext, aes_key)`

Déchiffre, retire le padding et décode en UTF-8. Une seule erreur (Err04) pour padding ou UTF-8 invalide.

> Même erreur volontairement car 255/256 cas seront une erreur de padding.

#### compute_hmac

`compute_hmac(hmac_key, data)`

Calcule un HMAC-SHA256 (32 octets).

#### verify_hmac

`verify_hmac(hmac_key, data, mac)`

Vérifie un MAC en temps constant. Retourne `True` ou `False`.

> Temps constant natif dans la librairie `cryptography` donc pas besoin de l'implémenter en plus.

## Doc: rsa_utils

#### generer_paire_rsa

`generer_paire_rsa()`

Génère une paire RSA 3072 bits (exposant 65537). Retourne `(private_key, public_key)`.

#### rsa_chiffrer_cle

`rsa_chiffrer_cle(cles, rsa_public_key)`

Chiffre les clés (typiquement `aes_key || hmac_key`, 64 octets) avec OAEP-SHA256. Taille max 318 octets.

> Les octets obligatoires sont : 1 (0x00) + hLen (seed) + hLen (lHash) + 1 (0x01) = 2·hLen + 2.
> Donc mLen_max = k - 2·hLen - 2. Pour RSA 3072 bits, SHA-256 :

```
k = 3072 / 8 = 384 octets
hLen = 32
mLen_max = 384 − 64 − 2 = 318 octets
```

#### rsa_dechiffrer_cle

`rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key)`

Déchiffre avec la clé privée. Une seule erreur (Err03) pour toute cause d'échec.

## Doc: messenger

#### send_message

`send_message(plaintext, rsa_public_key)`

Chiffre `plaintext` pour le destinataire détenteur de la clé privée associée à `rsa_public_key`.

Description :

- Tire `aes_key` et `hmac_key` (32 octets chacune, `os.urandom`), nouvelles à chaque message.
- Chiffre le message : `iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key)`.
- Calcule `hmac = HMAC-SHA256(hmac_key, iv || ciphertext)`.
- Chiffre `aes_key || hmac_key` (64 octets) avec RSA-OAEP.

Sortie : dictionnaire de chaînes en hex.

#### receive_message

`receive_message(packet, rsa_private_key)`

Vérifie et déchiffre un paquet produit par `send_message`.

Description :

- Décode les 4 champs hex.
- Déchiffre `cles_chiffrees` avec la clé privée RSA.
- Sépare AES (32 premiers octets) et HMAC (32 suivants).
- Vérifie le MAC en temps constant, *avant* tout déchiffrement AES.
- Déchiffre en AES-CBC, retire le padding, décode en UTF-8 (voir [aes_cbc_decrypt](#aes_cbc_decrypt)).

Sortie : le message en clair (sauf s'il a été modifié).



# Tests & Erreurs

## Tests

test.py est autoporteur : lancer `python test.py` teste et renvoie les résultats pour chaque fonction des autres modules (PASS ou FAIL, ERROR si erreur inattendue)


## Codes d'erreur

| Module | Code | Signification |
|---|---|---|
| crypto_utils | Err01 | Taille de clé AES ≠ 32 octets |
| crypto_utils | Err02 | Taille d'IV ≠ 16 octets |
| crypto_utils | Err03 | Chiffré vide ou non multiple de 16 |
| crypto_utils | Err04 | Déchiffrement échoué (padding ou UTF-8) |
| crypto_utils | Err05 | Taille de clé HMAC ≠ 32 octets |
| rsa_utils | Err01 | Clés à chiffrer : taille hors de 1 à 318 octets |
| rsa_utils | Err02 | Chiffré RSA de taille ≠ k octets |
| rsa_utils | Err03 | Déchiffrement RSA échoué |
| messenger | Err01 | Paquet mal formé |
| messenger | Err02 | Clés déchiffrées ≠ 64 octets |
| messenger | Err03 | MAC invalide |
