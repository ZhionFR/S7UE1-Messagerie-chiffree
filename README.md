# S7UE1-Messagerie-chiffree

Ce repo contient le projet de cryptographie d'octobre 2026.

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


# Description

Alice et Bob communiquent de manière chiffrée.

Eve voit les paquets mais ne peut pas lire les messages.

## Processus

Bob génère sa paire de clés RSA et publie la clé publique.

Alice :

1. Génère une clé AES et HMAC (aléatoire)
2. Chiffre les deux clés en RSA-OAEP avec la clé de Bob
3. Chiffre le message en AES-256-CBC avec un IV neuf
4. Génère un horodatage et un nonce (16 octets aléatoires), puis calcule le HMAC-SHA256 de timestamp ‖ nonce ‖ IV ‖ message chiffré
5. Transmet à Bob {clés chiffrées, IV, message chiffré, HMAC, timestamp, nonce}

Bob :

1. Déchiffre les clés avec sa clé privée
2. Vérifie le HMAC et rejette le paquet s'il est faux
3. Rejette le paquet si le timestamp est hors de la fenêtre de 60 s ou si le nonce a déjà été vu (anti-rejeu)
4. Déchiffre le message

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
├── test.py
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

- `send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac, timestamp, nonce}` (en hex)
- `receive_message(packet, rsa_private_key, replay_cache=None, now=None) -> plaintext`
  - Lève une exception si le message n'est pas intègre
- `ReplayCache` : mémoire des nonces déjà acceptés

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

> Même erreur volontairement pour éviter l'attaque de Vaudenay.
> Aussi 255/256 cas seront une erreur de padding.


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
- Ajoute `timestamp` (secondes Unix, 8 octets big-endian) et `nonce` (16 octets, `os.urandom`).
- Calcule `hmac = HMAC-SHA256(hmac_key, timestamp || nonce || iv || ciphertext)`.
- Chiffre `aes_key || hmac_key` (64 octets) avec RSA-OAEP.

Sortie : dictionnaire de chaînes en hex.


#### receive_message

`receive_message(packet, rsa_private_key, replay_cache=None, now=None)`

Vérifie et déchiffre un paquet produit par `send_message`.

Description :

- Décodage des 6 champs hex, tailles de `timestamp` (8) et `nonce` (16) → Err01
- Déchiffre `cles_chiffrees` avec la clé privée RSA.
- Sépare AES (32 premiers octets) et HMAC (32 suivants).
- Vérifie le MAC en temps constant, *avant* tout déchiffrement AES.
- Fenêtre de temps : `|now - timestamp| <= 60 s`. Nonce absent du cache, puis ajouté
- Déchiffre en AES-CBC, retire le padding, décode en UTF-8 (voir [aes_cbc_decrypt](#aes_cbc_decrypt)).

Sortie : le message en clair.
-> la fonction lève une ValueError avec un code en cas de corruption du paquet

> Le nonce n'est enregistré qu'**après** le MAC. Avant, Eve pourrait consommer la place d'un vrai paquet en envoyant un faux paquet portant le même nonce (DoS).
> `replay_cache` : par défaut un cache partagé par le processus. `now` n'existe que pour les tests (simuler un paquet périmé sans attendre).


#### ReplayCache

Mémorise les nonces acceptés (`nonce -> timestamp`).

- `add(nonce, timestamp)`, `nonce in cache`, `len(cache)`
- `purge(now)` : oublie les nonces dont le timestamp est sorti de la fenêtre.

> Invariant : un nonce est conservé au moins aussi longtemps que son timestamp reste acceptable. Après ce délai, le paquet serait de toute façon rejeté par la fenêtre (Err04), donc la purge ne rouvre aucun rejeu et la mémoire reste bornée.


# Tests & Erreurs

## Tests

test.py est autoporteur : lancer `python test.py` teste et renvoie les résultats pour chaque groupe (`crypto_utils`, `rsa_utils`, `messenger`, `anti_rejeu`) des autres modules (PASS ou FAIL, ERROR si erreur inattendue)
Il accepte aussi `python test.py <group_name>` et `--list` (liste les groupes).

### Resultats des tests

Sortie attendue de `python test.py` :
```
[PASS] crypto_utils
[PASS] rsa_utils
[PASS] messenger
[PASS] anti_rejeu
```

| Résultat | Signification                                                    |
| -------- | ---------------------------------------------------------------- |
| `PASS`   | Toutes les assertions du groupe sont vérifiées                   |
| `FAIL`   | Une assertion a échoué (la trace est affichée)                   |
| `ERROR`  | Exception inattendue (autre qu'une assertion)                    |
| `SKIP`   | Groupe pas encore implémenté (`NotImplementedError`)             |

Le code de retour est `0` si tout passe, `1` s'il y a au moins un `FAIL` ou `ERROR`. Un nom de groupe inconnu arrête le script avec un message d'erreur (Test inconnu).

> Les tests génèrent plusieurs paires RSA 3072 bits, l'exécution n'est donc pas instantanée mais ne doit pas prendre plus de quelques secondes.


## Codes d'erreur

| Module        | Code  | Signification                                                              |
| ------------- | ----- | -------------------------------------------------------------------------- |
| crypto\_utils | Err01 | Taille de clé AES ≠ 32 octets                                              |
| crypto\_utils | Err02 | Taille d'IV ≠ 16 octets                                                    |
| crypto\_utils | Err03 | Chiffré vide ou non multiple de 16                                         |
| crypto\_utils | Err04 | Déchiffrement échoué (padding ou UTF-8)                                    |
| crypto\_utils | Err05 | Taille de clé HMAC ≠ 32 octets                                             |
| rsa\_utils    | Err01 | Clés à chiffrer : taille hors de 1 à 318 octets                            |
| rsa\_utils    | Err02 | Chiffré RSA de taille ≠ k octets                                           |
| rsa\_utils    | Err03 | Déchiffrement RSA échoué                                                   |
| messenger     | Err01 | Paquet mal formé (champ manquant, hex invalide, taille timestamp ≠ 8 ou nonce ≠ 16) |
| messenger     | Err02 | Clés déchiffrées ≠ 64 octets                                               |
| messenger     | Err03 | MAC invalide (données, timestamp ou nonce altérés)                         |
| messenger     | Err04 | Horodatage hors fenêtre (périmé ou dans le futur, écart > 60 s)            |
| messenger     | Err05 | Rejeu détecté (nonce déjà vu)                                              |
