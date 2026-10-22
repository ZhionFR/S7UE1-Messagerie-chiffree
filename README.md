# S7UE1-Messagerie-chiffree

Ce repo contient le projet de cryptographie d'octobre 2026.

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
    - [rsa_signer](#rsa_signer)
    - [rsa_verifier](#rsa_verifier)
  - [Doc: messenger](#doc-messenger)
    - [send_message](#send_message)
    - [receive_message](#receive_message)
    - [sign_packet](#sign_packet)
    - [ReplayCache](#replaycache)
- [Tests & erreurs](#tests--erreurs)
  - [Tests](#tests)
    - [Résultats des tests](#resultats-des-tests)
    - [Groupes de tests](#groupes-de-tests)
      - [crypto_utils](#crypto_utils)
      - [rsa_utils](#rsa_utils)
      - [messenger](#messenger)
      - [authentification](#authentification)
      - [anti_rejeu](#anti_rejeu)
  - [Codes d'erreur](#codes-derreur)
- [Roadmap et limites](#roadmap-et-limites)


# Description

Alice et Bob communiquent de manière **chiffrée** et **authentifiée**.

Eve voit les paquets mais ne peut pas **lire** les messages, ni en **fabriquer** un au nom d'Alice.

## Processus

Bob génère sa paire de clés RSA et publie la clé publique.
Alice génère sa propre paire RSA (signature) et publie sa clé publique.

Alice :

1. Génère une clé AES et HMAC (aléatoire)
2. Chiffre les deux clés en RSA-OAEP avec la clé de Bob
3. Chiffre le message en AES-256-CBC avec un IV neuf
4. Génère un horodatage et un nonce (16 octets aléatoires), puis calcule le HMAC-SHA256 de timestamp ‖ nonce ‖ IV ‖ message chiffré
5. Signe (RSA-PSS SHA-256, clé privée d'Alice) clés chiffrées ‖ timestamp ‖ nonce ‖ IV ‖ HMAC ‖ message chiffré
6. Transmet à Bob {clés chiffrées, IV, message chiffré, HMAC, timestamp, nonce, signature}

Bob :

1. Vérifie la signature d'Alice et rejette le paquet si elle est fausse (avant tout déchiffrement)
2. Déchiffre les clés avec sa clé privée
3. Vérifie le HMAC et rejette le paquet s'il est faux
4. Rejette le paquet si le timestamp est hors de la fenêtre de 60 s ou si le nonce a déjà été vu (anti-rejeu)
5. Déchiffre le message

## Specs

- RSA transporte les clés
- AES chiffre le message
- HMAC pour l'intégrité
- Signature RSA-PSS pour l'authenticité de l'expéditeur
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
- `rsa_signer(data, rsa_private_key) -> bytes`
- `rsa_verifier(data, signature, rsa_public_key) -> bool`

**`messenger.py`**

- `send_message(plaintext, rsa_public_key, sender_private_key) -> {cles_chiffrees, iv, ciphertext, hmac, timestamp, nonce, signature}` (en hex)
- `receive_message(packet, rsa_private_key, sender_public_key, replay_cache=None, now=None) -> plaintext`
  - Lève une exception si le message n'est pas intègre ou pas authentique
- `sign_packet(packet, sender_private_key) -> packet` : (re)calcule le champ `signature` d'un paquet
- `ReplayCache` : mémoire des nonces déjà acceptés

**`main.py`**

- Déroule toute la séquence décrite dans [Processus](#processus)

Exemple d'output attendu : 

```
$python main.py

---------- Partie 1 : déroulé étape par étape (fonctions de bas niveau) ----------

=== Bob ===
Bob a généré sa paire RSA 3072 bits et publie sa clé publique.

=== Alice ===
Alice a généré sa paire RSA 3072 bits de signature et publie sa clé publique.
Clés AES et HMAC générées (32 octets chacune).
Clés chiffrées en RSA-OAEP : 384 octets.
Message chiffré : IV 16 octets, chiffré 48 octets.
Horodatage (8 octets) et nonce (16 octets) générés.
HMAC-SHA256 : d1297f88aa0f9be21c6b92c30dd0652ffa78293548325f97c493c5e7104bb408
Signature RSA-PSS : 384 octets.

=== Eve (ce qui circule sur le réseau) ===
cles_chiffrees  9fda66f308a6e89fe43bea2d70eee5a2587ef5673c8b94e7...
iv              55ab7f3bad2e2f6156330d5dcc3b67c3
ciphertext      1e056a4658bf6face33a18c6a101849d8547fc2db7c10d73...
hmac            d1297f88aa0f9be21c6b92c30dd0652ffa78293548325f97...
timestamp       000000006ad9c4c5
nonce           50525b1fb2712b9df9a9e33d1180ac2b
signature       293838d32194fe5a83a3d358ff1cab97a6e0bc970adc44fe...

=== Bob ===
Signature d'Alice valide.
HMAC valide.
Horodatage et nonce valides.
Message déchiffré : Salut Bob, ce message est secret !! Alice.

---------- Partie 2 : même échange via messenger.py ----------

=== Même échange via send_message / receive_message ===
Aller-retour OK.

---------- Partie 3 : Eve modifie le paquet ----------

=== Eve altère le chiffré ===
Paquet rejeté par Bob avec l'erreur "messenger : Err06"

---------- Partie 4 : Eve rejoue un paquet valide ----------

=== Eve rejoue un paquet intercepté ===
Premier envoi accepté par Bob.
Rejeu rejeté par Bob avec l'erreur "messenger : Err05"
Nonce modifié rejeté par Bob avec l'erreur "messenger : Err06"
Horodatage modifié rejeté par Bob avec l'erreur "messenger : Err06"
Paquet périmé rejeté par Bob avec l'erreur "messenger : Err04"

---------- Partie 5 : Eve usurpe Alice ou tente de « brûler » un nonce ----------

=== Eve usurpe l'identité d'Alice ===
Paquet forgé (signé par Eve) rejeté par Bob avec l'erreur "messenger : Err06"

=== Eve tente de faire rejeter le vrai paquet d'Alice ===
Paquet piégé (clés d'Eve, MAC valide, signature d'Alice recopiée) rejeté par Bob avec l'erreur "messenger : Err06"
Le vrai paquet d'Alice est ensuite accepté : le nonce n'a pas été consommé.
```

Les limites connues et les évolutions possibles sont listées dans la section [Roadmap et limites](#roadmap-et-limites).


# Documentation du projet

## Doc: crypto_utils

#### aes_cbc_encrypt

`aes_cbc_encrypt(plaintext, aes_key)`

Chiffre un str en AES-256-CBC (IV aléatoire de 16 octets, padding PKCS7). Retourne `(iv, ciphertext)`.

> À noter que la taille de l'IV est toujours 16 même avec une clé de 32 (AES-256) car les blocs AES font TOUS 128 bits indépendamment de la clé.

#### aes_cbc_decrypt

`aes_cbc_decrypt(iv, ciphertext, aes_key)`

Déchiffre, retire le padding et décode en UTF-8. Une seule erreur (Err04) pour padding ou UTF-8 invalide.

> Même erreur volontairement sinon, l'erreur UTF-8 n'apparaîtrait que si le padding est valide (environ 1/256 cas), ce qui constituerait un oracle de padding (attaque de Vaudenay)
> C'est une défense en profondeur. La protection effective est le MAC vérifié *avant* tout déchiffrement (Encrypt-then-MAC, voir [receive_message](#receive_message))


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

#### rsa_signer

`rsa_signer(data, rsa_private_key)`

Signe `data` avec RSA-PSS (MGF1-SHA256, hash SHA-256, sel de 32 octets). Retourne la signature (384 octets pour RSA 3072 bits).

> PSS est probabiliste (sel aléatoire) : deux signatures du même message diffèrent, et sont toutes deux valides.
> PSS est préféré à PKCS#1 v1.5, qui n'a pas de preuve de sécurité aussi solide.

#### rsa_verifier

`rsa_verifier(data, signature, rsa_public_key)`

Vérifie la signature RSA-PSS. Retourne `True` ou `False` (ne lève pas d'exception pour une signature invalide, de mauvaise taille ou issue d'une autre clé).

## Doc: messenger

#### send_message

`send_message(plaintext, rsa_public_key, sender_private_key)`

Chiffre `plaintext` pour le destinataire détenteur de la clé privée associée à `rsa_public_key`, et signe le paquet avec `sender_private_key`.

Description :

- Tire `aes_key` et `hmac_key` (32 octets chacune, `os.urandom`), nouvelles à chaque message.
- Chiffre le message : `iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key)`.
- Ajoute `timestamp` (secondes Unix, 8 octets big-endian) et `nonce` (16 octets, `os.urandom`).
- Calcule `hmac = HMAC-SHA256(hmac_key, timestamp || nonce || iv || ciphertext)`.
- Chiffre `aes_key || hmac_key` (64 octets) avec RSA-OAEP.
- Signe `cles_chiffrees || timestamp || nonce || iv || hmac || ciphertext` avec RSA-PSS.

Sortie : dictionnaire de chaînes en hex.

> La signature couvre `cles_chiffrees` : Eve ne peut pas remplacer le bloc de clés, et un destinataire ne peut pas réexpédier un message d'Alice à un tiers en re-chiffrant les clés pour lui.


#### receive_message

`receive_message(packet, rsa_private_key, sender_public_key, replay_cache=None, now=None)`

Vérifie, authentifie et déchiffre un paquet produit par `send_message`.

Description :

- Décodage des 7 champs hex, tailles des champs de taille fixe (`timestamp` 8, `nonce` 16, `iv` 16, `hmac` 32, `cles_chiffrees` = taille de la clé RSA) -> Err01
- Vérifie la signature de l'expéditeur avec `sender_public_key`, **avant** tout déchiffrement -> Err06
- Déchiffre `cles_chiffrees` avec la clé privée RSA.
- Sépare AES (32 premiers octets) et HMAC (32 suivants).
- Vérifie le MAC en temps constant, *avant* tout déchiffrement AES.
- Fenêtre de temps : `|now - timestamp| <= 60 s`. Nonce absent du cache, puis ajouté
- Déchiffre en AES-CBC, retire le padding, décode en UTF-8 (voir [aes_cbc_decrypt](#aes_cbc_decrypt)).

Sortie : le message en clair.
-> la fonction lève une ValueError avec un code en cas de corruption ou de falsification du paquet

> La signature est vérifiée en premier : un paquet qui n'est pas d'Alice est rejeté à faible coût, sans déchiffrement RSA (opération coûteuse) et sans toucher au cache de rejeu.
> Le nonce n'est enregistré qu'**après** la signature et le MAC (pour eviter les DoS)
> Le HMAC reste vérifié mais n'apporte plus d'intégrité supplémentaire face à Eve
> Voir la section [roadmap et limites](#roadmap-et-limites) pour les limites restantes de cette protection (cache en mémoire, clés publiques non authentifiées)
> `replay_cache` : par défaut un cache partagé par le processus. `now` n'existe que pour les tests (simuler un paquet périmé sans attendre).


#### sign_packet

`sign_packet(packet, sender_private_key)`

Retourne une copie du paquet avec le champ `signature` (re)calculé sur les 6 autres champs. Utilisé par `send_message`, et par les tests pour re-signer un paquet volontairement altéré


#### ReplayCache

Mémorise les nonces acceptés (`nonce -> timestamp`).

- `add(nonce, timestamp)`, `nonce in cache`, `len(cache)`
- `purge(now)` : oublie les nonces dont le timestamp est sorti de la fenêtre.

> Invariant : un nonce est conservé au moins aussi longtemps que son timestamp reste acceptable. Après ce délai, le paquet serait de toute façon rejeté par la fenêtre (Err04), donc la purge ne rouvre aucun rejeu et la mémoire reste bornée.


# Tests & Erreurs

## Tests

test.py est autoporteur : lancer `python test.py` teste et renvoie les résultats pour chaque groupe (`crypto_utils`, `rsa_utils`, `messenger`, `authentification`, `anti_rejeu`) des autres modules (PASS ou FAIL, ERROR si erreur inattendue)
Il accepte aussi `python test.py <group_name>` et `--list` (liste les groupes).

### Resultats des tests

Sortie attendue de `python test.py` :
```
[PASS] crypto_utils
[PASS] rsa_utils
[PASS] messenger
[PASS] authentification
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

### Groupes de tests

#### `crypto_utils`

**AES-256-CBC**
- Tailles : IV de 16 octets, padding PKCS7 (7 octets -> 16, 16 -> 32, 17 -> 32, message vide -> 16)
- IV et chiffré différents à chaque appel pour un même message
- Aller-retour : message vide, 16 et 17 caractères, Unicode, 10k caractères
- Erreurs : mauvaise taille de clé (Err01), d'IV (Err02), chiffré vide ou non multiple de 16 (Err03), padding invalide ou UTF-8 invalide (Err04)

**HMAC-SHA256**
- Sortie de 32 octets, déterministe, identique à l'implémentation de la stdlib (`hmac` + `hashlib`)
- `verify_hmac` rejette : données altérées, MAC altéré, mauvaise clé, MAC trop court, trop long ou vide
- Mauvaise taille de clé (Err05)

#### `rsa_utils`

- Aller-retour, chiffré de 384 octets (RSA 3072 bits)
- OAEP probabiliste : deux chiffrés différents pour un même clair
- Tailles limites : 1 octet et 318 octets (maximum)
- Chiffrement : clés vides ou de 319 octets (Err01)
- Déchiffrement : chiffré trop court, trop long ou vide (Err02) ; chiffré altéré ou mauvaise clé privée (Err03)
- Signature RSA-PSS : aller-retour (384 octets), signatures différentes pour un même message mais toutes valides, message vide
- `rsa_verifier` rejette : données altérées, signature altérée, trop courte, trop longue ou vide, mauvaise clé publique

#### `messenger`

- Aller-retour : message vide, 16 caractères, Unicode, 10k caractères
- Paquet de 7 champs, tailles en hex (`cles_chiffrees` 768, `iv` 32, `hmac` 64, `timestamp` 16, `nonce` 32, `signature` 768)
- Deux envois du même message donnent des paquets différents
- Altération de n'importe quel champ : rejet par la signature (Err06)
- Altération re-signée de `iv`, `ciphertext`, `hmac`, `timestamp` ou `nonce` : rejet par le MAC (Err03), la couche MAC reste une seconde barrière
- `cles_chiffrees` altéré (re-signé) ou mauvaise clé privée : erreur RSA (rsa_utils Err03)
- Paquet mal formé (champ manquant, hex invalide, longueur impaire, `None`, champ de taille fixe de mauvaise taille) : Err01
- Clés déchiffrées de taille ≠ 64 octets (paquet signé) : Err02

#### `authentification`

- Paquet forgé de toutes pièces par Eve (signé avec sa clé) : rejeté (Err06)
- Mauvaise clé publique d'expéditeur côté Bob : rejeté (Err06) ; la bonne clé accepte le paquet
- Signature recopiée d'un autre paquet, ou signature nulle : rejeté (Err06)
- Réexpédition à un tiers (clés re-chiffrées pour Charlie) : rejetée (Err06), la signature couvre `cles_chiffrees`
- `sign_packet` sur un paquet intact : le paquet reste valide

#### `anti_rejeu`

- Paquet valide accepté une première fois, puis rejoué à l'identique : rejeté (Err05)
- Même texte renvoyé légitimement (nouveau nonce) : accepté
- `nonce` modifié pour contourner le cache : rejeté (Err06), la signature (et le MAC) couvre le nonce
- `timestamp` modifié pour rafraîchir un vieux paquet : rejeté (Err06), la signature (et le MAC) couvre la date
- Paquet périmé (> 60 s) ou daté du futur : rejeté (Err04) et non mémorisé
- Faux paquet (signature ou MAC invalide) portant le nonce d'un vrai : rejeté (Err06 / Err03), le vrai reste acceptable car le nonce n'est mémorisé qu'après la signature et le MAC
- Attaque « nonce brûlé » (nonce et date copiés, clés d'Eve, MAC valide, signature d'Alice recopiée) : rejetée (Err06), le cache reste vide et le vrai paquet est accepté ensuite
- `ReplayCache.purge()` après la fenêtre : nonces oubliés, mémoire bornée
- Appel sans cache explicite : le cache par défaut rejette aussi le rejeu

> Le paramètre `now` de `receive_message` permet de simuler un paquet périmé ou futur sans attendre 60 secondes.


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
| messenger     | Err01 | Paquet mal formé (champ manquant, hex invalide, taille d'un champ de taille fixe incorrecte) |
| messenger     | Err02 | Clés déchiffrées ≠ 64 octets                                               |
| messenger     | Err03 | MAC invalide (données, timestamp ou nonce altérés)                         |
| messenger     | Err04 | Horodatage hors fenêtre (périmé ou dans le futur, écart > 60 s)            |
| messenger     | Err05 | Rejeu détecté (nonce déjà vu)                                              |
| messenger     | Err06 | Signature de l'expéditeur invalide (paquet forgé ou altéré, mauvaise clé publique d'expéditeur) |



# Roadmap et limites


Voici une liste des limites et évolutions potentielles identifiées :

- **\[DONE\]** Authentification de l'expéditeur : (signature RSA-PSS, voir [la note de receive_message](#receive_message))
  Le vol d'identité et le DoS impliqué par l'absence de signature sont maintenant réglés.
  -> Reste à régler : l'authenticité des clés publiques elles-mêmes (voir ci-dessous)

- Mise en place de certificats pour la distribution des clés publiques
  La signature prouve que le paquet vient du détenteur de la clé privée associée à `sender_public_key`, pas que cette clé est bien celle d'Alice. Un attaquant qui remplace les clés publiques au moment de leur publication (MITM) n'est pas détecté

- Passage sur le réseau
  Pour le moment certaines mechaniques sont fragiles : le cache anti-rejet est en mémoire donc supprimé au redémarrage (pas un problème actuellement comme tout tourne en local mais devra être persisté si plusieurs clients doivent tourner en même temps)
  Le cache n'est pas non plus thread-safe, suppose des horloges synchronisées à ±60 s, et il n'y a ni stockage ni sérialisation des clés (c'est une bibliothèque, pas une application)

- Confidentialité des messages bancale
  Si la clé primaire de Bob fuite tous les messages précédemment envoyés sont compromis (pas de forward-secrecy)

- Longueur des messages masquée
  Si on voulait être rigoureux on imposerait une taille maximale aux messages et mettrait un padding fixe pour éviter toute information d'être découverte. Heureusement c'est un projet local en python et pas des communication militaires donc cette amélioration est mineure (mais mérite une mention).
  -> À envisager en fonction du niveau de sécurité souhaité (on ne voudrait pas ralentir tout le réseau pour des messages courts)

