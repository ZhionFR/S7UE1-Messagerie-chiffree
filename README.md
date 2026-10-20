# S7UE1-Messagerie-chiffree

## Description

Ce repo contient du projet de cryptographie d'octobre 2026.

### Cahier des charges

#### Description
Alice et Bob communiquent de manière chiffrée
Eve voit les paquets mais ne peut pas lire les messages

#### Processus
Bob génère sa paire de clés RSA et publie la clé publique

Alice génère une clé AES et HMAC (aléatoire)
Alice chiffre les deux clés en RSA-OAEP avec la clé de Bob
Alice chiffre le message en AES-256-CBC avec un IV neuf
Alice calcule le HMAC-SHA256 de l'IV + message chiffré

Alice transmets à Bob {clés chiffrées, IV, message chiffré, HMAC}

Bob déchiffre les clés avec sa clé privée
Bob vérifier le HMAC et rejette le paquet s'il est faux
Bob déchiffre le message

#### Specs
- RSA transporte les clés
- AES chiffre le message
- HMAC pour l'intégrité
- Python3 + librairie `cryptography`

#### Architecture

messagerie/
	crypto_utils.py
	rsa_utils.py
	messenger.py
	main.py
	README.md

##### Fichiers
crypto_utils.py
	aes_cbc_encrypt(plaintext, aes_key) -> (iv, ciphertext)
	aes_cbc_decrypt(iv, ciphertext, aes_key) -> plaintext
	compute_hmac(hmac_key, data) -> 32 octets
	verify_hmac(hmac_key, data, mac) -> bool

rsa_utils.py
	generer_paire_rsa() -> (private_key, public_key)
	rsa_chiffrer_cle(cles, rsa_public_key) -> bytes
	rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key) -> bytes

messenger.py
	send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac} (en hex)
	recieve_message(packet, rsa_private_key) -> plaintext
		-> exception si le message est faux

main.py
	Déroule toute la séquence décrite dans [[Processus]]
