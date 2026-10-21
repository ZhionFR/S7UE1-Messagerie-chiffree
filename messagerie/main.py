## Imports
import os
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import generer_paire_rsa, rsa_chiffrer_cle, rsa_dechiffrer_cle
from messenger import send_message, receive_message, ReplayCache

## Constantes
MESSAGE = "Salut Bob, ce message est secret !! Alice."


## Fonctions utilitaires
def titre(texte: str) -> None:
    print(f"\n=== {texte} ===")


## ---------- Partie 1 : déroulé étape par étape (fonctions de bas niveau) ----------

titre("Bob")
## Bob genere sa paire de cles RSA
bob_private, bob_public = generer_paire_rsa()

## Bob publie sa cle publique RSA
print("Bob a généré sa paire RSA 3072 bits et publie sa clé publique.")

titre("Alice")
## Alice genere une cle AES et HMAC
aes_key = os.urandom(32)
hmac_key = os.urandom(32)
print("Clés AES et HMAC générées (32 octets chacune).")

## Alice chiffre les deux cles avec la cle de Bob
cles_chiffrees = rsa_chiffrer_cle(aes_key + hmac_key, bob_public)
print(f"Clés chiffrées en RSA-OAEP : {len(cles_chiffrees)} octets.")

## Alice chiffre le message en AES-256-CBC avec un IV neuf
iv, ciphertext = aes_cbc_encrypt(MESSAGE, aes_key)
print(f"Message chiffré : IV {len(iv)} octets, chiffré {len(ciphertext)} octets.")

## Alice calcule le HMAC-SHA256 de l'IV + msg chiffre
mac = compute_hmac(hmac_key, iv + ciphertext)
print(f"HMAC-SHA256 : {mac.hex()}")

## Alice transmets les cles a Bob (paquet en hex, c'est ce que voit Eve)
packet = {
    "cles_chiffrees": cles_chiffrees.hex(),
    "iv": iv.hex(),
    "ciphertext": ciphertext.hex(),
    "hmac": mac.hex(),
}

titre("Eve (ce qui circule sur le réseau)")
for champ, valeur in packet.items():
    print(f"{champ:15} {valeur[:48]}{'...' if len(valeur) > 48 else ''}")

titre("Bob")
r_cles_chiffrees = bytes.fromhex(packet["cles_chiffrees"])
r_iv = bytes.fromhex(packet["iv"])
r_ciphertext = bytes.fromhex(packet["ciphertext"])
r_mac = bytes.fromhex(packet["hmac"])

## Bob dechiffre les cles avec sa cle privee
cles = rsa_dechiffrer_cle(r_cles_chiffrees, bob_private)
r_aes_key, r_hmac_key = cles[:32], cles[32:]

## Bob verifie le HMAC et rejette le paquet s'il est faux
if not verify_hmac(r_hmac_key, r_iv + r_ciphertext, r_mac):
    raise SystemExit("HMAC invalide : paquet rejeté.")
print("HMAC valide.")

## Bob dechiffre le message
resultat = aes_cbc_decrypt(r_iv, r_ciphertext, r_aes_key)
print(f"Message déchiffré : {resultat}")
assert resultat == MESSAGE


## ---------- Partie 2 : même échange via messenger.py ----------

titre("Même échange via send_message / receive_message")
packet = send_message(MESSAGE, bob_public)
assert receive_message(packet, bob_private) == MESSAGE
print("Aller-retour OK.")


## ---------- Partie 3 : Eve modifie le paquet ----------

titre("Eve altère le chiffré")
premier = packet["ciphertext"][0]
altere = {**packet, "ciphertext": ("1" if premier == "0" else "0") + packet["ciphertext"][1:]}
try:
    receive_message(altere, bob_private)
    print("ERREUR : paquet altéré accepté !")
except ValueError as e:
    print(f"Paquet rejeté par Bob avec l'erreur \"{e}\"")



## ---------- Partie 4 : Eve rejoue un paquet valide ----------

titre("Eve rejoue un paquet intercepté")
cache = ReplayCache()
packet = send_message(MESSAGE, bob_public)
assert receive_message(packet, bob_private, cache) == MESSAGE
print("Premier envoi accepté par Bob.")
try:
    receive_message(packet, bob_private, cache)
    print("ERREUR : rejeu accepté !")
except ValueError as e:
    print(f"Rejeu rejeté par Bob avec l'erreur \"{e}\"")

## Eve tente de contourner le cache en changeant le nonce
contournement = {**packet, "nonce": ("1" if packet["nonce"][0] == "0" else "0") + packet["nonce"][1:]}
try:
    receive_message(contournement, bob_private, cache)
    print("ERREUR : nonce modifié accepté !")
except ValueError as e:
    print(f"Nonce modifié rejeté par Bob avec l'erreur \"{e}\"")