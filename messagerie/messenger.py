## Imports
import os
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import rsa_chiffrer_cle, rsa_dechiffrer_cle


## Constantes
FIELDS = ("cles_chiffrees", "iv", "ciphertext", "hmac")


## send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac} en hex
def send_message(plaintext: str, rsa_public_key) -> dict[str, str]:
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)

    iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key)
    mac = compute_hmac(hmac_key, iv + ciphertext)  # MAC sur iv || ciphertext
    cles_chiffrees = rsa_chiffrer_cle(aes_key + hmac_key, rsa_public_key)

    return {
        "cles_chiffrees": cles_chiffrees.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac": mac.hex(),
    }


## receive_message(packet, rsa_private_key) -> str
def receive_message(packet: dict[str, str], rsa_private_key) -> str:
    # Décode les 4 champs hex
    try:
        cles_chiffrees = bytes.fromhex(packet["cles_chiffrees"])
        iv = bytes.fromhex(packet["iv"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        mac = bytes.fromhex(packet["hmac"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("messenger : Err01") from None
    ## messenger : Err01 : Malformed packet (missing field or invalid hex).

    # Déchiffre cles_chiffrees avec la clé privée RSA
    cles = rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key)
    if len(cles) != 64:
        raise ValueError("messenger : Err02")
    ## messenger : Err02 : Unexpected decrypted keys size, expected 64 bytes (aes_key || hmac_key).

    # sépare les clés AES (32 premiers octets) et HMAC (32 suivants)
    aes_key, hmac_key = cles[:32], cles[32:]

    # Vérification du MAC AVANT tout déchiffrement AES / retrait du padding
    if not verify_hmac(hmac_key, iv + ciphertext, mac):
        raise ValueError("messenger : Err03")
    ## messenger : Err03 : MAC verification failed (tampered data).

    # Déchiffre en AES-CBC, retire le padding, décode en UTF-8 (défaut)
    return aes_cbc_decrypt(iv, ciphertext, aes_key)