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
