## Imports
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


## aes_cbc_encrypt(plaintext, aes_key) -> (iv, ciphertext)
def aes_cbc_encrypt(plaintext : str, aes_key : bytes) -> tuple[bytes, bytes]:
    if len(aes_key) != 32:
        raise ValueError("Err01") 
    ## Err01 : Unexpected key size expected 32 bytes.

    iv = os.urandom(16)

    # block_size = 128 bits
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv, ciphertext


## aes_cbc_decrypt(iv, ciphertext, aes_key) -> plaintext


## compute_hmac(hmac_key, data) -> 32 octets


## verify_hmac(hmac_key, data, mac) -> bool
