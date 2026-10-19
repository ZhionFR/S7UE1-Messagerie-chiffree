## Imports
import os
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

## aes_cbc_encrypt(plaintext, aes_key) -> (iv, ciphertext)
def aes_cbc_encrypt(plaintext : str, aes_key : bytes) -> tuple[bytes, bytes]:
    if len(aes_key) != 32:
        raise ValueError("crypto_utils : Err01") 
    ## crypto_utils : Err01 : Unexpected key size expected 32 bytes.

    iv = os.urandom(16)

    # block_size = 128 bits
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv, ciphertext

## aes_cbc_decrypt(iv, ciphertext, aes_key) -> plaintext
def aes_cbc_decrypt(iv: bytes, ciphertext: bytes, aes_key: bytes) -> str:
    if len(aes_key) != 32:
        raise ValueError("crypto_utils : Err01")
    if len(iv) != 16:
        raise ValueError("crypto_utils : Err02")
    ## crypto_utils : Err02 : Unexpected IV size, expected 16 bytes.
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("crypto_utils : Err03")
    ## crypto_utils : Err03 : Unexpected ciphertext size, expected multiple of 16

    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8")
    except ValueError:
        raise ValueError("crypto_utils : Err04") from None
    ## crypto_utils : Err04 : Decryption failed (invalid padding or invalid UTF-8)

## compute_hmac(hmac_key, data) -> 32 octets
def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:
    if len(hmac_key) != 32:
        raise ValueError("crypto_utils : Err05")
    ## crypto_utils : Err05 : Unexpected HMAC key size, expected 32 bytes.

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    return h.finalize()

## verify_hmac(hmac_key, data, mac) -> bool
def verify_hmac(hmac_key: bytes, data: bytes, mac: bytes) -> bool:
    if len(hmac_key) != 32:
        raise ValueError("crypto_utils : Err05")

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(mac)  # HMAC.verfy(signature) fait du temps constant par défaut
        return True
    except InvalidSignature:
        return False