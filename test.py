## Imports
import os
import sys
import hashlib
import hmac as std_hmac
import traceback
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt

from crypto_utils import *

## Helpers

def expect_error(func, code):
    """Vérifie que func() lève une ValueError portant le code attendu."""
    try:
        func()
    except ValueError as e:
        assert str(e) == f"crypto_utils : {code}", f"attendu {code}, obtenu {e}"
        return
    raise AssertionError(f"{code} non levée")


def raw_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffre `data` tel quel (déjà aligné sur 16 octets), sans padding."""
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


## Tests : crypto_utils.py

def test_crypto_utils():
    key = os.urandom(32)
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)

    ## --- aes_cbc_encrypt : tailles ---
    iv, ct = aes_cbc_encrypt("Bonjour", key)
    assert len(iv) == 16
    assert len(ct) == 16                                  # 7 octets + 9 de padding
    assert len(aes_cbc_encrypt("A" * 16, key)[1]) == 32   # bloc de padding complet
    assert len(aes_cbc_encrypt("A" * 17, key)[1]) == 32
    assert len(aes_cbc_encrypt("", key)[1]) == 16         # message vide

    # IV différent à chaque appel
    iv1, ct1 = aes_cbc_encrypt("Bonjour", key)
    iv2, ct2 = aes_cbc_encrypt("Bonjour", key)
    assert iv1 != iv2 and ct1 != ct2

    ## --- AES-CBC : aller-retour ---
    for msg in ["Bonjour", "", "A" * 16, "A" * 17, "Bonjour é€ 🔐", "x" * 10_000]:
        iv, ct = aes_cbc_encrypt(msg, key)
        assert aes_cbc_decrypt(iv, ct, key) == msg

    ## --- AES-CBC : erreurs ---
    expect_error(lambda: aes_cbc_encrypt("test", os.urandom(16)), "Err01")
    expect_error(lambda: aes_cbc_encrypt("test", os.urandom(33)), "Err01")

    iv, ct = aes_cbc_encrypt("Bonjour", key)
    expect_error(lambda: aes_cbc_decrypt(iv, ct, os.urandom(16)), "Err01")
    expect_error(lambda: aes_cbc_decrypt(iv[:15], ct, key), "Err02")
    expect_error(lambda: aes_cbc_decrypt(iv + b"\x00", ct, key), "Err02")
    expect_error(lambda: aes_cbc_decrypt(iv, b"", key), "Err03")
    expect_error(lambda: aes_cbc_decrypt(iv, ct + b"\x00", key), "Err03")

    # Err04 : padding invalide (dernier octet 0x00, jamais valide en PKCS7)
    iv = os.urandom(16)
    bad_padding = raw_encrypt(b"\x00" * 16, key, iv)
    expect_error(lambda: aes_cbc_decrypt(iv, bad_padding, key), "Err04")

    # Err04 : padding correct mais UTF-8 invalide
    padder = padding.PKCS7(128).padder()
    padded = padder.update(b"\xff\xfe") + padder.finalize()
    bad_utf8 = raw_encrypt(padded, key, iv)
    expect_error(lambda: aes_cbc_decrypt(iv, bad_utf8, key), "Err04")

    ## --- HMAC ---
    data = b"message"
    mac = compute_hmac(hmac_key, data)
    assert len(mac) == 32
    assert compute_hmac(hmac_key, data) == mac                           # déterministe
    assert mac == std_hmac.new(hmac_key, data, hashlib.sha256).digest()  # référence stdlib
    assert len(compute_hmac(hmac_key, b"")) == 32

    assert verify_hmac(hmac_key, data, mac) is True
    assert verify_hmac(hmac_key, b"messagf", mac) is False               # données altérées
    bad = bytes([mac[0] ^ 0x01]) + mac[1:]
    assert verify_hmac(hmac_key, data, bad) is False                     # MAC altéré
    assert verify_hmac(os.urandom(32), data, mac) is False               # mauvaise clé
    assert verify_hmac(hmac_key, data, mac[:31]) is False                # MAC trop court
    assert verify_hmac(hmac_key, data, mac + b"\x00") is False           # MAC trop long
    assert verify_hmac(hmac_key, data, b"") is False

    expect_error(lambda: compute_hmac(os.urandom(16), data), "Err05")
    expect_error(lambda: verify_hmac(os.urandom(16), data, mac), "Err05")

    ## --- Encrypt-then-MAC : aller-retour ---
    for msg in ["Bonjour", "", "A" * 16, "Bonjour é€ 🔐", "x" * 10_000]:
        blob = encrypt_then_mac(msg, aes_key, hmac_key)
        assert len(blob) % 16 == 0 and len(blob) >= 64
        assert verify_then_decrypt(blob, aes_key, hmac_key) == msg

    blob = encrypt_then_mac("Bonjour", aes_key, hmac_key)
    assert len(blob) == 16 + 16 + 32                                     # iv + chiffré + mac

    ## --- Encrypt-then-MAC : erreurs ---
    # Altération de n'importe quel octet (iv, chiffré ou mac) -> Err08
    for i in range(len(blob)):
        tampered = blob[:i] + bytes([blob[i] ^ 0x01]) + blob[i + 1:]
        expect_error(lambda: verify_then_decrypt(tampered, aes_key, hmac_key), "Err08")

    # Mauvaise clé HMAC -> Err08
    expect_error(lambda: verify_then_decrypt(blob, aes_key, os.urandom(32)), "Err08")

    # Tailles de blob invalides -> Err07
    expect_error(lambda: verify_then_decrypt(b"", aes_key, hmac_key), "Err07")
    expect_error(lambda: verify_then_decrypt(blob[:48], aes_key, hmac_key), "Err07")
    expect_error(lambda: verify_then_decrypt(blob[:-1], aes_key, hmac_key), "Err07")
    expect_error(lambda: verify_then_decrypt(blob + b"\x00", aes_key, hmac_key), "Err07")

    # Clés identiques -> Err06
    expect_error(lambda: encrypt_then_mac("test", aes_key, aes_key), "Err06")
    expect_error(lambda: verify_then_decrypt(blob, aes_key, aes_key), "Err06")

    # Tailles de clé -> Err05 (HMAC) / Err01 (AES)
    expect_error(lambda: encrypt_then_mac("test", aes_key, os.urandom(16)), "Err05")
    expect_error(lambda: encrypt_then_mac("test", os.urandom(16), hmac_key), "Err01")

## Tests : rsa_utils.py

def test_rsa_utils():
    raise NotImplementedError("à écrire")


## Tests : messenger.py

def test_messenger():
    raise NotImplementedError("à écrire")


## Registre : nom du groupe -> fonction
TESTS = {
    "crypto_utils": test_crypto_utils,
    "rsa_utils": test_rsa_utils,
    "messenger": test_messenger,
}


## Lanceur
def run(names):
    failed = 0
    for name in names:
        try:
            TESTS[name]()
            print(f"[PASS] {name}")
        except NotImplementedError as e:
            print(f"[SKIP] {name} ({e})")
        except AssertionError:
            failed += 1
            print(f"[FAIL] {name}")
            traceback.print_exc()
        except Exception:
            failed += 1
            print(f"[ERROR] {name}")
            traceback.print_exc()
    return failed


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--list"]:
        print("\n".join(TESTS))
        sys.exit(0)

    unknown = [a for a in args if a not in TESTS]
    if unknown:
        sys.exit(f"Test inconnu : {', '.join(unknown)} (voir --list)")

    sys.exit(1 if run(args or list(TESTS)) else 0)