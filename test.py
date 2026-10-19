## Imports
import os
import sys
import traceback
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt


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

    # Tailles de sortie
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

    # Aller-retour
    for msg in ["Bonjour", "", "A" * 16, "A" * 17, "Bonjour é€ 🔐", "x" * 10_000]:
        iv, ct = aes_cbc_encrypt(msg, key)
        assert aes_cbc_decrypt(iv, ct, key) == msg

    # Erreurs : chiffrement
    expect_error(lambda: aes_cbc_encrypt("test", os.urandom(16)), "Err01")
    expect_error(lambda: aes_cbc_encrypt("test", os.urandom(33)), "Err01")

    # Erreurs : déchiffrement
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