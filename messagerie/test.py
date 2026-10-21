## Imports
import os
import sys
import hashlib
import time
import hmac as std_hmac
import traceback
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

### Pas * pour redondance
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import generer_paire_rsa, rsa_chiffrer_cle, rsa_dechiffrer_cle
from messenger import send_message, receive_message, ReplayCache, REPLAY_WINDOW

## Helpers

def expect_error(func, code, module="crypto_utils"):
    """Vérifie que func() lève une ValueError portant le code attendu."""
    try:
        func()
    except ValueError as e:
        assert str(e) == f"{module} : {code}", f"attendu {code}, obtenu {e}"
        return
    raise AssertionError(f"{code} non levée")


def raw_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffre `data` tel quel (déjà aligné sur 16 octets), sans padding."""
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


## Tests : crypto_utils.py

def test_crypto_utils():
    key = os.urandom(32)
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
    padder = sym_padding.PKCS7(128).padder()
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

## Tests : rsa_utils.py

def test_rsa_utils():
    err = lambda f, c: expect_error(f, c, module="rsa_utils")

    priv, pub = generer_paire_rsa()
    cles = os.urandom(32) + os.urandom(32)  # aes_key || hmac_key

    # Aller-retour
    ct = rsa_chiffrer_cle(cles, pub)
    assert len(ct) == 3072 // 8
    assert rsa_dechiffrer_cle(ct, priv) == cles

    # OAEP probabiliste : deux chiffrés différents pour le même clair
    assert rsa_chiffrer_cle(cles, pub) != ct

    # Tailles limites : 1 octet et max (318 octets en 3072 bits)
    assert rsa_dechiffrer_cle(rsa_chiffrer_cle(b"\x01", pub), priv) == b"\x01"
    max_clair = os.urandom(3072 // 8 - 66)
    assert rsa_dechiffrer_cle(rsa_chiffrer_cle(max_clair, pub), priv) == max_clair

    # Erreurs : chiffrement
    err(lambda: rsa_chiffrer_cle(b"", pub), "Err01")
    err(lambda: rsa_chiffrer_cle(os.urandom(3072 // 8 - 65), pub), "Err01")

    # Erreurs : déchiffrement
    err(lambda: rsa_dechiffrer_cle(ct[:-1], priv), "Err02")
    err(lambda: rsa_dechiffrer_cle(ct + b"\x00", priv), "Err02")
    err(lambda: rsa_dechiffrer_cle(b"", priv), "Err02")

    # Chiffré altéré -> Err03
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    err(lambda: rsa_dechiffrer_cle(tampered, priv), "Err03")

    # Mauvaise clé privée -> Err03
    other_priv, _ = generer_paire_rsa()
    err(lambda: rsa_dechiffrer_cle(ct, other_priv), "Err03")


## Tests : messenger.py

def test_messenger():
    err = lambda f, c, m="messenger": expect_error(f, c, module=m)

    priv, pub = generer_paire_rsa()

    # Aller-retour
    for msg in ["Bonjour", "", "A" * 16, "Bonjour é€ 🔐", "x" * 10_000]:
        packet = send_message(msg, pub)
        assert set(packet) == {"cles_chiffrees", "iv", "ciphertext", "hmac", "timestamp", "nonce"}
        assert receive_message(packet, priv) == msg

    # Tailles (en hex : 2 caractères par octet)
    packet = send_message("Bonjour", pub)
    assert len(packet["cles_chiffrees"]) == 2 * (3072 // 8)
    assert len(packet["iv"]) == 32
    assert len(packet["hmac"]) == 64
    assert len(packet["timestamp"]) == 16
    assert len(packet["nonce"]) == 32

    # Deux envois du même message -> paquets différents
    assert send_message("Bonjour", pub) != packet

    # Altération de iv, ciphertext, hmac, timestamp ou nonce -> Err03
    def flip(s):
        return ("1" if s[0] == "0" else "0") + s[1:]

    for field in ("iv", "ciphertext", "hmac", "timestamp", "nonce"):
        bad = {**packet, field: flip(packet[field])}
        err(lambda: receive_message(bad, priv), "Err03")

    # Altération de cles_chiffrees -> erreur RSA
    bad = {**packet, "cles_chiffrees": flip(packet["cles_chiffrees"])}
    err(lambda: receive_message(bad, priv), "Err03", "rsa_utils")

    # Mauvaise clé privée -> erreur RSA
    other_priv, _ = generer_paire_rsa()
    err(lambda: receive_message(packet, other_priv), "Err03", "rsa_utils")

    # Paquet mal formé -> Err01
    err(lambda: receive_message({}, priv), "Err01")
    err(lambda: receive_message({k: v for k, v in packet.items() if k != "iv"}, priv), "Err01")
    err(lambda: receive_message({**packet, "iv": "zz"}, priv), "Err01")
    err(lambda: receive_message({**packet, "hmac": "abc"}, priv), "Err01")  # longueur impaire
    err(lambda: receive_message({**packet, "iv": None}, priv), "Err01")
    err(lambda: receive_message({k: v for k, v in packet.items() if k != "nonce"}, priv), "Err01")
    err(lambda: receive_message({k: v for k, v in packet.items() if k != "timestamp"}, priv), "Err01")
    err(lambda: receive_message({**packet, "nonce": "00"}, priv), "Err01")      # mauvaise taille
    err(lambda: receive_message({**packet, "timestamp": "00"}, priv), "Err01")  # mauvaise taille


    # Err02 : clés déchiffrées de taille ≠ 64 octets
    forged = {**packet, "cles_chiffrees": rsa_chiffrer_cle(os.urandom(48), pub).hex()}
    err(lambda: receive_message(forged, priv), "Err02")


## Tests : anti-rejeu

def test_anti_rejeu():
    err = lambda f, c: expect_error(f, c, module="messenger")

    def flip(s):
        return ("1" if s[0] == "0" else "0") + s[1:]

    priv, pub = generer_paire_rsa()
    now = int(time.time())

    # Premier envoi accepté, rejeu à l'identique rejeté (Err05)
    cache = ReplayCache()
    packet = send_message("Bonjour", pub)
    assert receive_message(packet, priv, cache, now=now) == "Bonjour"
    err(lambda: receive_message(packet, priv, cache, now=now), "Err05")

    # Même texte renvoyé légitimement -> nouveau nonce, accepté
    assert receive_message(send_message("Bonjour", pub), priv, cache, now=now) == "Bonjour"
    assert len(cache) == 2

    # Eve change le nonce pour contourner le cache -> le MAC le détecte (Err03)
    err(lambda: receive_message({**packet, "nonce": flip(packet["nonce"])}, priv, cache, now=now), "Err03")

    # Eve rafraîchit le timestamp pour rejouer un vieux paquet -> le MAC le détecte (Err03)
    err(lambda: receive_message({**packet, "timestamp": flip(packet["timestamp"])}, priv, cache, now=now), "Err03")

    # Paquet périmé ou venant du futur -> Err04 (marge de 5 s pour éviter les effets de bord)
    cache = ReplayCache()
    packet = send_message("Bonjour", pub)
    err(lambda: receive_message(packet, priv, cache, now=now + REPLAY_WINDOW + 5), "Err04")
    err(lambda: receive_message(packet, priv, cache, now=now - REPLAY_WINDOW - 5), "Err04")
    assert len(cache) == 0  # un paquet rejeté n'est pas mémorisé

    # Un faux paquet (MAC invalide) ne « brûle » pas le nonce du vrai
    forged = {**packet, "hmac": flip(packet["hmac"])}
    err(lambda: receive_message(forged, priv, cache, now=now), "Err03")
    assert len(cache) == 0
    assert receive_message(packet, priv, cache, now=now) == "Bonjour"

    # Purge : les nonces sortis de la fenêtre sont oubliés (la mémoire reste bornée)
    assert len(cache) == 1
    cache.purge(now + REPLAY_WINDOW + 5)
    assert len(cache) == 0

    # Cache par défaut (sans argument) : rejeu rejeté aussi
    packet = send_message("Bonjour", pub)
    assert receive_message(packet, priv) == "Bonjour"
    err(lambda: receive_message(packet, priv), "Err05")



## Registre : nom du groupe -> fonction
TESTS = {
    "crypto_utils": test_crypto_utils,
    "rsa_utils": test_rsa_utils,
    "messenger": test_messenger,
    "anti_rejeu": test_anti_rejeu,
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
    # Pour tests localisés, par défaut (sans arguments) on teste tout
    args = sys.argv[1:]
    if args == ["--list"]:
        print("\n".join(TESTS))
        sys.exit(0)

    unknown = [a for a in args if a not in TESTS]
    if unknown:
        sys.exit(f"Test inconnu : {', '.join(unknown)} (voir --list)")

    sys.exit(1 if run(args or list(TESTS)) else 0)