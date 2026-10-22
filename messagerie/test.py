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
from rsa_utils import generer_paire_rsa, rsa_chiffrer_cle, rsa_dechiffrer_cle, rsa_signer, rsa_verifier
from messenger import send_message, receive_message, sign_packet, ReplayCache, REPLAY_WINDOW

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


def flip(s: str) -> str:
    """Modifie le premier caractère d'un champ hex."""
    return ("1" if s[0] == "0" else "0") + s[1:]


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

    ## --- Signature RSA-PSS ---
    data = b"message a signer"
    sig = rsa_signer(data, priv)
    assert len(sig) == 3072 // 8
    assert rsa_verifier(data, sig, pub) is True
    assert rsa_verifier(data, rsa_signer(data, priv), pub) is True      # PSS probabiliste : autre signature, aussi valide
    assert rsa_signer(data, priv) != sig                                # (sel aléatoire)
    assert rsa_verifier(b"message a signes", sig, pub) is False         # données altérées
    assert rsa_verifier(data, bytes([sig[0] ^ 0x01]) + sig[1:], pub) is False  # signature altérée
    assert rsa_verifier(data, sig[:-1], pub) is False                   # signature trop courte
    assert rsa_verifier(data, sig + b"\x00", pub) is False              # signature trop longue
    assert rsa_verifier(data, b"", pub) is False
    _, other_pub = generer_paire_rsa()
    assert rsa_verifier(data, sig, other_pub) is False                  # mauvaise clé publique
    assert rsa_verifier(b"", rsa_signer(b"", priv), pub) is True        # message vide


## Tests : messenger.py

def test_messenger():
    err = lambda f, c, m="messenger": expect_error(f, c, module=m)

    bob_priv, bob_pub = generer_paire_rsa()
    alice_priv, alice_pub = generer_paire_rsa()

    # Aller-retour
    for msg in ["Bonjour", "", "A" * 16, "Bonjour é€ 🔐", "x" * 10_000]:
        packet = send_message(msg, bob_pub, alice_priv)
        assert set(packet) == {"cles_chiffrees", "iv", "ciphertext", "hmac", "timestamp", "nonce", "signature"}
        assert receive_message(packet, bob_priv, alice_pub) == msg

    # Tailles (en hex : 2 caractères par octet)
    packet = send_message("Bonjour", bob_pub, alice_priv)
    assert len(packet["cles_chiffrees"]) == 2 * (3072 // 8)
    assert len(packet["iv"]) == 32
    assert len(packet["hmac"]) == 64
    assert len(packet["timestamp"]) == 16
    assert len(packet["nonce"]) == 32
    assert len(packet["signature"]) == 2 * (3072 // 8)

    # Deux envois du même message -> paquets différents
    assert send_message("Bonjour", bob_pub, alice_priv) != packet

    # Altération de n'importe quel champ -> la signature d'Alice ne correspond plus (Err06)
    for field in ("cles_chiffrees", "iv", "ciphertext", "hmac", "timestamp", "nonce", "signature"):
        bad = {**packet, field: flip(packet[field])}
        err(lambda: receive_message(bad, bob_priv, alice_pub), "Err06")

    # Altération RE-SIGNÉE (clé d'Alice supposée compromise) : la couche MAC reste une seconde barrière (Err03)
    for field in ("iv", "ciphertext", "hmac", "timestamp", "nonce"):
        bad = sign_packet({**packet, field: flip(packet[field])}, alice_priv)
        err(lambda: receive_message(bad, bob_priv, alice_pub), "Err03")

    # cles_chiffrees altéré puis re-signé -> erreur RSA
    bad = sign_packet({**packet, "cles_chiffrees": flip(packet["cles_chiffrees"])}, alice_priv)
    err(lambda: receive_message(bad, bob_priv, alice_pub), "Err03", "rsa_utils")

    # Mauvaise clé privée de Bob (signature valide, mais clés chiffrées pour un autre) -> erreur RSA
    other_priv, _ = generer_paire_rsa()
    err(lambda: receive_message(packet, other_priv, alice_pub), "Err03", "rsa_utils")

    # Paquet mal formé -> Err01
    err(lambda: receive_message({}, bob_priv, alice_pub), "Err01")
    for champ in ("iv", "nonce", "timestamp", "signature", "hmac", "ciphertext", "cles_chiffrees"):
        err(lambda: receive_message({k: v for k, v in packet.items() if k != champ}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "iv": "zz"}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "hmac": "abc"}, bob_priv, alice_pub), "Err01")  # longueur impaire
    err(lambda: receive_message({**packet, "iv": None}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "signature": "zz"}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "nonce": "00"}, bob_priv, alice_pub), "Err01")      # mauvaise taille
    err(lambda: receive_message({**packet, "timestamp": "00"}, bob_priv, alice_pub), "Err01")  # mauvaise taille
    err(lambda: receive_message({**packet, "iv": packet["iv"] + "00"}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "hmac": packet["hmac"][:-2]}, bob_priv, alice_pub), "Err01")
    err(lambda: receive_message({**packet, "cles_chiffrees": packet["cles_chiffrees"][:-2]}, bob_priv, alice_pub), "Err01")

    # Err02 : clés déchiffrées de taille ≠ 64 octets (paquet signé par Alice, donc la signature passe)
    forged = sign_packet({**packet, "cles_chiffrees": rsa_chiffrer_cle(os.urandom(48), bob_pub).hex()}, alice_priv)
    err(lambda: receive_message(forged, bob_priv, alice_pub), "Err02")


## Tests : authentification de l'expéditeur

def test_authentification():
    err = lambda f, c: expect_error(f, c, module="messenger")

    bob_priv, bob_pub = generer_paire_rsa()
    alice_priv, alice_pub = generer_paire_rsa()
    eve_priv, eve_pub = generer_paire_rsa()

    # Paquet forgé de toutes pièces (Eve ne connaît que la clé publique de Bob) : rejeté
    forged = send_message("Virement validé. Alice.", bob_pub, eve_priv)
    err(lambda: receive_message(forged, bob_priv, alice_pub), "Err06")

    # Mauvaise clé publique d'expéditeur côté Bob : le paquet légitime est rejeté
    packet = send_message("Bonjour", bob_pub, alice_priv)
    err(lambda: receive_message(packet, bob_priv, eve_pub), "Err06")
    assert receive_message(packet, bob_priv, alice_pub) == "Bonjour"

    # Signature d'un autre paquet recopiée : rejetée
    autre = send_message("Autre message", bob_pub, alice_priv)
    err(lambda: receive_message({**packet, "signature": autre["signature"]}, bob_priv, alice_pub), "Err06")

    # Paquet sans signature valide (signature nulle) : rejeté
    err(lambda: receive_message({**packet, "signature": "00" * (3072 // 8)}, bob_priv, alice_pub), "Err06")

    # Retransmission à un autre destinataire : Bob re-chiffre les clés pour Charlie, la signature (qui couvre
    # cles_chiffrees) ne correspond plus -> rejeté, un destinataire ne peut pas réexpédier un message d'Alice
    charlie_priv, charlie_pub = generer_paire_rsa()
    cles = rsa_dechiffrer_cle(bytes.fromhex(packet["cles_chiffrees"]), bob_priv)
    reexpedie = {**packet, "cles_chiffrees": rsa_chiffrer_cle(cles, charlie_pub).hex()}
    err(lambda: receive_message(reexpedie, charlie_priv, alice_pub), "Err06")

    # sign_packet : idempotent sur le contenu (ré-signer un paquet intact reste valide)
    assert receive_message(sign_packet(packet, alice_priv), bob_priv, alice_pub, ReplayCache()) == "Bonjour"


## Tests : anti-rejeu

def test_anti_rejeu():
    err = lambda f, c: expect_error(f, c, module="messenger")

    bob_priv, bob_pub = generer_paire_rsa()
    alice_priv, alice_pub = generer_paire_rsa()
    now = int(time.time())

    # Premier envoi accepté, rejeu à l'identique rejeté (Err05)
    cache = ReplayCache()
    packet = send_message("Bonjour", bob_pub, alice_priv)
    assert receive_message(packet, bob_priv, alice_pub, cache, now=now) == "Bonjour"
    err(lambda: receive_message(packet, bob_priv, alice_pub, cache, now=now), "Err05")

    # Même texte renvoyé légitimement -> nouveau nonce, accepté
    assert receive_message(send_message("Bonjour", bob_pub, alice_priv), bob_priv, alice_pub, cache, now=now) == "Bonjour"
    assert len(cache) == 2

    # Eve change le nonce pour contourner le cache -> la signature le détecte (Err06)
    err(lambda: receive_message({**packet, "nonce": flip(packet["nonce"])}, bob_priv, alice_pub, cache, now=now), "Err06")

    # Eve rafraîchit le timestamp pour rejouer un vieux paquet -> la signature le détecte (Err06)
    err(lambda: receive_message({**packet, "timestamp": flip(packet["timestamp"])}, bob_priv, alice_pub, cache, now=now), "Err06")

    # Paquet périmé ou venant du futur -> Err04 (marge de 5 s pour éviter les effets de bord)
    cache = ReplayCache()
    packet = send_message("Bonjour", bob_pub, alice_priv)
    err(lambda: receive_message(packet, bob_priv, alice_pub, cache, now=now + REPLAY_WINDOW + 5), "Err04")
    err(lambda: receive_message(packet, bob_priv, alice_pub, cache, now=now - REPLAY_WINDOW - 5), "Err04")
    assert len(cache) == 0  # un paquet rejeté n'est pas mémorisé

    # Un faux paquet (signature invalide) ne « brûle » pas le nonce du vrai
    forged = {**packet, "hmac": flip(packet["hmac"])}
    err(lambda: receive_message(forged, bob_priv, alice_pub, cache, now=now), "Err06")
    assert len(cache) == 0

    # Même chose pour un faux paquet re-signé mais au MAC invalide (couche MAC)
    forged = sign_packet({**packet, "hmac": flip(packet["hmac"])}, alice_priv)
    err(lambda: receive_message(forged, bob_priv, alice_pub, cache, now=now), "Err03")
    assert len(cache) == 0

    # Attaque « nonce brûlé » : Eve copie nonce et date, met SES clés et un MAC valide, recopie la signature d'Alice.
    # Sans signature couvrant cles_chiffrees, ce paquet aurait consommé le nonce du vrai ; ici il est rejeté (Err06).
    eve_aes, eve_hmac = os.urandom(32), os.urandom(32)
    ts, nonce = bytes.fromhex(packet["timestamp"]), bytes.fromhex(packet["nonce"])
    iv, ct = bytes.fromhex(packet["iv"]), bytes.fromhex(packet["ciphertext"])
    piege = {**packet,
             "cles_chiffrees": rsa_chiffrer_cle(eve_aes + eve_hmac, bob_pub).hex(),
             "hmac": compute_hmac(eve_hmac, ts + nonce + iv + ct).hex()}
    err(lambda: receive_message(piege, bob_priv, alice_pub, cache, now=now), "Err06")
    assert len(cache) == 0
    assert receive_message(packet, bob_priv, alice_pub, cache, now=now) == "Bonjour"

    # Purge : les nonces sortis de la fenêtre sont oubliés (la mémoire reste bornée)
    assert len(cache) == 1
    cache.purge(now + REPLAY_WINDOW + 5)
    assert len(cache) == 0

    # Cache par défaut (sans argument) : rejeu rejeté aussi
    packet = send_message("Bonjour", bob_pub, alice_priv)
    assert receive_message(packet, bob_priv, alice_pub) == "Bonjour"
    err(lambda: receive_message(packet, bob_priv, alice_pub), "Err05")



## Registre : nom du groupe -> fonction
TESTS = {
    "crypto_utils": test_crypto_utils,
    "rsa_utils": test_rsa_utils,
    "messenger": test_messenger,
    "authentification": test_authentification,
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