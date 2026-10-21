## Imports
import os
import time
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import rsa_chiffrer_cle, rsa_dechiffrer_cle
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


## Constantes
FIELDS = ("cles_chiffrees", "iv", "ciphertext", "hmac", "timestamp", "nonce")
TIMESTAMP_SIZE = 8      # /!\ Big-endian
NONCE_SIZE = 16
REPLAY_WINDOW = 60


class ReplayCache:
    def __init__(self, window: int = REPLAY_WINDOW):
        self.window = window
        self._seen: dict[bytes, int] = {}   # nonce -> timestamp

    def __len__(self) -> int:
        return len(self._seen)

    def __contains__(self, nonce: bytes) -> bool:
        return nonce in self._seen

    def add(self, nonce: bytes, timestamp: int) -> None:
        self._seen[nonce] = timestamp

    def purge(self, now: int) -> None:
        """Oublie les nonces dont le timestamp est sorti de la fenêtre."""
        limite = now - self.window
        self._seen = {n: t for n, t in self._seen.items() if t >= limite}


## Cache partagé par défaut
_DEFAULT_CACHE = ReplayCache()


## send_message(plaintext, rsa_public_key) -> {cles_chiffrees, iv, ciphertext, hmac, timestamp, nonce} en hex
def send_message(plaintext: str, rsa_public_key: RSAPublicKey) -> dict[str, str]:
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)
    timestamp = int(time.time()).to_bytes(TIMESTAMP_SIZE, "big")
    nonce = os.urandom(NONCE_SIZE)

    iv, ciphertext = aes_cbc_encrypt(plaintext, aes_key)
    mac = compute_hmac(hmac_key, timestamp + nonce + iv + ciphertext)  # MAC sur timestamp || nonce || iv || ciphertext
    cles_chiffrees = rsa_chiffrer_cle(aes_key + hmac_key, rsa_public_key)

    return {
        "cles_chiffrees": cles_chiffrees.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac": mac.hex(),
        "timestamp": timestamp.hex(),
        "nonce": nonce.hex(),
    }


## receive_message(packet, rsa_private_key, replay_cache=None, now=None) -> str
## le parametre `now` n'existe que pour pouvoir tester la fenêtre sans attendre plus de REPLAY_WINDOW secondes
def receive_message( packet: dict[str, str], rsa_private_key: RSAPrivateKey,
            replay_cache: ReplayCache | None = None, now: int | None = None,) -> str:
    if replay_cache is None:
        replay_cache = _DEFAULT_CACHE
    if now is None:
        now = int(time.time())

    # Décode les 6 champs hex
    try:
        cles_chiffrees = bytes.fromhex(packet["cles_chiffrees"])
        iv = bytes.fromhex(packet["iv"])
        ciphertext = bytes.fromhex(packet["ciphertext"])
        mac = bytes.fromhex(packet["hmac"])
        timestamp = bytes.fromhex(packet["timestamp"])
        nonce = bytes.fromhex(packet["nonce"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("messenger : Err01") from None
    if len(timestamp) != TIMESTAMP_SIZE or len(nonce) != NONCE_SIZE:
        raise ValueError("messenger : Err01")
    ## messenger : Err01 : Malformed packet (missing field, invalid hex or wrong timestamp/nonce size).

    # Déchiffre cles_chiffrees avec la clé privée RSA
    cles = rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key)
    if len(cles) != 64:
        raise ValueError("messenger : Err02")
    ## messenger : Err02 : Unexpected decrypted keys size, expected 64 bytes (aes_key || hmac_key).

    # sépare les clés AES (32 premiers octets) et HMAC (32 suivants)
    aes_key, hmac_key = cles[:32], cles[32:]

    # Vérification du MAC AVANT tout déchiffrement AES / retrait du padding
    # Le MAC couvre timestamp et nonce : Eve ne peut ni rafraîchir la date ni changer le nonce
    if not verify_hmac(hmac_key, timestamp + nonce + iv + ciphertext, mac):
        raise ValueError("messenger : Err03")
    ## messenger : Err03 : MAC verification failed (tampered data).

    # Anti-rejeu : seulement APRÈS le MAC (timestamp et nonce sont alors authentifiés).
    # Sinon Eve pourrait consommer le cache avec un faux paquet et faire rejeter le vrai.
    ts = int.from_bytes(timestamp, "big")
    if abs(now - ts) > replay_cache.window:
        raise ValueError("messenger : Err04")
    ## messenger : Err04 : Timestamp outside the accepted window (expired or from the future) -> DeLorean speed limiter muhahaha

    replay_cache.purge(now)
    if nonce in replay_cache:
        raise ValueError("messenger : Err05")
    ## messenger : Err05 : Replay detected (nonce in replay cache)
    replay_cache.add(nonce, ts)

    # Déchiffre en AES-CBC, retire le padding, décode en UTF-8 (défaut)
    return aes_cbc_decrypt(iv, ciphertext, aes_key)