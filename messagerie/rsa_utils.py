## Imports
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


## Constantes
RSA_KEY_SIZE = 3072


## generer_paire_rsa() -> (private_key, public_key)
def generer_paire_rsa() -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return private_key, private_key.public_key()


## _oaep() -> padding       ## Pure encapsulation pour lisibilité
def _oaep() -> asym_padding.OAEP:    
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


## rsa_chiffrer_cle(cles, rsa_public_key) -> bytes
def rsa_chiffrer_cle(cles: bytes, rsa_public_key: RSAPublicKey) -> bytes:
    max_len = rsa_public_key.key_size // 8 - 2 * 32 - 2 ## mLen_max = k - 2·hLen - 2
    if len(cles) == 0 or len(cles) > max_len:
        raise ValueError("rsa_utils : Err01")
    ## rsa_utils : Err01 : Unexpected keys size, expected 1 to (key_size/8 - 66) bytes.

    return rsa_public_key.encrypt(cles, _oaep())


## rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key) -> bytes
def rsa_dechiffrer_cle(cles_chiffrees: bytes, rsa_private_key: RSAPrivateKey) -> bytes:
    if len(cles_chiffrees) != rsa_private_key.key_size // 8:
        raise ValueError("rsa_utils : Err02")
    ## rsa_utils : Err02 : Unexpected encrypted keys size, expected key_size/8 bytes.

    try:
        return rsa_private_key.decrypt(cles_chiffrees, _oaep())
    except ValueError:
        raise ValueError("rsa_utils : Err03") from None
    ## rsa_utils : Err03 : RSA decryption failed (wrong key or corrupted data).


## _pss() -> padding        ## encapsulation pour lisibilité
def _pss() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH,
    )


## rsa_signer(data, rsa_private_key) -> bytes
def rsa_signer(data: bytes, rsa_private_key: RSAPrivateKey) -> bytes:
    return rsa_private_key.sign(data, _pss(), hashes.SHA256())


## rsa_verifier(data, signature, rsa_public_key) -> bool
def rsa_verifier(data: bytes, signature: bytes, rsa_public_key: RSAPublicKey) -> bool:
    try:
        rsa_public_key.verify(signature, data, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False