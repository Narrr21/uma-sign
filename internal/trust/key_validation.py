import base64
import binascii
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from internal.crypto.common import (
    ALG_ECDSA,
    ALG_ED25519,
    ALG_RSA_PSS,
    RSA_BITS,
    RSA_EXPONENT,
    key_id,
    public_der,
)

from .errors import FormatError


_PEM_BLOCK = re.compile(
    rb"\s*-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]*)-----END PUBLIC KEY-----\s*"
)


def load_public_key(pem):
    if isinstance(pem, str):
        try:
            pem = pem.encode("ascii")
        except UnicodeEncodeError as error:
            raise FormatError("public key PEM must be ASCII") from error
    if not isinstance(pem, bytes):
        raise FormatError("public key must be an SPKI PEM labeled PUBLIC KEY")
    match = _PEM_BLOCK.fullmatch(pem)
    if match is None:
        raise FormatError("public key must be an SPKI PEM labeled PUBLIC KEY")
    try:
        der = base64.b64decode(b"".join(match.group(1).split()), validate=True)
        public_key = serialization.load_der_public_key(der)
    except (binascii.Error, ValueError, TypeError, UnsupportedAlgorithm) as error:
        raise FormatError(f"invalid public key PEM: {error}") from error
    if der != public_der(public_key):
        raise FormatError("public key DER is not in canonical SPKI encoding")
    return public_key


def profile_of(public_key) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size != RSA_BITS or public_key.public_numbers().e != RSA_EXPONENT:
            raise FormatError(f"RSA key must be {RSA_BITS} bits with e = {RSA_EXPONENT}")
        return ALG_RSA_PSS
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise FormatError("EC key must use curve P-256")
        return ALG_ECDSA
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return ALG_ED25519
    raise FormatError("unsupported key type")


def compute_keyid(public_key) -> str:
    # SHA-256 dari DER SPKI
    return key_id(public_key)


def verify_key(keyid: str, public_key_pem, algorithm: str):
    public_key = load_public_key(public_key_pem)
    if profile_of(public_key) != algorithm:
        raise FormatError(f"key {keyid}: key profile does not match algorithm {algorithm!r}")
    if compute_keyid(public_key) != keyid:
        raise FormatError(f"keyid {keyid} does not match public key")
    return public_key
