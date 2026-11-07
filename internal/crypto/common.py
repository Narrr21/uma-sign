import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


ALG_RSA_PSS = "rsa-pss-sha256"
ALG_ECDSA = "ecdsa-p256-sha256"
ALG_ED25519 = "ed25519"

ALGORITHMS = [ALG_RSA_PSS, ALG_ECDSA, ALG_ED25519]

RSA_BITS = 3072
RSA_EXPONENT = 65537
PSS_SALT_LENGTH = 32


def pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=PSS_SALT_LENGTH
    )

def public_der(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def key_id(public_key):
    return hashlib.sha256(public_der(public_key)).hexdigest()