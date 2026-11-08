import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature
)

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519


ALG_RSA_PSS = "rsa-pss-sha256"
ALG_ECDSA = "ecdsa-p256-sha256"
ALG_ED25519 = "ed25519"

ALGORITHMS = [ALG_RSA_PSS, ALG_ECDSA, ALG_ED25519]

RSA_BITS = 3072
RSA_EXPONENT = 65537
PSS_SALT_LENGTH = 32


ECDSA_COORD_LENGTH = 32
ECDSA_SIGNATURE_LENGTH = 2 * ECDSA_COORD_LENGTH

SIGNATURE_LENGTHS = {
    ALG_RSA_PSS: RSA_BITS // 8,
    ALG_ECDSA: ECDSA_SIGNATURE_LENGTH,
    ALG_ED25519: 64,
}

def pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=PSS_SALT_LENGTH
    )

def get_algorithm_from_key(private_key):
    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.public_key().public_numbers()
        if private_key.key_size != 3072 or numbers.e != 65537:
            raise ValueError("RSA key must be at least 3072 bits and have a public exponent of at least 65537")
        return ALG_RSA_PSS
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        if private_key.curve.name != "secp256r1":
            raise ValueError("ECDSA key must use the P-256 curve")
        return ALG_ECDSA
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        return ALG_ED25519
    else:
        raise ValueError("Unsupported private key type")

def der_to_raw(der_signature):
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(ECDSA_COORD_LENGTH, byteorder="big") + s.to_bytes(ECDSA_COORD_LENGTH, byteorder="big")

def raw_to_der(raw_signature):
    if len(raw_signature) != ECDSA_SIGNATURE_LENGTH:
        raise ValueError(f"Invalid raw signature length: {len(raw_signature)}")
    r = int.from_bytes(raw_signature[:ECDSA_COORD_LENGTH], byteorder="big")
    s = int.from_bytes(raw_signature[ECDSA_COORD_LENGTH:], byteorder="big")
    return encode_dss_signature(r, s)

def public_der(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def key_id(public_key):
    return hashlib.sha256(public_der(public_key)).hexdigest()

def load_private_key(path):
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None)
    return key, get_algorithm_from_key(key)

def load_public_key(pem_data):
    return serialization.load_pem_public_key(
        pem_data
    )
