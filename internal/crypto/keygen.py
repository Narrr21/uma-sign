import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .common import (
    ALG_RSA_PSS,
    ALG_ECDSA,
    ALG_ED25519,
    ALGORITHMS,
    RSA_BITS,
    RSA_EXPONENT,
    key_id
)

def generate_key(algorithm):
    if algorithm == ALG_RSA_PSS:
        return rsa.generate_private_key(
            public_exponent=RSA_EXPONENT,
            key_size=RSA_BITS
        )
    elif algorithm == ALG_ECDSA:
        return ec.generate_private_key(ec.SECP256R1())
    elif algorithm == ALG_ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def save_key(private_key, out_prefix):
    if not os.path.basename(out_prefix):
        raise ValueError("prefix tidak boleh kosong atau berakhir dengan pemisah folder")

    private_path = f"{out_prefix}.key.pem"
    public_path = f"{out_prefix}.pub.pem"

    out_dir = os.path.dirname(out_prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    if os.path.exists(private_path) or os.path.exists(public_path):
        raise FileExistsError(f"Key files already exist: {private_path}, {public_path}")
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    with os.fdopen(fd, 'wb') as f:
        f.write(private_pem)

    fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)

    with os.fdopen(fd, 'wb') as f:
        f.write(public_pem)


def key_gen(algorithm, out_prefix):
    private_key = generate_key(algorithm)
    save_key(private_key, out_prefix)
    public_key = private_key.public_key()
    return key_id(public_key)

def register(subparsers):
    parser = subparsers.add_parser(
        "keygen",
        help="Generate a new key pair (private and public keys)."
    )
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=ALGORITHMS,
    )
    parser.add_argument(
        "--out_prefix",
        required=True,
        metavar="PREFIX",
    )
    parser.set_defaults(func=run)


def run(args):
    try:
        print(key_gen(args.algorithm, args.out_prefix))
    except Exception as e:
        print(f"Error generating key pair: {e}", file=sys.stderr)
        return 1
    return 0