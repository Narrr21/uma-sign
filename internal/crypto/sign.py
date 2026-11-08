import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .common import (
    ALG_RSA_PSS,
    ALG_ECDSA,
    ALG_ED25519,
    get_algorithm_from_key,
    pss_padding,
    der_to_raw,
    load_private_key,
    key_id
)

from ..manifest.builder import ManifestBuilder
from ..manifest.serializer import serialize_manifest
from ..manifest.canonical import parse_and_check
from ..bundle.bundle_structure import BundleBuilder
from ..bundle.bundle_file_management import save_bundle


MANIFEST_SCHEMA = "umasign-manifest/v1"
BUNDLE_SCHEMA = "umasign-bundle/v1"


    
def sign_manifest(algorithm, private_key, manifest_data):
    if algorithm == ALG_RSA_PSS:
        return private_key.sign(
            manifest_data,
            pss_padding(),
            hashes.SHA256()
        )
    elif algorithm == ALG_ECDSA:
        der_signature = private_key.sign(
            manifest_data,
            ec.ECDSA(hashes.SHA256())
        )
        return der_to_raw(der_signature)
    elif algorithm == ALG_ED25519:
        return private_key.sign(manifest_data)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def sign(file_path, package, version, key_path, output_path):
    private_key, algorithm = load_private_key(key_path)

    public_key = private_key.public_key()
    keyid = key_id(public_key)

    builder = ManifestBuilder(
        schema=MANIFEST_SCHEMA,
        package=package,
        version=version,
        algorithm=algorithm,
        keyid=keyid
    )

    manifest = builder.build_from_file(file_path)
    manifest_data = serialize_manifest(manifest)
    _ = parse_and_check(manifest_data)

    signature = sign_manifest(algorithm, private_key, manifest_data)

    bundle_builder = BundleBuilder(schema=BUNDLE_SCHEMA)

    bundle = bundle_builder.build(manifest_data, signature)

    save_bundle(output_path, bundle)

    
def register(subparsers):
    parser = subparsers.add_parser(
        "sign",
        help="Sign a file and create a bundle containing the manifest and signature."
    )
    parser.add_argument(
        "--file",
        required=True,
        metavar="PATH"
    )
    parser.add_argument(
        "--package",
        required=True
    )
    parser.add_argument(
        "--version",
        required=True
    )
    parser.add_argument(
        "--key",
        required=True,
        metavar="PRIVATE.PEM"
    )
    parser.add_argument(
        "--out",
        required=True,
        metavar="BUNDLE.JSON"
    )
    parser.set_defaults(func=run)

def run(args):
    try:
        sign(args.file, args.package, args.version, args.key, args.out)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    return 0