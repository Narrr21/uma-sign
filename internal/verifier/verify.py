import json
import os
import sys
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ..bundle.bundle_file_management import load_bundle

from ..manifest.canonical import parse_and_check
from ..manifest.errors import ManifestError
from ..manifest.hash import hash_artifact
from ..trust.errors import FormatError
from ..trust.errors import InputError
from ..trust.trust_store_file_management import load_store

from ..crypto.common import (
    ALG_ECDSA,
    ALG_ED25519,
    ALG_RSA_PSS,
    ALGORITHMS,
    RSA_BITS,
    RSA_EXPONENT,
    SIGNATURE_LENGTHS,
    key_id,
    load_public_key,
    pss_padding,
    raw_to_der,
)

INPUT_ERROR = "INPUT_ERROR"
FORMAT_ERROR = "FORMAT_ERROR"
UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
METADATA_MISMATCH = "METADATA_MISMATCH"
ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
OK = "OK"


@dataclass
class VerifyResult:
    valid: bool = False
    status: str = ""
    message: str = ""
    algorithm: str | None = None
    keyid: str | None = None
    package: str | None = None
    version: str | None = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "status": self.status,
            "message": self.message,
            "algorithm": self.algorithm,
            "keyid": self.keyid,
            "package": self.package,
            "version": self.version,
        }


class Rejected(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def exit_code(result: VerifyResult) -> int:
    if result.status == OK:
        return 0
    if result.status == INPUT_ERROR:
        return 2
    return 1



def _profile_of_public_key(key) -> str | None:
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size == RSA_BITS and key.public_numbers().e == RSA_EXPONENT:
            return ALG_RSA_PSS
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name == "secp256r1":
            return ALG_ECDSA
    elif isinstance(key, ed25519.Ed25519PublicKey):
        return ALG_ED25519
    return None


def _verify_signature(public_key, algorithm: str, data: bytes, signature: bytes) -> bool:
    try:
        if algorithm == ALG_RSA_PSS:
            public_key.verify(signature, data, pss_padding(), hashes.SHA256())
        elif algorithm == ALG_ECDSA:
            public_key.verify(raw_to_der(signature), data, ec.ECDSA(hashes.SHA256()))
        elif algorithm == ALG_ED25519:
            public_key.verify(signature, data)
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def _check_readable(path: str, label: str) -> None:
    try:
        with open(path, "rb") as f:
            f.read(1)
    except OSError as error:
        raise Rejected(INPUT_ERROR, f"cannot read {label} {path}: {error}") from error


def _run(r: VerifyResult, file_path, bundle_path, trust_path, package, version) -> None:
    missing = [
        name
        for name, value in (
            ("--file", file_path),
            ("--bundle", bundle_path),
            ("--trust-store", trust_path),
            ("--package", package),
            ("--version", version),
        )
        if value is None
    ]
    if missing:
        raise Rejected(INPUT_ERROR, "missing required option(s): " + ", ".join(missing))
    _check_readable(file_path, "artifact")
    _check_readable(bundle_path, "bundle")
    _check_readable(trust_path, "trust store")


    try:
        bundle = load_bundle(bundle_path)
    except InputError as error:
        raise Rejected(INPUT_ERROR, str(error)) from error
    except FormatError as error:
        raise Rejected(FORMAT_ERROR, f"bundle: {error}") from error

    try:
        manifest = parse_and_check(bundle.manifest)
    except ManifestError as error:
        raise Rejected(FORMAT_ERROR, f"manifest: {error}") from error

    r.algorithm = manifest.algorithm
    r.keyid = manifest.keyid
    r.package = manifest.package
    r.version = manifest.version

    expected_len = SIGNATURE_LENGTHS.get(manifest.algorithm)
    if expected_len is not None and len(bundle.signature) != expected_len:
        raise Rejected(
            FORMAT_ERROR,
            f"bundle: signature must be {expected_len} bytes for {manifest.algorithm}, "
            f"got {len(bundle.signature)}",
        )

    try:
        store = load_store(trust_path)
    except InputError as error:
        raise Rejected(INPUT_ERROR, str(error)) from error
    except FormatError as error:
        raise Rejected(FORMAT_ERROR, f"trust store: {error}") from error

    if manifest.algorithm not in ALGORITHMS:
        raise Rejected(UNSUPPORTED_ALGORITHM, f"unsupported algorithm: {manifest.algorithm}")

    entry = next((k for k in store.keys if k.keyid == manifest.keyid), None)
    if entry is None:
        raise Rejected(KEY_NOT_TRUSTED, "keyid is not in the trust store")
    if entry.algorithm != manifest.algorithm:
        raise Rejected(KEY_NOT_TRUSTED, "trusted key profile differs from the manifest")
    try:
        public_key = load_public_key(entry.public_key_pem.encode("utf-8"))
    except Exception as error:
        raise Rejected(KEY_NOT_TRUSTED, "trusted public key cannot be loaded") from error
    if _profile_of_public_key(public_key) != manifest.algorithm:
        raise Rejected(KEY_NOT_TRUSTED, "trusted key type or parameters do not match the profile")
    if key_id(public_key) != manifest.keyid:
        raise Rejected(KEY_NOT_TRUSTED, "trusted key fingerprint does not match keyid")
    if package not in entry.packages:
        raise Rejected(KEY_NOT_TRUSTED, f"key is not allowed for package {package}")

    if not _verify_signature(public_key, manifest.algorithm, bundle.manifest, bundle.signature):
        raise Rejected(INVALID_SIGNATURE, "signature does not match the manifest")

    if manifest.package != package:
        raise Rejected(METADATA_MISMATCH, "package differs from the manifest")
    if manifest.version != version:
        raise Rejected(METADATA_MISMATCH, "version differs from the manifest")
    if manifest.artifact.name != os.path.basename(file_path):
        raise Rejected(METADATA_MISMATCH, "artifact name differs from the file name")

    try:
        size, sha256 = hash_artifact(file_path)
    except OSError as error:
        raise Rejected(INPUT_ERROR, f"cannot read artifact {file_path}: {error}") from error
    if size != manifest.artifact.size:
        raise Rejected(ARTIFACT_MISMATCH, "artifact size differs from the manifest")
    if sha256 != manifest.artifact.sha256:
        raise Rejected(ARTIFACT_MISMATCH, "artifact SHA-256 differs from the manifest")

    r.valid = True
    r.status = OK
    r.message = "all checks passed"


def verify(file_path, bundle_path, trust_path, package, version) -> VerifyResult:
    r = VerifyResult()
    try:
        _run(r, file_path, bundle_path, trust_path, package, version)
    except Rejected as error:
        r.valid, r.status, r.message = False, error.status, str(error)
    except Exception as error:
        r.valid, r.status = False, INPUT_ERROR
        r.message = f"unexpected error: {type(error).__name__}: {error}"
    return r


def register(subparsers):
    p = subparsers.add_parser(
        "verify", help="Verifikasi artefak rilis", allow_abbrev=False
    )
    p.add_argument("--file", metavar="PATH")
    p.add_argument("--bundle", metavar="BUNDLE.JSON")
    p.add_argument("--trust-store", metavar="TRUST.JSON")
    p.add_argument("--package")
    p.add_argument("--version")
    p.add_argument("--json", action="store_true", help="keluaran JSON")
    p.set_defaults(func=run)


def run(args) -> int:
    result = verify(args.file, args.bundle, args.trust_store, args.package, args.version)
    if args.json:
        print(json.dumps(result.to_dict()))
    else:
        print(f"{result.status}: {result.message}")
    return exit_code(result)