import json

import pytest  # type: ignore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from internal.trust import trust_store
# Testing errors.py dan trust_store_structure.py
from internal.trust.errors import FormatError, KeyNotTrusted
from internal.trust.key_validation import compute_keyid, load_public_key, profile_of, verify_key
from internal.trust.trust_store_file_management import parse_store
from internal.trust.trust_store_structure import empty_store


def _pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


@pytest.fixture(scope="module")
def keys():
    return {
        "rsa-pss-sha256": _pem(rsa.generate_private_key(65537, 3072)),
        "ecdsa-p256-sha256": _pem(ec.generate_private_key(ec.SECP256R1())),
        "ed25519": _pem(ed25519.Ed25519PrivateKey.generate()),
    }


def _entry(pem, packages=("pkg",)):
    key = load_public_key(pem)
    return {
        "keyid": compute_keyid(key),
        "algorithm": profile_of(key),
        "public_key_pem": pem,
        "packages": list(packages),
    }


def _raw(*entries):
    return json.dumps({"schema": "umasign-trust/v1", "keys": list(entries)}).encode()


# Testing key_validation

@pytest.mark.parametrize("algorithm", ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"])
def test_verify_key_each_profile(keys, algorithm):
    pem = keys[algorithm]
    keyid = compute_keyid(load_public_key(pem))
    assert verify_key(keyid, pem, algorithm) is not None


@pytest.mark.parametrize(
    "make_key",
    [
        pytest.param(lambda: rsa.generate_private_key(65537, 2048), id="rsa-wrong-size"),
        pytest.param(lambda: ec.generate_private_key(ec.SECP384R1()), id="ec-wrong-curve"),
    ],
)
def test_profile_rejects_wrong_key(make_key):
    with pytest.raises(FormatError):
        profile_of(load_public_key(_pem(make_key())))


# Testing parse_store

def test_parse_valid(keys):
    store = parse_store(_raw(*(_entry(p) for p in keys.values())))
    assert len(store.keys) == 3


def test_parse_duplicate_field():
    with pytest.raises(FormatError):
        parse_store(b'{"schema":"umasign-trust/v1","schema":"umasign-trust/v1","keys":[]}')


def test_parse_extra_field(keys):
    entry = _entry(keys["ed25519"])
    entry["extra"] = "x"
    with pytest.raises(FormatError):
        parse_store(_raw(entry))


def test_parse_duplicate_keyid(keys):
    pem = keys["ed25519"]
    with pytest.raises(FormatError):
        parse_store(_raw(_entry(pem), _entry(pem, packages=("other",))))


def test_parse_keyid_mismatch(keys):
    entry = _entry(keys["ed25519"])
    entry["keyid"] = "0" * 64
    with pytest.raises(FormatError):
        parse_store(_raw(entry))


def test_parse_packages_empty(keys):
    with pytest.raises(FormatError):
        parse_store(_raw(_entry(keys["ed25519"], packages=())))


# Testing authorize

@pytest.fixture
def store(keys):
    return trust_store.add(empty_store(), keys["ed25519"], "pkg").store


def test_authorize_ok(store):
    entry = store.keys[0]
    key = trust_store.authorize(store, entry.keyid, "ed25519", "pkg")
    assert compute_keyid(key) == entry.keyid


def test_authorize_unknown_keyid(store):
    with pytest.raises(KeyNotTrusted):
        trust_store.authorize(store, "0" * 64, "ed25519", "pkg")


def test_authorize_algorithm_mismatch(store):
    with pytest.raises(KeyNotTrusted):
        trust_store.authorize(store, store.keys[0].keyid, "ecdsa-p256-sha256", "pkg")


def test_authorize_package_not_trusted(store):
    with pytest.raises(KeyNotTrusted):
        trust_store.authorize(store, store.keys[0].keyid, "ed25519", "other")
