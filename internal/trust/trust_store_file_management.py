import json
import os
import tempfile

from internal.common.strict_json import loads
from internal.manifest.serializer import _PACKAGE_PATTERN

from .errors import FormatError, InputError
from .key_validation import verify_key
from .trust_store_structure import SCHEMA, TrustStore, TrustStoreKey, empty_store

_ROOT_FIELDS = {"schema", "keys"}
_KEY_FIELDS = {"keyid", "algorithm", "public_key_pem", "packages"}


def _require_fields(value, expected, location):
    if not isinstance(value, dict):
        raise FormatError(f"{location} must be an object")
    if set(value) != expected:
        raise FormatError(f"{location} must have exactly the fields: {', '.join(sorted(expected))}")


def _parse_key(value, location) -> TrustStoreKey:
    _require_fields(value, _KEY_FIELDS, location)
    keyid = value["keyid"]
    algorithm = value["algorithm"]
    public_key_pem = value["public_key_pem"]
    packages = value["packages"]

    for name in ("keyid", "algorithm", "public_key_pem"):
        if not isinstance(value[name], str):
            raise FormatError(f"{location}.{name} must be a string")
    if not isinstance(packages, list) or not packages:
        raise FormatError(f"{location}.packages must be a non-empty array")
    for package in packages:
        if not isinstance(package, str) or _PACKAGE_PATTERN.fullmatch(package) is None:
            raise FormatError(f"{location}.packages contains an invalid package name")
    if len(set(packages)) != len(packages):
        raise FormatError(f"{location}.packages contains duplicates")

    verify_key(keyid, public_key_pem, algorithm)
    return TrustStoreKey(keyid, algorithm, public_key_pem, tuple(packages))


def parse_store(raw: bytes) -> TrustStore:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FormatError("trust store is not valid UTF-8") from error
    value = loads(text)

    _require_fields(value, _ROOT_FIELDS, "root")
    if value["schema"] != SCHEMA:
        raise FormatError(f'schema must be "{SCHEMA}"')
    if not isinstance(value["keys"], list):
        raise FormatError("keys must be an array")

    keys = tuple(_parse_key(item, f"keys[{i}]") for i, item in enumerate(value["keys"]))
    if len({entry.keyid for entry in keys}) != len(keys):
        raise FormatError("duplicate keyid")
    return TrustStore(SCHEMA, keys)


def serialize_store(store: TrustStore) -> bytes:
    document = {
        "schema": store.schema,
        "keys": [
            {
                "keyid": entry.keyid,
                "algorithm": entry.algorithm,
                "public_key_pem": entry.public_key_pem,
                "packages": list(entry.packages),
            }
            for entry in store.keys
        ],
    }
    return json.dumps(document, indent=2).encode("utf-8")


def load_store(path) -> TrustStore:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as error:
        raise InputError(f"cannot read trust store {path}: {error}") from error
    return parse_store(raw)


def load_store_or_empty(path) -> TrustStore:
    if not os.path.exists(path):
        return empty_store()
    return load_store(path)


def save_store(path, store: TrustStore) -> None:
    data = serialize_store(store)
    directory = os.path.dirname(os.path.abspath(path))
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=directory)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
    except OSError as error:
        raise InputError(f"cannot write trust store {path}: {error}") from error
    finally:
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
