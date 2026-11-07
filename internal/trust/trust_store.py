from dataclasses import dataclass

from internal.manifest.serializer import _PACKAGE_PATTERN

from .errors import FormatError, KeyIdNotFound, KeyNotTrusted
from .key_validation import compute_keyid, load_public_key, profile_of
from .trust_store_structure import TrustStore, TrustStoreKey, find


@dataclass(frozen=True)
class AddResult:
    store: TrustStore
    entry: TrustStoreKey
    changed: bool


def add(store: TrustStore, public_key_pem, package: str) -> AddResult:
    if not isinstance(package, str) or _PACKAGE_PATTERN.fullmatch(package) is None:
        raise FormatError(f"invalid package name: {package!r}")
    public_key = load_public_key(public_key_pem)
    algorithm = profile_of(public_key)
    keyid = compute_keyid(public_key)
    if isinstance(public_key_pem, bytes):
        public_key_pem = public_key_pem.decode("ascii")

    existing = find(store, keyid)
    if existing is None:
        entry = TrustStoreKey(keyid, algorithm, public_key_pem, (package,))
        return AddResult(TrustStore(store.schema, store.keys + (entry,)), entry, True)

    if package in existing.packages:
        return AddResult(store, existing, False)

    entry = TrustStoreKey(
        existing.keyid, existing.algorithm, existing.public_key_pem,
        existing.packages + (package,),
    )
    keys = tuple(entry if k.keyid == keyid else k for k in store.keys)
    return AddResult(TrustStore(store.schema, keys), entry, True)


def list_keys(store: TrustStore) -> tuple[TrustStoreKey, ...]:
    return store.keys


def remove(store: TrustStore, keyid: str) -> TrustStore:
    if find(store, keyid) is None:
        raise KeyIdNotFound(f"keyid not found: {keyid}")
    return TrustStore(store.schema, tuple(k for k in store.keys if k.keyid != keyid))


def authorize(store: TrustStore, keyid: str, algorithm: str, package: str):
    entry = find(store, keyid)
    if entry is None:
        raise KeyNotTrusted(f"keyid {keyid} is not in the trust store")
    if entry.algorithm != algorithm:
        raise KeyNotTrusted(f"algorithm {algorithm!r} does not match trusted key")
    if package not in entry.packages:
        raise KeyNotTrusted(f"key {keyid} is not trusted for package {package!r}")
    return load_public_key(entry.public_key_pem)
