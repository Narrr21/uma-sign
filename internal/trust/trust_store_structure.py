from dataclasses import dataclass

SCHEMA = "minisign-trust/v1"


@dataclass(frozen=True)
class TrustStoreKey:
    keyid: str
    algorithm: str
    public_key_pem: str
    packages: tuple[str, ...]


@dataclass(frozen=True)
class TrustStore:
    schema: str
    keys: tuple[TrustStoreKey, ...]


def empty_store() -> TrustStore:
    return TrustStore(schema=SCHEMA, keys=())


def find(store: TrustStore, keyid: str) -> TrustStoreKey | None:
    for entry in store.keys:
        if entry.keyid == keyid:
            return entry
    return None
