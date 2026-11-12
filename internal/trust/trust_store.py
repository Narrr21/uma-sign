import sys
from dataclasses import dataclass

from internal.manifest.serializer import _PACKAGE_PATTERN

from .errors import FormatError, InputError, KeyIdNotFound, KeyNotTrusted
from .key_validation import compute_keyid, load_public_key, profile_of
from .trust_store_file_management import load_store_or_empty, save_store, load_store
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


def register(subparsers):
    p = subparsers.add_parser(
        "trust", help="Kelola trust store", allow_abbrev=False
    )
    commands = p.add_subparsers(dest="trust_command", required=True, metavar="command")

    add_parser = commands.add_parser(
        "add", help="Tambahkan public key ke trust store", allow_abbrev=False
    )
    add_parser.add_argument("--store", required=True, metavar="TRUST.JSON")
    add_parser.add_argument("--key", required=True, metavar="PUBLIC.PEM")
    add_parser.add_argument("--package", required=True)
    add_parser.set_defaults(func=run_add)

    list_parser = commands.add_parser(
        "list", help="Tampilkan key dalam trust store", allow_abbrev=False
    )
    list_parser.add_argument("--store", required=True, metavar="TRUST.JSON")
    list_parser.set_defaults(func=run_list)

    remove_parser = commands.add_parser(
        "remove", help="Hapus key dari trust store", allow_abbrev=False
    )
    remove_parser.add_argument("--store", required=True, metavar="TRUST.JSON")
    remove_parser.add_argument("--keyid", required=True)
    remove_parser.set_defaults(func=run_remove)


def _read_public_key(path):
    try:
        with open(path, "rb") as public_key_file:
            return public_key_file.read()
    except OSError as error:
        raise InputError(f"cannot read public key {path}: {error}") from error


def _entry_to_dict(entry: TrustStoreKey) -> dict:
    return {
        "keyid": entry.keyid,
        "algorithm": entry.algorithm,
        "public_key_pem": entry.public_key_pem,
        "packages": list(entry.packages),
    }


def run_add(args) -> int:
    try:
        store = load_store_or_empty(args.store)
        result = add(store, _read_public_key(args.key), args.package)
        if result.changed:
            save_store(args.store, result.store)
        print(result.entry.keyid)
        return 0
    except (InputError, FormatError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2 if isinstance(error, InputError) else 1


def run_list(args) -> int:
    try:
        store = load_store_or_empty(args.store)
        entries = [_entry_to_dict(entry) for entry in list_keys(store)]
        for entry in entries:
            packages = ", ".join(entry["packages"])
            print(f'{entry["keyid"]} {entry["algorithm"]} [{packages}]')
        return 0
    except (InputError, FormatError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2 if isinstance(error, InputError) else 1


def run_remove(args) -> int:
    try:
        store = load_store(args.store)
        save_store(args.store, remove(store, args.keyid))
        print(args.keyid)
        return 0
    except (InputError, FormatError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2 if isinstance(error, InputError) else 1