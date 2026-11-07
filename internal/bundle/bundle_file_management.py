import base64
import json
import os
import tempfile

from internal.common.b64 import strict_b64decode
from internal.common.strict_json import loads
from internal.trust.errors import FormatError, InputError

from .bundle_structure import SCHEMA, Bundle

MAX_BUNDLE_SIZE = 64 * 1024

_FIELDS = {"schema", "manifest_b64", "signature_b64"}


def parse_bundle(raw: bytes) -> Bundle:
    if len(raw) > MAX_BUNDLE_SIZE:
        raise FormatError(f"bundle exceeds {MAX_BUNDLE_SIZE} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise FormatError("UTF-8 BOM is not allowed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FormatError("bundle is not valid UTF-8") from error

    value = loads(text)
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise FormatError("bundle must have exactly the fields: " + ", ".join(sorted(_FIELDS)))
    for name in _FIELDS:
        if not isinstance(value[name], str):
            raise FormatError(f"{name} must be a string")
    if value["schema"] != SCHEMA:
        raise FormatError(f'schema must be "{SCHEMA}"')

    return Bundle(
        schema=SCHEMA,
        manifest=strict_b64decode(value["manifest_b64"]),
        signature=strict_b64decode(value["signature_b64"]),
    )


def serialize_bundle(bundle: Bundle) -> bytes:
    document = {
        "schema": bundle.schema,
        "manifest_b64": base64.b64encode(bundle.manifest).decode("ascii"),
        "signature_b64": base64.b64encode(bundle.signature).decode("ascii"),
    }
    return json.dumps(document, indent=2).encode("utf-8")


def load_bundle(path) -> Bundle:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BUNDLE_SIZE + 1)
    except OSError as error:
        raise InputError(f"cannot read bundle {path}: {error}") from error
    return parse_bundle(raw)


def save_bundle(path, bundle: Bundle) -> None:
    data = serialize_bundle(bundle)
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
        raise InputError(f"cannot write bundle {path}: {error}") from error
    finally:
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
