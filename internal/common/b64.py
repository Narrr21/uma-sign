import base64
import binascii

from internal.trust.errors import FormatError


def strict_b64decode(s: str) -> bytes:
    try:
        data = base64.b64decode(s.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise FormatError(f"invalid Base64: {error}") from error
    if base64.b64encode(data).decode("ascii") != s:
        raise FormatError("Base64 is not in canonical form")
    return data
