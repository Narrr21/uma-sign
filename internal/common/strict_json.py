import json

from internal.trust.errors import FormatError


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FormatError(f"duplicate field: {key}")
        result[key] = value
    return result


def loads(text: str):
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except FormatError:
        raise
    except ValueError as error:
        raise FormatError(f"invalid JSON: {error}") from error
