class TrustError(Exception):
    status = None
    exit_code = None


class InputError(TrustError):
    status = "INPUT_ERROR"
    exit_code = 2


class KeyIdNotFound(InputError):
    pass


class FormatError(TrustError):
    status = "FORMAT_ERROR"
    exit_code = 1


class KeyNotTrusted(TrustError):
    status = "KEY_NOT_TRUSTED"
    exit_code = 1
