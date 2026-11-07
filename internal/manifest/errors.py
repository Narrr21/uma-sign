class ManifestError(Exception):
    """Base class for manifest-related errors."""


class ManifestValidationError(ManifestError):
    """A manifest cannot be produced because its values are invalid."""


class ManifestFormatError(ManifestError):
    """Manifest input is malformed or is not in canonical form."""