"""Errors shared by the converter modules."""


class ConversionError(RuntimeError):
    """The source profile cannot be converted safely."""
