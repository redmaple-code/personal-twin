"""Error types shared across the package.

All messages are written so they can be shown to a human *and* safely pasted
into an AI transcript: they never include field values.
"""

from __future__ import annotations


class TwinError(Exception):
    """Base class for user-facing errors. Exit code 1 by default."""

    exit_code = 1


class ConfigError(TwinError):
    exit_code = 2


class VaultError(TwinError):
    exit_code = 3


class AuthError(TwinError):
    exit_code = 4


class NotFoundError(TwinError):
    exit_code = 5


class AmbiguousMatchError(TwinError):
    exit_code = 6


class PolicyError(TwinError):
    """The requested operation is blocked by policy (e.g. reveal without TTY)."""

    exit_code = 7


class UnsupportedError(TwinError):
    exit_code = 8
