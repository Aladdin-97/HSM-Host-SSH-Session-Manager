"""hsm domain errors and handling of uncaught exceptions.

Every `HsmError` carries a message written for the end user: the CLI prints
it as is, without a traceback. Unexpected exceptions, instead, are reduced to
just their type name, because their message (or the local variables of a
"rich" traceback) could contain a password.
"""

import sys
import traceback
from collections.abc import Callable
from types import TracebackType


class HsmError(Exception):
    """Expected error: the message is meant for the user."""


class InsecurePermissionsError(HsmError):
    """A private file or directory is accessible to other users."""


class VaultError(HsmError):
    """Generic problem with the vault."""


class VaultFormatError(VaultError):
    """The file is not a valid hsm vault or uses an unsupported version."""


class VaultAuthError(VaultError):
    """Decryption failed: wrong password or tampered file."""


ExceptHook = Callable[[type[BaseException], BaseException, TracebackType | None], None]


def make_excepthook(*, debug: bool) -> ExceptHook:
    """Build a `sys.excepthook` that does not expose sensitive data.

    With `debug=True` it prints Python's standard traceback, which does NOT
    include local variables (unlike rich/typer).
    """

    def hook(
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        if debug:
            traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
        elif issubclass(exc_type, KeyboardInterrupt):
            print(file=sys.stderr)
        elif issubclass(exc_type, HsmError):
            print(f"hsm: {exc}", file=sys.stderr)
        else:
            print(
                f"hsm: internal error ({exc_type.__name__}). "
                "Run again with --debug for details.",
                file=sys.stderr,
            )

    return hook
