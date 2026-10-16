"""Errori di dominio di hsm e gestione delle eccezioni non catturate.

Ogni `HsmError` porta un messaggio scritto per l'utente finale: la CLI lo
stampa così com'è, senza traceback. Le eccezioni inattese invece vengono
ridotte al solo nome del tipo, perché il loro messaggio (o le variabili
locali di un traceback "ricco") potrebbe contenere una password.
"""

import sys
import traceback
from collections.abc import Callable
from types import TracebackType


class HsmError(Exception):
    """Errore previsto: il messaggio è destinato all'utente."""


class InsecurePermissionsError(HsmError):
    """Un file o una directory privata è accessibile ad altri utenti."""


class VaultError(HsmError):
    """Problema generico con il vault."""


class VaultFormatError(VaultError):
    """Il file non è un vault hsm valido o usa una versione non supportata."""


class VaultAuthError(VaultError):
    """Decifratura fallita: password sbagliata o file manomesso."""


ExceptHook = Callable[[type[BaseException], BaseException, TracebackType | None], None]


def make_excepthook(*, debug: bool) -> ExceptHook:
    """Costruisce un `sys.excepthook` che non espone dati sensibili.

    Con `debug=True` stampa il traceback standard di Python, che NON include
    le variabili locali (a differenza di rich/typer).
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
                f"hsm: errore interno ({exc_type.__name__}). "
                "Rilancia con --debug per i dettagli.",
                file=sys.stderr,
            )

    return hook
