"""Copia una password negli appunti e la cancella da sola dopo N secondi.

Come funziona:
1. scriviamo il testo con NSPasteboard (AppKit via pyobjc), dichiarando
   anche due tipi "marcatore" della convenzione nspasteboard.org:
   - org.nspasteboard.ConcealedType: il contenuto è riservato, non mostrarlo;
   - org.nspasteboard.TransientType: non salvarlo nella cronologia.
   I gestori di appunti più diffusi (Maccy, Raycast, Paste...) li rispettano;
   `pbcopy` non permette di dichiararli.
2. teniamo il `changeCount` restituito dalla nostra scrittura: macOS lo
   incrementa a ogni scrittura negli appunti, da qualsiasi app.
3. avviamo un piccolo processo staccato (`python -I -m hsm.clipboard`) che
   aspetta fino a una scadenza e poi svuota gli appunti SOLO se il
   `changeCount` è ancora il nostro: se nel frattempo hai copiato altro,
   non lo tocca.
4. il processo ci conferma di essere pronto scrivendo un byte su una pipe.
   Se la conferma non arriva (es. è morto all'avvio), svuotiamo subito.

Al processo staccato passiamo solo il numero e la scadenza. Non riceve la
password né un suo hash: un hash in chiaro negli argomenti (visibili con
`ps`) sarebbe un bersaglio per il brute force offline.

La scadenza è un istante sull'orologio reale, non "dormi 30 s": su macOS
time.sleep non conta il tempo in cui il Mac è in stop, e con il coperchio
chiuso i 30 s diventerebbero ore. Dormiamo a passi brevi e ricontrolliamo.

Limiti: chi legge gli appunti nei N secondi (qualsiasi app) vede la
password; un gestore che ignora i marcatori la registra comunque; se il
watchdog viene ucciso (logout, kill) nessuno cancella (al logout però gli
appunti vengono comunque svuotati dal sistema). Tra il controllo del
changeCount e lo svuotamento c'è una finestra minima: non esiste un'API
atomica per farlo.
"""

import argparse
import os
import select
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from hsm.errors import HsmError
from hsm.secret import Secret

STRING_TYPE = "public.utf8-plain-text"  # NSPasteboardTypeString
CONCEALED_TYPE = "org.nspasteboard.ConcealedType"
TRANSIENT_TYPE = "org.nspasteboard.TransientType"

DEFAULT_SECONDS = 30
_MAX_SECONDS = 600
# Passo massimo di attesa del watchdog: dopo un risveglio dallo stop, la
# cancellazione arriva entro questo tempo.
_STEP_SECONDS = 2.0
# Tempo concesso al watchdog per avviarsi e importare AppKit.
_READY_TIMEOUT = 5.0

Spawn = Callable[..., Any]


def _general_pasteboard() -> Any:
    try:
        import AppKit  # import pigro: solo macOS, solo quando serve davvero
    except ImportError:
        raise HsmError("pyobjc (AppKit) non disponibile: non posso usare gli appunti.") from None
    return AppKit.NSPasteboard.generalPasteboard()


def _spawn_detached(argv: list[str], **kwargs: Any) -> None:
    # Non conserviamo il Popen: hsm è un comando breve, e quando termina il
    # watchdog viene adottato da launchd, che ne raccoglie l'uscita.
    subprocess.Popen(argv, **kwargs)


class Clipboard:
    """Appunti di sistema con cancellazione automatica."""

    def __init__(
        self,
        *,
        pasteboard: Any = None,
        spawn: Spawn = _spawn_detached,
        clock: Callable[[], float] = time.time,
        ready_timeout: float = _READY_TIMEOUT,
    ) -> None:
        self._pasteboard = pasteboard
        self._spawn = spawn
        self._clock = clock
        self._ready_timeout = ready_timeout

    def copy_with_autoclear(self, secret: Secret, seconds: int = DEFAULT_SECONDS) -> None:
        """Copia `secret` e programma la cancellazione dopo `seconds`.

        Se qualcosa va storto dopo la scrittura, anche un Ctrl-C, gli
        appunti vengono svuotati prima di propagare l'errore: la password
        non deve mai restarci senza un watchdog.
        """
        if not 1 <= seconds <= _MAX_SECONDS:
            raise ValueError(f"seconds deve essere tra 1 e {_MAX_SECONDS}")
        try:
            # bytes(...), poi str, poi l'NSString di pyobjc: tre copie
            # immutabili che non possiamo azzerare (limite noto).
            text = bytes(secret.view()).decode("utf-8")
        except UnicodeDecodeError:
            raise HsmError("La password non è UTF-8 valido: non posso copiarla.") from None

        pb = self._pasteboard if self._pasteboard is not None else _general_pasteboard()
        expected: int | None = None
        try:
            # declareTypes svuota gli appunti e restituisce il nuovo
            # changeCount: è quello della NOSTRA scrittura. Rileggerlo dopo
            # rischierebbe di catturare la scrittura di un'altra app.
            expected = pb.declareTypes_owner_([STRING_TYPE, CONCEALED_TYPE, TRANSIENT_TYPE], None)
            written = (
                pb.setString_forType_(text, STRING_TYPE)
                and pb.setString_forType_("", CONCEALED_TYPE)
                and pb.setString_forType_("", TRANSIENT_TYPE)
            )
            del text
            if not written:
                raise HsmError("Impossibile scrivere negli appunti.")
            if pb.changeCount() != expected:
                raise HsmError(
                    "Un'altra app ha scritto negli appunti durante la copia: riprova."
                )
            self._start_watchdog(expected, self._clock() + seconds)
        except BaseException as exc:
            if expected is not None:
                # Solo se gli appunti contengono ancora la nostra scrittura:
                # una copia fatta dall'utente nel frattempo non si tocca.
                clear_if_unchanged(pb, expected=expected)
            if isinstance(exc, HsmError) or not isinstance(exc, Exception):
                raise  # HsmError, KeyboardInterrupt, SystemExit: così come sono
            raise HsmError(
                f"Errore durante la copia negli appunti ({type(exc).__name__})."
            ) from None

    def _start_watchdog(self, expected: int, deadline: float) -> None:
        read_fd, write_fd = os.pipe()
        try:
            argv = [
                sys.executable,
                # -I: modalità isolata, ignora PYTHONPATH e la directory
                # corrente, così nessun modulo "hsm" finto può sostituirsi.
                "-I",
                "-m",
                "hsm.clipboard",
                "--expect",
                str(expected),
                "--deadline",
                repr(deadline),
                "--ready-fd",
                str(write_fd),
            ]
            try:
                self._spawn(
                    argv,
                    # Nuova sessione: niente Ctrl-C dal terminale, e il
                    # processo sopravvive alla sua chiusura.
                    start_new_session=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(write_fd,),
                )
            except (OSError, subprocess.SubprocessError):
                raise HsmError(
                    "Non posso avviare la cancellazione automatica degli appunti: "
                    "li ho svuotati per sicurezza."
                ) from None
            # Chiudiamo la nostra copia del lato di scrittura: se il figlio
            # muore senza scrivere, la lettura vede EOF subito, senza attese.
            os.close(write_fd)
            write_fd = -1
            if not _wait_ready(read_fd, self._ready_timeout):
                raise HsmError(
                    "La cancellazione automatica degli appunti non è partita: "
                    "li ho svuotati per sicurezza."
                )
        finally:
            os.close(read_fd)
            if write_fd != -1:
                os.close(write_fd)


def _wait_ready(fd: int, timeout: float) -> bool:
    readable, _, _ = select.select([fd], [], [], timeout)
    return bool(readable) and os.read(fd, 1) == b"1"


def clear_if_unchanged(pasteboard: Any, *, expected: int) -> bool:
    """Svuota gli appunti se nessuno li ha modificati dopo di noi."""
    if pasteboard.changeCount() != expected:
        return False
    pasteboard.clearContents()
    return True


def main(
    argv: Sequence[str] | None = None,
    *,
    pasteboard: Any = None,
    sleep: Callable[[float], object] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> int:
    """Entry point del watchdog: `python -I -m hsm.clipboard --expect N --deadline T`."""
    parser = argparse.ArgumentParser(
        prog="python -m hsm.clipboard",
        description="Svuota gli appunti a una scadenza, se non sono cambiati.",
    )
    parser.add_argument("--expect", type=int, required=True, help="changeCount atteso")
    parser.add_argument("--deadline", type=float, required=True, help="scadenza (epoch, secondi)")
    parser.add_argument("--ready-fd", type=int, help="fd su cui confermare l'avvio")
    args = parser.parse_args(argv)
    now = clock()
    if not now - _MAX_SECONDS <= args.deadline <= now + _MAX_SECONDS:
        parser.error("--deadline fuori intervallo")

    # Prima tutto ciò che può fallire (import di AppKit), poi la conferma:
    # il padre deve saperlo se non siamo in grado di cancellare.
    pb = pasteboard if pasteboard is not None else _general_pasteboard()
    if args.ready_fd is not None:
        os.write(args.ready_fd, b"1")
        os.close(args.ready_fd)

    while (remaining := args.deadline - clock()) > 0:
        sleep(min(_STEP_SECONDS, remaining))
    clear_if_unchanged(pb, expected=args.expect)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
