"""Memorizza la chiave del vault nel login keychain di macOS via /usr/bin/security.

Cosa salviamo: la chiave derivata da Argon2id (32 byte, in esadecimale), non
la master password. Se l'item venisse letto, chi lo legge apre il vault ma
non scopre una password che potresti riusare altrove; in più gli unlock
successivi saltano Argon2.

Dove: un "generic password" con service `hsm` e account = `vault.key_id()`,
cioè un hash del salt. Dopo un rekey il salt cambia, quindi l'item vecchio
non viene più cercato (e unlock lo cancella).

Cosa NON fa questo modulo: non protegge l'item con la biometria. Un item
creato da `security` è leggibile senza prompt da qualunque processo che giri
come il tuo utente e invochi `security`. Il Touch ID davanti alla lettura
(touchid.py) è un controllo d'interfaccia, non un confine di sicurezza.
"""

import binascii
import re
import subprocess
from collections.abc import Callable, Sequence

from hsm.errors import HsmError
from hsm.secret import Secret
from hsm.vault import KEY_SIZE

SECURITY = "/usr/bin/security"
SERVICE = "hsm"
LABEL = "hsm-vault-key"

# `security` esce con 44 quando l'item non esiste (errSecItemNotFound).
_EXIT_NOT_FOUND = 44

# Il keychain può mostrare un dialog (keychain bloccato): diamo tempo
# all'utente di rispondere, ma non restiamo appesi per sempre.
_TIMEOUT_S = 60

# Service e account finiscono nella riga che `security -i` interpreta come
# comando: ammettiamo solo caratteri che non possono aprire nuove opzioni
# (niente "-" iniziale), spezzare argomenti (spazi) o comandi (a capo).
_KEY_ID_RE = re.compile(r"[0-9a-f]{1,64}")
_SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# Esattamente ciò che scriviamo noi: 64 cifre esadecimali minuscole. Più
# rigido di bytearray.fromhex, che tollera spazi e maiuscole.
_HEX_KEY_RE = re.compile(rb"[0-9a-f]{%d}" % (2 * KEY_SIZE))

# Quanto di stderr riportiamo all'utente.
_MAX_REASON = 200

Runner = Callable[[Sequence[str], bytes | bytearray | None], subprocess.CompletedProcess[bytes]]


class KeychainError(HsmError):
    """Il Keychain ha risposto con un errore."""


class KeychainUnavailable(KeychainError):
    """Il Keychain non è utilizzabile su questo sistema."""


def _run(
    argv: Sequence[str], stdin: bytes | bytearray | None
) -> subprocess.CompletedProcess[bytes]:
    # Niente shell: argv va al processo così com'è, senza interpretazione.
    if stdin is None:
        # Senza input chiudiamo stdin: `security` non deve poter leggere (o
        # restare in attesa di) ciò che l'utente digita nel terminale.
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_TIMEOUT_S,
        )
    return subprocess.run(
        list(argv), input=stdin, capture_output=True, check=False, timeout=_TIMEOUT_S
    )


class Keychain:
    """Accesso alla chiave del vault salvata nel login keychain."""

    def __init__(
        self, service: str = SERVICE, *, security: str = SECURITY, runner: Runner = _run
    ) -> None:
        if not _SERVICE_RE.fullmatch(service):
            raise ValueError(f"Nome di service non valido: {service!r}")
        self._service = service
        self._security = security
        self._runner = runner

    def store_key(self, key_id: str, key: Secret) -> None:
        """Salva (o aggiorna) la chiave del vault identificata da `key_id`."""
        _check_key_id(key_id)
        if len(key) != KEY_SIZE:
            raise ValueError(f"La chiave deve essere di {KEY_SIZE} byte")
        # `security add-generic-password -w <segreto>` metterebbe il segreto
        # nella riga di comando, leggibile da chiunque con `ps`. Con `-i`
        # security legge i comandi da stdin, e stdin è privato del processo.
        # -U aggiorna l'item se esiste già invece di fallire.
        command = bytearray(
            f"add-generic-password -U -s {self._service} -a {key_id} -l {LABEL} -w ".encode()
        )
        # Azzeramento "best effort": hexlify produce comunque una copia
        # immutabile della chiave in esadecimale, che non possiamo cancellare.
        # Passiamo il bytearray così com'è per non crearne un'altra.
        command += binascii.hexlify(key.view())
        command += b"\n"
        try:
            result = self._call(["-i"], stdin=command, writing=True)
        finally:
            command[:] = bytes(len(command))
        if result.returncode != 0:
            # Volutamente senza stderr: in modalità -i potrebbe riportare
            # pezzi del comando, e il comando contiene la chiave.
            raise KeychainError(
                f"Impossibile salvare la chiave nel Keychain (codice {result.returncode})."
            )

    def load_key(self, key_id: str) -> Secret | None:
        """Restituisce la chiave salvata, o None se l'item non esiste."""
        _check_key_id(key_id)
        # -w stampa solo il segreto su stdout, che leggiamo via pipe.
        result = self._call(["find-generic-password", "-s", self._service, "-a", key_id, "-w"])
        if result.returncode == _EXIT_NOT_FOUND:
            return None
        if result.returncode != 0:
            raise KeychainError(f"Lettura dal Keychain fallita: {_reason(result)}")
        out = result.stdout
        if out.endswith(b"\n"):  # security aggiunge un solo a capo finale
            out = out[:-1]
        if not _HEX_KEY_RE.fullmatch(out):
            raise KeychainError("Item del Keychain non valido: formato inatteso.")
        # stdout (bytes immutabili) resta in memoria fino al GC: limite noto.
        return Secret(bytearray.fromhex(out.decode("ascii")))

    def delete_key(self, key_id: str) -> bool:
        """Cancella l'item. True se esisteva, False se non c'era."""
        _check_key_id(key_id)
        result = self._call(["delete-generic-password", "-s", self._service, "-a", key_id])
        if result.returncode == _EXIT_NOT_FOUND:
            return False
        if result.returncode != 0:
            raise KeychainError(f"Cancellazione dal Keychain fallita: {_reason(result)}")
        return True

    def _call(
        self, args: list[str], stdin: bytearray | None = None, *, writing: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return self._runner([self._security, *args], stdin)
        except FileNotFoundError:
            raise KeychainUnavailable(
                f"{self._security} non trovato: Keychain non disponibile."
            ) from None
        except subprocess.TimeoutExpired:
            msg = f"Il Keychain non ha risposto entro {_TIMEOUT_S} s."
            if writing:
                # Il processo è stato ucciso a metà: l'item potrebbe essere
                # stato scritto oppure no.
                msg += " Lo stato dell'item è incerto: verrà riscritto al prossimo unlock."
            raise KeychainError(msg) from None
        except (OSError, subprocess.SubprocessError) as exc:
            # Binario non eseguibile, fork fallita, ecc. Tutto diventa
            # KeychainError, così unlock può sempre ripiegare sulla password.
            raise KeychainError(
                f"Impossibile eseguire {self._security} ({type(exc).__name__})."
            ) from None


def _check_key_id(key_id: str) -> None:
    if not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError(f"key_id non valido: {key_id!r}")


def _reason(result: subprocess.CompletedProcess[bytes]) -> str:
    """Prima riga di stderr, utile all'utente (es. "User interaction is not allowed")."""
    lines = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
    if not lines:
        return f"codice {result.returncode}"
    # stderr è testo esterno che finisce sul terminale: togliamo i caratteri
    # di controllo (es. sequenze ANSI) e tagliamo le righe troppo lunghe.
    return "".join(c for c in lines[0] if c.isprintable())[:_MAX_REASON]
