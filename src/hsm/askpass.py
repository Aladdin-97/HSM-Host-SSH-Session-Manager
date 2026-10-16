"""Password automatica per ssh tramite SSH_ASKPASS, senza sshpass.

OpenSSH sa chiedere la password a un programma esterno invece che al
terminale: con SSH_ASKPASS=<programma> e SSH_ASKPASS_REQUIRE=force, a ogni
domanda ssh lancia `<programma> "<testo della domanda>"` e legge la risposta
dal suo stdout. Il programma qui è `hsm-askpass` (la funzione `main` sotto).

    hsm connect ──► AskpassServer (socket Unix privato, solo durante il connect)
        │                    ▲
        └─► /usr/bin/ssh ──► hsm-askpass "admin@10.0.0.9's password: "
                                 │  token + domanda ──►  server
                                 │  ◄── password / "chiedi all'utente" / "no"
                                 └─► stdout ──► ssh

Perché un socket: ssh chiude all'avvio tutti i file descriptor oltre
stdin/stdout/stderr, quindi una pipe passata da hsm non arriverebbe
all'helper (cosa che invece funzionava con sshpass).

Le regole, tutte verificate dai test:
- la password va SOLO alla domanda esatta "<user>@<host>'s password: " (o
  "(<user>@<host>) Password: ", keyboard-interactive) dell'host di
  destinazione, e SOLO a un helper figlio del processo ssh principale. Il
  pid lo verifica il kernel (LOCAL_PEERPID), non lo dichiara l'helper.
  Così il ssh figlio che ssh lancia per un jump host (-J) non la riceve,
  nemmeno se quel bastion avesse lo stesso user@host su un'altra porta;
- tutto il resto (conferma della chiave host, password del bastion, OTP,
  passphrase) viene girato a te sul terminale. La conferma di una chiave
  host sconosciuta non riceve MAI risposta automatica: un "yes" automatico
  accetterebbe un server qualsiasi (verificato: con SSH_ASKPASS_REQUIRE=force
  anche quella domanda passa da qui);
- il testo delle domande può venire dal server (keyboard-interactive):
  prima di mostrarlo togliamo i caratteri di controllo, e la risposta si
  vede mentre la scrivi solo per la vera domanda di ssh sulla chiave host;
- la password viene fornita una volta sola: se ssh la richiede, era
  sbagliata, e la parola passa a te;
- niente segreti nell'ambiente: ssh e l'helper ricevono solo il percorso
  del socket e un token casuale, che senza il server attivo non vale nulla;
- il socket vive in una directory 0700 creata per l'occasione e viene
  rimosso a fine connessione.

Limite: i processi che ssh lancia per conto tuo (ProxyCommand, LocalCommand,
`Match exec` del tuo ~/.ssh/config) sono anch'essi figli di ssh ed ereditano
token e socket: potrebbero chiedere la password al posto dell'helper. Sono
comandi che hai configurato tu e girano con il tuo utente, cioè dentro il
confine di fiducia di hsm (vedi THREAT_MODEL.md).
"""

import contextlib
import getpass
import hmac
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from types import FrameType, TracebackType
from typing import BinaryIO, Self

from hsm.errors import HsmError
from hsm.secret import Secret

ENV_SOCKET = "HSM_ASKPASS_SOCKET"
ENV_TOKEN = "HSM_ASKPASS_TOKEN"

# Risposte del server all'helper (un byte di tipo, poi l'eventuale dato).
_PASSWORD = b"P"
_ASK_USER = b"A"
_DENY = b"D"

_MAX_REQUEST = 16 * 1024
_IO_TIMEOUT = 5.0

# macOS: getsockopt(SOL_LOCAL, LOCAL_PEERPID) restituisce il pid del
# processo all'altro capo di un socket Unix, garantito dal kernel.
_SOL_LOCAL = 0
_LOCAL_PEERPID = 2

_HOST_KEY_QUESTION = re.compile(
    r"The authenticity of host [^\n]*\n.*"
    r"Are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)\? ",
    re.DOTALL,
)

Relay = Callable[[str], str | None]
Notify = Callable[[str], None]


def is_password_prompt(prompt: str, *, user: str, hostname: str) -> bool:
    """True solo per la domanda di password di `user@hostname`.

    Confronto esatto sull'intera stringa: un testo che contiene la domanda
    in mezzo ad altro (o seguita da un'altra domanda) non vale.
    """
    target = f"{re.escape(user)}@{re.escape(hostname)}"
    # Autenticazione "password":        admin@10.0.0.9's password:
    # Keyboard-interactive (OpenSSH 8+): (admin@10.0.0.9) Password:
    pattern = rf"{target}'s password: |\({target}\) (?i:password): ?"
    return re.fullmatch(pattern, prompt) is not None


def is_host_key_question(prompt: str) -> bool:
    """True per la domanda di ssh su una chiave host sconosciuta.

    Un server non può imitarla: il testo keyboard-interactive che sceglie
    arriva sempre prefissato da ssh con "(user@host) ".
    """
    return _HOST_KEY_QUESTION.fullmatch(prompt) is not None


def _printable(text: str) -> str:
    """Il testo senza caratteri di controllo (sequenze ANSI, BEL...), a capo esclusi."""
    return "".join(c for c in text if c == "\n" or c.isprintable())


def _parent_pid(pid: int) -> int | None:
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "ppid=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=_IO_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = result.stdout.strip()
    return int(text) if result.returncode == 0 and text.isdigit() else None


class AskpassServer:
    """Serve la password a hsm-askpass per la durata di un `with`."""

    def __init__(
        self,
        password: Secret,
        *,
        user: str,
        hostname: str,
        aliases: Iterable[tuple[str, str]] = (),
        pid_wait: float = 2.0,
    ) -> None:
        view = password.view()
        if 0x0A in view or 0x0D in view or 0x00 in view:
            # ssh legge una riga dallo stdout dell'helper: un a capo la
            # spezzerebbe.
            raise ValueError("la password contiene un a capo o un byte nullo")
        self._password = Secret(bytearray(view))  # copia propria, azzerata in __exit__
        # Le coppie (utente, host) con cui ssh può presentare la domanda:
        # quelle dell'inventario e quelle effettive secondo `ssh -G`.
        self._names = {(user, hostname), *aliases}
        self._token = secrets.token_hex(32)
        self._answered = False
        self._ssh_pid: int | None = None
        self._ssh_known = threading.Event()
        self._pid_wait = pid_wait
        self._stop = threading.Event()
        self._dir: Path | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        #: quante volte ssh ha richiesto la password dopo averla già ricevuta
        self.rejected = 0

    def expect_ssh(self, pid: int) -> None:
        """Il pid del processo ssh principale: solo i suoi helper ricevono la password."""
        self._ssh_pid = pid
        self._ssh_known.set()

    def __enter__(self) -> Self:
        # mkdtemp crea la directory con permessi 0700: solo noi possiamo
        # anche solo vedere il socket. Sta in $TMPDIR, che su macOS è già
        # per-utente (/var/folders/...).
        self._dir = Path(tempfile.mkdtemp(prefix="hsm-askpass-"))
        path = self._dir / "s"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(path))
            os.chmod(path, 0o600)
            sock.listen(8)
            sock.settimeout(0.2)  # per poter controllare _stop
        except OSError as exc:
            sock.close()
            self._cleanup()
            # Il caso tipico: percorso oltre i ~104 byte ammessi per un socket Unix.
            raise HsmError(
                f"Impossibile creare il socket per la password ({exc.strerror}). "
                "Se TMPDIR è un percorso molto lungo, usane uno più corto."
            ) from None
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="hsm-askpass", daemon=True)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if self._sock is not None:
            self._sock.close()
        self._cleanup()
        self._password.wipe()

    def env(self, helper: str) -> dict[str, str]:
        """Le variabili da aggiungere all'ambiente di ssh. Nessun segreto."""
        if self._dir is None:
            raise RuntimeError("AskpassServer va usato dentro un `with`")
        return {
            "SSH_ASKPASS": helper,
            # force: usa l'helper anche se c'è un terminale (OpenSSH ≥ 8.4).
            "SSH_ASKPASS_REQUIRE": "force",
            ENV_SOCKET: str(self._dir / "s"),
            ENV_TOKEN: self._token,
        }

    def _cleanup(self) -> None:
        if self._dir is None:
            return
        (self._dir / "s").unlink(missing_ok=True)
        self._dir.rmdir()
        self._dir = None

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return  # socket chiuso
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    pass  # helper sparito o lento: semplicemente non riceve nulla

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_IO_TIMEOUT)
        token, sep, rest = _recv_all(conn).partition(b"\0")
        kind, sep2, raw_prompt = rest.partition(b"\0")
        if not (sep and sep2) or not hmac.compare_digest(token, self._token.encode()):
            conn.sendall(_DENY)
            return
        prompt = raw_prompt.decode("utf-8", errors="replace")
        # kind non vuoto = domanda di conferma o informativa (SSH_ASKPASS_PROMPT):
        # mai una password.
        if kind or not any(
            is_password_prompt(prompt, user=u, hostname=h) for u, h in self._names
        ):
            conn.sendall(_ASK_USER)
            return
        if not self._from_main_ssh(conn):
            conn.sendall(_ASK_USER)
            return
        if self._answered:
            # ssh la richiede: quella che abbiamo dato era sbagliata.
            self.rejected += 1
            conn.sendall(_ASK_USER)
            return
        self._deliver(conn)
        # Solo dopo un invio riuscito: se l'helper è sparito a metà, la
        # prossima richiesta riceve ancora la password.
        self._answered = True

    def _from_main_ssh(self, conn: socket.socket) -> bool:
        """L'helper all'altro capo è figlio del processo ssh principale?"""
        if not self._ssh_known.wait(self._pid_wait):
            return False
        try:
            peer = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID)
        except OSError:
            return False  # senza la verifica del kernel, niente password
        return _parent_pid(peer) == self._ssh_pid

    def _deliver(self, conn: socket.socket) -> None:
        conn.sendall(_PASSWORD)
        conn.sendall(self._password.view())


def _recv_all(conn: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size <= _MAX_REQUEST and (chunk := conn.recv(4096)):
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:_MAX_REQUEST]


def _request(path: str, token: str, kind: str, prompt: str) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(_IO_TIMEOUT)
        sock.connect(path)
        payload = b"\0".join(
            [token.encode(), kind.encode(), prompt.encode("utf-8", errors="replace")]
        )
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        return _recv_all(sock)


@contextlib.contextmanager
def _restore_tty_on_sigterm() -> Iterator[None]:
    # ssh può terminare l'helper con SIGTERM mentre aspetta una risposta.
    # Il default ucciderebbe il processo senza eseguire i `finally` di
    # getpass, lasciando il terminale senza eco: lo trasformiamo in SystemExit.
    def stop(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    try:
        previous = signal.signal(signal.SIGTERM, stop)
    except ValueError:  # non siamo nel thread principale (es. nei test)
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _relay_to_tty(prompt: str) -> str | None:
    """Gira la domanda all'utente sul terminale. None se non c'è un terminale."""
    shown = _printable(prompt)
    try:
        tty = open("/dev/tty", "r+", encoding="utf-8", errors="replace")  # noqa: SIM115
    except OSError:
        return None
    with tty:
        if is_host_key_question(prompt):
            # Conferma della chiave host: la risposta si vede mentre la scrivi.
            tty.write(shown)
            tty.flush()
            line = tty.readline()
            return line.rstrip("\n") if line else None
    try:
        with _restore_tty_on_sigterm():
            return getpass.getpass(shown)  # legge da /dev/tty senza eco
    except EOFError:
        return None


def _notify_tty(text: str) -> None:
    with contextlib.suppress(OSError), open("/dev/tty", "w", encoding="utf-8") as tty:
        tty.write(_printable(text) + "\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdout: BinaryIO | None = None,
    relay: Relay | None = None,
    notify: Notify | None = None,
) -> int:
    """Entry point di `hsm-askpass`, lanciato da ssh con la domanda come argomento."""
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    out = stdout if stdout is not None else sys.stdout.buffer
    ask_user = relay if relay is not None else _relay_to_tty
    show = notify if notify is not None else _notify_tty
    prompt = argv[1] if len(argv) > 1 else ""
    kind = env.get("SSH_ASKPASS_PROMPT", "")

    if kind == "none":
        # Solo informativa (es. "tocca la chiave di sicurezza"): ssh non
        # aspetta risposta e chiuderà l'helper quando non serve più.
        show(prompt)
        return 0

    reply: bytes | None = None
    path, token = env.get(ENV_SOCKET), env.get(ENV_TOKEN)
    if path and token:
        try:
            reply = _request(path, token, kind, prompt)
        except OSError:
            reply = None  # server non raggiungibile: si chiede all'utente
    if reply is not None and reply.startswith(_PASSWORD):
        # `reply` è una copia immutabile della password: limite noto, vive
        # solo fino alla fine di questo processo, che termina subito.
        out.write(reply[len(_PASSWORD) :] + b"\n")
        out.flush()
        return 0
    if reply == _DENY:
        return 1
    answer = ask_user(prompt)
    if answer is None:
        return 1  # nessuna risposta: per ssh vale "no"
    out.write(answer.encode("utf-8") + b"\n")
    out.flush()
    return 0
