"""Apre la sessione con /usr/bin/ssh, il client nativo del sistema.

Gli argomenti sono costruiti dai campi dell'host, quindi `hsm connect`
funziona anche senza aver mai fatto `hsm sync`:

    /usr/bin/ssh -l deploy -p 2222 -J jump@bastion:2200 \\
                 -i /Users/me/.ssh/id -o IdentitiesOnly=yes -- 10.0.0.1

Il `--` prima della destinazione dice a ssh che da lì in poi non ci sono
più opzioni: anche un hostname che iniziasse con "-" non verrebbe mai
interpretato come opzione (Host lo vieta già; questa è una seconda difesa).

Il jump_host può essere un alias dell'inventario: lo traduciamo in
`user@hostname:port` (e risaliamo la catena se il bastion ha a sua volta un
jump). Limite: l'identity_file del bastion vale solo dopo `hsm sync`,
perché -J usa la configurazione ssh per i salti intermedi.

Password (caso secondario: il default è la chiave SSH): ssh la chiede a
`hsm-askpass` tramite SSH_ASKPASS, senza programmi esterni (vedi
askpass.py). La password non passa mai dagli argomenti (visibili con `ps`)
né dall'ambiente; viene data solo alla domanda esatta dell'host di
destinazione, una volta. Ogni altra domanda (chiave host sconosciuta,
password del bastion, OTP) la vedi tu sul terminale.
"""

import contextlib
import getpass
import ipaddress
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from hsm.askpass import AskpassServer
from hsm.errors import HsmError
from hsm.inventory import Host, Inventory
from hsm.secret import Secret

SSH = "/usr/bin/ssh"

# Una password più lunga di così è certamente un errore.
_MAX_PASSWORD = 4096

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _run(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    """Esegue la sessione nel terminale corrente e ne attende la fine.

    Durante la sessione Ctrl-C deve arrivare a ssh, non a noi: se Python
    reagisse, subprocess ucciderebbe ssh lasciando il terminale in modalità
    raw. Per questo ignoriamo SIGINT, ma solo DOPO aver avviato il figlio:
    SIG_IGN si eredita, e ssh non potrebbe più essere interrotto.
    """
    on_spawn = kwargs.pop("on_spawn", None)
    proc = subprocess.Popen(list(argv), **kwargs)
    if on_spawn is not None:
        on_spawn(proc.pid)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        returncode = proc.wait()
    finally:
        signal.signal(signal.SIGINT, previous)
    return subprocess.CompletedProcess(list(argv), returncode)


def default_askpass_helper() -> Path:
    """`hsm-askpass` installato accanto all'interprete che esegue hsm.

    Cerchiamo lì e non nel PATH: è la console script dello stesso pacchetto,
    nello stesso virtualenv (o tool di uv). Un "hsm-askpass" finto nel PATH
    riceverebbe la password.
    """
    return Path(sys.executable).parent / "hsm-askpass"


def resolve_effective_names(argv: Sequence[str]) -> list[tuple[str, str]]:
    """(utente, host) effettivi secondo `ssh -G` per questi argomenti.

    ~/.ssh/config può cambiare HostName o User, e la domanda della password
    usa quei valori. `ssh -G` stampa la configurazione risolta senza
    collegarsi. Se fallisce non è grave: la password verrà chiesta a te.
    """
    try:
        result = subprocess.run(
            [SSH, "-G", *argv[1:]],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    values = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
    if "user" in values and "hostname" in values:
        return [(values["user"], values["hostname"])]
    return []


@contextlib.contextmanager
def _exit_on_termination() -> Iterator[None]:
    """SIGTERM/SIGHUP (es. finestra del terminale chiusa) diventano SystemExit.

    Il default ucciderebbe Python senza eseguire i `with`: resterebbe il
    socket in $TMPDIR e la password non verrebbe azzerata.
    """

    def stop(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def build_argv(
    host: Host,
    inventory: Inventory,
    *,
    warn: Callable[[str], None] | None = None,
) -> list[str]:
    """Gli argomenti di /usr/bin/ssh per `host`."""
    argv = [SSH]
    if host.user is not None:
        argv += ["-l", host.user]
    argv += ["-p", str(host.port)]
    hops = _jump_chain(host, inventory, seen={host.alias.casefold()}, warn=warn)
    if hops:
        argv += ["-J", ",".join(hops)]
    if host.identity_file is not None:
        # IdentitiesOnly: senza, ssh prova prima tutte le chiavi dell'agent e
        # il server può chiudere ("Too many authentication failures") prima
        # di arrivare a quella indicata.
        argv += ["-i", os.path.expanduser(host.identity_file), "-o", "IdentitiesOnly=yes"]
    argv += ["--", host.hostname]
    return argv


class Connector:
    """Lancia ssh. Le dipendenze esterne sono iniettabili per i test."""

    def __init__(
        self,
        *,
        runner: Runner = _run,
        warn: Callable[[str], None],
        askpass_helper: Callable[[], Path] = default_askpass_helper,
        local_user: Callable[[], str] = getpass.getuser,
        resolve: Callable[[Sequence[str]], list[tuple[str, str]]] = resolve_effective_names,
    ) -> None:
        self._runner = runner
        self._warn = warn
        self._askpass_helper = askpass_helper
        self._local_user = local_user
        self._resolve = resolve

    def connect(self, host: Host, inventory: Inventory, *, password: Secret | None = None) -> int:
        """Apre la sessione e restituisce il codice d'uscita (stile shell)."""
        argv = build_argv(host, inventory, warn=self._warn)
        if password is None:
            return self._spawn(argv)

        # Un memoryview contiene interi: `b"\n" in view` sarebbe sempre False.
        view = password.view()
        if 0x0A in view or 0x0D in view or 0x00 in view:
            raise HsmError("La password contiene un a capo: ssh non può riceverla.")
        if len(password) > _MAX_PASSWORD:
            raise HsmError("La password è troppo lunga.")
        helper = self._askpass_helper()
        if not (helper.is_file() and os.access(helper, os.X_OK)):
            raise HsmError(
                f"{helper} non trovato: reinstalla hsm (uv tool install --reinstall .) "
                "oppure, nel progetto, lancia uv sync."
            )
        if host.jump_host is not None:
            self._warn(
                f"La password salvata vale solo per {host.alias}: le altre richieste "
                "(es. il jump host) le inserisci tu."
            )

        # ssh usa l'utente locale quando `user` non è indicato: la domanda
        # che riconosciamo deve avere lo stesso nome.
        user = host.user if host.user is not None else self._local_user()
        server = AskpassServer(password, user=user, hostname=host.hostname, aliases=self._resolve(argv))
        with _exit_on_termination(), server:
            env = {**os.environ, **server.env(str(helper))}
            # on_spawn: il server deve conoscere il pid di ssh per dare la
            # password solo ai suoi helper (non al ssh del jump host).
            code = self._spawn(argv, env=env, on_spawn=server.expect_ssh)
        if server.rejected:
            self._warn(
                f"Il server ha rifiutato la password salvata per {host.alias}: "
                f"aggiornala con hsm pw set {host.alias}."
            )
        return code

    def _spawn(self, argv: list[str], **kwargs: Any) -> int:
        try:
            code = self._runner(argv, **kwargs).returncode
        except FileNotFoundError:
            raise HsmError(f"{argv[0]} non trovato.") from None
        # Ucciso da un segnale: subprocess dà -N, la shell userebbe 128+N.
        return 128 - code if code < 0 else code


def _find_alias(inventory: Inventory, name: str) -> Host | None:
    # ssh confronta gli alias senza maiuscole, e l'inventario li tiene unici
    # allo stesso modo: "Bastion" deve trovare "bastion".
    folded = name.casefold()
    return next((h for h in inventory.hosts() if h.alias.casefold() == folded), None)


def _jump_chain(
    host: Host,
    inventory: Inventory,
    *,
    seen: set[str],
    warn: Callable[[str], None] | None,
) -> list[str]:
    """I salti da passare a -J, dal più esterno al più interno."""
    if host.jump_host is None:
        return []
    jump = _find_alias(inventory, host.jump_host)
    if jump is None:
        # Non è un alias: valore letterale, già validato da Host.
        if warn is not None and _looks_like_alias(host.jump_host):
            warn(
                f"jump_host {host.jump_host!r} non è un alias dell'inventario: "
                "lo uso come nome host (è un refuso?)."
            )
        return [host.jump_host]
    if jump.alias.casefold() in seen:
        raise HsmError(f"Catena di jump_host con un ciclo: passa due volte da {jump.alias}.")
    return [*_jump_chain(jump, inventory, seen=seen | {jump.alias.casefold()}, warn=warn), _hop(jump)]


def _looks_like_alias(jump: str) -> bool:
    """Un nome senza punti che non è un IP: più probabilmente un alias sbagliato."""
    host = jump.rpartition("@")[2]
    if host.startswith("["):
        return False
    host = host.partition(":")[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." not in host
    return False


def _hop(host: Host) -> str:
    if "%" in host.hostname:
        raise HsmError(
            f"{host.alias}: un jump host con zona IPv6 ({host.hostname}) non è supportato da -J."
        )
    # In -J un IPv6 va tra parentesi quadre, altrimenti ":porta" è ambiguo.
    address = f"[{host.hostname}]" if ":" in host.hostname else host.hostname
    user = f"{host.user}@" if host.user is not None else ""
    return f"{user}{address}:{host.port}"
