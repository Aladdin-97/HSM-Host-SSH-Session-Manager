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

Password (caso secondario: il default è la chiave SSH):
- via `sshpass -d <fd>`: la password viaggia in una pipe anonima che solo
  il processo figlio eredita. Mai negli argomenti (visibili a tutti con
  `ps`) e mai in una variabile d'ambiente (leggibile da altri processi
  dello stesso utente e ereditata da ogni figlio).
- forziamo l'autenticazione a password: se la chiave SSH bastasse, sshpass
  non leggerebbe mai la pipe e la password resterebbe lì, ereditata da ssh.
- sshpass viene cercato solo in directory di sistema note, non nel PATH:
  un "sshpass" finto in una directory scrivibile riceverebbe la password.
- sshpass risponde a un solo prompt: con un jump host, il bastion deve
  accettare la chiave SSH.
- se sshpass non c'è lo diciamo, proponiamo di copiare la password negli
  appunti e ci colleghiamo comunque: l'utente la incolla al prompt.
"""

import ipaddress
import os
import signal
import stat
import subprocess
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from hsm.errors import HsmError
from hsm.inventory import Host, Inventory
from hsm.secret import Secret

SSH = "/usr/bin/ssh"

# Dove cerchiamo sshpass: Homebrew (Apple Silicon e Intel), poi il sistema.
SSHPASS_DIRS = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"), Path("/usr/bin"))

# Una password più lunga di così è certamente un errore; e resta molto sotto
# la capacità della pipe (16 KiB su macOS), quindi la scrittura non si blocca.
_MAX_PASSWORD = 4096

# Codici d'uscita di sshpass (vedi `man sshpass`).
_SSHPASS_BAD_PASSWORD = 5
_SSHPASS_UNKNOWN_HOST_KEY = 6

_FORCE_PASSWORD = ["-o", "PreferredAuthentications=password,keyboard-interactive"]

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _run(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    """Esegue la sessione nel terminale corrente e ne attende la fine.

    Durante la sessione Ctrl-C deve arrivare a ssh, non a noi: se Python
    reagisse, subprocess ucciderebbe il figlio diretto (sshpass) lasciando
    ssh orfano e il terminale in modalità raw. Per questo ignoriamo SIGINT,
    ma solo DOPO aver avviato il figlio: SIG_IGN si eredita, e ssh non
    potrebbe più essere interrotto.
    """
    proc = subprocess.Popen(list(argv), **kwargs)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        returncode = proc.wait()
    finally:
        signal.signal(signal.SIGINT, previous)
    return subprocess.CompletedProcess(list(argv), returncode)


def find_sshpass(dirs: Iterable[Path] = SSHPASS_DIRS) -> str | None:
    """Il percorso di un sshpass affidabile, o None.

    Affidabile = file regolare eseguibile, di root o dell'utente, non
    scrivibile da gruppo o altri, in una directory con le stesse regole.
    Seguiamo i symlink (Homebrew li usa) e controlliamo la destinazione.
    """
    for directory in dirs:
        candidate = directory / "sshpass"
        try:
            real = candidate.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            continue
        if _trusted(real, directory=False) and _trusted(real.parent, directory=True) and _trusted(
            directory, directory=True
        ):
            return str(real)
    return None


def _trusted(path: Path, *, directory: bool) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    if directory != stat.S_ISDIR(st.st_mode):
        return False
    if not directory and not (stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IXUSR):
        return False
    return st.st_uid in (0, os.getuid()) and not st.st_mode & 0o022


def build_argv(
    host: Host,
    inventory: Inventory,
    *,
    password_auth: bool = False,
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
    if password_auth:
        argv += _FORCE_PASSWORD
    argv += ["--", host.hostname]
    return argv


class Connector:
    """Lancia ssh (o sshpass + ssh). Le dipendenze esterne sono iniettabili."""

    def __init__(
        self,
        *,
        runner: Runner = _run,
        find_sshpass: Callable[[], str | None] = find_sshpass,
        warn: Callable[[str], None],
        clipboard_fallback: Callable[[Secret], None] | None = None,
        confirm: Callable[[str], bool] | None = None,
    ) -> None:
        self._runner = runner
        self._find_sshpass = find_sshpass
        self._warn = warn
        self._clipboard_fallback = clipboard_fallback
        self._confirm = confirm

    def connect(self, host: Host, inventory: Inventory, *, password: Secret | None = None) -> int:
        """Apre la sessione e restituisce il codice d'uscita (stile shell)."""
        if password is None:
            return self._spawn(build_argv(host, inventory, warn=self._warn))

        # Un memoryview contiene interi: `b"\n" in view` sarebbe sempre False.
        view = password.view()
        if 0x0A in view or 0x0D in view:
            raise HsmError("La password contiene un a capo: sshpass non può usarla.")
        if len(password) > _MAX_PASSWORD:
            raise HsmError("La password è troppo lunga per essere passata a sshpass.")
        argv = build_argv(host, inventory, password_auth=True, warn=self._warn)
        if host.jump_host is not None:
            self._warn(
                f"La password vale solo per {host.alias}: il jump host deve accettare "
                "la tua chiave SSH (sshpass risponde a un solo prompt)."
            )

        sshpass = self._find_sshpass()
        if sshpass is None:
            return self._connect_without_sshpass(argv, password)

        code = self._spawn_with_password(sshpass, argv, password)
        # sshpass restituisce anche il codice della sessione remota: un
        # `exit 5` sul server sarebbe indistinguibile, da qui il "probabilmente".
        if code == _SSHPASS_BAD_PASSWORD:
            self._warn(
                "sshpass ha restituito 5: probabilmente la password è stata rifiutata. "
                f"Quella nel vault è ancora valida? (hsm pw set {host.alias})"
            )
        elif code == _SSHPASS_UNKNOWN_HOST_KEY:
            self._warn(
                "sshpass ha restituito 6: probabilmente non può confermare la chiave "
                "dell'host sconosciuta. Collegati una volta senza password per "
                "verificarla e accettarla."
            )
        return code

    def _connect_without_sshpass(self, argv: list[str], password: Secret) -> int:
        self._warn(
            "sshpass non trovato in "
            + ", ".join(str(d) for d in SSHPASS_DIRS)
            + " (es. brew install hudochenkov/sshpass/sshpass): la password andrà "
            "digitata o incollata al prompt di ssh."
        )
        if (
            self._clipboard_fallback is not None
            and self._confirm is not None
            and self._confirm("Copio la password negli appunti? (verrà cancellata dopo 30 s)")
        ):
            self._clipboard_fallback(password)
        return self._spawn(argv)

    def _spawn_with_password(self, sshpass: str, argv: list[str], password: Secret) -> int:
        # Pipe anonima: non ha un nome sul filesystem, quindi nessun altro
        # processo può aprirla. La scriviamo tutta e chiudiamo il lato di
        # scrittura prima di lanciare sshpass: lui leggerà fino a EOF.
        read_fd, write_fd = os.pipe()
        try:
            try:
                _write_all(write_fd, password.view())
            finally:
                os.close(write_fd)
            # pass_fds: il figlio eredita solo questo descriptor (gli altri
            # di Python sono non ereditabili per default, PEP 446).
            return self._spawn([sshpass, "-d", str(read_fd), *argv], pass_fds=(read_fd,))
        finally:
            os.close(read_fd)

    def _spawn(self, argv: list[str], **kwargs: Any) -> int:
        try:
            code = self._runner(argv, **kwargs).returncode
        except FileNotFoundError:
            raise HsmError(f"{argv[0]} non trovato.") from None
        # Ucciso da un segnale: subprocess dà -N, la shell userebbe 128+N.
        return 128 - code if code < 0 else code


def _write_all(fd: int, data: memoryview) -> None:
    while data:
        written = os.write(fd, data)
        data = data[written:]


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
