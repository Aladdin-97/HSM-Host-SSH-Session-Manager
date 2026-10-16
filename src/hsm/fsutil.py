"""Operazioni su file privati: controllo dei permessi e scrittura atomica.

Regola: i file di hsm sono 0600, le directory 0700, il proprietario è
l'utente corrente e non sono symlink. Se una condizione non vale ci
rifiutiamo di procedere e diciamo come correggere: non sistemiamo da soli,
perché un permesso sbagliato può essere il segno di qualcosa da capire.
"""

import contextlib
import errno
import fcntl
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from hsm.errors import HsmError, InsecurePermissionsError

# Nessun file di hsm si avvicina a questa soglia: oltre, qualcosa non va e
# non vogliamo caricarlo tutto in memoria.
MAX_READ_SIZE = 16 * 1024 * 1024


def _verify(st: os.stat_result, path: Path) -> None:
    """Applica la regola dei permessi a un risultato di stat già ottenuto."""
    is_dir = stat.S_ISDIR(st.st_mode)
    if not (is_dir or stat.S_ISREG(st.st_mode)):
        # FIFO, socket, device: aprirli può bloccare o avere effetti collaterali.
        raise InsecurePermissionsError(f"{path} non è un file regolare né una directory.")
    if st.st_uid != os.getuid():
        raise InsecurePermissionsError(
            f"{path} ha un proprietario diverso dall'utente corrente (uid {st.st_uid})."
        )
    mode = stat.S_IMODE(st.st_mode)
    # 0o077 = qualsiasi bit per gruppo o altri: devono essere tutti spenti.
    if mode & 0o077:
        wanted = "700" if is_dir else "600"
        raise InsecurePermissionsError(
            f"Permessi troppo aperti su {path} ({mode:03o}). "
            f"Correggi con: chmod {wanted} {path}"
        )


def check_private(path: Path) -> None:
    """Verifica che `path` (file o directory) sia privato dell'utente.

    Usa lstat, quindi un symlink viene rifiutato invece di essere seguito:
    altrimenti un link potrebbe farci leggere o scrivere un file altrui.
    Solleva FileNotFoundError se `path` non esiste.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise InsecurePermissionsError(f"{path} è un symlink: hsm richiede un file reale.")
    _verify(st, path)


def read_private(path: Path, max_size: int = MAX_READ_SIZE) -> bytes:
    """Legge un file privato dopo averne verificato i permessi.

    Controlla anche la directory che lo contiene: un file 0600 in una
    directory scrivibile da altri può essere rinominato o sostituito.
    Il controllo sul file avviene sul file descriptor già aperto (fstat),
    non sul nome: così non c'è una finestra tra controllo e lettura in cui
    il file possa essere scambiato (race TOCTOU).
    """
    check_private(path.parent)
    # O_NOFOLLOW: fallisce se l'ultimo componente è un symlink.
    # O_NONBLOCK: se al posto del file c'è una FIFO, open() non resta appeso
    #   in attesa di uno scrittore; la rifiutiamo subito dopo con fstat.
    # O_CLOEXEC: il descriptor non viene ereditato da ssh o altri figli.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InsecurePermissionsError(
                f"{path} è un symlink: hsm richiede un file reale."
            ) from None
        raise
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        _verify(st, path)
        if stat.S_ISDIR(st.st_mode):
            raise InsecurePermissionsError(f"{path} è una directory, non un file.")
        if st.st_size > max_size:
            raise HsmError(f"{path} è troppo grande ({st.st_size} byte): file non valido.")
        return f.read()


def ensure_private_dir(path: Path) -> None:
    """Crea `path` con permessi 0700 se manca, poi ne verifica i permessi."""
    # Il mode passato a makedirs vale solo per l'ultima directory creata;
    # l'umask può solo togliere bit, quindi il risultato è al massimo 0700.
    os.makedirs(path, mode=0o700, exist_ok=True)
    check_private(path)


def _full_fsync(fd: int) -> None:
    # Su macOS fsync() consegna i dati al disco ma non obbliga il disco a
    # svuotare la sua cache; F_FULLFSYNC sì. Per il vault perdere una
    # scrittura significa perdere tutte le password, quindi paghiamo il costo.
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_fsync is not None:
        try:
            fcntl.fcntl(fd, full_fsync)
            return
        except OSError:
            # Alcuni filesystem (SMB, NFS, certi dischi esterni) non lo
            # supportano: ripieghiamo su fsync, la garanzia migliore rimasta.
            pass
    os.fsync(fd)


def atomic_write(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """Scrive `data` in `path` in modo atomico e con permessi 0600.

    Chi legge vede o il file vecchio intero o quello nuovo intero, mai uno
    a metà, anche se il processo muore durante la scrittura:
    1. mkstemp crea un file temporaneo nella stessa directory con O_EXCL e
       permessi 0600 fin dalla creazione (nessun istante con permessi larghi);
    2. scriviamo e forziamo i dati su disco;
    3. pubblichiamo il file con il nome definitivo (operazione atomica sullo
       stesso filesystem);
    4. sincronizziamo la directory, perché è lei a registrare il nuovo nome.

    Con `exclusive=True` il passo 3 usa os.link, che fallisce con
    FileExistsError se `path` esiste già: serve a non sovrascrivere mai un
    file creato nel frattempo da un altro processo.
    """
    directory = path.parent
    check_private(directory)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    tmp_renamed = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            _full_fsync(f.fileno())
        if exclusive:
            # Crea un secondo nome per lo stesso file; il temporaneo viene
            # rimosso nel finally, e resta solo `path`.
            os.link(tmp_name, path)
        else:
            os.replace(tmp_name, path)
            tmp_renamed = True
    finally:
        if not tmp_renamed:
            # Errore a metà, o link riuscito: togliamo il nome temporaneo.
            # Un'eventuale eccezione originale continua a propagarsi.
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        _full_fsync(dir_fd)
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def locked(path: Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Lock esclusivo tra processi hsm, tenuto per tutta la durata del `with`.

    Serve attorno a lettura-modifica-scrittura del vault: senza, due
    `hsm pw set` in parallelo leggerebbero lo stesso file e il secondo
    salvataggio cancellerebbe la modifica del primo.
    flock è "consultivo": protegge solo da chi usa lo stesso lock, cioè da
    altri hsm, che è quello che ci serve. Il lock sparisce con il processo,
    quindi un crash non lascia file bloccati.
    """
    check_private(path.parent)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InsecurePermissionsError(f"{path} è un symlink: hsm richiede un file reale.") from None
        raise
    try:
        _verify(os.fstat(fd), path)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise HsmError(
                        f"Un altro hsm sta modificando il vault ({path}): riprova tra poco."
                    ) from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # chiudere il descriptor rilascia il lock
