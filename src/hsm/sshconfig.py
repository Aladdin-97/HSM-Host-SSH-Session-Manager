"""`hsm sync`: rigenera un blocco delimitato in ~/.ssh/config.

    # >>> hsm begin
    # Generato da `hsm sync`: le modifiche qui dentro verranno sovrascritte.

    Host web01
        HostName 10.0.0.1
        User deploy
        Port 2222
        ProxyJump bastion
        IdentityFile "~/.ssh/id_ed25519"

    # Riporta lo scope a globale per le righe che seguono il blocco.
    Host *
    # <<< hsm end

Regole:
- si scrive solo tra i due marker; tutto il resto resta byte per byte;
- se i marker non ci sono, il blocco va in cima: in ssh_config vince il
  primo valore trovato, quindi in cima i valori di hsm non vengono
  scavalcati da un `Host *` scritto più in basso;
- prima di ogni scrittura c'è un backup (0600) del file com'era;
- idempotente: se il risultato è identico, non si scrive nulla e non si
  crea nessun backup;
- marker malformati (uno solo, invertiti, doppi): ci fermiamo senza
  toccare nulla, perché non sapremmo cosa è nostro e cosa no.

Il `Host *` finale serve perché in ssh_config un'opzione appartiene al
blocco `Host` più vicino sopra di lei. Mettendo il nostro blocco in cima,
le opzioni globali che l'utente aveva all'inizio del file finirebbero
dentro il nostro ultimo host e smetterebbero di valere per gli altri.
`Host *` riapre uno scope che vale per tutti, come l'inizio del file.
"""

import difflib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from hsm.errors import HsmError
from hsm.fsutil import atomic_write, ensure_private_dir, read_private
from hsm.inventory import Host

BEGIN = "# >>> hsm begin"
END = "# <<< hsm end"

_MAX_BACKUP_SUFFIX = 100

# Caratteri che ssh_config interpreta in un valore senza virgolette:
# spazio e tab (separano argomenti), '"' (quoting), '#' (commento),
# '\' (escape), '$' (espansione ${VAR}), '=' (separatore chiave=valore).
_UNSAFE_UNQUOTED = frozenset(' \t"#\\$=')
# Dentro le virgolette restano pericolosi solo questi.
_UNSAFE_QUOTED = frozenset('"\\$')


class SshConfigError(HsmError):
    """~/.ssh/config non è in uno stato che possiamo modificare con sicurezza."""


@dataclass(frozen=True)
class SyncResult:
    """Esito di `apply`: cosa c'era, cosa c'è (o ci sarebbe), dove sta il backup."""

    path: Path
    changed: bool
    old: str
    new: str
    backup: Path | None

    def diff(self) -> str:
        """Diff unificato, utile per `--dry-run`."""
        return "".join(
            difflib.unified_diff(
                self.old.splitlines(keepends=True),
                self.new.splitlines(keepends=True),
                fromfile=str(self.path),
                tofile=f"{self.path} (dopo hsm sync)",
            )
        )


def render(hosts: Iterable[Host]) -> str:
    """Il blocco completo, marker inclusi. Stesso input, stesso output."""
    lines = [BEGIN, "# Generato da `hsm sync`: le modifiche qui dentro verranno sovrascritte.", ""]
    for host in sorted(hosts, key=lambda h: h.alias):
        lines.append(f"Host {_value(host.alias)}")
        # In HostName ssh espande %h, %% ecc.: "%" va raddoppiato, altrimenti
        # una zona IPv6 come fe80::1%en0 fa fallire ogni connessione.
        lines.append(f"    HostName {_value(host.hostname.replace('%', '%%'))}")
        if host.user is not None:
            lines.append(f"    User {_value(host.user)}")
        # Port sempre esplicita: non deve dipendere da un `Host *` dell'utente.
        lines.append(f"    Port {host.port}")
        if host.jump_host is not None:
            lines.append(f"    ProxyJump {_value(host.jump_host)}")
        if host.identity_file is not None:
            # Tra virgolette perché il percorso può contenere spazi; Host ha
            # già escluso '"', '\\' e '%' da identity_file.
            lines.append(f'    IdentityFile "{_value(host.identity_file, quoted=True)}"')
        lines.append("")
    lines += ["# Riporta lo scope a globale per le righe che seguono il blocco.", "Host *", END]
    return "\n".join(lines) + "\n"


def apply(
    path: Path, block: str, *, dry_run: bool = False, now: datetime | None = None
) -> SyncResult:
    """Inserisce o sostituisce il blocco in `path` (di solito ~/.ssh/config)."""
    if not (block.startswith(BEGIN + "\n") and block.endswith(END + "\n")):
        raise ValueError("il blocco deve iniziare e finire con i marker hsm")
    raw = _read_or_none(path)
    try:
        old = raw.decode("utf-8") if raw is not None else ""
    except UnicodeDecodeError:
        raise SshConfigError(f"{path} non è testo UTF-8: non lo modifico.") from None

    new = _splice(path, old, block)
    if raw is not None and new == old:
        return SyncResult(path=path, changed=False, old=old, new=new, backup=None)
    if dry_run:
        return SyncResult(path=path, changed=True, old=old, new=new, backup=None)

    ensure_private_dir(path.parent)
    backup = _backup(path, raw, now or datetime.now(UTC)) if raw is not None else None
    # Ultimo controllo prima di sostituire: se un editor ha salvato il file
    # mentre lavoravamo, sovrascriverlo cancellerebbe quella modifica (e il
    # backup avrebbe solo la versione precedente). Resta una finestra di
    # pochi microsecondi tra questo controllo e il rename: accettata.
    if _read_or_none(path) != raw:
        raise SshConfigError(
            f"{path} è stato modificato durante la sync: non lo sovrascrivo. Rilancia hsm sync."
        )
    atomic_write(path, new.encode("utf-8"))
    return SyncResult(path=path, changed=True, old=old, new=new, backup=backup)


def _read_or_none(path: Path) -> bytes | None:
    try:
        return read_private(path)
    except FileNotFoundError:
        return None


def _splice(path: Path, old: str, block: str) -> str:
    # Solo "\n" separa le righe, come in ssh. str.splitlines() spezzerebbe
    # anche su form feed, \x85, U+2028... e vedrebbe righe che ssh non vede.
    lines = re.split(r"(?<=\n)", old)
    # strip(): un marker con spazi attorno (editor, CRLF) resta un marker.
    # Altrimenti nascerebbe un secondo blocco e il vecchio resterebbe attivo.
    begins = [i for i, line in enumerate(lines) if line.strip(" \t\r\n") == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip(" \t\r\n") == END]
    if not begins and not ends:
        # Riga vuota di separazione dal contenuto dell'utente. Dalla seconda
        # sync in poi sta fuori dai marker, quindi non cambia più.
        return block + ("\n" + old if old else "")
    if len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0]:
        return "".join(lines[: begins[0]]) + block + "".join(lines[ends[0] + 1 :])
    raise SshConfigError(
        f"I marker hsm in {path} non sono validi (serve esattamente un "
        f"'{BEGIN}' seguito da un '{END}'). Correggi a mano: non modifico nulla."
    )


def _backup(path: Path, content: bytes, now: datetime) -> Path:
    """Copia 0600 del file originale accanto a lui, con timestamp nel nome."""
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%S")
    for n in range(_MAX_BACKUP_SUFFIX):
        suffix = stamp if n == 0 else f"{stamp}-{n}"
        target = path.with_name(f"{path.name}.hsm-backup-{suffix}")
        try:
            # exclusive: un backup esistente non va mai sovrascritto.
            atomic_write(target, content, exclusive=True)
        except FileExistsError:
            continue
        return target
    raise SshConfigError(f"Troppi backup di {path} nello stesso secondo.")


def _value(text: str, *, quoted: bool = False) -> str:
    """Seconda linea di difesa oltre alla validazione di Host.

    Nessun valore deve poter spezzare la riga, aggiungere direttive o essere
    letto da ssh in modo diverso da come l'abbiamo scritto: un solo valore
    sbagliato renderebbe invalido l'intero ~/.ssh/config, per tutti gli host.
    """
    unsafe = _UNSAFE_QUOTED if quoted else _UNSAFE_UNQUOTED
    if not text.isprintable() or any(c in unsafe for c in text):
        raise SshConfigError(f"Valore non scrivibile in ssh_config: {text!r}")
    return text
