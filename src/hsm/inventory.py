"""Inventario degli host in ~/.config/hsm/hosts.toml (in chiaro, senza segreti).

Formato, una tabella per host:

    [hosts.web01]
    hostname = "10.0.0.1"
    user = "deploy"
    port = 2222                      # omesso se 22
    tags = ["prod", "web"]
    jump_host = "bastion"            # alias hsm oppure [user@]host[:port]
    identity_file = "~/.ssh/id_ed25519"
    note = "frontend principale"

Due scelte che contano:

- Validazione stretta di ogni campo. hostname, user e jump_host finiscono
  negli argomenti di ssh e in ~/.ssh/config: un hostname come
  "-oProxyCommand=..." verrebbe letto da ssh come un'opzione ed eseguirebbe
  un comando; un a capo in un valore aggiungerebbe righe arbitrarie a
  ssh_config; `jump_host = "none"` disattiverebbe il bastion in silenzio.
  Per questo gli host vengono analizzati (indirizzo IP via `ipaddress`,
  oppure nome DNS etichetta per etichetta) invece di essere solo filtrati
  per caratteri. Il controllo sta in Host, quindi vale sia per i valori
  letti dal file sia per quelli passati da riga di comando.

- Gli alias sono unici senza distinguere maiuscole (come fa ssh con i
  pattern Host) e non possono coincidere con l'hostname di un altro host:
  "Host 10.0.0.1" catturerebbe chi digita `ssh 10.0.0.1`.

- tomlkit invece di tomllib: tomllib sa solo leggere, e riscrivere il file
  con un serializzatore qualsiasi cancellerebbe i commenti scritti a mano.
  tomlkit modifica il documento sul posto e conserva tutto il resto.
"""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.toml_document import TOMLDocument

from hsm.errors import HsmError
from hsm.fsutil import atomic_write, ensure_private_dir, read_private

DEFAULT_PORT = 22

# Alias: finisce nella riga "Host <alias>" di ssh_config, dove spazi e
# caratteri jolly (*, ?, !) cambierebbero il significato.
_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# Un'etichetta DNS: niente "-" all'inizio o alla fine. "_" ammesso perché
# compare in nomi interni reali, anche se non è standard.
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,31}")
_PORT_RE = re.compile(r"[0-9]{1,5}")


class InventoryError(HsmError):
    """hosts.toml non valido o operazione impossibile sull'inventario."""


class InvalidHostError(InventoryError):
    """Un campo di un host non rispetta le regole di validazione."""


class HostNotFound(InventoryError):
    """Nessun host con questo alias."""


class HostExistsError(InventoryError):
    """Esiste già un host con questo alias."""


@dataclass(frozen=True)
class Host:
    """Un host dell'inventario. La validazione avviene alla costruzione."""

    alias: str
    hostname: str
    user: str | None = None
    port: int = DEFAULT_PORT
    tags: tuple[str, ...] = ()
    jump_host: str | None = None
    identity_file: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.alias, str) or not _ALIAS_RE.fullmatch(self.alias):
            raise InvalidHostError(
                f"alias non valido: {self.alias!r} (lettere, cifre, '.', '_', '-'; "
                "deve iniziare con lettera o cifra)"
            )
        # La zona IPv6 (fe80::1%en0) è ammessa solo qui; chi scrive
        # ssh_config deve raddoppiare il "%", che lì viene espanso.
        if not isinstance(self.hostname, str) or not (
            _is_ip(self.hostname, allow_zone=True) or _is_dns_name(self.hostname)
        ):
            self._fail("hostname", self.hostname)
        if self.user is not None:
            self._check("user", _USER_RE, self.user)
        # bool è una sottoclasse di int: True varrebbe porta 1.
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            self._fail("port", self.port)
        # Una stringa è iterabile: tuple("web") darebbe ("w", "e", "b").
        if not isinstance(self.tags, (list, tuple)):
            self._fail("tags", self.tags)
        tags = tuple(self.tags)
        for tag in tags:
            self._check("tag", _TAG_RE, tag)
        # Ordinati e senza doppioni: confronti e output stabili.
        object.__setattr__(self, "tags", tuple(sorted(set(tags))))
        if self.jump_host is not None and not _is_jump(self.jump_host):
            self._fail("jump_host", self.jump_host)
        if self.identity_file is not None:
            ident = self.identity_file
            if (
                not isinstance(ident, str)
                or not ident
                or not ident.strip()
                or ident.startswith("-")
                # In ssh_config lo scriviamo tra virgolette: lì '"' chiude,
                # "\" fa da escape e "%x" viene espanso (o fa fallire ssh).
                or any(c in ident for c in '"\\%')
                or not ident.isprintable()
            ):
                self._fail("identity_file", ident)
        if self.note is not None and (not isinstance(self.note, str) or not self.note.isprintable()):
            # isprintable() esclude a capo e sequenze di escape del terminale.
            self._fail("note", self.note)

    def _check(self, field: str, pattern: re.Pattern[str], value: object) -> None:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            self._fail(field, value)

    def _fail(self, field: str, value: object) -> None:
        raise InvalidHostError(f"Host {self.alias}: {field} non valido: {value!r}")


def _is_ip(value: str, *, allow_zone: bool) -> bool:
    if "%" in value and not allow_zone:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_dns_name(value: str) -> bool:
    if not 0 < len(value) <= 253:
        return False
    return all(_DNS_LABEL_RE.fullmatch(label) for label in value.split("."))


def _is_jump(value: object) -> bool:
    """Valida un singolo salto `[user@]host[:port]`, con IPv6 tra [ ]."""
    if not isinstance(value, str):
        return False
    user, at, rest = value.partition("@")
    if not at:
        rest = value
    elif not _USER_RE.fullmatch(user):
        return False
    port: str | None
    if rest.startswith("["):
        host, bracket, tail = rest[1:].partition("]")
        if not bracket or not _is_ip(host, allow_zone=False) or ":" not in host:
            return False
        if tail == "":
            port = None
        elif tail.startswith(":"):
            port = tail[1:]
        else:
            return False
    else:
        host, colon, port_text = rest.partition(":")
        port = port_text if colon else None
        # Un IPv6 senza parentesi è ambiguo con ":porta": va scritto tra [ ].
        if not (_is_ip(host, allow_zone=False) and ":" not in host) and not _is_dns_name(host):
            return False
        # "none" ha un significato speciale per ProxyJump/-J: nessun salto.
        if host.lower() == "none":
            return False
    if port is not None and not (_PORT_RE.fullmatch(port) and 1 <= int(port) <= 65535):
        return False
    return True


_FIELDS = tuple(f.name for f in fields(Host))
# Tipo atteso in hosts.toml per ogni campo, per messaggi d'errore chiari.
_FILE_TYPES: dict[str, tuple[type, str]] = {
    "hostname": (str, "una stringa"),
    "user": (str, "una stringa"),
    "port": (int, "un intero"),
    "tags": (list, "una lista di stringhe"),
    "jump_host": (str, "una stringa"),
    "identity_file": (str, "una stringa"),
    "note": (str, "una stringa"),
}


class Inventory:
    """L'inventario caricato da un file, modificabile e salvabile."""

    def __init__(self, path: Path, doc: TOMLDocument, hosts: dict[str, Host]) -> None:
        self._path = path
        self._doc = doc
        self._hosts = hosts

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        """Legge e valida `path`. Se il file non esiste, inventario vuoto."""
        try:
            raw = read_private(path)
        except FileNotFoundError:
            return cls(path, tomlkit.document(), {})
        try:
            doc = tomlkit.parse(raw.decode("utf-8"))
        except (TOMLKitError, UnicodeDecodeError) as exc:
            raise InventoryError(f"{path}: TOML non valido ({exc})") from None
        section = doc.get("hosts")
        if section is None:
            return cls(path, doc, {})
        if not isinstance(section, Mapping):
            raise InventoryError(f"{path}: 'hosts' deve essere una tabella")
        hosts: dict[str, Host] = {}
        for alias, data in section.unwrap().items():
            host = _host_from_file(str(alias), data)
            _check_conflicts(host, hosts, replacing=None)
            hosts[host.alias] = host
        return cls(path, doc, hosts)

    def hosts(self, tag: str | None = None) -> list[Host]:
        """Gli host ordinati per alias, eventualmente filtrati per tag."""
        return [
            h for _, h in sorted(self._hosts.items()) if tag is None or tag in h.tags
        ]

    def get(self, alias: str) -> Host:
        try:
            return self._hosts[alias]
        except KeyError:
            raise HostNotFound(f"Nessun host con alias {alias!r}.") from None

    def add(self, host: Host) -> None:
        _check_conflicts(host, self._hosts, replacing=None)
        if "hosts" not in self._doc:
            # Super-table: nel file compare solo [hosts.<alias>], senza un
            # [hosts] vuoto sopra.
            self._doc["hosts"] = tomlkit.table(is_super_table=True)
        table = tomlkit.table()
        for key, value in _to_file(host).items():
            if value is not None:
                table[key] = value
        self._doc["hosts"][host.alias] = table  # type: ignore[index]
        self._hosts[host.alias] = host

    def update(self, host: Host) -> None:
        """Sostituisce i campi di un host esistente, conservando i commenti."""
        self.get(host.alias)
        _check_conflicts(host, self._hosts, replacing=host.alias)
        table = self._doc["hosts"][host.alias]  # type: ignore[index]
        # Modifica chiave per chiave invece di sostituire la tabella: così
        # i commenti e l'ordine delle righe non toccate restano dove sono.
        for key, value in _to_file(host).items():
            if value is None:
                if key in table:
                    del table[key]
            elif key not in table or table[key] != value:
                table[key] = value
        self._hosts[host.alias] = host

    def remove(self, alias: str, *, force: bool = False) -> Host:
        """Toglie un host. Se altri lo usano come jump_host serve `force`.

        Senza il blocco "Host <alias>" in ssh_config, un jump_host rimasto
        orfano verrebbe risolto via DNS: magari verso una macchina diversa.
        """
        host = self.get(alias)
        users = self.referenced_by(alias)
        if users and not force:
            raise InventoryError(
                f"{alias} è il jump_host di: {', '.join(users)}. "
                "Aggiorna quegli host o rimuovi forzando."
            )
        del self._doc["hosts"][alias]  # type: ignore[union-attr]
        del self._hosts[alias]
        return host

    def referenced_by(self, alias: str) -> list[str]:
        """Alias degli host che usano `alias` come jump_host."""
        return sorted(h.alias for h in self._hosts.values() if h.jump_host == alias)

    def save(self, *, dry_run: bool = False) -> str:
        """Scrive il file (0600, atomico) e restituisce il testo prodotto.

        Con `dry_run` non scrive nulla: il chiamante può mostrare il testo.
        """
        text = tomlkit.dumps(self._doc)
        if not dry_run:
            ensure_private_dir(self._path.parent)
            atomic_write(self._path, text.encode("utf-8"))
        return text


def _check_conflicts(host: Host, hosts: dict[str, Host], *, replacing: str | None) -> None:
    """Alias unici senza maiuscole, e mai uguali all'hostname di un altro."""
    alias = host.alias.casefold()
    for other in hosts.values():
        if other.alias == replacing:
            continue
        if other.alias.casefold() == alias:
            raise HostExistsError(
                f"Esiste già un host con alias {other.alias!r} "
                f"(ssh non distingue maiuscole: {host.alias!r} coinciderebbe)."
            )
        if other.hostname.casefold() == alias:
            raise InventoryError(
                f"L'alias {host.alias!r} coincide con l'hostname di {other.alias!r}: "
                f"`ssh {other.hostname}` finirebbe su {host.hostname}."
            )
        if other.alias.casefold() == host.hostname.casefold():
            raise InventoryError(
                f"L'hostname {host.hostname!r} coincide con l'alias {other.alias!r}: "
                "ssh applicherebbe le impostazioni di quell'host."
            )


def _host_from_file(alias: str, data: Any) -> Host:
    if not isinstance(data, Mapping):
        raise InventoryError(f"Host {alias}: deve essere una tabella")
    unknown = sorted(set(data) - set(_FIELDS))
    if unknown:
        raise InventoryError(f"Host {alias}: campo sconosciuto {', '.join(unknown)}")
    if "hostname" not in data:
        raise InventoryError(f"Host {alias}: manca hostname")
    for key, value in data.items():
        expected, description = _FILE_TYPES[key]
        if not isinstance(value, expected) or isinstance(value, bool):
            raise InventoryError(f"Host {alias}: {key} deve essere {description}")
    try:
        return Host(alias=alias, **{k: _from_toml(k, v) for k, v in data.items()})
    except InvalidHostError as exc:
        raise InventoryError(str(exc)) from None


def _from_toml(key: str, value: Any) -> Any:
    return tuple(value) if key == "tags" else value


def _to_file(host: Host) -> dict[str, Any]:
    """I campi da scrivere; None significa "chiave assente dal file"."""
    return {
        "hostname": host.hostname,
        "user": host.user,
        "port": host.port if host.port != DEFAULT_PORT else None,
        "tags": list(host.tags) if host.tags else None,
        "jump_host": host.jump_host,
        "identity_file": host.identity_file,
        "note": host.note,
    }
