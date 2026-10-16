"""Stato locale di hsm: quando è stato usato l'ultima volta ogni host.

Vive in ~/.config/hsm/state.toml, separato da hosts.toml: quel file è
pensato per essere versionato, e aggiornare un timestamp a ogni connect
riempirebbe la cronologia git di modifiche senza valore.

    # Generato da hsm: non modificare a mano.
    [last_used]
    web01 = 2026-10-16T10:00:00Z

È un dato di comodo, ma rivela quali macchine usi e quando: per questo
anche lui è 0600. Se due hsm scrivono insieme vince l'ultimo; per un
ordinamento di `hsm ls` è accettabile.
"""

import tomllib
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

import tomlkit

from hsm.errors import HsmError
from hsm.fsutil import atomic_write, ensure_private_dir, read_private
from hsm.inventory import is_valid_alias

_HEADER = "Generato da hsm: non modificare a mano."


class StateError(HsmError):
    """state.toml non valido."""


class State:
    """Timestamp di ultimo uso per alias, sempre in UTC e al secondo."""

    def __init__(self, path: Path, last_used: dict[str, datetime]) -> None:
        self._path = path
        self._last_used = last_used

    @classmethod
    def load(cls, path: Path) -> "State":
        """Legge `path`; se non esiste, stato vuoto."""
        try:
            raw = read_private(path)
        except FileNotFoundError:
            return cls(path, {})
        except PermissionError as exc:
            # Es. mode 0000: non è un problema di sicurezza, solo illeggibile.
            raise StateError(f"{path}: impossibile leggere ({exc.strerror})") from None
        # Qui basta tomllib (sola lettura, libreria standard): il file lo
        # scriviamo sempre per intero, non c'è nulla dell'utente da conservare.
        try:
            data = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise StateError(f"{path}: TOML non valido ({exc})") from None
        except RecursionError:
            # tomllib è ricorsivo: liste annidate a migliaia esauriscono lo stack.
            raise StateError(f"{path}: TOML annidato troppo in profondità") from None
        section = data.get("last_used", {})
        if not isinstance(section, dict):
            raise StateError(f"{path}: 'last_used' deve essere una tabella")
        last_used: dict[str, datetime] = {}
        for alias, value in section.items():
            if not is_valid_alias(alias):
                raise StateError(f"{path}: alias non valido {alias!r}")
            # datetime è sottoclasse di date: una data senza ora non passa,
            # e nemmeno un orario senza fuso.
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise StateError(f"{path}: {alias} deve essere una data e ora con fuso orario")
            try:
                last_used[alias] = _normalize(value)
            except OverflowError:
                raise StateError(f"{path}: {alias} ha una data fuori intervallo") from None
        return cls(path, last_used)

    @classmethod
    def load_or_empty(cls, path: Path, warn: Callable[[str], None]) -> "State":
        """Come `load`, ma un file rotto diventa uno stato vuoto con un avviso.

        Lo stato si può rigenerare: non deve mai impedire un connect. I
        permessi troppo larghi invece restano un errore, come per gli altri
        file di hsm (InsecurePermissionsError non è uno StateError).
        """
        try:
            return cls.load(path)
        except StateError as exc:
            warn(f"{exc}. Ignoro lo stato salvato; verrà riscritto.")
            return cls(path, {})

    def last_used(self, alias: str) -> datetime | None:
        return self._last_used.get(alias)

    def touch(self, alias: str, when: datetime | None = None) -> None:
        """Registra un uso di `alias` (default: adesso)."""
        if not is_valid_alias(alias):
            raise ValueError(f"alias non valido: {alias!r}")
        when = datetime.now(UTC) if when is None else when
        if when.tzinfo is None:
            raise ValueError("serve un datetime con fuso orario")
        try:
            self._last_used[alias] = _normalize(when)
        except OverflowError:
            raise ValueError(f"data fuori intervallo: {when!r}") from None

    def forget(self, alias: str) -> None:
        self._last_used.pop(alias, None)

    def rename(self, old: str, new: str) -> None:
        """Sposta l'ultimo uso di `old` sul nuovo alias (se c'era)."""
        if not is_valid_alias(new):
            raise ValueError(f"alias non valido: {new!r}")
        if old in self._last_used:
            self._last_used[new] = self._last_used.pop(old)

    def prune(self, known: Iterable[str]) -> None:
        """Dimentica gli alias che non sono più nell'inventario."""
        keep = set(known)
        for alias in [a for a in self._last_used if a not in keep]:
            del self._last_used[alias]

    def recent(self, aliases: Iterable[str]) -> list[str]:
        """Ordina `aliases`: usati più di recente prima, mai usati in fondo."""

        def key(alias: str) -> tuple[bool, float, str]:
            used = self._last_used.get(alias)
            # (mai usato?, -timestamp, alias): i mai usati vanno in coda,
            # a parità si ordina per nome.
            return (used is None, -used.timestamp() if used else 0.0, alias)

        return sorted(aliases, key=key)

    def save(self, *, dry_run: bool = False) -> str:
        """Riscrive il file per intero (0600, atomico) e ne restituisce il testo."""
        doc = tomlkit.document()
        doc.add(tomlkit.comment(_HEADER))
        table = tomlkit.table()
        for alias in sorted(self._last_used):
            table[alias] = self._last_used[alias]
        doc["last_used"] = table
        text = tomlkit.dumps(doc)
        if not dry_run:
            ensure_private_dir(self._path.parent)
            atomic_write(self._path, text.encode("utf-8"))
        return text


def _normalize(when: datetime) -> datetime:
    """UTC, al secondo: più precisione non serve e renderebbe il file rumoroso.

    Può sollevare OverflowError se la conversione in UTC esce dagli anni
    1..9999 (es. 0001-01-01T00:00:00+05:00).
    """
    return when.astimezone(UTC).replace(microsecond=0)
