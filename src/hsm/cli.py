"""Riga di comando di hsm: collega i moduli, non contiene logica di dominio.

    hsm                      selettore, invio = connect
    hsm add <alias>          flag o prompt interattivo     [--dry-run]
    hsm ls [--tag X] [--sort alias|tag|recent]
    hsm rm <alias>           [--force] [--dry-run]
    hsm edit <alias>         flag o prompt interattivo     [--dry-run]
    hsm connect <alias>
    hsm pw set|get|rm <alias>
    hsm vault rekey
    hsm sync                 [--dry-run]

All'avvio, prima di qualsiasi comando:
- niente core dump (RLIMIT_CORE = 0): un crash non deve lasciare su disco
  un'immagine della memoria con chiavi o password in chiaro;
- excepthook che stampa solo messaggi, mai traceback con variabili locali
  (con --debug il traceback standard, che le variabili non le mostra);
- controllo dei permessi di directory e file di hsm: se sono troppo larghi
  ci rifiutiamo di partire.

Le operazioni sul vault (pw set/rm, rm di un host con password, rekey)
avvengono sotto un lock, così due hsm in parallelo non si cancellano le
modifiche a vicenda.
"""

import argparse
import dataclasses
import difflib
import getpass
import os
import re
import resource
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from hsm import vault
from hsm.clipboard import DEFAULT_SECONDS, Clipboard
from hsm.connect import Connector
from hsm.errors import HsmError, make_excepthook
from hsm.fsutil import check_private, ensure_private_dir, locked
from hsm.inventory import DEFAULT_PORT, Host, Inventory, is_valid_alias
from hsm.picker import Picker, format_line
from hsm.secret import Secret
from hsm.sshconfig import apply, render
from hsm.state import State
from hsm.unlock import Unlocker
from hsm.vault import VaultEntry


@dataclasses.dataclass(frozen=True)
class Paths:
    """Dove vivono i file di hsm."""

    config_dir: Path
    ssh_config: Path

    @classmethod
    def default(cls) -> "Paths":
        home = Path.home()
        return cls(config_dir=home / ".config" / "hsm", ssh_config=home / ".ssh" / "config")

    @property
    def hosts(self) -> Path:
        return self.config_dir / "hosts.toml"

    @property
    def vault(self) -> Path:
        return self.config_dir / "vault.enc"

    @property
    def state(self) -> Path:
        return self.config_dir / "state.toml"

    @property
    def lock(self) -> Path:
        return self.config_dir / "vault.lock"


def _warn_stderr(message: str) -> None:
    print(f"hsm: {message}", file=sys.stderr)


class App:
    """I comandi di hsm. Ogni dipendenza esterna è iniettabile per i test."""

    def __init__(
        self,
        paths: Paths,
        *,
        unlocker_factory: Callable[[Path], Unlocker] = Unlocker,
        connector: Connector | None = None,
        clipboard: Clipboard | None = None,
        picker: Picker | None = None,
        ask: Callable[[str], str] = input,
        ask_secret: Callable[[str], str] = getpass.getpass,
        out: Callable[[str], None] = print,
        warn: Callable[[str], None] = _warn_stderr,
    ) -> None:
        self.paths = paths
        self._unlocker_factory = unlocker_factory
        self._clipboard = clipboard if clipboard is not None else Clipboard()
        self._connector = connector or Connector(
            warn=warn, clipboard_fallback=self._clipboard.copy_with_autoclear, confirm=self._confirm
        )
        self._picker = picker if picker is not None else Picker()
        self._ask_raw = ask
        self._ask_secret_raw = ask_secret
        self._out = out
        self._warn = warn

    # --- avvio --------------------------------------------------------------

    def preflight(self) -> None:
        """Rifiuta di partire se i file di hsm sono accessibili ad altri."""
        p = self.paths
        if os.path.lexists(p.config_dir):
            check_private(p.config_dir)
        for path in (p.hosts, p.vault, p.state, p.lock):
            if os.path.lexists(path):
                check_private(path)

    def run(self, args: argparse.Namespace) -> int:
        """Esegue il comando già analizzato; restituisce il codice d'uscita."""
        match args.command:
            case None:
                return self.pick()
            case "add":
                return self.add(args)
            case "ls":
                return self.ls(args.tag, args.sort)
            case "rm":
                return self.rm(args.alias, force=args.force, dry_run=args.dry_run)
            case "edit":
                return self.edit(args)
            case "connect":
                return self.connect(args.alias)
            case "pw":
                return {"set": self.pw_set, "get": self.pw_get, "rm": self.pw_rm}[args.pw_command](args.alias)
            case "vault":
                return self.vault_rekey()
            case "sync":
                return self.sync(dry_run=args.dry_run)
        raise HsmError(f"Comando sconosciuto: {args.command}")  # pragma: no cover - argparse lo impedisce

    # --- inventario ---------------------------------------------------------

    def add(self, args: argparse.Namespace) -> int:
        # Alias e duplicati controllati subito: inutile far rispondere a
        # sette domande per poi scoprire che l'alias non va bene.
        if not is_valid_alias(args.alias):
            raise HsmError(f"alias non valido: {args.alias!r}")
        Inventory.load(self.paths.hosts).add(Host(alias=args.alias, hostname="placeholder"))
        flags = _host_flags(args)
        use_password: bool = args.password
        if not flags:
            host = self._ask_host(args.alias, None)
            if not use_password and not args.dry_run:
                use_password = self._confirm("Usare una password per questo host (salvata nel vault)?")
        elif "hostname" not in flags:
            raise HsmError("Manca --hostname/--ip (oppure lancia `hsm add <alias>` senza flag).")
        else:
            host = Host(alias=args.alias, **flags)
        if use_password:
            host = dataclasses.replace(host, auth="password")

        if args.dry_run or not use_password:
            self._change_inventory(lambda inv: inv.add(host), dry_run=args.dry_run)
            if args.dry_run and use_password:
                self._out(f"(chiederei la password di {host.alias} e la salverei nel vault)")
            elif not args.dry_run:
                self._out(f"Aggiunto {host.alias}.")
            return 0

        # La password si chiede prima del lock (l'utente può metterci un po');
        # vault e inventario si aggiornano poi insieme, sotto lock.
        with self._ask_new_host_password(host.alias) as password:
            ensure_private_dir(self.paths.config_dir)
            with locked(self.paths.lock):
                inv = Inventory.load(self.paths.hosts)
                # Prima l'inventario in memoria: un alias già usato si scopre
                # qui, senza aver toccato il vault. Se l'unlock viene annullato
                # l'host non viene aggiunto.
                inv.add(host)
                self._store_password(host.alias, password)
                try:
                    inv.save()
                except (OSError, HsmError) as exc:
                    raise HsmError(
                        f"Password di {host.alias} salvata nel vault, ma non ho potuto "
                        f"aggiornare {self.paths.hosts} ({exc}): rilancia hsm add, oppure "
                        f"togli la password con hsm pw rm {host.alias}."
                    ) from None
        self._out(f"Aggiunto {host.alias}, con la password nel vault.")
        return 0

    def edit(self, args: argparse.Namespace) -> int:
        alias = args.alias
        flags = _host_flags(args)
        new_alias: str | None = args.new_alias
        if flags or new_alias:
            # Con i flag la modifica si applica alla versione più recente
            # dell'host, letta sotto lock.
            def change(inv: Inventory) -> None:
                target = alias
                if new_alias and new_alias != alias:
                    inv.rename(alias, new_alias)
                    target = new_alias
                if flags:
                    inv.update(dataclasses.replace(inv.get(target), **flags))
        else:
            host = self._ask_host(alias, Inventory.load(self.paths.hosts).get(alias), ask_alias=True)
            new_alias = host.alias

            def change(inv: Inventory) -> None:
                if host.alias != alias:
                    inv.rename(alias, host.alias)
                inv.update(host)

        if args.dry_run or new_alias is None or new_alias == alias:
            self._change_inventory(change, dry_run=args.dry_run)
            if not args.dry_run:
                self._out(f"Aggiornato {alias}.")
            return 0
        self._rename(alias, new_alias, change)
        return 0

    def _rename(self, old: str, new: str, change: Callable[[Inventory], None]) -> None:
        """Rinomina sotto lock: inventario, password nel vault, ultimo uso."""
        ensure_private_dir(self.paths.config_dir)
        with locked(self.paths.lock):
            inv = Inventory.load(self.paths.hosts)
            uses_password = inv.get(old).auth == "password"
            # Prima l'inventario in memoria: se il nuovo alias non è valido o
            # è già usato, ci fermiamo qui senza aver toccato il vault.
            change(inv)
            if uses_password and os.path.lexists(self.paths.vault):
                with self._unlocker().get_vault_key() as key:
                    entries = vault.load(self.paths.vault, key)
                    try:
                        entry = entries.pop(old, None)
                        if entry is not None:
                            entries[new] = entry
                            vault.save(self.paths.vault, key, entries)
                    finally:
                        _wipe(entries)
            try:
                inv.save()
            except (OSError, HsmError) as exc:
                raise HsmError(
                    f"La password nel vault ora è sotto {new}, ma non ho potuto aggiornare "
                    f"{self.paths.hosts} ({exc}): rinomina l'host a mano in {new}."
                ) from None
        self._update_state(lambda s: s.rename(old, new))
        self._out(f"Rinominato {old} in {new}.")
        self._out("Rilancia hsm sync per aggiornare ~/.ssh/config, che ha ancora il vecchio nome.")

    def ls(self, tag: str | None, sort: str) -> int:
        inv = Inventory.load(self.paths.hosts)
        hosts = inv.hosts(tag=tag)
        if not hosts:
            self._out("Nessun host. Aggiungine uno con: hsm add <alias>")
            return 0
        state = State.load_or_empty(self.paths.state, self._warn)
        if sort == "recent":
            order = state.recent([h.alias for h in hosts])
            hosts = sorted(hosts, key=lambda h: order.index(h.alias))
        elif sort == "tag":
            # Per primo tag; gli host senza tag in fondo.
            hosts = sorted(hosts, key=lambda h: (h.tags[0] if h.tags else "￿", h.alias))
        rows = [("ALIAS", "HOST", "TAG", "AUTH", "ULTIMO USO")]
        for host in hosts:
            alias, target, tags, _note = format_line(host).split("\t")
            used = state.last_used(host.alias)
            when = used.astimezone().strftime("%Y-%m-%d %H:%M") if used else "mai"
            rows.append((alias, target, tags or "-", host.auth, when))
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        for row in rows:
            self._out("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip())
        return 0

    def rm(self, alias: str, *, force: bool, dry_run: bool) -> int:
        if dry_run:
            inv = Inventory.load(self.paths.hosts)
            before = inv.save(dry_run=True)
            host = inv.remove(alias, force=force)
            self._preview(before, inv.save(dry_run=True))
            if host.auth == "password":
                self._out(f"(rimuoverei anche la password di {alias} dal vault)")
            return 0
        ensure_private_dir(self.paths.config_dir)
        with locked(self.paths.lock):
            inv = Inventory.load(self.paths.hosts)
            host = inv.remove(alias, force=force)
            # Prima il vault: se l'unlock viene annullato, l'host resta com'era.
            if host.auth == "password" and os.path.lexists(self.paths.vault):
                with self._unlocker().get_vault_key() as key:
                    entries = vault.load(self.paths.vault, key)
                    try:
                        removed = entries.pop(alias, None)
                        if removed is not None:
                            removed.password.wipe()
                        vault.save(self.paths.vault, key, entries)
                    finally:
                        _wipe(entries)
            try:
                inv.save()
            except (OSError, HsmError) as exc:
                raise HsmError(
                    f"Password di {alias} rimossa dal vault, ma non ho potuto aggiornare "
                    f"{self.paths.hosts} ({exc}): rilancia hsm rm {alias}."
                ) from None
        self._update_state(lambda s: s.forget(alias))
        self._out(f"Rimosso {alias}.")
        return 0

    # --- connessione ----------------------------------------------------------

    def connect(self, alias: str) -> int:
        inv = Inventory.load(self.paths.hosts)
        return self._connect(inv.get(alias), inv)

    def pick(self) -> int:
        inv = Inventory.load(self.paths.hosts)
        state = State.load_or_empty(self.paths.state, self._warn)
        hosts = {h.alias: h for h in inv.hosts()}
        ordered = [hosts[a] for a in state.recent(hosts)]
        host = self._picker.choose(ordered)
        return 0 if host is None else self._connect(host, inv)

    def _connect(self, host: Host, inv: Inventory) -> int:
        password: Secret | None = None
        try:
            # Solo gli host con auth = "password" aprono il vault: per quelli
            # a chiave nessun Touch ID e nessuna master password.
            if host.auth == "password":
                password = self._password_for(host.alias)
            # Prima della sessione: una sessione lunga o interrotta male non
            # deve far perdere l'aggiornamento.
            self._update_state(lambda s: s.touch(host.alias))
            return self._connector.connect(host, inv, password=password)
        finally:
            if password is not None:
                password.wipe()

    def _password_for(self, alias: str) -> Secret:
        """Una copia della sola password di `alias`.

        Chiave del vault e altre voci vengono azzerate subito: durante la
        sessione ssh, che può durare ore, in memoria resta solo ciò che serve.
        """
        with self._unlocker().get_vault_key() as key:
            entries = vault.load(self.paths.vault, key)
        try:
            entry = entries.get(alias)
            if entry is None:
                raise HsmError(
                    f"{alias} usa auth = password ma nel vault non c'è la sua "
                    f"password: hsm pw set {alias}"
                )
            return Secret(bytearray(entry.password.view()))
        finally:
            _wipe(entries)

    # --- password -------------------------------------------------------------

    def pw_set(self, alias: str) -> int:
        Inventory.load(self.paths.hosts).get(alias)  # errore subito se l'host non c'è
        with self._ask_new_host_password(alias) as password:
            ensure_private_dir(self.paths.config_dir)
            with locked(self.paths.lock):
                # Ricaricato sotto lock: nel frattempo (prompt, Touch ID)
                # un altro hsm potrebbe aver modificato l'inventario.
                inv = Inventory.load(self.paths.hosts)
                host = inv.get(alias)
                self._store_password(alias, password)
                if host.auth != "password":
                    try:
                        inv.update(dataclasses.replace(host, auth="password"))
                        inv.save()
                    except (OSError, HsmError) as exc:
                        raise HsmError(
                            f"Password salvata nel vault, ma non ho potuto aggiornare "
                            f"{self.paths.hosts} ({exc}): imposta a mano "
                            f'auth = "password" per {alias}, o rilancia hsm pw set {alias}.'
                        ) from None
                    self._out(f'Impostato auth = "password" per {alias} in {self.paths.hosts}.')
        self._out(f"Password di {alias} salvata nel vault.")
        return 0

    def _ask_new_host_password(self, alias: str) -> Secret:
        password = self._read_secret(f"Password per {alias}: ")
        try:
            with self._read_secret("Ripeti la password: ") as again:
                if len(password) == 0:
                    raise HsmError("La password è vuota.")
                if password != again:
                    raise HsmError("Le password non coincidono.")
        except BaseException:
            password.wipe()  # anche su Ctrl-C alla seconda domanda
            raise
        return password

    def _store_password(self, alias: str, password: Secret) -> None:
        """Scrive la password nel vault (creandolo se serve). Va chiamata sotto lock."""
        unlocker = self._unlocker()
        exists = os.path.lexists(self.paths.vault)
        key = unlocker.get_vault_key() if exists else unlocker.init_vault()
        with key:
            entries = vault.load(self.paths.vault, key) if exists else {}
            try:
                old = entries.pop(alias, None)
                if old is not None:
                    old.password.wipe()
                # Copia: `password` appartiene al chiamante e verrà azzerata lì.
                entries[alias] = VaultEntry.new(Secret(bytearray(password.view())))
                vault.save(self.paths.vault, key, entries)
            finally:
                _wipe(entries)

    def pw_get(self, alias: str) -> int:
        with self._unlocker().get_vault_key() as key:
            entries = vault.load(self.paths.vault, key)
        try:
            entry = entries.get(alias)
            if entry is None:
                raise HsmError(f"Nessuna password salvata per {alias}.")
            self._clipboard.copy_with_autoclear(entry.password, DEFAULT_SECONDS)
        finally:
            _wipe(entries)
        self._out(f"Password di {alias} copiata negli appunti: si cancella tra {DEFAULT_SECONDS} s.")
        return 0

    def pw_rm(self, alias: str) -> int:
        self._require_vault()
        with locked(self.paths.lock):
            with self._unlocker().get_vault_key() as key:
                entries = vault.load(self.paths.vault, key)
                try:
                    entry = entries.pop(alias, None)
                    if entry is None:
                        raise HsmError(f"Nessuna password salvata per {alias}.")
                    entry.password.wipe()
                    vault.save(self.paths.vault, key, entries)
                finally:
                    _wipe(entries)
            inv = Inventory.load(self.paths.hosts)
            host = next((h for h in inv.hosts() if h.alias == alias), None)
            if host is not None and host.auth == "password":
                inv.update(dataclasses.replace(host, auth="key"))
                inv.save()
        self._out(f"Password di {alias} rimossa dal vault.")
        return 0

    def vault_rekey(self) -> int:
        self._require_vault()
        with locked(self.paths.lock), self._unlocker().change_master_password():
            pass
        self._out("Master password cambiata.")
        return 0

    def _require_vault(self) -> None:
        # Solleva "Vault non trovato... hsm pw set" se manca, prima di
        # provare a prendere un lock in una directory che magari non esiste.
        vault.read_header(self.paths.vault)

    # --- ssh_config -----------------------------------------------------------

    def sync(self, *, dry_run: bool) -> int:
        inv = Inventory.load(self.paths.hosts)
        result = apply(self.paths.ssh_config, render(inv.hosts()), dry_run=dry_run)
        if dry_run:
            self._out(result.diff() or "Nessuna modifica.")
        elif not result.changed:
            self._out(f"{self.paths.ssh_config} già aggiornato.")
        else:
            backup = f" (backup: {result.backup})" if result.backup else ""
            self._out(f"Aggiornato {self.paths.ssh_config}{backup}.")
        return 0

    # --- supporto -------------------------------------------------------------

    def _unlocker(self) -> Unlocker:
        return self._unlocker_factory(self.paths.vault)

    def _change_inventory(self, change: Callable[[Inventory], None], *, dry_run: bool) -> None:
        """Applica `change` a hosts.toml.

        In dry-run mostra il diff e non tocca nulla (nemmeno il lock).
        Altrimenti rilegge il file sotto lock, applica e salva: la modifica
        parte sempre dalla versione più recente, e due hsm in parallelo non
        si cancellano gli host a vicenda.
        """
        if dry_run:
            inv = Inventory.load(self.paths.hosts)
            before = inv.save(dry_run=True)
            change(inv)
            self._preview(before, inv.save(dry_run=True))
            return
        ensure_private_dir(self.paths.config_dir)
        with locked(self.paths.lock):
            inv = Inventory.load(self.paths.hosts)
            change(inv)
            inv.save()

    def _preview(self, before: str, after: str) -> None:
        diff = difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=str(self.paths.hosts),
            tofile=f"{self.paths.hosts} (dopo)",
        )
        self._out("".join(diff).rstrip("\n") or "Nessuna modifica.")
        self._out("(dry-run: nessun file modificato)")

    def _update_state(self, change: Callable[[State], None]) -> None:
        # Lo stato è un dato di comodo: un suo problema non deve mai
        # bloccare un connect o un rm, al massimo produce un avviso.
        try:
            state = State.load_or_empty(self.paths.state, self._warn)
            change(state)
            state.save()
        except (HsmError, OSError) as exc:
            self._warn(f"Non riesco ad aggiornare {self.paths.state}: {exc}")

    def _ask(self, prompt: str) -> str:
        try:
            return self._ask_raw(prompt)
        except EOFError:
            raise HsmError("Nessun terminale disponibile per le domande interattive.") from None

    def _read_secret(self, prompt: str) -> Secret:
        try:
            text = self._ask_secret_raw(prompt)
        except EOFError:
            raise HsmError("Nessun terminale disponibile per chiedere la password.") from None
        try:
            return Secret.from_str(text)
        except UnicodeEncodeError:
            raise HsmError("La password contiene caratteri non validi.") from None

    def _confirm(self, question: str) -> bool:
        try:
            answer = self._ask_raw(f"{question} [s/N] ")
        except EOFError:
            return False
        return answer.strip().casefold() in ("s", "si", "sì", "y", "yes")

    def _ask_host(self, alias: str, current: Host | None, *, ask_alias: bool = False) -> Host:
        """Prompt campo per campo. Invio = valore mostrato, "-" = cancella."""

        def ask(label: str, value: str | None) -> str | None:
            shown = f" [{value}]" if value else ""
            answer = self._ask(f"{label}{shown}: ").strip()
            if answer == "":
                return value or None
            return None if answer == "-" else answer

        if ask_alias:
            new_alias = ask("Alias", alias)
            if new_alias is None:
                raise HsmError("Serve un alias.")
            alias = new_alias
        hostname = ask("Hostname o IP", current.hostname if current else None)
        if hostname is None:
            raise HsmError("Serve un hostname o un indirizzo IP.")
        user = ask("Utente (invio = default di ssh)", current.user if current else None)
        port_text = ask("Porta", str(current.port if current else DEFAULT_PORT))
        try:
            port = int(port_text) if port_text else DEFAULT_PORT
        except ValueError:
            raise HsmError(f"Porta non valida: {port_text!r}") from None
        tags_text = ask("Tag (separati da spazi)", " ".join(current.tags) if current else None)
        jump = ask("Jump host", current.jump_host if current else None)
        identity = ask("Chiave SSH (identity_file)", current.identity_file if current else None)
        note = ask("Nota", current.note if current else None)
        return Host(
            alias=alias,
            hostname=hostname,
            user=user,
            port=port,
            tags=tuple(t for t in re.split(r"[\s,]+", tags_text or "") if t),
            jump_host=jump,
            identity_file=identity,
            note=note,
            auth=current.auth if current else "key",
        )


def _host_flags(args: argparse.Namespace) -> dict[str, object]:
    """I campi passati come flag (solo quelli presenti)."""
    mapping = {
        "hostname": args.hostname,
        "user": args.user,
        "port": args.port,
        "tags": tuple(args.tag) if args.tag else None,
        "jump_host": args.jump,
        "identity_file": args.identity,
        "note": args.note,
    }
    return {k: v for k, v in mapping.items() if v is not None}


def _wipe(entries: dict[str, VaultEntry]) -> None:
    for entry in entries.values():
        entry.password.wipe()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hsm", description="Inventario di host SSH con vault cifrato.")
    parser.add_argument("--debug", action="store_true", help="mostra i traceback (senza variabili locali)")
    sub = parser.add_subparsers(dest="command", metavar="COMANDO")

    def host_fields(p: argparse.ArgumentParser) -> None:
        p.add_argument("alias")
        p.add_argument("--hostname", "--ip", dest="hostname", metavar="HOST_O_IP", help="nome DNS o indirizzo IP")
        p.add_argument("--user")
        p.add_argument("--port", type=int)
        p.add_argument("--tag", action="append", help="ripetibile")
        p.add_argument("--jump", help="jump host: alias hsm o [user@]host[:port]")
        p.add_argument("--identity", help="chiave SSH (identity_file)")
        p.add_argument("--note")
        p.add_argument("--dry-run", action="store_true", help="mostra le modifiche senza scriverle")

    add = sub.add_parser("add", help="aggiunge un host")
    host_fields(add)
    # Un interruttore, mai un valore: `--password s3cret` finirebbe nella
    # cronologia della shell e negli argomenti visibili con `ps`.
    add.add_argument(
        "--password", action="store_true", help="chiede la password (nascosta) e la salva nel vault"
    )
    edit = sub.add_parser("edit", help="modifica un host")
    host_fields(edit)
    # dest diverso dal positional `alias`: è il NUOVO nome.
    edit.add_argument("--alias", dest="new_alias", metavar="NUOVO", help="rinomina l'host")

    ls = sub.add_parser("ls", help="elenca gli host")
    ls.add_argument("--tag")
    ls.add_argument("--sort", choices=("alias", "tag", "recent"), default="alias")

    rm = sub.add_parser("rm", help="rimuove un host")
    rm.add_argument("alias")
    rm.add_argument("--force", action="store_true", help="anche se è il jump_host di altri")
    rm.add_argument("--dry-run", action="store_true")

    connect = sub.add_parser("connect", help="apre la sessione ssh")
    connect.add_argument("alias")

    pw = sub.add_parser("pw", help="password nel vault")
    pw_sub = pw.add_subparsers(dest="pw_command", metavar="AZIONE", required=True)
    for name, text in (("set", "salva"), ("get", "copia negli appunti (30 s)"), ("rm", "rimuove")):
        pw_sub.add_parser(name, help=text).add_argument("alias")

    v = sub.add_parser("vault", help="gestione del vault")
    v_sub = v.add_subparsers(dest="vault_command", metavar="AZIONE", required=True)
    v_sub.add_parser("rekey", help="cambia la master password")

    sync = sub.add_parser("sync", help="rigenera il blocco hsm in ~/.ssh/config")
    sync.add_argument("--dry-run", action="store_true")
    return parser


def _harden() -> None:
    # Nessun core dump: conterrebbe la memoria del processo, chiavi incluse.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main(argv: Sequence[str] | None = None, *, app: App | None = None) -> int:
    """Entry point del comando `hsm`."""
    args = build_parser().parse_args(argv)
    sys.excepthook = make_excepthook(debug=args.debug)
    _harden()
    app = app if app is not None else App(Paths.default())
    app.preflight()
    return app.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
