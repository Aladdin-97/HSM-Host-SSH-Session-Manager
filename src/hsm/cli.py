"""hsm command line: wires the modules together, holds no domain logic.

    hsm                      picker, Enter = connect
    hsm add <alias>          flags or interactive prompt   [--dry-run]
    hsm ls [--tag X] [--sort alias|tag|recent]
    hsm rm <alias>           [--force] [--dry-run]
    hsm edit <alias>         flags or interactive prompt   [--dry-run]
    hsm connect <alias>
    hsm pw set|get|rm <alias>
    hsm vault rekey
    hsm sync                 [--dry-run]
    hsm paths

At startup, before any command:
- no core dumps (RLIMIT_CORE = 0): a crash must not leave on disk a memory
  image with keys or passwords in clear;
- an excepthook that prints messages only, never tracebacks with local
  variables (with --debug, the standard traceback, which does not show them);
- a permission check on hsm's directory and files: if they are too open,
  we refuse to start.

Vault operations (pw set/rm, rm of a password host, rekey) run under a
lock, so two hsm processes in parallel do not overwrite each other's changes.
"""

import argparse
import dataclasses
import difflib
import getpass
import os
import re
import resource
import shutil
import stat
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

from hsm import vault
from hsm.clipboard import DEFAULT_SECONDS, Clipboard
from hsm.connect import SSH, Connector, default_askpass_helper
from hsm.errors import HsmError, InsecurePermissionsError, make_excepthook
from hsm.fsutil import check_private, ensure_private_dir, locked
from hsm.inventory import DEFAULT_PORT, Host, Inventory, is_valid_alias
from hsm.picker import Picker, format_line
from hsm.secret import Secret
from hsm.keychain import Keychain, KeychainError
from hsm.sshconfig import BEGIN, apply, render
from hsm.state import State
from hsm.unlock import Unlocker
from hsm.vault import VaultEntry


@dataclasses.dataclass(frozen=True)
class Paths:
    """Where hsm's files live."""

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
    """The hsm commands. Every external dependency is injectable for tests."""

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
        keychain: Keychain | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self.paths = paths
        self._keychain = keychain if keychain is not None else Keychain()
        self._which = which
        self._unlocker_factory = unlocker_factory
        self._clipboard = clipboard if clipboard is not None else Clipboard()
        self._connector = connector or Connector(warn=warn)
        self._picker = picker if picker is not None else Picker()
        self._ask_raw = ask
        self._ask_secret_raw = ask_secret
        self._out = out
        self._warn = warn

    # --- startup ------------------------------------------------------------

    def preflight(self) -> None:
        """Refuse to start if hsm's files are accessible to others."""
        p = self.paths
        if os.path.lexists(p.config_dir):
            check_private(p.config_dir)
        for path in (p.hosts, p.vault, p.state, p.lock):
            if os.path.lexists(path):
                check_private(path)

    def run(self, args: argparse.Namespace) -> int:
        """Run the parsed command; return the exit code."""
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
            case "paths":
                return self.show_paths()
        raise HsmError(f"Unknown command: {args.command}")  # pragma: no cover - argparse prevents it

    # --- inventory ----------------------------------------------------------

    def add(self, args: argparse.Namespace) -> int:
        # Alias and duplicates are checked up front: no point answering
        # seven questions only to find out the alias is not acceptable.
        if not is_valid_alias(args.alias):
            raise HsmError(f"invalid alias: {args.alias!r}")
        Inventory.load(self.paths.hosts).add(Host(alias=args.alias, hostname="placeholder"))
        flags = _host_flags(args)
        use_password: bool = args.password
        if not flags:
            host = self._ask_host(args.alias, None)
            if not use_password and not args.dry_run:
                use_password = self._confirm("Use a password for this host (stored in the vault)?")
        elif "hostname" not in flags:
            raise HsmError("Missing --hostname/--ip (or run `hsm add <alias>` without flags).")
        else:
            host = Host(alias=args.alias, **flags)
        if use_password:
            host = dataclasses.replace(host, auth="password")

        if args.dry_run or not use_password:
            self._change_inventory(lambda inv: inv.add(host), dry_run=args.dry_run)
            if args.dry_run and use_password:
                self._out(f"(would ask for the password of {host.alias} and store it in the vault)")
            elif not args.dry_run:
                self._out(f"Added {host.alias}.")
            return 0

        # The password is asked before taking the lock (the user may take a
        # while); vault and inventory are then updated together, under lock.
        with self._ask_new_host_password(host.alias) as password:
            ensure_private_dir(self.paths.config_dir)
            with locked(self.paths.lock):
                inv = Inventory.load(self.paths.hosts)
                # In-memory inventory first: an alias already in use is caught
                # here, before touching the vault. If the unlock is cancelled
                # the host is not added.
                inv.add(host)
                self._store_password(host.alias, password)
                try:
                    inv.save()
                except (OSError, HsmError) as exc:
                    raise HsmError(
                        f"Password for {host.alias} stored in the vault, but could not "
                        f"update {self.paths.hosts} ({exc}): run hsm add again, or "
                        f"remove the password with hsm pw rm {host.alias}."
                    ) from None
        self._out(f"Added {host.alias}, with its password in the vault.")
        return 0

    def edit(self, args: argparse.Namespace) -> int:
        alias = args.alias
        flags = _host_flags(args)
        new_alias: str | None = args.new_alias
        if flags or new_alias:
            # With flags the change applies to the latest version of the
            # host, read under lock.
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
                self._out(f"Updated {alias}.")
            return 0
        self._rename(alias, new_alias, change)
        return 0

    def _rename(self, old: str, new: str, change: Callable[[Inventory], None]) -> None:
        """Rename under lock: inventory, vault password, last use."""
        ensure_private_dir(self.paths.config_dir)
        with locked(self.paths.lock):
            inv = Inventory.load(self.paths.hosts)
            uses_password = inv.get(old).auth == "password"
            # In-memory inventory first: if the new alias is invalid or already
            # in use, we stop here without having touched the vault.
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
                    f"The vault password is now under {new}, but could not update "
                    f"{self.paths.hosts} ({exc}): rename the host to {new} by hand."
                ) from None
        self._update_state(lambda s: s.rename(old, new))
        self._out(f"Renamed {old} to {new}.")
        self._out("Run hsm sync to update ~/.ssh/config, which still has the old name.")

    def ls(self, tag: str | None, sort: str) -> int:
        inv = Inventory.load(self.paths.hosts)
        hosts = inv.hosts(tag=tag)
        if not hosts:
            self._out("No hosts. Add one with: hsm add <alias>")
            return 0
        state = State.load_or_empty(self.paths.state, self._warn)
        if sort == "recent":
            order = state.recent([h.alias for h in hosts])
            hosts = sorted(hosts, key=lambda h: order.index(h.alias))
        elif sort == "tag":
            # By first tag; hosts without tags go last.
            hosts = sorted(hosts, key=lambda h: (h.tags[0] if h.tags else "￿", h.alias))
        rows = [("ALIAS", "HOST", "TAG", "AUTH", "LAST USED")]
        for host in hosts:
            alias, target, tags, _note = format_line(host).split("\t")
            used = state.last_used(host.alias)
            when = used.astimezone().strftime("%Y-%m-%d %H:%M") if used else "never"
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
                self._out(f"(would also remove the password of {alias} from the vault)")
            return 0
        ensure_private_dir(self.paths.config_dir)
        with locked(self.paths.lock):
            inv = Inventory.load(self.paths.hosts)
            host = inv.remove(alias, force=force)
            # Vault first: if the unlock is cancelled, the host stays as it was.
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
                    f"Password for {alias} removed from the vault, but could not update "
                    f"{self.paths.hosts} ({exc}): run hsm rm {alias} again."
                ) from None
        self._update_state(lambda s: s.forget(alias))
        self._out(f"Removed {alias}.")
        return 0

    # --- connection -----------------------------------------------------------

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
            # Only hosts with auth = "password" open the vault: key-based hosts
            # get no Touch ID prompt and no master password.
            if host.auth == "password":
                password = self._password_for(host.alias)
            # Before the session: a long or badly interrupted session must
            # not lose the update.
            self._update_state(lambda s: s.touch(host.alias))
            return self._connector.connect(host, inv, password=password)
        finally:
            if password is not None:
                password.wipe()

    def _password_for(self, alias: str) -> Secret:
        """A copy of `alias`'s password alone.

        The vault key and the other entries are wiped right away: during the
        ssh session, which can last hours, only what is needed stays in memory.
        """
        with self._unlocker().get_vault_key() as key:
            entries = vault.load(self.paths.vault, key)
        try:
            entry = entries.get(alias)
            if entry is None:
                raise HsmError(
                    f"{alias} uses auth = password but the vault has no "
                    f"password for it: hsm pw set {alias}"
                )
            return Secret(bytearray(entry.password.view()))
        finally:
            _wipe(entries)

    # --- passwords ------------------------------------------------------------

    def pw_set(self, alias: str) -> int:
        Inventory.load(self.paths.hosts).get(alias)  # fail early if the host does not exist
        with self._ask_new_host_password(alias) as password:
            ensure_private_dir(self.paths.config_dir)
            with locked(self.paths.lock):
                # Reloaded under lock: meanwhile (prompt, Touch ID) another
                # hsm may have changed the inventory.
                inv = Inventory.load(self.paths.hosts)
                host = inv.get(alias)
                self._store_password(alias, password)
                if host.auth != "password":
                    try:
                        inv.update(dataclasses.replace(host, auth="password"))
                        inv.save()
                    except (OSError, HsmError) as exc:
                        raise HsmError(
                            f"Password stored in the vault, but could not update "
                            f"{self.paths.hosts} ({exc}): set "
                            f'auth = "password" for {alias} by hand, or run hsm pw set {alias} again.'
                        ) from None
                    self._out(f'Set auth = "password" for {alias} in {self.paths.hosts}.')
        self._out(f"Password for {alias} stored in the vault.")
        return 0

    def _ask_new_host_password(self, alias: str) -> Secret:
        password = self._read_secret(f"Password for {alias}: ")
        try:
            with self._read_secret("Repeat the password: ") as again:
                if len(password) == 0:
                    raise HsmError("The password is empty.")
                if password != again:
                    raise HsmError("The passwords do not match.")
        except BaseException:
            password.wipe()  # also on Ctrl-C at the second prompt
            raise
        return password

    def _store_password(self, alias: str, password: Secret) -> None:
        """Write the password to the vault (creating it if needed). Call under lock."""
        unlocker = self._unlocker()
        exists = os.path.lexists(self.paths.vault)
        key = unlocker.get_vault_key() if exists else unlocker.init_vault()
        with key:
            entries = vault.load(self.paths.vault, key) if exists else {}
            try:
                old = entries.pop(alias, None)
                if old is not None:
                    old.password.wipe()
                # Copy: `password` belongs to the caller and will be wiped there.
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
                raise HsmError(f"No password stored for {alias}.")
            self._clipboard.copy_with_autoclear(entry.password, DEFAULT_SECONDS)
        finally:
            _wipe(entries)
        self._out(f"Password for {alias} copied to the clipboard: cleared in {DEFAULT_SECONDS} s.")
        return 0

    def pw_rm(self, alias: str) -> int:
        self._require_vault()
        with locked(self.paths.lock):
            with self._unlocker().get_vault_key() as key:
                entries = vault.load(self.paths.vault, key)
                try:
                    entry = entries.pop(alias, None)
                    if entry is None:
                        raise HsmError(f"No password stored for {alias}.")
                    entry.password.wipe()
                    vault.save(self.paths.vault, key, entries)
                finally:
                    _wipe(entries)
            inv = Inventory.load(self.paths.hosts)
            host = next((h for h in inv.hosts() if h.alias == alias), None)
            if host is not None and host.auth == "password":
                inv.update(dataclasses.replace(host, auth="key"))
                inv.save()
        self._out(f"Password for {alias} removed from the vault.")
        return 0

    def vault_rekey(self) -> int:
        self._require_vault()
        with locked(self.paths.lock), self._unlocker().change_master_password():
            pass
        self._out("Master password changed.")
        return 0

    def _require_vault(self) -> None:
        # Raises "Vault not found... hsm pw set" if it is missing, before
        # trying to take a lock in a directory that may not exist.
        vault.read_header(self.paths.vault)

    # --- ssh_config -----------------------------------------------------------

    def sync(self, *, dry_run: bool) -> int:
        inv = Inventory.load(self.paths.hosts)
        result = apply(self.paths.ssh_config, render(inv.hosts()), dry_run=dry_run)
        if dry_run:
            self._out(result.diff() or "No changes.")
        elif not result.changed:
            self._out(f"{self.paths.ssh_config} already up to date.")
        else:
            backup = f" (backup: {result.backup})" if result.backup else ""
            self._out(f"Updated {self.paths.ssh_config}{backup}.")
        return 0

    # --- diagnostics ------------------------------------------------------------

    def show_paths(self) -> int:
        """Every file and program hsm uses, with its status.

        Read-only: creates nothing, does not open the vault, reads no secrets.
        Runs even with wrong permissions, precisely to show them.
        """
        p = self.paths
        rows = [
            ("WHAT", "PATH", "STATUS"),
            ("Config dir", str(p.config_dir), _status(p.config_dir)),
            ("Inventory", str(p.hosts), _status(p.hosts)),
            ("Vault", str(p.vault), _status(p.vault)),
            ("State", str(p.state), _status(p.state)),
            ("Lock", str(p.lock), _status(p.lock)),
            ("SSH config", str(p.ssh_config), self._ssh_config_status()),
            self._backups_row(),
            self._keychain_row(),
            ("ssh", SSH, "ok" if os.access(SSH, os.X_OK) else "not found"),
            self._askpass_row(),
            self._program_row("fzf", self._which("fzf"), "not installed: numbered list"),
            ("Python", sys.executable, "runs hsm and the clipboard watchdog"),
        ]
        widths = [max(len(r[i]) for r in rows) for i in range(2)]
        for label, path, status in rows:
            self._out(f"{label.ljust(widths[0])}  {path.ljust(widths[1])}  {status}".rstrip())
        return 0

    def _ssh_config_status(self) -> str:
        path = self.paths.ssh_config
        status = _status(path)
        if not os.path.isfile(path) or os.path.islink(path):
            return status
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"{status}, unreadable ({exc.strerror})"
        block = "hsm block present" if BEGIN in text else "no hsm block"
        return f"{status}, {block}"

    def _backups_row(self) -> tuple[str, str, str]:
        path = self.paths.ssh_config
        pattern = f"{path.name}.hsm-backup-*"
        backups = sorted(path.parent.glob(pattern)) if path.parent.is_dir() else []
        status = f"{len(backups)} file(s), latest {backups[-1].name}" if backups else "none"
        return ("Backup SSH config", str(path.parent / pattern), status)

    def _keychain_row(self) -> tuple[str, str, str]:
        label = "Keychain"
        if not os.path.lexists(self.paths.vault):
            return (label, "login keychain, service hsm", "no vault, no item")
        try:
            kid = vault.key_id(vault.read_header(self.paths.vault))
        except HsmError as exc:
            return (label, "login keychain, service hsm", f"vault unreadable: {exc}")
        where = f"login keychain, service hsm, account {kid}"
        try:
            present = self._keychain.has_key(kid)
        except KeychainError as exc:
            return (label, where, f"cannot check: {exc}")
        return (label, where, "present (unlock with Touch ID)" if present else "absent (master password required)")

    @staticmethod
    def _askpass_row() -> tuple[str, str, str]:
        helper = default_askpass_helper()
        ok = helper.is_file() and os.access(helper, os.X_OK)
        status = "ok (automatic password for ssh)" if ok else "missing: reinstall hsm"
        return ("hsm-askpass", str(helper), status)

    @staticmethod
    def _program_row(name: str, found: str | None, missing: str) -> tuple[str, str, str]:
        return (name, found or "-", "ok" if found else missing)

    # --- helpers --------------------------------------------------------------

    def _unlocker(self) -> Unlocker:
        return self._unlocker_factory(self.paths.vault)

    def _change_inventory(self, change: Callable[[Inventory], None], *, dry_run: bool) -> None:
        """Apply `change` to hosts.toml.

        In dry-run, show the diff and touch nothing (not even the lock).
        Otherwise reload the file under lock, apply and save: the change always
        starts from the latest version, and two hsm processes in parallel do
        not erase each other's hosts.
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
            tofile=f"{self.paths.hosts} (after)",
        )
        self._out("".join(diff).rstrip("\n") or "No changes.")
        self._out("(dry-run: no files modified)")

    def _update_state(self, change: Callable[[State], None]) -> None:
        # State is a convenience: a problem with it must never block a
        # connect or an rm; at most it produces a warning.
        try:
            state = State.load_or_empty(self.paths.state, self._warn)
            change(state)
            state.save()
        except (HsmError, OSError) as exc:
            self._warn(f"Cannot update {self.paths.state}: {exc}")

    def _ask(self, prompt: str) -> str:
        try:
            return self._ask_raw(prompt)
        except EOFError:
            raise HsmError("No terminal available for interactive prompts.") from None

    def _read_secret(self, prompt: str) -> Secret:
        try:
            text = self._ask_secret_raw(prompt)
        except EOFError:
            raise HsmError("No terminal available to ask for the password.") from None
        try:
            return Secret.from_str(text)
        except UnicodeEncodeError:
            raise HsmError("The password contains invalid characters.") from None

    def _confirm(self, question: str) -> bool:
        try:
            answer = self._ask_raw(f"{question} [y/N] ")
        except EOFError:
            return False
        return answer.strip().casefold() in ("y", "yes")

    def _ask_host(self, alias: str, current: Host | None, *, ask_alias: bool = False) -> Host:
        """Field-by-field prompt. Enter = shown value, "-" = clear."""

        def ask(label: str, value: str | None) -> str | None:
            shown = f" [{value}]" if value else ""
            answer = self._ask(f"{label}{shown}: ").strip()
            if answer == "":
                return value or None
            return None if answer == "-" else answer

        if ask_alias:
            new_alias = ask("Alias", alias)
            if new_alias is None:
                raise HsmError("An alias is required.")
            alias = new_alias
        hostname = ask("Hostname or IP", current.hostname if current else None)
        if hostname is None:
            raise HsmError("A hostname or IP address is required.")
        user = ask("User (Enter = ssh default)", current.user if current else None)
        port_text = ask("Port", str(current.port if current else DEFAULT_PORT))
        try:
            port = int(port_text) if port_text else DEFAULT_PORT
        except ValueError:
            raise HsmError(f"Invalid port: {port_text!r}") from None
        tags_text = ask("Tags (space-separated)", " ".join(current.tags) if current else None)
        jump = ask("Jump host", current.jump_host if current else None)
        identity = ask("SSH key (identity_file)", current.identity_file if current else None)
        note = ask("Note", current.note if current else None)
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
    """The fields passed as flags (only those present)."""
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


def _status(path: Path) -> str:
    """Exists? Private? In one line, without raising expected exceptions."""
    if not os.path.lexists(path):
        return "missing"
    try:
        check_private(path)
    except InsecurePermissionsError as exc:
        return f"PROBLEM: {exc}"
    return f"ok ({stat.S_IMODE(os.lstat(path).st_mode):03o})"


def _wipe(entries: dict[str, VaultEntry]) -> None:
    for entry in entries.values():
        entry.password.wipe()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hsm", description="SSH host inventory with an encrypted vault.")
    parser.add_argument("--debug", action="store_true", help="show tracebacks (without local variables)")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def host_fields(p: argparse.ArgumentParser) -> None:
        p.add_argument("alias")
        p.add_argument("--hostname", "--ip", dest="hostname", metavar="HOST_OR_IP", help="DNS name or IP address")
        p.add_argument("--user")
        p.add_argument("--port", type=int)
        p.add_argument("--tag", action="append", help="repeatable")
        p.add_argument("--jump", help="jump host: hsm alias or [user@]host[:port]")
        p.add_argument("--identity", help="SSH key (identity_file)")
        p.add_argument("--note")
        p.add_argument("--dry-run", action="store_true", help="show the changes without writing them")

    add = sub.add_parser("add", help="add a host")
    host_fields(add)
    # A switch, never a value: `--password s3cret` would end up in the
    # shell history and in the arguments visible with `ps`.
    add.add_argument(
        "--password", action="store_true", help="ask for the password (hidden) and store it in the vault"
    )
    edit = sub.add_parser("edit", help="edit a host")
    host_fields(edit)
    # dest differs from the positional `alias`: this is the NEW name.
    edit.add_argument("--alias", dest="new_alias", metavar="NEW", help="rename the host")

    ls = sub.add_parser("ls", help="list hosts")
    ls.add_argument("--tag")
    ls.add_argument("--sort", choices=("alias", "tag", "recent"), default="alias")

    rm = sub.add_parser("rm", help="remove a host")
    rm.add_argument("alias")
    rm.add_argument("--force", action="store_true", help="even if it is the jump_host of others")
    rm.add_argument("--dry-run", action="store_true")

    connect = sub.add_parser("connect", help="open the ssh session")
    connect.add_argument("alias")

    pw = sub.add_parser("pw", help="passwords in the vault")
    pw_sub = pw.add_subparsers(dest="pw_command", metavar="ACTION", required=True)
    for name, text in (("set", "store"), ("get", "copy to the clipboard (30 s)"), ("rm", "remove")):
        pw_sub.add_parser(name, help=text).add_argument("alias")

    v = sub.add_parser("vault", help="vault management")
    v_sub = v.add_subparsers(dest="vault_command", metavar="ACTION", required=True)
    v_sub.add_parser("rekey", help="change the master password")

    sync = sub.add_parser("sync", help="regenerate the hsm block in ~/.ssh/config")
    sync.add_argument("--dry-run", action="store_true")

    sub.add_parser("paths", help="show every file and program used, with its status")
    return parser


def _harden() -> None:
    # No core dumps: they would contain the process memory, keys included.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main(argv: Sequence[str] | None = None, *, app: App | None = None) -> int:
    """Entry point of the `hsm` command."""
    args = build_parser().parse_args(argv)
    sys.excepthook = make_excepthook(debug=args.debug)
    _harden()
    app = app if app is not None else App(Paths.default())
    # `paths` is the diagnostic: it must work even with wrong permissions,
    # in order to show them. It writes nothing and reads no secrets, so it can.
    if args.command != "paths":
        app.preflight()
    return app.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
