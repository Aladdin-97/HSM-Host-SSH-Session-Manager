import resource
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from hsm import vault
from hsm.cli import App, Paths, build_parser, main
from hsm.errors import HsmError, InsecurePermissionsError
from hsm.fsutil import atomic_write
from hsm.inventory import Host, Inventory
from hsm.secret import Secret
from hsm.state import State
from hsm.touchid import Presence
from hsm.unlock import Unlocker
from hsm.vault import KdfParams

FAST = KdfParams(memory_cost_kib=8, time_cost=1, parallelism=1)
MASTER = "correct horse battery"


class FakeKeychain:
    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def load_key(self, key_id: str) -> Secret | None:
        raw = self.items.get(key_id)
        return None if raw is None else Secret(raw)

    def store_key(self, key_id: str, key: Secret) -> None:
        self.items[key_id] = bytes(key.view())

    def delete_key(self, key_id: str) -> bool:
        return self.items.pop(key_id, None) is not None

    def has_key(self, key_id: str) -> bool:
        return key_id in self.items


@dataclass
class FakeConnector:
    code: int = 0
    calls: list[tuple[str, bytes | None]] = field(default_factory=list)

    def connect(self, host: Host, inventory: Inventory, *, password: Secret | None = None) -> int:
        self.calls.append((host.alias, None if password is None else bytes(password.view())))
        return self.code


@dataclass
class FakeClipboard:
    copied: list[tuple[bytes, int]] = field(default_factory=list)

    def copy_with_autoclear(self, secret: Secret, seconds: int = 30) -> None:
        self.copied.append((bytes(secret.view()), seconds))


@dataclass
class FakePicker:
    choice: str | None = None
    offered: list[str] = field(default_factory=list)

    def choose(self, hosts: list[Host]) -> Host | None:
        self.offered = [h.alias for h in hosts]
        return next((h for h in hosts if h.alias == self.choice), None)


@dataclass
class Env:
    root: Path
    answers: list[str] = field(default_factory=list)  # input() in chiaro
    secrets: list[str] = field(default_factory=list)  # getpass: master e password host
    out: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    connector: FakeConnector = field(default_factory=FakeConnector)
    clipboard: FakeClipboard = field(default_factory=FakeClipboard)
    picker: FakePicker = field(default_factory=FakePicker)
    keychain: FakeKeychain = field(default_factory=FakeKeychain)
    unlocks: int = 0

    @property
    def paths(self) -> Paths:
        return Paths(config_dir=self.root / "cfg" / "hsm", ssh_config=self.root / "ssh" / "config")

    def _ask(self, prompt: str) -> str:
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def _secret(self, prompt: str) -> str:
        if not self.secrets:
            raise EOFError
        return self.secrets.pop(0)

    def _unlocker(self, path: Path) -> Unlocker:
        self.unlocks += 1
        return Unlocker(
            path,
            keychain=self.keychain,  # type: ignore[arg-type]
            presence=lambda reason: Presence.UNAVAILABLE,
            prompt=self._secret,
            warn=self.warnings.append,
            params=FAST,
        )

    def app(self) -> App:
        return App(
            self.paths,
            unlocker_factory=self._unlocker,
            connector=self.connector,  # type: ignore[arg-type]
            clipboard=self.clipboard,  # type: ignore[arg-type]
            picker=self.picker,  # type: ignore[arg-type]
            ask=self._ask,
            ask_secret=self._secret,
            out=self.out.append,
            warn=self.warnings.append,
            keychain=self.keychain,  # type: ignore[arg-type]
            which=lambda name: {"fzf": "/opt/homebrew/bin/fzf"}.get(name),
        )

    def run(self, *argv: str) -> int:
        return self.app().run(build_parser().parse_args(list(argv)))

    def inventory(self) -> Inventory:
        return Inventory.load(self.paths.hosts)

    def text(self) -> str:
        return "\n".join(self.out)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    (tmp_path / "ssh").mkdir(mode=0o700)
    return Env(tmp_path)


def _add_web01(env: Env, *extra: str) -> None:
    assert env.run("add", "web01", "--hostname", "10.0.0.1", "--user", "deploy", *extra) == 0


def _vault_with_password(env: Env, alias: str, password: str) -> None:
    env.secrets = ["host-pw", "host-pw", MASTER, MASTER] if password == "host-pw" else [password, password, MASTER, MASTER]
    assert env.run("pw", "set", alias) == 0


# --- avvio ------------------------------------------------------------------------


def test_preflight_ok_when_nothing_exists(env: Env) -> None:
    env.app().preflight()


@pytest.mark.parametrize("target", ["dir", "hosts", "vault", "state"])
def test_preflight_refuses_permissive_files(env: Env, target: str) -> None:
    _add_web01(env)
    paths = env.paths
    files = {"hosts": paths.hosts, "vault": paths.vault, "state": paths.state}
    if target == "dir":
        paths.config_dir.chmod(0o755)
    else:
        atomic_write(files[target], b"")
        files[target].chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        env.app().preflight()


def test_main_hardens_process_and_installs_excepthook(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "excepthook", sys.__excepthook__)
    assert main(["ls"], app=env.app()) == 0
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)  # niente core dump con segreti
    assert sys.excepthook is not sys.__excepthook__


def test_no_arguments_means_picker(env: Env) -> None:
    assert build_parser().parse_args([]).command is None


# --- add ------------------------------------------------------------------------


def test_add_with_flags(env: Env) -> None:
    _add_web01(env, "--port", "2222", "--tag", "prod", "--tag", "web", "--jump", "bastion")
    host = env.inventory().get("web01")
    assert (host.hostname, host.user, host.port, host.tags, host.jump_host) == (
        "10.0.0.1", "deploy", 2222, ("prod", "web"), "bastion",
    )  # fmt: skip


def test_add_interactive(env: Env) -> None:
    # hostname, user, port, tag, jump, identity, note (invio = vuoto/default)
    env.answers = ["db.example.com", "postgres", "", "prod db", "", "~/.ssh/id_db", "il database"]
    assert env.run("add", "db") == 0
    host = env.inventory().get("db")
    assert host == Host(
        alias="db", hostname="db.example.com", user="postgres", tags=("db", "prod"),
        identity_file="~/.ssh/id_db", note="il database",
    )  # fmt: skip


def test_add_dry_run_shows_diff_without_writing(env: Env) -> None:
    assert env.run("add", "web01", "--hostname", "10.0.0.1", "--dry-run") == 0
    assert not env.paths.hosts.exists()
    assert "+[hosts.web01]" in env.text()


def test_add_duplicate_is_error(env: Env) -> None:
    _add_web01(env)
    with pytest.raises(HsmError, match="Esiste già"):
        env.run("add", "web01", "--hostname", "x")


def test_add_invalid_value_is_clean_error(env: Env) -> None:
    with pytest.raises(HsmError, match="hostname"):
        env.run("add", "evil", "--hostname=-oProxyCommand=x")


# --- ls ---------------------------------------------------------------------------


def test_ls_lists_hosts_with_last_use(env: Env) -> None:
    _add_web01(env, "--tag", "prod")
    assert env.run("add", "lab", "--hostname", "lab.local") == 0
    env.out.clear()
    assert env.run("ls") == 0
    text = env.text()
    assert "web01" in text and "deploy@10.0.0.1" in text and "#prod" in text
    assert "mai" in text


def test_ls_filters_by_tag(env: Env) -> None:
    _add_web01(env, "--tag", "prod")
    env.run("add", "lab", "--hostname", "lab.local")
    env.out.clear()
    env.run("ls", "--tag", "prod")
    assert "web01" in env.text() and "lab" not in env.text()


def test_ls_sort_recent(env: Env) -> None:
    from datetime import UTC, datetime

    for alias in ("alpha", "beta", "gamma"):
        env.run("add", alias, "--hostname", f"{alias}.lan")
    state = State.load(env.paths.state)
    state.touch("gamma", datetime(2026, 10, 16, tzinfo=UTC))
    state.save()
    env.out.clear()
    env.run("ls", "--sort", "recent")
    rows = [line.split()[0] for line in env.out[1:]]
    assert rows == ["gamma", "alpha", "beta"]


def test_ls_sort_tag(env: Env) -> None:
    env.run("add", "z", "--hostname", "z", "--tag", "a")
    env.run("add", "a", "--hostname", "a", "--tag", "b")
    env.run("add", "m", "--hostname", "m")
    env.out.clear()
    env.run("ls", "--sort", "tag")
    assert [line.split()[0] for line in env.out[1:]] == ["z", "a", "m"]


def test_ls_empty_inventory_hint(env: Env) -> None:
    env.run("ls")
    assert "hsm add" in env.text()


# --- edit -------------------------------------------------------------------------


def test_edit_with_flags_keeps_other_fields(env: Env) -> None:
    _add_web01(env, "--tag", "prod")
    assert env.run("edit", "web01", "--port", "2200") == 0
    host = env.inventory().get("web01")
    assert (host.port, host.user, host.tags) == (2200, "deploy", ("prod",))


def test_edit_interactive_keeps_defaults_and_clears_with_dash(env: Env) -> None:
    _add_web01(env, "--note", "vecchia nota")
    # alias, hostname, user, port, tag, jump, identity, note
    env.answers = ["", "", "-", "", "", "", "", "-"]
    assert env.run("edit", "web01") == 0
    host = env.inventory().get("web01")
    assert (host.hostname, host.user, host.note) == ("10.0.0.1", None, None)


def test_edit_dry_run(env: Env) -> None:
    _add_web01(env)
    before = env.paths.hosts.read_text()
    env.run("edit", "web01", "--port", "2200", "--dry-run")
    assert env.paths.hosts.read_text() == before
    assert "+port = 2200" in env.text()


# --- rm ---------------------------------------------------------------------------


def test_rm_removes_host_without_touching_vault_for_key_hosts(env: Env) -> None:
    _add_web01(env)
    assert env.run("rm", "web01") == 0
    assert env.inventory().hosts() == []
    assert env.unlocks == 0  # nessun Touch ID/password per un host a chiave


def test_rm_dry_run(env: Env) -> None:
    _add_web01(env)
    env.run("rm", "web01", "--dry-run")
    assert env.inventory().get("web01")


def test_rm_referenced_jump_needs_force(env: Env) -> None:
    env.run("add", "bastion", "--hostname", "b.example.com")
    _add_web01(env, "--jump", "bastion")
    with pytest.raises(HsmError, match="jump_host"):
        env.run("rm", "bastion")
    assert env.run("rm", "bastion", "--force") == 0


def test_rm_password_host_also_removes_vault_entry(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    assert env.run("rm", "web01") == 0
    key = vault.derive_key(Secret.from_str(MASTER), vault.read_header(env.paths.vault))
    assert "web01" not in vault.load(env.paths.vault, key)


# --- pw ---------------------------------------------------------------------------


def test_pw_set_creates_vault_and_marks_host(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    assert env.inventory().get("web01").auth == "password"
    key = vault.derive_key(Secret.from_str(MASTER), vault.read_header(env.paths.vault))
    assert vault.load(env.paths.vault, key)["web01"].password == Secret(b"host-pw")


def test_pw_set_preserves_comments_in_hosts_file(env: Env) -> None:
    _add_web01(env)
    text = "# i miei server\n" + env.paths.hosts.read_text()
    atomic_write(env.paths.hosts, text.encode())
    _vault_with_password(env, "web01", "host-pw")
    assert env.paths.hosts.read_text().startswith("# i miei server\n")


def test_pw_set_mismatch_is_error(env: Env) -> None:
    _add_web01(env)
    env.secrets = ["one", "two"]
    with pytest.raises(HsmError, match="non coincidono"):
        env.run("pw", "set", "web01")
    assert not env.paths.vault.exists()


def test_pw_set_empty_is_error(env: Env) -> None:
    _add_web01(env)
    env.secrets = ["", ""]
    with pytest.raises(HsmError, match="vuota"):
        env.run("pw", "set", "web01")


def test_pw_set_unknown_alias(env: Env) -> None:
    with pytest.raises(HsmError, match="nope"):
        env.run("pw", "set", "nope")


def test_pw_get_copies_with_30s_autoclear(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    assert env.run("pw", "get", "web01") == 0
    assert env.clipboard.copied == [(b"host-pw", 30)]
    assert "30 s" in env.text()
    assert "host-pw" not in env.text()


def test_pw_get_missing_entry(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.run("add", "lab", "--hostname", "lab.local")
    env.secrets = [MASTER]
    with pytest.raises(HsmError, match="lab"):
        env.run("pw", "get", "lab")


def test_pw_rm_removes_entry_and_resets_auth(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    assert env.run("pw", "rm", "web01") == 0
    assert env.inventory().get("web01").auth == "key"


def test_vault_rekey(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER, "a brand new master pw", "a brand new master pw"]
    assert env.run("vault", "rekey") == 0
    header = vault.read_header(env.paths.vault)
    key = vault.derive_key(Secret.from_str("a brand new master pw"), header)
    assert "web01" in vault.load(env.paths.vault, key)


# --- connect e selettore ------------------------------------------------------


def test_connect_key_host_never_unlocks(env: Env) -> None:
    _add_web01(env)
    assert env.run("connect", "web01") == 0
    assert env.connector.calls == [("web01", None)]
    assert env.unlocks == 0
    assert State.load(env.paths.state).last_used("web01") is not None


def test_connect_password_host_passes_password(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    env.run("connect", "web01")
    assert env.connector.calls == [("web01", b"host-pw")]


def test_connect_password_host_without_entry_is_error(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    inv = env.inventory()
    inv.add(Host(alias="orphan", hostname="o", auth="password"))
    inv.save()
    env.secrets = [MASTER]
    with pytest.raises(HsmError, match="hsm pw set orphan"):
        env.run("connect", "orphan")


def test_connect_propagates_exit_code(env: Env) -> None:
    _add_web01(env)
    env.connector.code = 255
    assert env.run("connect", "web01") == 255


def test_connect_survives_broken_state_file(env: Env) -> None:
    _add_web01(env)
    atomic_write(env.paths.state, b"[last_used\n")
    assert env.run("connect", "web01") == 0
    assert any("state.toml" in w for w in env.warnings)


def test_picker_offers_recent_first_and_connects(env: Env) -> None:
    from datetime import UTC, datetime

    for alias in ("alpha", "beta"):
        env.run("add", alias, "--hostname", f"{alias}.lan")
    state = State.load(env.paths.state)
    state.touch("beta", datetime(2026, 10, 16, tzinfo=UTC))
    state.save()
    env.picker.choice = "alpha"
    assert env.run() == 0
    assert env.picker.offered == ["beta", "alpha"]
    assert env.connector.calls == [("alpha", None)]


def test_picker_cancel_does_not_connect(env: Env) -> None:
    _add_web01(env)
    env.picker.choice = None
    assert env.run() == 0
    assert env.connector.calls == []


# --- sync ---------------------------------------------------------------------------


def test_sync_writes_block(env: Env) -> None:
    _add_web01(env)
    assert env.run("sync") == 0
    assert "Host web01" in env.paths.ssh_config.read_text()


def test_sync_dry_run_shows_diff(env: Env) -> None:
    _add_web01(env)
    env.run("sync", "--dry-run")
    assert not env.paths.ssh_config.exists()
    assert "+Host web01" in env.text()


def test_sync_twice_reports_up_to_date(env: Env) -> None:
    _add_web01(env)
    env.run("sync")
    env.out.clear()
    env.run("sync")
    assert "aggiornato" in env.text()


# --- rami di errore -------------------------------------------------------------


def test_add_flags_without_hostname_is_error(env: Env) -> None:
    with pytest.raises(HsmError, match="--hostname"):
        env.run("add", "web01", "--user", "deploy")


def test_add_interactive_without_terminal(env: Env) -> None:
    with pytest.raises(HsmError, match="terminale"):
        env.run("add", "web01")


def test_add_interactive_requires_hostname(env: Env) -> None:
    env.answers = ["-"]
    with pytest.raises(HsmError, match="hostname"):
        env.run("add", "web01")


def test_add_interactive_bad_port(env: Env) -> None:
    env.answers = ["h.example.com", "", "abc"]
    with pytest.raises(HsmError, match="Porta"):
        env.run("add", "web01")


def test_rm_dry_run_mentions_vault_for_password_hosts(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.out.clear()
    env.run("rm", "web01", "--dry-run")
    assert "vault" in env.text()


def test_pw_rm_missing_entry(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    with pytest.raises(HsmError, match="Nessuna password"):
        env.run("pw", "rm", "lab")


def test_pw_set_without_terminal(env: Env) -> None:
    _add_web01(env)
    with pytest.raises(HsmError, match="terminale"):
        env.run("pw", "set", "web01")


def test_sync_reports_backup(env: Env) -> None:
    _add_web01(env)
    atomic_write(env.paths.ssh_config, b"Host old\n")
    env.run("sync")
    assert "backup" in env.text()


def test_confirm_accepts_italian_yes(env: Env) -> None:
    app = env.app()
    env.answers = ["sì"]
    assert app._confirm("Ok?") is True
    env.answers = ["n"]
    assert app._confirm("Ok?") is False
    assert app._confirm("Ok?") is False  # EOF = no


def test_default_paths_live_under_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    paths = Paths.default()
    assert paths.vault == tmp_path / ".config" / "hsm" / "vault.enc"
    assert paths.ssh_config == tmp_path / ".ssh" / "config"


# --- rilievi della security review --------------------------------------------


def _concurrent_add(env: Env, alias: str) -> None:
    """Un altro `hsm add` che finisce mentre questo comando è in attesa."""
    other = Inventory.load(env.paths.hosts)
    other.add(Host(alias=alias, hostname=f"{alias}.lan"))
    other.save()


def test_pw_set_does_not_lose_hosts_added_meanwhile(env: Env) -> None:
    _add_web01(env)
    original = env._secret
    calls = {"n": 0}

    def secret(prompt: str) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            _concurrent_add(env, "added-meanwhile")
        return original(prompt)

    env._secret = secret  # type: ignore[method-assign]
    env.secrets = ["host-pw", "host-pw", MASTER, MASTER]
    env.run("pw", "set", "web01")
    inv = env.inventory()
    assert inv.get("added-meanwhile")
    assert inv.get("web01").auth == "password"


def test_add_interactive_does_not_lose_hosts_added_meanwhile(env: Env) -> None:
    original = env._ask

    def ask(prompt: str) -> str:
        if prompt.startswith("Hostname"):
            _concurrent_add(env, "added-meanwhile")
        return original(prompt)

    env._ask = ask  # type: ignore[method-assign]
    env.answers = ["h.lan", "", "", "", "", "", ""]
    env.run("add", "mine")
    inv = env.inventory()
    assert inv.get("added-meanwhile") and inv.get("mine")


def test_rm_holds_the_lock_while_waiting_for_the_master_password(env: Env) -> None:
    # Un altro hsm che volesse scrivere in quel momento deve aspettare,
    # invece di salvare una versione che rm sovrascriverebbe.
    from hsm.fsutil import locked

    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    original = env._secret
    seen: list[bool] = []

    def secret(prompt: str) -> str:
        try:
            with locked(env.paths.lock, timeout=0.1):
                seen.append(False)
        except HsmError:
            seen.append(True)
        return original(prompt)

    env._secret = secret  # type: ignore[method-assign]
    env.secrets = [MASTER]
    env.run("rm", "web01")
    assert seen == [True]


class KeyTracker:
    """Avvolge l'Unlocker per conservare le chiavi restituite."""

    def __init__(self, env: Env) -> None:
        self.keys: list[Secret] = []
        self._factory = env._unlocker

    def __call__(self, path: Path) -> Unlocker:
        unlocker = self._factory(path)
        original = unlocker.get_vault_key

        def tracked() -> Secret:
            key = original()
            self.keys.append(key)
            return key

        unlocker.get_vault_key = tracked  # type: ignore[method-assign]
        return unlocker


def test_connect_wipes_vault_key_before_session_and_password_after(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    tracker = KeyTracker(env)
    env._unlocker = tracker  # type: ignore[method-assign]
    seen: dict[str, object] = {}

    class Inspecting(FakeConnector):
        def connect(self, host: Host, inventory: Inventory, *, password: Secret | None = None) -> int:
            # Durante la sessione ssh la chiave del vault non serve più.
            with pytest.raises(ValueError):
                tracker.keys[0].view()
            seen["password"] = password
            return super().connect(host, inventory, password=password)

    env.connector = Inspecting()
    env.secrets = [MASTER]
    env.run("connect", "web01")
    assert env.connector.calls == [("web01", b"host-pw")]
    with pytest.raises(ValueError):  # e la password sparisce a sessione finita
        seen["password"].view()  # type: ignore[union-attr]


@pytest.mark.parametrize("argv", [("pw", "rm", "web01"), ("vault", "rekey"), ("pw", "get", "web01")])
def test_vault_commands_on_fresh_install_are_clean_errors(env: Env, argv: tuple[str, ...]) -> None:
    with pytest.raises(HsmError, match="Vault non trovato"):
        env.run(*argv)


def test_pw_set_reports_hosts_file_failure_with_recovery_hint(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add_web01(env)
    original = Inventory.save

    def failing(self: Inventory, *, dry_run: bool = False) -> str:
        if not dry_run:
            raise OSError("disco pieno")
        return original(self, dry_run=True)

    monkeypatch.setattr(Inventory, "save", failing)
    env.secrets = ["host-pw", "host-pw", MASTER, MASTER]
    with pytest.raises(HsmError, match='auth = "password"'):
        env.run("pw", "set", "web01")


def test_add_validates_alias_before_asking_anything(env: Env) -> None:
    with pytest.raises(HsmError, match="alias"):
        env.run("add", "bad alias")
    assert env.answers == []  # nessuna domanda consumata (e nessun EOF)


# --- rinomina ---------------------------------------------------------------------


def test_edit_alias_renames_and_updates_dependents(env: Env) -> None:
    env.run("add", "bastion", "--hostname", "b.example.com")
    _add_web01(env, "--jump", "bastion")
    env.out.clear()
    assert env.run("edit", "bastion", "--alias", "gw") == 0
    inv = env.inventory()
    assert inv.get("gw").hostname == "b.example.com"
    assert inv.get("web01").jump_host == "gw"
    assert "hsm sync" in env.text()  # il vecchio blocco in ssh_config va rigenerato


def test_edit_alias_together_with_other_flags(env: Env) -> None:
    _add_web01(env)
    env.run("edit", "web01", "--alias", "web02", "--port", "2200")
    assert env.inventory().get("web02").port == 2200


def test_edit_interactive_asks_alias_first(env: Env) -> None:
    _add_web01(env)
    env.answers = ["web02", "", "", "", "", "", "", ""]
    env.run("edit", "web01")
    assert env.inventory().get("web02").hostname == "10.0.0.1"


def test_edit_alias_moves_vault_entry_and_last_use(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = [MASTER]
    env.run("connect", "web01")  # registra l'ultimo uso
    env.secrets = [MASTER]
    env.run("edit", "web01", "--alias", "web02")
    assert State.load(env.paths.state).last_used("web02") is not None
    env.secrets = [MASTER]
    env.connector.calls.clear()
    env.run("connect", "web02")
    assert env.connector.calls == [("web02", b"host-pw")]


def test_edit_alias_dry_run_changes_nothing(env: Env) -> None:
    _add_web01(env)
    before = env.paths.hosts.read_text()
    env.run("edit", "web01", "--alias", "web02", "--dry-run")
    assert env.paths.hosts.read_text() == before
    assert "+[hosts.web02]" in env.text()


# --- add: Hostname/IP e password subito -------------------------------------------


def test_add_accepts_ip_as_synonym_of_hostname(env: Env) -> None:
    assert env.run("add", "web01", "--ip", "10.0.0.1") == 0
    assert env.inventory().get("web01").hostname == "10.0.0.1"


def test_add_interactive_label_mentions_ip(env: Env) -> None:
    prompts: list[str] = []
    original = env._ask

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        return original(prompt)

    env._ask = ask  # type: ignore[method-assign]
    env.answers = ["10.0.0.1", "", "", "", "", "", ""]
    env.run("add", "web01")
    assert prompts[0].startswith("Hostname o IP")


def test_add_with_password_flag_stores_it_right_away(env: Env) -> None:
    # password host (due volte), poi master password nuova (due volte)
    env.secrets = ["host-pw", "host-pw", MASTER, MASTER]
    assert env.run("add", "legacy01", "--ip", "10.0.0.9", "--user", "admin", "--password") == 0
    assert env.inventory().get("legacy01").auth == "password"
    env.secrets = [MASTER]
    env.run("connect", "legacy01")
    assert env.connector.calls == [("legacy01", b"host-pw")]


def test_add_password_is_never_an_argv_value(env: Env) -> None:
    # `--password s3cret` finirebbe nella cronologia della shell e in `ps`.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["add", "x", "--ip", "h", "--password", "s3cret"])


def test_add_password_mismatch_adds_nothing(env: Env) -> None:
    env.secrets = ["one", "two"]
    with pytest.raises(HsmError, match="non coincidono"):
        env.run("add", "legacy01", "--ip", "10.0.0.9", "--password")
    assert env.inventory().hosts() == []
    assert not env.paths.vault.exists()


def test_add_password_cancelled_unlock_adds_nothing(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    env.secrets = ["pw2", "pw2"]  # poi EOF alla master password
    with pytest.raises(HsmError):
        env.run("add", "legacy01", "--ip", "10.0.0.9", "--password")
    with pytest.raises(HsmError):
        env.inventory().get("legacy01")


def test_add_interactive_offers_password(env: Env) -> None:
    env.answers = ["10.0.0.9", "admin", "", "", "", "", "", "s"]
    env.secrets = ["host-pw", "host-pw", MASTER, MASTER]
    env.run("add", "legacy01")
    assert env.inventory().get("legacy01").auth == "password"


def test_add_interactive_default_is_key(env: Env) -> None:
    env.answers = ["10.0.0.1", "", "", "", "", "", "", ""]
    env.run("add", "web01")
    assert env.inventory().get("web01").auth == "key"
    assert not env.paths.vault.exists()


def test_add_password_dry_run_asks_nothing_and_writes_nothing(env: Env) -> None:
    assert env.run("add", "legacy01", "--ip", "10.0.0.9", "--password", "--dry-run") == 0
    assert not env.paths.hosts.exists() and not env.paths.vault.exists()
    assert '+auth = "password"' in env.text()
    assert "vault" in env.text()


# --- hsm paths ---------------------------------------------------------------------


def _paths_rows(env: Env) -> dict[str, str]:
    env.out.clear()
    assert env.run("paths") == 0
    # Righe "ETICHETTA  PERCORSO  STATO" (a parte l'intestazione).
    return {line.split("  ")[0].strip(): line for line in env.out[1:]}


def test_paths_on_fresh_install_creates_nothing(env: Env) -> None:
    rows = _paths_rows(env)
    for label in ("Configurazione", "Inventario", "Vault", "Stato", "Lock", "SSH config"):
        assert "non esiste" in rows[label], label
    assert str(env.paths.vault) in rows["Vault"]
    assert not env.paths.config_dir.exists()


def test_paths_reports_ok_files_and_ssh_block(env: Env) -> None:
    _add_web01(env)
    atomic_write(env.paths.ssh_config, b"Host old\n")
    env.run("sync")
    rows = _paths_rows(env)
    assert "ok" in rows["Inventario"] and "600" in rows["Inventario"]
    assert "ok" in rows["Configurazione"] and "700" in rows["Configurazione"]
    assert "blocco hsm presente" in rows["SSH config"]
    assert "1 file" in rows["Backup SSH config"]


def test_paths_shows_permission_problems_instead_of_refusing(env: Env) -> None:
    _add_web01(env)
    env.paths.hosts.chmod(0o644)
    # Gli altri comandi si rifiutano di partire; paths deve mostrare il problema.
    assert main(["paths"], app=env.app()) == 0
    rows = {line.split("  ")[0].strip(): line for line in env.out if "  " in line}
    assert "chmod 600" in rows["Inventario"]


def test_paths_keychain_row(env: Env) -> None:
    rows = _paths_rows(env)
    assert "nessun vault" in rows["Keychain"]
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    rows = _paths_rows(env)
    kid = vault.key_id(vault.read_header(env.paths.vault))
    assert kid in rows["Keychain"] and "presente" in rows["Keychain"]
    env.keychain.items.clear()
    assert "assente" in _paths_rows(env)["Keychain"]


def test_paths_lists_programs(env: Env) -> None:
    rows = _paths_rows(env)
    assert "/usr/bin/ssh" in rows["ssh"]
    assert "/opt/homebrew/bin/fzf" in rows["fzf"]
    assert sys.executable in rows["Python"]


def test_paths_never_unlocks(env: Env) -> None:
    _add_web01(env)
    _vault_with_password(env, "web01", "host-pw")
    before = env.unlocks
    _paths_rows(env)
    assert env.unlocks == before
