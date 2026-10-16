from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from hsm import vault
from hsm.errors import HsmError, VaultAuthError, VaultError
from hsm.keychain import KeychainError, KeychainUnavailable
from hsm.secret import Secret
from hsm.touchid import Presence
from hsm.unlock import MAX_ATTEMPTS, MIN_PASSWORD_LENGTH, Unlocker
from hsm.vault import KdfParams

FAST = KdfParams(memory_cost_kib=8, time_cost=1, parallelism=1)
MASTER = "correct horse battery"
NEW_MASTER = "another long password"


@dataclass
class FakeKeychain:
    items: dict[str, bytes] = field(default_factory=dict)
    fail_load: KeychainError | None = None
    fail_store: KeychainError | None = None
    loads: int = 0

    def load_key(self, key_id: str) -> Secret | None:
        self.loads += 1
        if self.fail_load:
            raise self.fail_load
        raw = self.items.get(key_id)
        return None if raw is None else Secret(raw)

    def store_key(self, key_id: str, key: Secret) -> None:
        if self.fail_store:
            raise self.fail_store
        self.items[key_id] = bytes(key.view())

    def delete_key(self, key_id: str) -> bool:
        return self.items.pop(key_id, None) is not None


@dataclass
class Env:
    """Tutto ciò che Unlocker usa del mondo esterno, sostituito da finti."""

    path: Path
    keychain: FakeKeychain = field(default_factory=FakeKeychain)
    presence: Presence = Presence.GRANTED
    answers: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    presence_calls: int = 0

    def ask_presence(self, reason: str) -> Presence:
        self.presence_calls += 1
        return self.presence

    def prompt(self, label: str) -> str:
        self.prompts.append(label)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def unlocker(self) -> Unlocker:
        return Unlocker(
            self.path,
            keychain=self.keychain,  # type: ignore[arg-type]
            presence=self.ask_presence,
            prompt=self.prompt,
            warn=self.warnings.append,
            params=FAST,
        )

    def kid(self) -> str:
        return vault.key_id(vault.read_header(self.path))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(path=tmp_path / "hsm" / "vault.enc")


@pytest.fixture
def ready(env: Env) -> Iterator[Env]:
    """Un vault esistente con MASTER, Keychain vuoto."""
    vault.create(env.path, Secret.from_str(MASTER), FAST)
    yield env


def _opens(path: Path, key: Secret) -> bool:
    vault.load(path, key)  # solleva se la chiave non apre il vault
    return True


# --- get_vault_key ----------------------------------------------------------


def test_touch_id_and_cached_key_need_no_password(ready: Env) -> None:
    ready.keychain.items[ready.kid()] = bytes(
        vault.derive_key(Secret.from_str(MASTER), vault.read_header(ready.path)).view()
    )
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert ready.prompts == []


def test_first_unlock_prompts_then_caches_key(ready: Env) -> None:
    ready.answers = [MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert ready.keychain.items[ready.kid()] == bytes(key.view())


@pytest.mark.parametrize("presence", [Presence.DENIED, Presence.UNAVAILABLE])
def test_no_touch_id_falls_back_to_password_never_to_keychain(
    ready: Env, presence: Presence
) -> None:
    ready.presence = presence
    ready.keychain.items[ready.kid()] = b"\x00" * 32  # non deve nemmeno leggerlo
    ready.answers = [MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert ready.keychain.loads == 0
    assert ready.warnings  # l'utente sa perché gli chiediamo la password


def test_keychain_error_on_load_falls_back_to_password(ready: Env) -> None:
    ready.keychain.fail_load = KeychainError("User interaction is not allowed.")
    ready.answers = [MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert any("Keychain" in w for w in ready.warnings)


def test_keychain_unavailable_on_store_still_unlocks(ready: Env) -> None:
    ready.keychain.fail_store = KeychainUnavailable("security non trovato")
    ready.answers = [MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert any("Keychain" in w for w in ready.warnings)


def test_stale_cached_key_is_deleted_and_replaced(ready: Env) -> None:
    kid = ready.kid()
    ready.keychain.items[kid] = b"\x01" * 32  # non apre il vault
    ready.answers = [MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert ready.keychain.items[kid] == bytes(key.view())


def test_wrong_password_then_right_one(ready: Env) -> None:
    ready.answers = ["wrong", MASTER]
    key = ready.unlocker().get_vault_key()
    assert _opens(ready.path, key)
    assert any("errata" in w for w in ready.warnings)


def test_too_many_wrong_passwords(ready: Env) -> None:
    ready.answers = ["wrong"] * MAX_ATTEMPTS
    with pytest.raises(VaultAuthError):
        ready.unlocker().get_vault_key()
    assert ready.keychain.items == {}
    assert len(ready.prompts) == MAX_ATTEMPTS


def test_no_terminal_is_clean_error(ready: Env) -> None:
    ready.answers = []  # il prompt solleva EOFError
    with pytest.raises(HsmError, match="terminale"):
        ready.unlocker().get_vault_key()


def test_missing_vault_fails_before_touch_id(env: Env) -> None:
    with pytest.raises(VaultError, match="non trovato"):
        env.unlocker().get_vault_key()
    assert env.presence_calls == 0


def test_warnings_never_contain_passwords(ready: Env) -> None:
    ready.presence = Presence.DENIED
    ready.answers = ["wrong-secret-xyz", MASTER]
    ready.unlocker().get_vault_key()
    assert not any("wrong-secret-xyz" in w or MASTER in w for w in ready.warnings)


# --- init_vault --------------------------------------------------------------


def test_init_creates_vault_and_caches_key(env: Env) -> None:
    env.answers = [MASTER, MASTER]
    key = env.unlocker().init_vault()
    assert _opens(env.path, key)
    assert env.keychain.items[env.kid()] == bytes(key.view())


def test_init_retries_on_mismatch(env: Env) -> None:
    env.answers = [MASTER, MASTER + "x", MASTER, MASTER]
    key = env.unlocker().init_vault()
    assert _opens(env.path, key)
    assert any("non coincidono" in w for w in env.warnings)


def test_init_rejects_short_password(env: Env) -> None:
    short = "x" * (MIN_PASSWORD_LENGTH - 1)
    env.answers = [short, MASTER, MASTER]
    env.unlocker().init_vault()
    assert any(str(MIN_PASSWORD_LENGTH) in w for w in env.warnings)


def test_init_gives_up_without_creating_anything(env: Env) -> None:
    env.answers = ["short", "short"] * MAX_ATTEMPTS
    with pytest.raises(VaultError):
        env.unlocker().init_vault()
    assert not env.path.exists()


def test_init_refuses_existing_vault_before_prompting(ready: Env) -> None:
    with pytest.raises(VaultError, match="Esiste già"):
        ready.unlocker().init_vault()
    assert ready.prompts == []


def test_init_works_without_keychain(env: Env) -> None:
    env.keychain.fail_store = KeychainUnavailable("no")
    env.answers = [MASTER, MASTER]
    assert _opens(env.path, env.unlocker().init_vault())


# --- change_master_password --------------------------------------------------


def test_change_requires_typed_old_password_not_touch_id(ready: Env) -> None:
    ready.keychain.items[ready.kid()] = bytes(
        vault.derive_key(Secret.from_str(MASTER), vault.read_header(ready.path)).view()
    )
    ready.answers = [MASTER, NEW_MASTER, NEW_MASTER]
    ready.unlocker().change_master_password()
    assert ready.presence_calls == 0
    assert len(ready.prompts) == 3


def test_change_rotates_keychain_item(ready: Env) -> None:
    old_kid = ready.kid()
    ready.keychain.items[old_kid] = b"\x00" * 32
    ready.answers = [MASTER, NEW_MASTER, NEW_MASTER]
    new_key = ready.unlocker().change_master_password()
    new_kid = ready.kid()
    assert new_kid != old_kid
    assert old_kid not in ready.keychain.items
    assert ready.keychain.items[new_kid] == bytes(new_key.view())


def test_change_new_password_works_old_does_not(ready: Env) -> None:
    ready.answers = [MASTER, NEW_MASTER, NEW_MASTER]
    ready.unlocker().change_master_password()
    header = vault.read_header(ready.path)
    assert _opens(ready.path, vault.derive_key(Secret.from_str(NEW_MASTER), header))
    with pytest.raises(VaultAuthError):
        vault.load(ready.path, vault.derive_key(Secret.from_str(MASTER), header))


def test_change_with_wrong_old_password_leaves_vault_untouched(ready: Env) -> None:
    before = ready.path.read_bytes()
    ready.answers = ["wrong"] * MAX_ATTEMPTS
    with pytest.raises(VaultAuthError):
        ready.unlocker().change_master_password()
    assert ready.path.read_bytes() == before


def test_default_construction_uses_real_components(tmp_path: Path) -> None:
    # Costruire un Unlocker senza argomenti non deve toccare nulla.
    Unlocker(tmp_path / "vault.enc")


def test_empty_password_counts_as_attempt(ready: Env) -> None:
    ready.presence = Presence.UNAVAILABLE
    ready.answers = ["", MASTER]
    assert _opens(ready.path, ready.unlocker().get_vault_key())
    assert any("vuota" in w for w in ready.warnings)


def test_failure_to_delete_stale_item_is_only_a_warning(ready: Env) -> None:
    class StickyKeychain(FakeKeychain):
        def delete_key(self, key_id: str) -> bool:
            raise KeychainError("delete fallita")

    ready.keychain = StickyKeychain()
    ready.keychain.items[ready.kid()] = b"\x01" * 32
    ready.answers = [MASTER]
    assert _opens(ready.path, ready.unlocker().get_vault_key())
    assert any("rimuovere" in w for w in ready.warnings)


def test_default_warn_goes_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    from hsm.unlock import _warn_stderr

    _warn_stderr("attenzione")
    assert capsys.readouterr().err == "hsm: attenzione\n"


# --- rilievi della security review --------------------------------------------


def test_unlock_does_not_decode_entries_just_to_verify(
    ready: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Verificare la chiave non deve decifrare tutte le password in memoria.
    def no_load(*args: object) -> None:
        raise AssertionError("vault.load usato per verificare")

    monkeypatch.setattr(vault, "load", no_load)
    ready.answers = [MASTER]
    ready.unlocker().get_vault_key()


def test_non_utf8_input_is_clean_error_without_echo(ready: Env) -> None:
    ready.presence = Presence.UNAVAILABLE
    ready.answers = ["abc\udcff"]
    with pytest.raises(HsmError, match="caratteri non validi") as info:
        ready.unlocker().get_vault_key()
    assert "udcff" not in str(info.value) and "\udcff" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_min_length_counts_characters_not_bytes(env: Env) -> None:
    # 4 emoji = 16 byte UTF-8 ma solo 4 caratteri: troppo corta.
    emoji = "🔑🔑🔑🔑"
    env.answers = [emoji, MASTER, MASTER]
    env.unlocker().init_vault()
    assert any(str(MIN_PASSWORD_LENGTH) in w for w in env.warnings)
    assert len(env.prompts) == 3


def test_first_entry_wiped_if_confirmation_fails(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[Secret] = []
    original = Secret.from_str.__func__  # type: ignore[attr-defined]

    def tracking(cls: type[Secret], text: str) -> Secret:
        s = original(cls, text)
        created.append(s)
        return s

    monkeypatch.setattr(Secret, "from_str", classmethod(tracking))
    env.answers = [MASTER]  # la conferma solleva EOFError
    with pytest.raises(HsmError):
        env.unlocker().init_vault()
    with pytest.raises(ValueError):  # già azzerato
        created[0].view()


def test_rekey_stores_new_item_before_forgetting_old(ready: Env) -> None:
    order: list[str] = []
    kc = ready.keychain
    orig_store, orig_delete = kc.store_key, kc.delete_key

    def store(key_id: str, key: Secret) -> None:
        order.append("store")
        orig_store(key_id, key)

    def delete(key_id: str) -> bool:
        order.append("delete")
        return orig_delete(key_id)

    kc.store_key = store  # type: ignore[method-assign]
    kc.delete_key = delete  # type: ignore[method-assign]
    ready.answers = [MASTER, NEW_MASTER, NEW_MASTER]
    ready.unlocker().change_master_password()
    # Se il processo muore a metà, deve esistere già l'item nuovo.
    assert order == ["store", "delete"]


def test_corrupt_vault_propagates_format_error(ready: Env) -> None:
    from hsm.errors import VaultFormatError

    data = ready.path.read_bytes()
    ready.path.write_bytes(data[: vault.HEADER_SIZE + 3])
    ready.answers = [MASTER]
    ready.presence = Presence.UNAVAILABLE
    with pytest.raises(VaultFormatError):
        ready.unlocker().get_vault_key()


def test_corrupt_vault_with_cached_key_propagates_and_keeps_item(ready: Env) -> None:
    from hsm.errors import VaultFormatError

    kid = ready.kid()
    ready.keychain.items[kid] = b"\x01" * 32
    data = ready.path.read_bytes()
    ready.path.write_bytes(data[: vault.HEADER_SIZE + 3])
    with pytest.raises(VaultFormatError):
        ready.unlocker().get_vault_key()
    # Un vault rotto non è colpa della chiave: l'item resta.
    assert kid in ready.keychain.items
