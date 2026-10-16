import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hsm import vault
from hsm.errors import InsecurePermissionsError, VaultAuthError, VaultError, VaultFormatError
from hsm.secret import Secret
from hsm.vault import HEADER_SIZE, KdfParams, VaultEntry

# Parametri minimi per tenere i test veloci (ms invece di ~1 s).
# I parametri reali sono verificati a parte in test_default_kdf_params.
FAST = KdfParams(memory_cost_kib=8, time_cost=1, parallelism=1)


def pw(text: str = "correct horse") -> Secret:
    return Secret.from_str(text)


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "hsm" / "vault.enc"


@pytest.fixture
def key(vault_path: Path) -> Secret:
    return vault.create(vault_path, pw(), FAST)


def _flip(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))


# --- parametri ---------------------------------------------------------------


def test_default_kdf_params() -> None:
    assert vault.DEFAULT_KDF == KdfParams(memory_cost_kib=262_144, time_cost=3, parallelism=4)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"memory_cost_kib": 7, "time_cost": 1, "parallelism": 1},  # sotto 8*p
        {"memory_cost_kib": 600_000, "time_cost": 1, "parallelism": 1},  # oltre il tetto
        {"memory_cost_kib": 64, "time_cost": 9, "parallelism": 1},  # oltre il tetto
        {"memory_cost_kib": 64, "time_cost": 0, "parallelism": 1},
        {"memory_cost_kib": 64, "time_cost": 1, "parallelism": 0},
    ],
)
def test_kdf_params_bounds(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        KdfParams(**kwargs)


# --- create / load / save ----------------------------------------------------


def test_create_then_load_is_empty(vault_path: Path, key: Secret) -> None:
    assert vault.load(vault_path, key) == {}


def test_save_then_load_roundtrip(vault_path: Path, key: Secret) -> None:
    entries = {"web01": VaultEntry(pw("s3cret"), "2026-10-16T10:00:00Z")}
    vault.save(vault_path, key, entries)
    loaded = vault.load(vault_path, key)
    assert loaded == entries


def test_unlock_with_password_roundtrip(vault_path: Path, key: Secret) -> None:
    vault.save(vault_path, key, {"a": VaultEntry.new(pw("x"))})
    derived = vault.derive_key(pw(), vault.read_header(vault_path))
    assert derived == key
    assert "a" in vault.load(vault_path, derived)


def test_wrong_password_is_auth_error(vault_path: Path, key: Secret) -> None:
    wrong = vault.derive_key(pw("wrong"), vault.read_header(vault_path))
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, wrong)


def test_create_refuses_existing_vault(vault_path: Path, key: Secret) -> None:
    with pytest.raises(VaultError, match="Esiste già"):
        vault.create(vault_path, pw(), FAST)


def test_create_rejects_empty_password(vault_path: Path) -> None:
    with pytest.raises(VaultError, match="vuota"):
        vault.create(vault_path, pw(""), FAST)


def test_create_makes_private_dir_and_file(vault_path: Path, key: Secret) -> None:
    assert stat.S_IMODE(vault_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(vault_path.stat().st_mode) == 0o600


def test_load_missing_vault_is_vault_error(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="non trovato"):
        vault.read_header(tmp_path / "nope.enc")


def test_load_refuses_permissive_vault(vault_path: Path, key: Secret) -> None:
    vault_path.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        vault.load(vault_path, key)


def test_plaintext_password_never_on_disk(vault_path: Path, key: Secret) -> None:
    vault.save(vault_path, key, {"web01": VaultEntry.new(pw("UNIQUE-PLAINTEXT-123"))})
    raw = vault_path.read_bytes()
    assert b"UNIQUE-PLAINTEXT-123" not in raw
    assert b"web01" not in raw  # anche gli alias sono cifrati


def test_entry_repr_hides_password() -> None:
    assert "s3cret" not in repr(VaultEntry.new(pw("s3cret")))


# --- nonce e salt ------------------------------------------------------------


def test_every_save_uses_a_fresh_nonce(vault_path: Path, key: Secret) -> None:
    nonces = {vault.read_header(vault_path).nonce}
    for _ in range(20):
        vault.save(vault_path, key, {})
        nonces.add(vault.read_header(vault_path).nonce)
    assert len(nonces) == 21


def test_same_content_gives_different_ciphertext(vault_path: Path, key: Secret) -> None:
    vault.save(vault_path, key, {})
    first = vault_path.read_bytes()
    vault.save(vault_path, key, {})
    assert vault_path.read_bytes()[HEADER_SIZE:] != first[HEADER_SIZE:]


def test_salt_is_stable_across_saves(vault_path: Path, key: Secret) -> None:
    salt = vault.read_header(vault_path).salt
    vault.save(vault_path, key, {})
    assert vault.read_header(vault_path).salt == salt
    assert len(salt) == 16


def test_different_vaults_get_different_salts(tmp_path: Path) -> None:
    a, b = tmp_path / "a" / "v.enc", tmp_path / "b" / "v.enc"
    vault.create(a, pw(), FAST)
    vault.create(b, pw(), FAST)
    assert vault.read_header(a).salt != vault.read_header(b).salt


# --- manomissioni ------------------------------------------------------------


def test_tampered_ciphertext_is_rejected(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, HEADER_SIZE + 2)
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, key)


def test_tampered_tag_is_rejected(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, len(vault_path.read_bytes()) - 1)
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, key)


def test_tampered_nonce_is_rejected(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, HEADER_SIZE - 1)
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, key)


def test_tampered_kdf_params_are_rejected(vault_path: Path, key: Secret) -> None:
    # time_cost sta agli offset 10..13. Un valore ancora valido (2 invece di 1)
    # supera il parsing: deve essere fermato dall'autenticazione.
    data = bytearray(vault_path.read_bytes())
    data[10:14] = (2).to_bytes(4, "big")
    vault_path.write_bytes(bytes(data))
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, key)


def test_bad_magic_is_format_error(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, 0)
    with pytest.raises(VaultFormatError):
        vault.read_header(vault_path)


def test_unsupported_version_is_format_error(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, 4)
    with pytest.raises(VaultFormatError, match="versione"):
        vault.read_header(vault_path)


def test_truncated_file_is_format_error(vault_path: Path, key: Secret) -> None:
    vault_path.write_bytes(vault_path.read_bytes()[: HEADER_SIZE + 5])
    with pytest.raises(VaultFormatError):
        vault.load(vault_path, key)


def test_header_with_absurd_memory_is_format_error(vault_path: Path, key: Secret) -> None:
    # Un header manomesso non deve poterci far allocare gigabyte.
    data = bytearray(vault_path.read_bytes())
    data[6:10] = (0xFFFFFFFF).to_bytes(4, "big")
    vault_path.write_bytes(bytes(data))
    with pytest.raises(VaultFormatError):
        vault.read_header(vault_path)


# --- save con chiave sbagliata e rekey ---------------------------------------


def test_save_with_wrong_key_refuses_and_keeps_file(vault_path: Path, key: Secret) -> None:
    before = vault_path.read_bytes()
    wrong = Secret(bytes(32))
    with pytest.raises(VaultAuthError):
        vault.save(vault_path, wrong, {})
    assert vault_path.read_bytes() == before


def test_rekey_changes_salt_and_password(vault_path: Path, key: Secret) -> None:
    vault.save(vault_path, key, {"web01": VaultEntry.new(pw("s3cret"))})
    old_salt = vault.read_header(vault_path).salt

    new_key = vault.rekey(vault_path, key, pw("new password"), FAST)

    header = vault.read_header(vault_path)
    assert header.salt != old_salt
    assert vault.load(vault_path, new_key)["web01"].password == pw("s3cret")
    with pytest.raises(VaultAuthError):
        vault.load(vault_path, vault.derive_key(pw(), header))


def test_rekey_rejects_empty_password(vault_path: Path, key: Secret) -> None:
    with pytest.raises(VaultError, match="vuota"):
        vault.rekey(vault_path, key, pw(""), FAST)


def test_key_id_tracks_salt(vault_path: Path, key: Secret) -> None:
    kid = vault.key_id(vault.read_header(vault_path))
    vault.save(vault_path, key, {})
    assert vault.key_id(vault.read_header(vault_path)) == kid
    vault.rekey(vault_path, key, pw("other"), FAST)
    assert vault.key_id(vault.read_header(vault_path)) != kid


def test_file_shorter_than_header_is_format_error(vault_path: Path, key: Secret) -> None:
    vault_path.write_bytes(b"HSMV\x01")
    with pytest.raises(VaultFormatError, match="troncato"):
        vault.read_header(vault_path)


def test_unknown_kdf_id_is_format_error(vault_path: Path, key: Secret) -> None:
    _flip(vault_path, 5)
    with pytest.raises(VaultFormatError):
        vault.read_header(vault_path)


# --- payload autenticato ma non valido ---------------------------------------


def _reencrypt(path: Path, key: Secret, plaintext: bytes) -> None:
    """Scrive un payload arbitrario cifrato correttamente con `key`."""
    header = path.read_bytes()[: HEADER_SIZE]
    nonce = header[-12:]
    path.write_bytes(header + AESGCM(key.view()).encrypt(nonce, plaintext, header))


@pytest.mark.parametrize(
    "plaintext",
    [b"not json", b"[]", b'{"schema": 1}', b'{"schema": 1, "entries": {"a": {}}}', b"\xff"],
)
def test_malformed_payload_is_format_error(vault_path: Path, key: Secret, plaintext: bytes) -> None:
    _reencrypt(vault_path, key, plaintext)
    with pytest.raises(VaultFormatError, match="non valido"):
        vault.load(vault_path, key)


def test_unknown_payload_schema_is_format_error(vault_path: Path, key: Secret) -> None:
    _reencrypt(vault_path, key, b'{"schema": 2, "entries": {}}')
    with pytest.raises(VaultFormatError, match="Schema"):
        vault.load(vault_path, key)


def test_create_never_overwrites_a_vault_created_concurrently(
    vault_path: Path, key: Secret, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simula la gara: il controllo iniziale non vede il file, ma intanto un
    # altro processo lo ha creato. Il vault esistente deve restare intatto.
    before = vault_path.read_bytes()
    monkeypatch.setattr(vault.os.path, "lexists", lambda p: False)
    with pytest.raises(VaultError, match="Esiste già"):
        vault.create(vault_path, pw("other"), FAST)
    assert vault_path.read_bytes() == before


def test_non_utf8_password_is_clean_vault_error(vault_path: Path, key: Secret) -> None:
    with pytest.raises(VaultError, match="UTF-8"):
        vault.save(vault_path, key, {"web01": VaultEntry.new(Secret(b"\xff\xfe"))})
