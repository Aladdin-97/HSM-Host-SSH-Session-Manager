import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest

from hsm.errors import HsmError
from hsm.keychain import SECURITY, Keychain, KeychainError, KeychainUnavailable
from hsm.secret import Secret

KEY = bytes(range(32))
KEY_HEX = KEY.hex()
KID = "0123456789abcdef"


@dataclass
class FakeSecurity:
    """Sostituisce /usr/bin/security: registra le chiamate, risponde a copione."""

    returncode: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    raises: BaseException | None = None
    calls: list[tuple[list[str], bytes | None]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], stdin: bytes | None) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(argv), None if stdin is None else bytes(stdin)))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(list(argv), self.returncode, self.stdout, self.stderr)


def _kc(fake: FakeSecurity) -> Keychain:
    return Keychain(runner=fake)


# --- store --------------------------------------------------------------------


def test_store_passes_secret_only_via_stdin() -> None:
    fake = FakeSecurity()
    _kc(fake).store_key(KID, Secret(KEY))
    argv, stdin = fake.calls[0]
    # La riga di comando è visibile a tutti con `ps`: niente segreto lì.
    assert argv == [SECURITY, "-i"]
    assert not any(KEY_HEX in arg for arg in argv)
    assert stdin is not None and KEY_HEX.encode() in stdin


def test_store_command_shape() -> None:
    fake = FakeSecurity()
    _kc(fake).store_key(KID, Secret(KEY))
    stdin = fake.calls[0][1]
    assert stdin == (
        f"add-generic-password -U -s hsm -a {KID} -l hsm-vault-key -w {KEY_HEX}\n".encode()
    )


def test_store_failure_does_not_leak_secret_in_message() -> None:
    fake = FakeSecurity(returncode=1, stderr=f"echo {KEY_HEX}".encode())
    with pytest.raises(KeychainError) as info:
        _kc(fake).store_key(KID, Secret(KEY))
    assert KEY_HEX not in str(info.value)


def test_store_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        _kc(FakeSecurity()).store_key(KID, Secret(b"short"))


# --- load ---------------------------------------------------------------------


def test_load_returns_key() -> None:
    fake = FakeSecurity(stdout=KEY_HEX.encode() + b"\n")
    key = _kc(fake).load_key(KID)
    assert key == Secret(KEY)
    assert fake.calls[0][0] == [SECURITY, "find-generic-password", "-s", "hsm", "-a", KID, "-w"]


def test_load_missing_item_returns_none() -> None:
    assert _kc(FakeSecurity(returncode=44)).load_key(KID) is None


def test_load_other_error_raises_with_reason() -> None:
    fake = FakeSecurity(returncode=51, stderr=b"security: User interaction is not allowed.\n")
    with pytest.raises(KeychainError, match="User interaction is not allowed"):
        _kc(fake).load_key(KID)


@pytest.mark.parametrize("stdout", [b"not-hex\n", b"abcd\n", b""])
def test_load_malformed_item_raises(stdout: bytes) -> None:
    with pytest.raises(KeychainError, match="non valido"):
        _kc(FakeSecurity(stdout=stdout)).load_key(KID)


# --- delete -------------------------------------------------------------------


def test_delete_existing_returns_true() -> None:
    fake = FakeSecurity(stdout=b"password has been deleted.\n")
    assert _kc(fake).delete_key(KID) is True
    assert fake.calls[0][0] == [SECURITY, "delete-generic-password", "-s", "hsm", "-a", KID]


def test_delete_missing_returns_false() -> None:
    assert _kc(FakeSecurity(returncode=44)).delete_key(KID) is False


def test_delete_other_error_raises() -> None:
    with pytest.raises(KeychainError):
        _kc(FakeSecurity(returncode=1, stderr=b"boom")).delete_key(KID)


# --- validazione e disponibilità ----------------------------------------------


@pytest.mark.parametrize("bad", ["", "ABC", "a b", "a\nadd-generic-password", "x" * 65, "-w"])
def test_invalid_key_id_is_rejected_everywhere(bad: str) -> None:
    # Il key_id finisce nella riga letta da `security -i`: spazi o a capo
    # permetterebbero di iniettare opzioni o comandi.
    kc = _kc(FakeSecurity())
    with pytest.raises(ValueError):
        kc.store_key(bad, Secret(KEY))
    with pytest.raises(ValueError):
        kc.load_key(bad)
    with pytest.raises(ValueError):
        kc.delete_key(bad)


@pytest.mark.parametrize("bad", ["", "my service", "a\nb", "-x"])
def test_invalid_service_is_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        Keychain(service=bad)


def test_missing_security_binary_is_unavailable() -> None:
    fake = FakeSecurity(raises=FileNotFoundError(SECURITY))
    with pytest.raises(KeychainUnavailable):
        _kc(fake).load_key(KID)


def test_timeout_is_keychain_error() -> None:
    fake = FakeSecurity(raises=subprocess.TimeoutExpired(SECURITY, 1))
    with pytest.raises(KeychainError, match="non ha risposto"):
        _kc(fake).load_key(KID)


def test_errors_are_hsm_errors() -> None:
    assert issubclass(KeychainUnavailable, KeychainError)
    assert issubclass(KeychainError, HsmError)


# --- integrazione con il Keychain vero (opt-in) ------------------------------


@pytest.mark.skipif(
    os.environ.get("HSM_KEYCHAIN_TESTS") != "1",
    reason="tocca il login keychain reale: abilita con HSM_KEYCHAIN_TESTS=1",
)
def test_real_keychain_roundtrip() -> None:
    kc = Keychain(service="hsm-test")
    kid = "feedfacecafebeef"
    kc.delete_key(kid)
    try:
        assert kc.load_key(kid) is None
        kc.store_key(kid, Secret(KEY))
        assert kc.load_key(kid) == Secret(KEY)
        # -U: un secondo store aggiorna invece di fallire.
        kc.store_key(kid, Secret(bytes(32)))
        assert kc.load_key(kid) == Secret(bytes(32))
    finally:
        assert kc.delete_key(kid) is True
    assert kc.load_key(kid) is None


# --- rilievi della security review --------------------------------------------


def test_store_command_is_a_single_line() -> None:
    # Invariante anti-iniezione: un solo comando, terminato dall'unico a capo.
    fake = FakeSecurity()
    _kc(fake).store_key(KID, Secret(KEY))
    stdin = fake.calls[0][1]
    assert stdin is not None
    assert stdin.count(b"\n") == 1 and stdin.endswith(b"\n")


@pytest.mark.parametrize(
    "stdout",
    [
        KEY_HEX.upper().encode() + b"\n",  # maiuscolo: non è ciò che scriviamo noi
        (KEY_HEX[:10] + " " + KEY_HEX[10:]).encode() + b"\n",  # spazi interni
        KEY_HEX.encode() + b"\r\n",
    ],
)
def test_load_accepts_only_exact_lowercase_hex(stdout: bytes) -> None:
    with pytest.raises(KeychainError, match="non valido"):
        _kc(FakeSecurity(stdout=stdout)).load_key(KID)


def test_reason_strips_control_chars_and_is_capped() -> None:
    # stderr è testo esterno che finisce sul terminale: niente sequenze ANSI.
    fake = FakeSecurity(returncode=1, stderr=b"\x1b[31mevil" + b"x" * 500)
    with pytest.raises(KeychainError) as info:
        _kc(fake).load_key(KID)
    msg = str(info.value)
    assert "\x1b" not in msg
    assert len(msg) < 300


def test_store_timeout_says_state_is_unknown() -> None:
    fake = FakeSecurity(raises=subprocess.TimeoutExpired(SECURITY, 1))
    with pytest.raises(KeychainError, match="incerto"):
        _kc(fake).store_key(KID, Secret(KEY))


def test_default_runner_closes_stdin_when_no_input(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import keychain

    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(keychain.subprocess, "run", fake_run)
    keychain._run([SECURITY, "find-generic-password"], None)
    assert seen["stdin"] is subprocess.DEVNULL
    assert "input" not in seen


@pytest.mark.parametrize(
    "exc", [PermissionError("non eseguibile"), OSError("fork fallita"), subprocess.SubprocessError()]
)
def test_any_subprocess_failure_is_keychain_error(exc: BaseException) -> None:
    # unlock ripiega sulla password solo per KeychainError: nient'altro deve
    # sfuggire da qui, altrimenti un Keychain rotto bloccherebbe l'unlock.
    with pytest.raises(KeychainError):
        _kc(FakeSecurity(raises=exc)).load_key(KID)
