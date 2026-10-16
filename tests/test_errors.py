import sys

import pytest

from hsm.errors import HsmError, VaultAuthError, make_excepthook


def _raise_and_capture(exc: BaseException) -> tuple[type[BaseException], BaseException, object]:
    try:
        raise exc
    except BaseException:  # noqa: BLE001 - serve solo a catturare exc_info nel test
        return sys.exc_info()  # type: ignore[return-value]


def test_hsm_error_prints_only_the_user_message(capsys: pytest.CaptureFixture[str]) -> None:
    hook = make_excepthook(debug=False)
    hook(*_raise_and_capture(VaultAuthError("master password errata")))
    err = capsys.readouterr().err
    assert err == "hsm: master password errata\n"


def test_unexpected_error_hides_message_and_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    # Il messaggio di un'eccezione inattesa potrebbe contenere dati sensibili:
    # senza --debug mostriamo solo il tipo.
    hook = make_excepthook(debug=False)
    hook(*_raise_and_capture(ValueError("contiene hunter2")))
    err = capsys.readouterr().err
    assert "hunter2" not in err
    assert "Traceback" not in err
    assert "ValueError" in err
    assert "--debug" in err


def test_debug_prints_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    hook = make_excepthook(debug=True)
    hook(*_raise_and_capture(ValueError("dettaglio")))
    err = capsys.readouterr().err
    assert "Traceback" in err
    assert "dettaglio" in err


def test_keyboard_interrupt_is_quiet(capsys: pytest.CaptureFixture[str]) -> None:
    hook = make_excepthook(debug=False)
    hook(*_raise_and_capture(KeyboardInterrupt()))
    assert "Traceback" not in capsys.readouterr().err


def test_hierarchy() -> None:
    assert issubclass(VaultAuthError, HsmError)
