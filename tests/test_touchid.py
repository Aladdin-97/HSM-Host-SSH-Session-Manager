import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from hsm import touchid
from hsm.touchid import POLICY, Presence, require_user_presence

# Codici LAError (LocalAuthentication/LAError.h).
AUTH_FAILED = -1
USER_CANCEL = -2
USER_FALLBACK = -3
PASSCODE_NOT_SET = -5
BIOMETRY_NOT_AVAILABLE = -6
BIOMETRY_LOCKOUT = -8
NOT_INTERACTIVE = -1004


LA_DOMAIN = "com.apple.LocalAuthentication"


class FakeNSError:
    def __init__(self, code: int, domain: str = LA_DOMAIN) -> None:
        self._code = code
        self._domain = domain

    def code(self) -> int:
        return self._code

    def domain(self) -> str:
        return self._domain


@dataclass
class FakeContext:
    """Imita LAContext: risponde a copione, registra le chiamate."""

    can_evaluate: bool = True
    can_error: int | None = None
    success: bool = True
    error: int | None = None
    reply: bool = True  # False: non chiama mai la callback (simula un blocco)
    reply_error: object | None = None  # passato così com'è alla callback
    raise_on: str | None = None  # "can" | "evaluate": simula un'eccezione pyobjc
    threaded: bool = False  # True: callback su un altro thread, come nel sistema
    calls: list[tuple[int, str]] = field(default_factory=list)
    invalidated: bool = False
    threads: list[threading.Thread] = field(default_factory=list)

    def canEvaluatePolicy_error_(self, policy: int, error: None) -> tuple[bool, FakeNSError | None]:  # noqa: N802
        if self.raise_on == "can":
            raise ValueError("NSInvalidArgumentException")
        err = FakeNSError(self.can_error) if self.can_error is not None else None
        return self.can_evaluate, err

    def evaluatePolicy_localizedReason_reply_(  # noqa: N802
        self, policy: int, reason: str, reply: Callable[[bool, FakeNSError | None], None]
    ) -> None:
        self.calls.append((policy, reason))
        if self.raise_on == "evaluate":
            import objc

            raise objc.error("NSInternalInconsistencyException")
        if self.reply_error is not None:
            if self.threaded:
                t = threading.Thread(target=reply, args=(self.success, self.reply_error))
                self.threads.append(t)
                t.start()
            else:
                reply(self.success, self.reply_error)
        elif self.reply:
            reply(self.success, FakeNSError(self.error) if self.error is not None else None)

    def invalidate(self) -> None:
        self.invalidated = True


def _ask(ctx: FakeContext, **kwargs: float) -> Presence:
    return require_user_presence("sbloccare il vault", context_factory=lambda: ctx, **kwargs)


def test_granted() -> None:
    ctx = FakeContext()
    assert _ask(ctx) is Presence.GRANTED
    assert ctx.calls == [(POLICY, "sbloccare il vault")]


def test_policy_is_device_owner_authentication() -> None:
    # Touch ID con ripiego sulla password di macOS (o Apple Watch):
    # funziona anche a coperchio chiuso.
    assert POLICY == 2


@pytest.mark.parametrize("code", [PASSCODE_NOT_SET, BIOMETRY_NOT_AVAILABLE])
def test_cannot_evaluate_is_unavailable_without_prompt(code: int) -> None:
    ctx = FakeContext(can_evaluate=False, can_error=code)
    assert _ask(ctx) is Presence.UNAVAILABLE
    assert ctx.calls == []


@pytest.mark.parametrize("code", [AUTH_FAILED, USER_CANCEL, USER_FALLBACK, BIOMETRY_LOCKOUT])
def test_refusals_are_denied(code: int) -> None:
    assert _ask(FakeContext(success=False, error=code)) is Presence.DENIED


def test_not_interactive_is_unavailable() -> None:
    # Es. sessione SSH verso il Mac: nessuno può toccare il sensore.
    assert _ask(FakeContext(success=False, error=NOT_INTERACTIVE)) is Presence.UNAVAILABLE


def test_failure_without_error_is_denied() -> None:
    assert _ask(FakeContext(success=False, error=None)) is Presence.DENIED


def test_no_reply_times_out_as_denied_and_invalidates() -> None:
    ctx = FakeContext(reply=False)
    assert _ask(ctx, timeout=0.05) is Presence.DENIED
    assert ctx.invalidated


def test_context_is_invalidated_after_use() -> None:
    ctx = FakeContext()
    _ask(ctx)
    assert ctx.invalidated


def test_missing_framework_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(touchid, "_default_context", lambda: None)
    assert require_user_presence("sbloccare il vault") is Presence.UNAVAILABLE


def test_empty_reason_is_rejected() -> None:
    # LAContext solleva un'eccezione Objective-C con un reason vuoto.
    with pytest.raises(ValueError):
        require_user_presence("", context_factory=FakeContext)


def test_never_fails_open() -> None:
    # Qualsiasi risultato diverso da successo esplicito non è GRANTED.
    for code in [AUTH_FAILED, USER_CANCEL, -4, -9, NOT_INTERACTIVE, -999, None]:
        assert _ask(FakeContext(success=False, error=code)) is not Presence.GRANTED


@pytest.mark.skipif(
    os.environ.get("HSM_TOUCHID_TESTS") != "1",
    reason="mostra un prompt Touch ID reale: abilita con HSM_TOUCHID_TESTS=1",
)
def test_real_touch_id_prompt() -> None:
    print("\nAppoggia il dito sul sensore (o annulla per verificare DENIED)...")
    result = require_user_presence("verificare il test di hsm")
    print(f"risultato: {result}")
    assert result in (Presence.GRANTED, Presence.DENIED)


def test_default_context_is_a_real_lacontext() -> None:
    pytest.importorskip("LocalAuthentication")
    # Crea il contesto senza valutare nessuna policy: nessun prompt.
    ctx = touchid._default_context()
    assert ctx is not None
    assert type(ctx).__name__ == "LAContext"
    ctx.invalidate()


def test_default_context_without_pyobjc_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    # None in sys.modules fa fallire l'import con ImportError.
    monkeypatch.setitem(sys.modules, "LocalAuthentication", None)
    assert touchid._default_context() is None


# --- rilievi della security review --------------------------------------------


@pytest.mark.parametrize("where", ["can", "evaluate"])
def test_pyobjc_exceptions_become_unavailable(where: str) -> None:
    ctx = FakeContext(raise_on=where)
    assert _ask(ctx) is Presence.UNAVAILABLE
    assert ctx.invalidated


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_broken_error_object_in_reply_does_not_hang_or_grant() -> None:
    class Broken:
        def domain(self) -> str:
            raise RuntimeError("rotto")

        def code(self) -> int:
            raise RuntimeError("rotto")

    # La callback gira su un thread di sistema: se esplode lì, il thread
    # principale non deve restare appeso fino al timeout, e niente GRANTED.
    ctx = FakeContext(success=True, reply_error=Broken(), threaded=True)
    start = time.monotonic()
    assert _ask(ctx, timeout=5) is Presence.DENIED
    assert time.monotonic() - start < 2
    for t in ctx.threads:  # l'eccezione del thread resta in questo test
        t.join()


def test_foreign_domain_error_is_denied_not_unavailable() -> None:
    err = FakeNSError(BIOMETRY_NOT_AVAILABLE, domain="NSCocoaErrorDomain")
    assert _ask(FakeContext(success=False, reply_error=err)) is Presence.DENIED
