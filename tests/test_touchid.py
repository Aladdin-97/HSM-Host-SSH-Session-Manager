import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from hsm import touchid
from hsm.touchid import POLICY, Presence, require_user_presence

# LAError codes (LocalAuthentication/LAError.h).
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
    """Mimics LAContext: replies from a script, records calls."""

    can_evaluate: bool = True
    can_error: int | None = None
    success: bool = True
    error: int | None = None
    reply: bool = True  # False: never calls the callback (simulates a hang)
    reply_error: object | None = None  # passed as is to the callback
    raise_on: str | None = None  # "can" | "evaluate": simulates a pyobjc exception
    threaded: bool = False  # True: callback on another thread, as in the system
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
    return require_user_presence("unlock the vault", context_factory=lambda: ctx, **kwargs)


def test_granted() -> None:
    ctx = FakeContext()
    assert _ask(ctx) is Presence.GRANTED
    assert ctx.calls == [(POLICY, "unlock the vault")]


def test_policy_is_device_owner_authentication() -> None:
    # Touch ID falling back to the macOS password (or Apple Watch):
    # it also works with the lid closed.
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
    # E.g. SSH session to the Mac: nobody can touch the sensor.
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
    assert require_user_presence("unlock the vault") is Presence.UNAVAILABLE


def test_empty_reason_is_rejected() -> None:
    # LAContext raises an Objective-C exception with an empty reason.
    with pytest.raises(ValueError):
        require_user_presence("", context_factory=FakeContext)


def test_never_fails_open() -> None:
    # Any result other than explicit success is not GRANTED.
    for code in [AUTH_FAILED, USER_CANCEL, -4, -9, NOT_INTERACTIVE, -999, None]:
        assert _ask(FakeContext(success=False, error=code)) is not Presence.GRANTED


@pytest.mark.skipif(
    os.environ.get("HSM_TOUCHID_TESTS") != "1",
    reason="shows a real Touch ID prompt: enable with HSM_TOUCHID_TESTS=1",
)
def test_real_touch_id_prompt() -> None:
    print("\nPlace your finger on the sensor (or cancel to check DENIED)...")
    result = require_user_presence("verify the hsm test")
    print(f"result: {result}")
    assert result in (Presence.GRANTED, Presence.DENIED)


def test_default_context_is_a_real_lacontext() -> None:
    pytest.importorskip("LocalAuthentication")
    # Creates the context without evaluating any policy: no prompt.
    ctx = touchid._default_context()
    assert ctx is not None
    assert type(ctx).__name__ == "LAContext"
    ctx.invalidate()


def test_default_context_without_pyobjc_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    # None in sys.modules makes the import fail with ImportError.
    monkeypatch.setitem(sys.modules, "LocalAuthentication", None)
    assert touchid._default_context() is None


# --- security review findings ------------------------------------------------


@pytest.mark.parametrize("where", ["can", "evaluate"])
def test_pyobjc_exceptions_become_unavailable(where: str) -> None:
    ctx = FakeContext(raise_on=where)
    assert _ask(ctx) is Presence.UNAVAILABLE
    assert ctx.invalidated


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_broken_error_object_in_reply_does_not_hang_or_grant() -> None:
    class Broken:
        def domain(self) -> str:
            raise RuntimeError("broken")

        def code(self) -> int:
            raise RuntimeError("broken")

    # The callback runs on a system thread: if it blows up there, the main
    # thread must not hang until the timeout, and no GRANTED.
    ctx = FakeContext(success=True, reply_error=Broken(), threaded=True)
    start = time.monotonic()
    assert _ask(ctx, timeout=5) is Presence.DENIED
    assert time.monotonic() - start < 2
    for t in ctx.threads:  # the thread's exception stays within this test
        t.join()


def test_foreign_domain_error_is_denied_not_unavailable() -> None:
    err = FakeNSError(BIOMETRY_NOT_AVAILABLE, domain="NSCocoaErrorDomain")
    assert _ask(FakeContext(success=False, reply_error=err)) is Presence.DENIED
