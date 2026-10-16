"""User presence check with Touch ID (LocalAuthentication via pyobjc).

It serves a single purpose: asking "is it really you?" before reading the
vault key from the Keychain. The result is a yes/no, not a secret.

Limitation to keep in mind: this is a UI check, not a security boundary.
The Keychain item is not cryptographically bound to biometrics (that would
need a signed binary with an entitlement), so a malicious process running as
your user can skip this check and read the item directly. It protects
against careless use or someone who finds the Mac unlocked and runs `hsm`,
not against malware.
"""

import threading
from collections.abc import Callable
from enum import Enum
from typing import Any

# LAPolicyDeviceOwnerAuthentication: Touch ID, falling back to Apple Watch or
# the macOS password. Preferred over the "biometrics only" variant because
# it also works with the lid closed or with the sensor temporarily locked out.
POLICY = 2

LA_ERROR_DOMAIN = "com.apple.LocalAuthentication"

# LAError codes that mean "we can't ask here", not "the user said no":
# in these cases unlock falls back to the master password.
_UNAVAILABLE_CODES = frozenset(
    {
        -5,  # LAErrorPasscodeNotSet
        -6,  # LAErrorBiometryNotAvailable
        -7,  # LAErrorBiometryNotEnrolled
        -10,  # LAErrorInvalidContext
        -1004,  # LAErrorNotInteractive (e.g. SSH session, no GUI)
    }
)

# If the dialog gets no answer (user away), we close it.
DEFAULT_TIMEOUT_S = 60.0

ContextFactory = Callable[[], Any]


class Presence(Enum):
    """Outcome of the check."""

    GRANTED = "granted"  # the user authenticated
    DENIED = "denied"  # the user cancelled, failed or didn't answer
    UNAVAILABLE = "unavailable"  # Touch ID not usable here


def _pyobjc_errors() -> tuple[type[Exception], ...]:
    """The exceptions pyobjc uses to report an Objective-C error.

    NSInvalidArgumentException becomes ValueError; other NSExceptions
    become objc.error. We catch only these, not Exception in general.
    """
    try:
        import objc
    except ImportError:
        return (ValueError,)
    return (ValueError, objc.error)


def _default_context() -> Any:
    """Create an LAContext, or None if pyobjc/LocalAuthentication is missing."""
    try:
        import LocalAuthentication  # lazy import: macOS only, only when needed
    except ImportError:
        return None
    return LocalAuthentication.LAContext.alloc().init()


def require_user_presence(
    reason: str,
    *,
    context_factory: ContextFactory | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> Presence:
    """Show the system prompt and wait for the user's answer.

    `reason` appears in the dialog ("python3.12 is trying to <reason>").
    It doesn't raise for the expected cases: the caller decides what to do
    with DENIED and UNAVAILABLE. Returns GRANTED only on explicit success.
    A pyobjc error counts as UNAVAILABLE: unlock falls back to the password.
    """
    if not reason:
        raise ValueError("reason cannot be empty")
    ctx = (context_factory or _default_context)()
    if ctx is None:
        return Presence.UNAVAILABLE
    try:
        return _evaluate(ctx, reason, timeout)
    except _pyobjc_errors():
        return Presence.UNAVAILABLE
    finally:
        # Closes any dialog still open (timeout) and prevents reusing the
        # authentication just performed for other requests.
        ctx.invalidate()


def _evaluate(ctx: Any, reason: str, timeout: float) -> Presence:
    can, _err = ctx.canEvaluatePolicy_error_(POLICY, None)
    if not can:
        return Presence.UNAVAILABLE

    # evaluatePolicy is asynchronous: it calls `reply` on a system queue.
    # We turn it into a blocking call with an Event.
    done = threading.Event()
    # "Closed" starting values: if the callback breaks off halfway,
    # whatever is left here means DENIED, never GRANTED.
    outcome: dict[str, Any] = {"success": False, "code": None}

    def reply(success: bool, error: Any) -> None:
        try:
            if error is not None and error.domain() == LA_ERROR_DOMAIN:
                outcome["code"] = error.code()
            # success last: we write it only if everything else went through.
            outcome["success"] = bool(success)
        finally:
            # Even if something above raises, we release the main thread
            # instead of leaving it hanging until the timeout.
            done.set()

    ctx.evaluatePolicy_localizedReason_reply_(POLICY, reason, reply)
    if not done.wait(timeout):
        # A reply that arrives after the timeout is ignored: the dict is no
        # longer read, and invalidate() closes the dialog anyway.
        return Presence.DENIED
    if outcome["success"]:
        return Presence.GRANTED
    if outcome["code"] in _UNAVAILABLE_CODES:
        return Presence.UNAVAILABLE
    return Presence.DENIED
