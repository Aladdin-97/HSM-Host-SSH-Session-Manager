"""Copies a password to the clipboard and clears it by itself after N seconds.

How it works:
1. we write the text with NSPasteboard (AppKit via pyobjc), also declaring
   two "marker" types from the nspasteboard.org convention:
   - org.nspasteboard.ConcealedType: the content is confidential, don't show it;
   - org.nspasteboard.TransientType: don't save it in the history.
   The most common clipboard managers (Maccy, Raycast, Paste...) honor them;
   `pbcopy` cannot declare them.
2. we keep the `changeCount` returned by our write: macOS increments it on
   every clipboard write, from any app.
3. we start a small detached process (`python -I -m hsm.clipboard`) that
   waits until a deadline and then clears the clipboard ONLY if the
   `changeCount` is still ours: if you copied something else meanwhile,
   it leaves it alone.
4. the process confirms it is ready by writing one byte to a pipe. If the
   confirmation does not arrive (e.g. it died at startup), we clear at once.

The detached process gets only the number and the deadline. It receives
neither the password nor a hash of it: a plain hash in the arguments
(visible with `ps`) would be a target for offline brute force.

The deadline is an instant on the wall clock, not "sleep 30 s": on macOS
time.sleep does not count the time the Mac is asleep, and with the lid
closed 30 s would turn into hours. We sleep in short steps and recheck.

Limitations: anyone reading the clipboard within the N seconds (any app)
sees the password; a manager that ignores the markers records it anyway;
if the watchdog is killed (logout, kill) nobody clears it (on logout,
though, the system clears the clipboard anyway). Between the changeCount
check and the clearing there is a tiny window: there is no atomic API
for it.
"""

import argparse
import os
import select
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from hsm.errors import HsmError
from hsm.secret import Secret

STRING_TYPE = "public.utf8-plain-text"  # NSPasteboardTypeString
CONCEALED_TYPE = "org.nspasteboard.ConcealedType"
TRANSIENT_TYPE = "org.nspasteboard.TransientType"

DEFAULT_SECONDS = 30
_MAX_SECONDS = 600
# Maximum watchdog wait step: after waking from sleep, the clearing
# happens within this time.
_STEP_SECONDS = 2.0
# Time allowed for the watchdog to start and import AppKit.
_READY_TIMEOUT = 5.0

Spawn = Callable[..., Any]


def _general_pasteboard() -> Any:
    try:
        import AppKit  # lazy import: macOS only, only when really needed
    except ImportError:
        raise HsmError("pyobjc (AppKit) not available: cannot use the clipboard.") from None
    return AppKit.NSPasteboard.generalPasteboard()


def _spawn_detached(argv: list[str], **kwargs: Any) -> None:
    # We don't keep the Popen: hsm is a short-lived command, and when it ends
    # the watchdog is adopted by launchd, which reaps its exit.
    subprocess.Popen(argv, **kwargs)


class Clipboard:
    """System clipboard with automatic clearing."""

    def __init__(
        self,
        *,
        pasteboard: Any = None,
        spawn: Spawn = _spawn_detached,
        clock: Callable[[], float] = time.time,
        ready_timeout: float = _READY_TIMEOUT,
    ) -> None:
        self._pasteboard = pasteboard
        self._spawn = spawn
        self._clock = clock
        self._ready_timeout = ready_timeout

    def copy_with_autoclear(self, secret: Secret, seconds: int = DEFAULT_SECONDS) -> None:
        """Copies `secret` and schedules the clearing after `seconds`.

        If anything goes wrong after the write, even a Ctrl-C, the
        clipboard is cleared before the error propagates: the password
        must never stay there without a watchdog.
        """
        if not 1 <= seconds <= _MAX_SECONDS:
            raise ValueError(f"seconds must be between 1 and {_MAX_SECONDS}")
        try:
            # bytes(...), then str, then pyobjc's NSString: three immutable
            # copies we cannot wipe (known limitation).
            text = bytes(secret.view()).decode("utf-8")
        except UnicodeDecodeError:
            raise HsmError("The password is not valid UTF-8: cannot copy it.") from None

        pb = self._pasteboard if self._pasteboard is not None else _general_pasteboard()
        expected: int | None = None
        try:
            # declareTypes clears the clipboard and returns the new
            # changeCount: the one of OUR write. Reading it again later
            # could capture another app's write.
            expected = pb.declareTypes_owner_([STRING_TYPE, CONCEALED_TYPE, TRANSIENT_TYPE], None)
            written = (
                pb.setString_forType_(text, STRING_TYPE)
                and pb.setString_forType_("", CONCEALED_TYPE)
                and pb.setString_forType_("", TRANSIENT_TYPE)
            )
            del text
            if not written:
                raise HsmError("Cannot write to the clipboard.")
            if pb.changeCount() != expected:
                raise HsmError(
                    "Another app wrote to the clipboard during the copy: try again."
                )
            self._start_watchdog(expected, self._clock() + seconds)
        except BaseException as exc:
            if expected is not None:
                # Only if the clipboard still holds our write: a copy the
                # user made in the meantime is left alone.
                clear_if_unchanged(pb, expected=expected)
            if isinstance(exc, HsmError) or not isinstance(exc, Exception):
                raise  # HsmError, KeyboardInterrupt, SystemExit: as they are
            raise HsmError(
                f"Error while copying to the clipboard ({type(exc).__name__})."
            ) from None

    def _start_watchdog(self, expected: int, deadline: float) -> None:
        read_fd, write_fd = os.pipe()
        try:
            argv = [
                sys.executable,
                # -I: isolated mode, ignores PYTHONPATH and the current
                # directory, so no fake "hsm" module can take its place.
                "-I",
                "-m",
                "hsm.clipboard",
                "--expect",
                str(expected),
                "--deadline",
                repr(deadline),
                "--ready-fd",
                str(write_fd),
            ]
            try:
                self._spawn(
                    argv,
                    # New session: no Ctrl-C from the terminal, and the
                    # process survives the terminal closing.
                    start_new_session=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(write_fd,),
                )
            except (OSError, subprocess.SubprocessError):
                raise HsmError(
                    "Cannot start the automatic clipboard clearing: "
                    "cleared it to be safe."
                ) from None
            # Close our copy of the write end: if the child dies without
            # writing, the read sees EOF right away, without waiting.
            os.close(write_fd)
            write_fd = -1
            if not _wait_ready(read_fd, self._ready_timeout):
                raise HsmError(
                    "The automatic clipboard clearing did not start: "
                    "cleared it to be safe."
                )
        finally:
            os.close(read_fd)
            if write_fd != -1:
                os.close(write_fd)


def _wait_ready(fd: int, timeout: float) -> bool:
    readable, _, _ = select.select([fd], [], [], timeout)
    return bool(readable) and os.read(fd, 1) == b"1"


def clear_if_unchanged(pasteboard: Any, *, expected: int) -> bool:
    """Clears the clipboard if nobody changed it after us."""
    if pasteboard.changeCount() != expected:
        return False
    pasteboard.clearContents()
    return True


def main(
    argv: Sequence[str] | None = None,
    *,
    pasteboard: Any = None,
    sleep: Callable[[float], object] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> int:
    """Watchdog entry point: `python -I -m hsm.clipboard --expect N --deadline T`."""
    parser = argparse.ArgumentParser(
        prog="python -m hsm.clipboard",
        description="Clears the clipboard at a deadline, if it has not changed.",
    )
    parser.add_argument("--expect", type=int, required=True, help="expected changeCount")
    parser.add_argument("--deadline", type=float, required=True, help="deadline (epoch, seconds)")
    parser.add_argument("--ready-fd", type=int, help="fd to confirm startup on")
    args = parser.parse_args(argv)
    now = clock()
    if not now - _MAX_SECONDS <= args.deadline <= now + _MAX_SECONDS:
        parser.error("--deadline out of range")

    # First everything that can fail (importing AppKit), then the
    # confirmation: the parent must know if we are unable to clear.
    pb = pasteboard if pasteboard is not None else _general_pasteboard()
    if args.ready_fd is not None:
        os.write(args.ready_fd, b"1")
        os.close(args.ready_fd)

    while (remaining := args.deadline - clock()) > 0:
        sleep(min(_STEP_SECONDS, remaining))
    clear_if_unchanged(pb, expected=args.expect)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
