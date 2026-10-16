"""Stores the vault key in the macOS login keychain via /usr/bin/security.

What we store: the key derived by Argon2id (32 bytes, in hex), not the
master password. If the item were read, the reader could open the vault but
would not learn a password you might reuse elsewhere; on top of that,
subsequent unlocks skip Argon2.

Where: a "generic password" with service `hsm` and account = `vault.key_id()`,
i.e. a hash of the salt. After a rekey the salt changes, so the old item is
no longer looked up (and unlock deletes it).

What this module does NOT do: it doesn't protect the item with biometrics.
An item created by `security` can be read without a prompt by any process
running as your user that invokes `security`. The Touch ID in front of the
read (touchid.py) is a UI check, not a security boundary.
"""

import binascii
import re
import subprocess
from collections.abc import Callable, Sequence

from hsm.errors import HsmError
from hsm.secret import Secret
from hsm.vault import KEY_SIZE

SECURITY = "/usr/bin/security"
SERVICE = "hsm"
LABEL = "hsm-vault-key"

# `security` exits with 44 when the item doesn't exist (errSecItemNotFound).
_EXIT_NOT_FOUND = 44

# The keychain can show a dialog (locked keychain): we give the user time
# to answer, but we don't hang forever.
_TIMEOUT_S = 60

# Service and account end up in the line that `security -i` parses as a
# command: we only allow characters that can't start new options
# (no leading "-"), split arguments (spaces) or commands (newlines).
_KEY_ID_RE = re.compile(r"[0-9a-f]{1,64}")
_SERVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# Exactly what we write: 64 lowercase hex digits. Stricter than
# bytearray.fromhex, which tolerates spaces and uppercase.
_HEX_KEY_RE = re.compile(rb"[0-9a-f]{%d}" % (2 * KEY_SIZE))

# How much of stderr we report to the user.
_MAX_REASON = 200

Runner = Callable[[Sequence[str], bytes | bytearray | None], subprocess.CompletedProcess[bytes]]


class KeychainError(HsmError):
    """The Keychain responded with an error."""


class KeychainUnavailable(KeychainError):
    """The Keychain is not usable on this system."""


def _run(
    argv: Sequence[str], stdin: bytes | bytearray | None
) -> subprocess.CompletedProcess[bytes]:
    # No shell: argv goes to the process as is, without interpretation.
    if stdin is None:
        # Without input we close stdin: `security` must not be able to read
        # (or wait for) what the user types in the terminal.
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_TIMEOUT_S,
        )
    return subprocess.run(
        list(argv), input=stdin, capture_output=True, check=False, timeout=_TIMEOUT_S
    )


class Keychain:
    """Access to the vault key stored in the login keychain."""

    def __init__(
        self, service: str = SERVICE, *, security: str = SECURITY, runner: Runner = _run
    ) -> None:
        if not _SERVICE_RE.fullmatch(service):
            raise ValueError(f"Invalid service name: {service!r}")
        self._service = service
        self._security = security
        self._runner = runner

    def store_key(self, key_id: str, key: Secret) -> None:
        """Store (or update) the vault key identified by `key_id`."""
        _check_key_id(key_id)
        if len(key) != KEY_SIZE:
            raise ValueError(f"The key must be {KEY_SIZE} bytes")
        # `security add-generic-password -w <secret>` would put the secret
        # on the command line, readable by anyone with `ps`. With `-i`
        # security reads commands from stdin, and stdin is private to the process.
        # -U updates the item if it already exists instead of failing.
        command = bytearray(
            f"add-generic-password -U -s {self._service} -a {key_id} -l {LABEL} -w ".encode()
        )
        # "Best effort" zeroing: hexlify still produces an immutable hex copy
        # of the key, which we cannot erase.
        # We pass the bytearray as is so as not to create another one.
        command += binascii.hexlify(key.view())
        command += b"\n"
        try:
            result = self._call(["-i"], stdin=command, writing=True)
        finally:
            command[:] = bytes(len(command))
        if result.returncode != 0:
            # Deliberately without stderr: in -i mode it could echo parts
            # of the command, and the command contains the key.
            raise KeychainError(
                f"Unable to store the key in the Keychain (code {result.returncode})."
            )

    def load_key(self, key_id: str) -> Secret | None:
        """Return the stored key, or None if the item doesn't exist."""
        _check_key_id(key_id)
        # -w prints only the secret on stdout, which we read via a pipe.
        result = self._call(["find-generic-password", "-s", self._service, "-a", key_id, "-w"])
        if result.returncode == _EXIT_NOT_FOUND:
            return None
        if result.returncode != 0:
            raise KeychainError(f"Keychain read failed: {_reason(result)}")
        out = result.stdout
        if out.endswith(b"\n"):  # security adds a single trailing newline
            out = out[:-1]
        if not _HEX_KEY_RE.fullmatch(out):
            raise KeychainError("Invalid Keychain item: unexpected format.")
        # stdout (immutable bytes) stays in memory until GC: known limitation.
        return Secret(bytearray.fromhex(out.decode("ascii")))

    def has_key(self, key_id: str) -> bool:
        """True if the item exists. Doesn't read the secret (no -w), so no
        prompt and no sensitive data in the output: used by `hsm paths`."""
        _check_key_id(key_id)
        result = self._call(["find-generic-password", "-s", self._service, "-a", key_id])
        if result.returncode == _EXIT_NOT_FOUND:
            return False
        if result.returncode != 0:
            raise KeychainError(f"Keychain read failed: {_reason(result)}")
        return True

    def delete_key(self, key_id: str) -> bool:
        """Delete the item. True if it existed, False if it wasn't there."""
        _check_key_id(key_id)
        result = self._call(["delete-generic-password", "-s", self._service, "-a", key_id])
        if result.returncode == _EXIT_NOT_FOUND:
            return False
        if result.returncode != 0:
            raise KeychainError(f"Keychain deletion failed: {_reason(result)}")
        return True

    def _call(
        self, args: list[str], stdin: bytearray | None = None, *, writing: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return self._runner([self._security, *args], stdin)
        except FileNotFoundError:
            raise KeychainUnavailable(
                f"{self._security} not found: Keychain unavailable."
            ) from None
        except subprocess.TimeoutExpired:
            msg = f"The Keychain did not respond within {_TIMEOUT_S} s."
            if writing:
                # The process was killed halfway: the item may or may not
                # have been written.
                msg += " The item's state is uncertain: it will be rewritten on the next unlock."
            raise KeychainError(msg) from None
        except (OSError, subprocess.SubprocessError) as exc:
            # Binary not executable, fork failed, etc. Everything becomes
            # KeychainError, so unlock can always fall back to the password.
            raise KeychainError(
                f"Unable to run {self._security} ({type(exc).__name__})."
            ) from None


def _check_key_id(key_id: str) -> None:
    if not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError(f"Invalid key_id: {key_id!r}")


def _reason(result: subprocess.CompletedProcess[bytes]) -> str:
    """First line of stderr, useful to the user (e.g. "User interaction is not allowed")."""
    lines = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
    if not lines:
        return f"code {result.returncode}"
    # stderr is external text that ends up on the terminal: we strip control
    # characters (e.g. ANSI sequences) and truncate overly long lines.
    return "".join(c for c in lines[0] if c.isprintable())[:_MAX_REASON]
