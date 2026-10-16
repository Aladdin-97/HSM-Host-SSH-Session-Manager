"""Obtains the vault key: Touch ID + Keychain, otherwise the master password.

Flow of `get_vault_key`:

    Touch ID ──GRANTED──► key from Keychain ──opens the vault?──yes──► done
       │                         │                    │
    DENIED / UNAVAILABLE      missing / error         no: stale item, delete it
       │                         │                    │
       └─────────────────────────┴────────────────────┴──► master password prompt
                                                            (max 3 attempts)
                                                            └─► store the key in the Keychain

Guarantees:
- it returns only a key that has just opened the vault, or it raises;
- there is no "unencrypted" path: if everything fails, it's an error;
- a Keychain problem never blocks use with the master password.
"""

import getpass
import os
import sys
from collections.abc import Callable
from pathlib import Path

from hsm import touchid, vault
from hsm.errors import HsmError, VaultAuthError, VaultError
from hsm.keychain import Keychain, KeychainError
from hsm.secret import Secret
from hsm.touchid import Presence
from hsm.vault import DEFAULT_KDF, KdfParams, VaultHeader

MAX_ATTEMPTS = 3
# In characters, not bytes (4 emoji are 16 bytes). With Argon2 at 256 MiB
# 12 random characters are out of reach; a short password is not.
MIN_PASSWORD_LENGTH = 12
REASON = "unlock the hsm vault"

Prompt = Callable[[str], str]
Warn = Callable[[str], None]
PresenceCheck = Callable[[str], Presence]


def _char_count(secret: Secret) -> int:
    """Count UTF-8 characters without decoding (no copy into a str).

    In UTF-8 every character has exactly one leading byte; continuation
    bytes have the form 10xxxxxx and must not be counted.
    """
    return sum(1 for b in secret.view() if b & 0xC0 != 0x80)


def _warn_stderr(message: str) -> None:
    print(f"hsm: {message}", file=sys.stderr)


class Unlocker:
    """Manages the lifecycle of the vault key for a given file.

    External dependencies (Keychain, Touch ID, prompt, warnings) are
    injectable: the defaults are the real ones, tests pass fakes.
    """

    def __init__(
        self,
        path: Path,
        *,
        keychain: Keychain | None = None,
        presence: PresenceCheck | None = None,
        prompt: Prompt = getpass.getpass,
        warn: Warn = _warn_stderr,
        params: KdfParams = DEFAULT_KDF,
    ) -> None:
        self._path = path
        self._keychain = keychain if keychain is not None else Keychain()
        self._presence = presence if presence is not None else touchid.require_user_presence
        self._prompt = prompt
        self._warn = warn
        self._params = params

    def get_vault_key(self) -> Secret:
        """Return the vault key, verified."""
        # Header first: if the vault doesn't exist there's no point asking for Touch ID.
        header = vault.read_header(self._path)
        kid = vault.key_id(header)
        cached = self._cached_key(kid)
        if cached is not None:
            return cached
        key = self._ask_existing_password(header)
        self._remember(kid, key)
        return key

    def init_vault(self) -> Secret:
        """Create the vault by asking for a new master password (twice)."""
        if os.path.lexists(self._path):
            raise VaultError(f"A vault already exists at {self._path}.")
        with self._ask_new_password() as password:
            key = vault.create(self._path, password, self._params)
        self._remember(vault.key_id(vault.read_header(self._path)), key)
        return key

    def change_master_password(self) -> Secret:
        """Change the master password and rotate the Keychain item.

        The old password must be typed: Touch ID is not enough. Someone who
        finds the Mac unlocked must not be able to change the password and
        lock the owner out.
        """
        header = vault.read_header(self._path)
        old_kid = vault.key_id(header)
        with self._ask_existing_password(header) as old_key:
            with self._ask_new_password() as new_password:
                new_key = vault.rekey(self._path, old_key, new_password, self._params)
        # First we store the new key, then remove the old one (which no longer
        # opens anything): if the process dies in between, the right item is there.
        self._remember(vault.key_id(vault.read_header(self._path)), new_key)
        self._forget(old_kid)
        return new_key

    # --- Keychain -------------------------------------------------------------

    def _cached_key(self, kid: str) -> Secret | None:
        presence = self._presence(REASON)
        if presence is Presence.DENIED:
            self._warn("Touch ID cancelled: enter the master password.")
            return None
        if presence is Presence.UNAVAILABLE:
            self._warn("Touch ID unavailable: enter the master password.")
            return None
        try:
            key = self._keychain.load_key(kid)
        except KeychainError as exc:
            self._warn(f"Keychain not usable ({exc}): enter the master password.")
            return None
        if key is None:
            return None
        try:
            # Verify: a key that doesn't open the vault must not be returned.
            vault.verify(self._path, key)
        except VaultAuthError:
            key.wipe()
            self._warn("The key in the Keychain doesn't open the vault: removing it.")
            self._forget(kid)
            return None
        except VaultError:
            key.wipe()
            raise
        return key

    def _remember(self, kid: str, key: Secret) -> None:
        try:
            self._keychain.store_key(kid, key)
        except KeychainError as exc:
            self._warn(
                f"Unable to store the key in the Keychain ({exc}): "
                "the master password will be needed again next time."
            )

    def _forget(self, kid: str) -> None:
        try:
            self._keychain.delete_key(kid)
        except KeychainError as exc:
            self._warn(f"Unable to remove an old key from the Keychain ({exc}).")

    # --- prompt ---------------------------------------------------------------

    def _read(self, label: str) -> Secret:
        try:
            text = self._prompt(label)
        except EOFError:
            raise HsmError("No terminal available to ask for the master password.") from None
        # getpass returns an immutable str: we convert it right away, but
        # the original stays in memory until GC (known limitation).
        try:
            return Secret.from_str(text)
        except UnicodeEncodeError:
            # `from None`: the original message quotes the typed character.
            raise HsmError("The password contains invalid characters.") from None

    def _ask_existing_password(self, header: VaultHeader) -> Secret:
        for _ in range(MAX_ATTEMPTS):
            with self._read("Master password: ") as password:
                if len(password) == 0:
                    self._warn("Empty master password.")
                    continue
                key = vault.derive_key(password, header)
            try:
                vault.verify(self._path, key)
            except VaultAuthError:
                key.wipe()
                self._warn("Wrong master password.")
                continue
            except VaultError:
                key.wipe()
                raise
            return key
        raise VaultAuthError("Too many attempts: wrong master password or corrupted vault.")

    def _ask_new_password(self) -> Secret:
        for _ in range(MAX_ATTEMPTS):
            first = self._read("New master password: ")
            if _char_count(first) < MIN_PASSWORD_LENGTH:
                first.wipe()
                self._warn(
                    f"The master password must be at least {MIN_PASSWORD_LENGTH} characters."
                )
                continue
            try:
                second = self._read("Repeat the master password: ")
            except BaseException:
                # Ctrl-C, terminal closed...: wipe the first one and re-raise.
                first.wipe()
                raise
            with second:
                if first == second:
                    return first
            first.wipe()
            self._warn("The passwords don't match.")
        raise VaultError("Too many attempts: master password not set.")
