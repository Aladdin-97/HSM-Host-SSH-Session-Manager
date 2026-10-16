"""Secrets vault: a binary file encrypted with AES-256-GCM.

Layout of vault.enc (big-endian integers):

    offset  size  field
    0       4     magic            b"HSMV"
    4       1     format_version   1
    5       1     kdf_id           1 = Argon2id v1.3
    6       4     memory_cost_kib  u32
    10      4     time_cost        u32
    14      1     parallelism      u8
    15      1     salt_len         u8 (16)
    16      16    salt
    32      1     nonce_len        u8 (12)
    33      12    nonce
    45      ...   ciphertext || GCM tag (16 bytes)

The first 45 bytes (the header) are in clear and are passed to GCM as
"associated data": they are not encrypted but they are authenticated, so any
change to the header makes decryption fail.

The decrypted payload is JSON:
    {"schema": 1, "entries": {"<alias>": {"password": "...", "updated_at": "..."}}}

This module doesn't ask for passwords and doesn't talk to the Keychain: it
receives a password and returns a key, or receives a key and reads/writes.
"""

import hashlib
import json
import os
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from hsm.errors import VaultAuthError, VaultError, VaultFormatError
from hsm.fsutil import atomic_write, ensure_private_dir, read_private
from hsm.secret import Secret

MAGIC = b"HSMV"
FORMAT_VERSION = 1
KDF_ARGON2ID = 1
PAYLOAD_SCHEMA = 1

# AES-256: 32-byte key. 256 bits instead of 128 not out of fear of a real
# attack on AES-128, but because the cost is nil and it leaves margin even
# against future scenarios (e.g. Grover on quantum computers).
KEY_SIZE = 32

# 128-bit salt, the minimum recommended by RFC 9106. It is not secret: it
# only makes the same password yield different keys on different vaults,
# making precomputed tables useless.
SALT_SIZE = 16

# 96-bit nonce: it is GCM's native size (other lengths go through an
# internal hash). Generated at random on every write: with 96 bits the
# collision probability stays negligible for billions of writes.
NONCE_SIZE = 12
TAG_SIZE = 16

_HEADER = struct.Struct(">4sBBIIBB16sB12s")
HEADER_SIZE = _HEADER.size  # 45

# Caps on the parameters a header can declare (about twice the default):
# a tampered file must not be able to make us allocate gigabytes or compute
# for minutes before we even get to check the tag.
MAX_MEMORY_KIB = 524_288  # 512 MiB
MAX_TIME_COST = 8
MAX_PARALLELISM = 64


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. They are stored in the header of every vault."""

    memory_cost_kib: int
    time_cost: int
    parallelism: int

    def __post_init__(self) -> None:
        if not 1 <= self.parallelism <= MAX_PARALLELISM:
            raise ValueError(f"parallelism out of range: {self.parallelism}")
        if not 1 <= self.time_cost <= MAX_TIME_COST:
            raise ValueError(f"time_cost out of range: {self.time_cost}")
        # Argon2 requires at least 8 KiB per lane.
        if not 8 * self.parallelism <= self.memory_cost_kib <= MAX_MEMORY_KIB:
            raise ValueError(f"memory_cost out of range: {self.memory_cost_kib}")


# Argon2id, the variant recommended by RFC 9106: it resists both side-channel
# attacks (like Argon2i) and GPU/ASIC cracking (like Argon2d).
# 256 MiB and 3 passes cost ~0.15 s on Apple Silicon (measured): little for
# an unlock, but every brute-force attempt has to pay 256 MiB of RAM.
# 4 lanes use the cores for the user without lowering the cost for an attacker.
DEFAULT_KDF = KdfParams(memory_cost_kib=262_144, time_cost=3, parallelism=4)


@dataclass(frozen=True)
class VaultHeader:
    """The clear (but authenticated) part of the file."""

    params: KdfParams
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        return _HEADER.pack(
            MAGIC,
            FORMAT_VERSION,
            KDF_ARGON2ID,
            self.params.memory_cost_kib,
            self.params.time_cost,
            self.params.parallelism,
            SALT_SIZE,
            self.salt,
            NONCE_SIZE,
            self.nonce,
        )

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        if len(data) < HEADER_SIZE:
            raise VaultFormatError("The vault file is truncated.")
        magic, version, kdf_id, mem, t, p, salt_len, salt, nonce_len, nonce = (
            _HEADER.unpack_from(data)
        )
        if magic != MAGIC:
            raise VaultFormatError("The file is not an hsm vault.")
        if version != FORMAT_VERSION:
            raise VaultFormatError(f"Vault format version {version} is not supported.")
        if kdf_id != KDF_ARGON2ID or salt_len != SALT_SIZE or nonce_len != NONCE_SIZE:
            raise VaultFormatError("Invalid vault header.")
        try:
            params = KdfParams(memory_cost_kib=mem, time_cost=t, parallelism=p)
        except ValueError as exc:
            raise VaultFormatError(f"Invalid vault KDF parameters: {exc}") from None
        return cls(params=params, salt=salt, nonce=nonce)


@dataclass(frozen=True)
class VaultEntry:
    """A saved password. The repr doesn't show the password (it's a Secret)."""

    password: Secret
    updated_at: str

    @classmethod
    def new(cls, password: Secret) -> Self:
        """Create an entry with the current UTC timestamp."""
        return cls(password=password, updated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


# --- public API ---------------------------------------------------------------


def create(path: Path, password: Secret, params: KdfParams = DEFAULT_KDF) -> Secret:
    """Create an empty vault and return the derived key.

    The salt is generated here, only once: it stays the same for the whole
    life of the vault (it changes only with `rekey`).
    """
    _require_password(password)
    ensure_private_dir(path.parent)
    if os.path.lexists(path):
        raise VaultError(f"A vault already exists at {path}.")
    # secrets uses the operating system's CSPRNG (like os.urandom); the module
    # name makes it explicit that these bytes serve security.
    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive(password, salt, params)
    try:
        # exclusive: if another process created the vault while we were
        # deriving the key, we fail instead of erasing theirs.
        _write(path, key, params, salt, {}, exclusive=True)
    except FileExistsError:
        raise VaultError(f"A vault already exists at {path}.") from None
    return key


def read_header(path: Path) -> VaultHeader:
    """Read the header: needed to derive the key (salt, parameters) and for `key_id`."""
    return VaultHeader.unpack(_read(path))


def derive_key(password: Secret, header: VaultHeader) -> Secret:
    """Derive the vault key from the master password (Argon2id)."""
    return _derive(password, header.salt, header.params)


def load(path: Path, key: Secret) -> dict[str, VaultEntry]:
    """Decrypt the vault and return the entries by alias."""
    data = _read(path)
    return _decode(_decrypt(key, data))


def verify(path: Path, key: Secret) -> None:
    """Check that `key` opens the vault, without decoding the entries.

    Raises VaultAuthError if the key is wrong. GCM cannot verify without
    decrypting, so the plaintext still exists for a moment as immutable
    bytes; we at least avoid turning it into objects.
    """
    _decrypt(key, _read(path))


def save(path: Path, key: Secret, entries: dict[str, VaultEntry]) -> None:
    """Rewrite the vault with `entries`, with a new nonce.

    It first checks that `key` opens the existing vault: otherwise a wrong
    key would produce a file the master password can no longer open.
    """
    data = _read(path)
    header = VaultHeader.unpack(data)
    _decrypt(key, data)
    _write(path, key, header.params, header.salt, entries)


def rekey(
    path: Path, old_key: Secret, new_password: Secret, params: KdfParams = DEFAULT_KDF
) -> Secret:
    """Change the master password: new salt, new key, same entries.

    The new salt ensures the old key (even if stolen from the Keychain)
    doesn't open the new file. The write is atomic: on a crash the old
    vault remains, intact.
    """
    _require_password(new_password)
    entries = load(path, old_key)
    salt = secrets.token_bytes(SALT_SIZE)
    new_key = _derive(new_password, salt, params)
    _write(path, new_key, params, salt, entries)
    return new_key


def key_id(header: VaultHeader) -> str:
    """Stable vault identifier, used as the name of the Keychain item.

    It is a hash of the (public) salt, not cryptographic material: it only
    ensures that after `rekey` the old key in the Keychain is not found.
    """
    return hashlib.sha256(header.salt).hexdigest()[:16]


# --- internals ----------------------------------------------------------------


def _require_password(password: Secret) -> None:
    if len(password) == 0:
        raise VaultError("The master password cannot be empty.")


def _read(path: Path) -> bytes:
    try:
        return read_private(path)
    except FileNotFoundError:
        raise VaultError(
            f"Vault not found at {path}. Create it with: hsm pw set <alias>"
        ) from None


def _derive(password: Secret, salt: bytes, params: KdfParams) -> Secret:
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=params.time_cost,
        lanes=params.parallelism,
        memory_cost=params.memory_cost_kib,
    )
    # derive() returns immutable bytes: we wrap them in a Secret right away,
    # but the original copy stays in memory until GC (known limitation).
    return Secret(kdf.derive(password.view()))


def _decrypt(key: Secret, data: bytes) -> bytes:
    header = VaultHeader.unpack(data)
    ciphertext = data[HEADER_SIZE:]
    if len(ciphertext) < TAG_SIZE:
        raise VaultFormatError("The vault file is truncated.")
    try:
        return AESGCM(key.view()).decrypt(header.nonce, ciphertext, data[:HEADER_SIZE])
    except InvalidTag:
        # GCM doesn't distinguish "wrong key" from "altered file", and we
        # don't want to either: a single message gives an attacker no hints.
        raise VaultAuthError("Wrong master password or corrupted vault.") from None


def _write(
    path: Path,
    key: Secret,
    params: KdfParams,
    salt: bytes,
    entries: dict[str, VaultEntry],
    *,
    exclusive: bool = False,
) -> None:
    # A new nonce on every write, always. With GCM, reusing a nonce with the
    # same key is catastrophic: it reveals the XOR of the two plaintexts and
    # allows forging tags.
    nonce = secrets.token_bytes(NONCE_SIZE)
    aad = VaultHeader(params=params, salt=salt, nonce=nonce).pack()
    ciphertext = AESGCM(key.view()).encrypt(nonce, _encode(entries), aad)
    # Only header + ciphertext reach the disk: the plaintext stays in memory.
    atomic_write(path, aad + ciphertext, exclusive=exclusive)


def _encode(entries: dict[str, VaultEntry]) -> bytes:
    encoded: dict[str, dict[str, str]] = {}
    for alias, entry in entries.items():
        try:
            password = bytes(entry.password.view()).decode("utf-8")
        except UnicodeDecodeError:
            # `from None`: the original exception contains the password bytes.
            raise VaultError(f"The password for {alias} is not valid UTF-8.") from None
        encoded[alias] = {"password": password, "updated_at": entry.updated_at}
    payload = {"schema": PAYLOAD_SCHEMA, "entries": encoded}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode(plaintext: bytes) -> dict[str, VaultEntry]:
    # The text is already authenticated, so an error here points to a bug or
    # a vault written by a different version, not an attack.
    try:
        payload = json.loads(plaintext)
        if payload["schema"] != PAYLOAD_SCHEMA:
            raise VaultFormatError(f"Payload schema {payload['schema']} is not supported.")
        return {
            str(alias): VaultEntry(
                password=Secret.from_str(raw["password"]),
                updated_at=str(raw["updated_at"]),
            )
            for alias, raw in payload["entries"].items()
        }
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, AttributeError):
        raise VaultFormatError("Invalid vault content.") from None
