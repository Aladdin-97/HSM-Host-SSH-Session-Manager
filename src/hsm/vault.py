"""Vault dei segreti: un file binario cifrato con AES-256-GCM.

Layout di vault.enc (interi big-endian):

    offset  size  campo
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
    45      ...   ciphertext || tag GCM (16 byte)

I primi 45 byte (l'header) sono in chiaro e vengono passati a GCM come
"associated data": non sono cifrati ma sono autenticati, quindi qualsiasi
modifica all'header fa fallire la decifratura.

Il payload decifrato è JSON:
    {"schema": 1, "entries": {"<alias>": {"password": "...", "updated_at": "..."}}}

Questo modulo non chiede password e non parla con il Keychain: riceve una
password e restituisce una chiave, oppure riceve una chiave e legge/scrive.
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

# AES-256: chiave da 32 byte. 256 bit invece di 128 non per paura di un
# attacco reale ad AES-128, ma perché il costo è nullo e dà margine anche
# contro scenari futuri (es. Grover su computer quantistici).
KEY_SIZE = 32

# Salt da 128 bit, il minimo raccomandato da RFC 9106. Non è segreto: serve
# solo a far sì che la stessa password dia chiavi diverse su vault diversi,
# rendendo inutili le tabelle precalcolate.
SALT_SIZE = 16

# Nonce da 96 bit: è la dimensione nativa di GCM (altre lunghezze passano da
# un hash interno). Generato casuale a ogni scrittura: con 96 bit la
# probabilità di collisione resta trascurabile per miliardi di scritture.
NONCE_SIZE = 12
TAG_SIZE = 16

_HEADER = struct.Struct(">4sBBIIBB16sB12s")
HEADER_SIZE = _HEADER.size  # 45

# Tetti ai parametri dichiarabili nell'header (circa il doppio del default):
# un file manomesso non deve poterci far allocare gigabyte o calcolare per
# minuti prima ancora di arrivare a verificare il tag.
MAX_MEMORY_KIB = 524_288  # 512 MiB
MAX_TIME_COST = 8
MAX_PARALLELISM = 64


@dataclass(frozen=True)
class KdfParams:
    """Parametri di Argon2id. Sono salvati nell'header di ogni vault."""

    memory_cost_kib: int
    time_cost: int
    parallelism: int

    def __post_init__(self) -> None:
        if not 1 <= self.parallelism <= MAX_PARALLELISM:
            raise ValueError(f"parallelism fuori intervallo: {self.parallelism}")
        if not 1 <= self.time_cost <= MAX_TIME_COST:
            raise ValueError(f"time_cost fuori intervallo: {self.time_cost}")
        # Argon2 richiede almeno 8 KiB per lane.
        if not 8 * self.parallelism <= self.memory_cost_kib <= MAX_MEMORY_KIB:
            raise ValueError(f"memory_cost fuori intervallo: {self.memory_cost_kib}")


# Argon2id, la variante raccomandata da RFC 9106: resiste sia agli attacchi
# side-channel (come Argon2i) sia al cracking con GPU/ASIC (come Argon2d).
# 256 MiB e 3 passate costano ~0,15 s su Apple Silicon (misurato): poco per
# un unlock, ma ogni tentativo di brute force deve pagare 256 MiB di RAM.
# 4 lane sfruttano i core per l'utente senza ridurre il costo per chi attacca.
DEFAULT_KDF = KdfParams(memory_cost_kib=262_144, time_cost=3, parallelism=4)


@dataclass(frozen=True)
class VaultHeader:
    """La parte in chiaro (ma autenticata) del file."""

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
            raise VaultFormatError("Il file del vault è troncato.")
        magic, version, kdf_id, mem, t, p, salt_len, salt, nonce_len, nonce = (
            _HEADER.unpack_from(data)
        )
        if magic != MAGIC:
            raise VaultFormatError("Il file non è un vault hsm.")
        if version != FORMAT_VERSION:
            raise VaultFormatError(f"Formato del vault in versione {version} non supportato.")
        if kdf_id != KDF_ARGON2ID or salt_len != SALT_SIZE or nonce_len != NONCE_SIZE:
            raise VaultFormatError("Header del vault non valido.")
        try:
            params = KdfParams(memory_cost_kib=mem, time_cost=t, parallelism=p)
        except ValueError as exc:
            raise VaultFormatError(f"Parametri KDF del vault non validi: {exc}") from None
        return cls(params=params, salt=salt, nonce=nonce)


@dataclass(frozen=True)
class VaultEntry:
    """Una password salvata. Il repr non mostra la password (è un Secret)."""

    password: Secret
    updated_at: str

    @classmethod
    def new(cls, password: Secret) -> Self:
        """Crea una voce con timestamp UTC corrente."""
        return cls(password=password, updated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))


# --- API pubblica -------------------------------------------------------------


def create(path: Path, password: Secret, params: KdfParams = DEFAULT_KDF) -> Secret:
    """Crea un vault vuoto e restituisce la chiave derivata.

    Il salt viene generato qui, una sola volta: resta lo stesso per tutta la
    vita del vault (cambia solo con `rekey`).
    """
    _require_password(password)
    ensure_private_dir(path.parent)
    if os.path.lexists(path):
        raise VaultError(f"Esiste già un vault in {path}.")
    # secrets usa il CSPRNG del sistema operativo (come os.urandom); il nome
    # del modulo rende esplicito che questi byte servono alla sicurezza.
    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive(password, salt, params)
    try:
        # exclusive: se un altro processo ha creato il vault mentre noi
        # derivavamo la chiave, falliamo invece di cancellare il suo.
        _write(path, key, params, salt, {}, exclusive=True)
    except FileExistsError:
        raise VaultError(f"Esiste già un vault in {path}.") from None
    return key


def read_header(path: Path) -> VaultHeader:
    """Legge l'header: serve a derivare la chiave (salt, parametri) e a `key_id`."""
    return VaultHeader.unpack(_read(path))


def derive_key(password: Secret, header: VaultHeader) -> Secret:
    """Deriva la chiave del vault dalla master password (Argon2id)."""
    return _derive(password, header.salt, header.params)


def load(path: Path, key: Secret) -> dict[str, VaultEntry]:
    """Decifra il vault e restituisce le voci per alias."""
    data = _read(path)
    return _decode(_decrypt(key, data))


def save(path: Path, key: Secret, entries: dict[str, VaultEntry]) -> None:
    """Riscrive il vault con `entries`, con un nonce nuovo.

    Prima verifica che `key` apra il vault esistente: altrimenti una chiave
    sbagliata produrrebbe un file che la master password non apre più.
    """
    data = _read(path)
    header = VaultHeader.unpack(data)
    _decrypt(key, data)
    _write(path, key, header.params, header.salt, entries)


def rekey(
    path: Path, old_key: Secret, new_password: Secret, params: KdfParams = DEFAULT_KDF
) -> Secret:
    """Cambia master password: nuovo salt, nuova chiave, stesse voci.

    Il salt nuovo fa sì che la vecchia chiave (anche se rubata dal Keychain)
    non apra il nuovo file. La scrittura è atomica: in caso di crash resta
    il vault vecchio, intero.
    """
    _require_password(new_password)
    entries = load(path, old_key)
    salt = secrets.token_bytes(SALT_SIZE)
    new_key = _derive(new_password, salt, params)
    _write(path, new_key, params, salt, entries)
    return new_key


def key_id(header: VaultHeader) -> str:
    """Identificativo stabile del vault, usato come nome dell'item Keychain.

    È un hash del salt (pubblico), non materiale crittografico: serve solo a
    far sì che dopo `rekey` la chiave vecchia nel Keychain non venga trovata.
    """
    return hashlib.sha256(header.salt).hexdigest()[:16]


# --- interni ------------------------------------------------------------------


def _require_password(password: Secret) -> None:
    if len(password) == 0:
        raise VaultError("La master password non può essere vuota.")


def _read(path: Path) -> bytes:
    try:
        return read_private(path)
    except FileNotFoundError:
        raise VaultError(
            f"Vault non trovato in {path}. Crealo con: hsm pw set <alias>"
        ) from None


def _derive(password: Secret, salt: bytes, params: KdfParams) -> Secret:
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=params.time_cost,
        lanes=params.parallelism,
        memory_cost=params.memory_cost_kib,
    )
    # derive() restituisce bytes immutabili: li avvolgiamo subito in un
    # Secret, ma la copia originale resta in memoria fino al GC (limite noto).
    return Secret(kdf.derive(password.view()))


def _decrypt(key: Secret, data: bytes) -> bytes:
    header = VaultHeader.unpack(data)
    ciphertext = data[HEADER_SIZE:]
    if len(ciphertext) < TAG_SIZE:
        raise VaultFormatError("Il file del vault è troncato.")
    try:
        return AESGCM(key.view()).decrypt(header.nonce, ciphertext, data[:HEADER_SIZE])
    except InvalidTag:
        # GCM non distingue "chiave sbagliata" da "file alterato", e non
        # vogliamo farlo noi: un messaggio unico non dà indizi a chi attacca.
        raise VaultAuthError("Master password errata o vault corrotto.") from None


def _write(
    path: Path,
    key: Secret,
    params: KdfParams,
    salt: bytes,
    entries: dict[str, VaultEntry],
    *,
    exclusive: bool = False,
) -> None:
    # Nonce nuovo a ogni scrittura, sempre. Con GCM riusare un nonce con la
    # stessa chiave è catastrofico: rivela lo XOR dei due testi in chiaro e
    # permette di falsificare i tag.
    nonce = secrets.token_bytes(NONCE_SIZE)
    aad = VaultHeader(params=params, salt=salt, nonce=nonce).pack()
    ciphertext = AESGCM(key.view()).encrypt(nonce, _encode(entries), aad)
    # Su disco finisce solo header + testo cifrato: il chiaro resta in memoria.
    atomic_write(path, aad + ciphertext, exclusive=exclusive)


def _encode(entries: dict[str, VaultEntry]) -> bytes:
    encoded: dict[str, dict[str, str]] = {}
    for alias, entry in entries.items():
        try:
            password = bytes(entry.password.view()).decode("utf-8")
        except UnicodeDecodeError:
            # `from None`: l'eccezione originale contiene i byte della password.
            raise VaultError(f"La password di {alias} non è UTF-8 valido.") from None
        encoded[alias] = {"password": password, "updated_at": entry.updated_at}
    payload = {"schema": PAYLOAD_SCHEMA, "entries": encoded}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode(plaintext: bytes) -> dict[str, VaultEntry]:
    # Il testo è già autenticato, quindi un errore qui indica un bug o un
    # vault scritto da una versione diversa, non un attacco.
    try:
        payload = json.loads(plaintext)
        if payload["schema"] != PAYLOAD_SCHEMA:
            raise VaultFormatError(f"Schema del payload {payload['schema']} non supportato.")
        return {
            str(alias): VaultEntry(
                password=Secret.from_str(raw["password"]),
                updated_at=str(raw["updated_at"]),
            )
            for alias, raw in payload["entries"].items()
        }
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, AttributeError):
        raise VaultFormatError("Contenuto del vault non valido.") from None
