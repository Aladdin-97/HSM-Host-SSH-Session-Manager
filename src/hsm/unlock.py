"""Ottiene la chiave del vault: Touch ID + Keychain, altrimenti master password.

Flusso di `get_vault_key`:

    Touch ID ──GRANTED──► chiave dal Keychain ──apre il vault?──sì──► fatto
       │                         │                    │
    DENIED / UNAVAILABLE      assente / errore        no: item vecchio, lo cancello
       │                         │                    │
       └─────────────────────────┴────────────────────┴──► prompt master password
                                                            (max 3 tentativi)
                                                            └─► salvo la chiave nel Keychain

Garanzie:
- restituisce solo una chiave che ha appena aperto il vault, oppure solleva;
- non esiste un percorso "senza cifratura": se tutto fallisce, errore;
- un problema del Keychain non blocca mai l'uso con la master password.
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
# In caratteri, non in byte (4 emoji sono 16 byte). Con Argon2 a 256 MiB
# 12 caratteri casuali sono fuori portata; una password corta no.
MIN_PASSWORD_LENGTH = 12
REASON = "sbloccare il vault di hsm"

Prompt = Callable[[str], str]
Warn = Callable[[str], None]
PresenceCheck = Callable[[str], Presence]


def _char_count(secret: Secret) -> int:
    """Conta i caratteri UTF-8 senza decodificare (niente copia in str).

    In UTF-8 ogni carattere ha esattamente un byte iniziale; i byte di
    continuazione hanno la forma 10xxxxxx e non vanno contati.
    """
    return sum(1 for b in secret.view() if b & 0xC0 != 0x80)


def _warn_stderr(message: str) -> None:
    print(f"hsm: {message}", file=sys.stderr)


class Unlocker:
    """Gestisce il ciclo di vita della chiave del vault per un file dato.

    Le dipendenze esterne (Keychain, Touch ID, prompt, avvisi) sono
    iniettabili: i default sono quelli reali, i test passano dei finti.
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
        """Restituisce la chiave del vault, verificata."""
        # Prima l'header: se il vault non esiste è inutile chiedere il Touch ID.
        header = vault.read_header(self._path)
        kid = vault.key_id(header)
        cached = self._cached_key(kid)
        if cached is not None:
            return cached
        key = self._ask_existing_password(header)
        self._remember(kid, key)
        return key

    def init_vault(self) -> Secret:
        """Crea il vault chiedendo una nuova master password (due volte)."""
        if os.path.lexists(self._path):
            raise VaultError(f"Esiste già un vault in {self._path}.")
        with self._ask_new_password() as password:
            key = vault.create(self._path, password, self._params)
        self._remember(vault.key_id(vault.read_header(self._path)), key)
        return key

    def change_master_password(self) -> Secret:
        """Cambia la master password e ruota l'item nel Keychain.

        La vecchia password va digitata: il Touch ID non basta. Chi trova il
        Mac sbloccato non deve poter cambiare la password e chiudere fuori
        il proprietario.
        """
        header = vault.read_header(self._path)
        old_kid = vault.key_id(header)
        with self._ask_existing_password(header) as old_key:
            with self._ask_new_password() as new_password:
                new_key = vault.rekey(self._path, old_key, new_password, self._params)
        # Prima salviamo la chiave nuova, poi togliamo la vecchia (che non
        # apre più nulla): se il processo muore in mezzo, l'item giusto c'è.
        self._remember(vault.key_id(vault.read_header(self._path)), new_key)
        self._forget(old_kid)
        return new_key

    # --- Keychain -------------------------------------------------------------

    def _cached_key(self, kid: str) -> Secret | None:
        presence = self._presence(REASON)
        if presence is Presence.DENIED:
            self._warn("Touch ID annullato: inserisci la master password.")
            return None
        if presence is Presence.UNAVAILABLE:
            self._warn("Touch ID non disponibile: inserisci la master password.")
            return None
        try:
            key = self._keychain.load_key(kid)
        except KeychainError as exc:
            self._warn(f"Keychain non utilizzabile ({exc}): inserisci la master password.")
            return None
        if key is None:
            return None
        try:
            # Verifica: una chiave che non apre il vault non va restituita.
            vault.verify(self._path, key)
        except VaultAuthError:
            key.wipe()
            self._warn("La chiave nel Keychain non apre il vault: la rimuovo.")
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
                f"Impossibile salvare la chiave nel Keychain ({exc}): "
                "la prossima volta servirà di nuovo la master password."
            )

    def _forget(self, kid: str) -> None:
        try:
            self._keychain.delete_key(kid)
        except KeychainError as exc:
            self._warn(f"Impossibile rimuovere una chiave vecchia dal Keychain ({exc}).")

    # --- prompt ---------------------------------------------------------------

    def _read(self, label: str) -> Secret:
        try:
            text = self._prompt(label)
        except EOFError:
            raise HsmError("Nessun terminale disponibile per chiedere la master password.") from None
        # getpass restituisce uno str immutabile: lo convertiamo subito, ma
        # l'originale resta in memoria fino al GC (limite noto).
        try:
            return Secret.from_str(text)
        except UnicodeEncodeError:
            # `from None`: il messaggio originale cita il carattere digitato.
            raise HsmError("La password contiene caratteri non validi.") from None

    def _ask_existing_password(self, header: VaultHeader) -> Secret:
        for _ in range(MAX_ATTEMPTS):
            with self._read("Master password: ") as password:
                if len(password) == 0:
                    self._warn("Master password vuota.")
                    continue
                key = vault.derive_key(password, header)
            try:
                vault.verify(self._path, key)
            except VaultAuthError:
                key.wipe()
                self._warn("Master password errata.")
                continue
            except VaultError:
                key.wipe()
                raise
            return key
        raise VaultAuthError("Troppi tentativi: master password errata o vault corrotto.")

    def _ask_new_password(self) -> Secret:
        for _ in range(MAX_ATTEMPTS):
            first = self._read("Nuova master password: ")
            if _char_count(first) < MIN_PASSWORD_LENGTH:
                first.wipe()
                self._warn(f"La master password deve avere almeno {MIN_PASSWORD_LENGTH} caratteri.")
                continue
            try:
                second = self._read("Ripeti la master password: ")
            except BaseException:
                # Ctrl-C, terminale chiuso...: azzeriamo la prima e rilanciamo.
                first.wipe()
                raise
            with second:
                if first == second:
                    return first
            first.wipe()
            self._warn("Le password non coincidono.")
        raise VaultError("Troppi tentativi: master password non impostata.")
