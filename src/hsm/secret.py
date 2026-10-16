"""Contenitore per segreti (password, chiavi) che limita le fughe accidentali.

Cosa fa:
- `repr`/`str`/f-string non mostrano mai il contenuto, quindi un segreto
  finito in un log, in un print di debug o in un traceback resta coperto;
- il contenuto vive in un `bytearray` (mutabile), che `wipe()` azzera;
- vieta pickle e copy, per non moltiplicare le copie in memoria.

Cosa NON può fare: Python non garantisce la cancellazione della memoria.
Ogni `bytes`/`str` creato a partire dal segreto (per esempio l'output di
`getpass` o di una decifratura) è immutabile e resta in memoria finché il
garbage collector non lo libera. `Secret` riduce il problema, non lo elimina.
"""

import hmac
from types import TracebackType
from typing import Self


class Secret:
    """Byte sensibili con rappresentazione redatta e azzeramento esplicito."""

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray) -> None:
        # Se riceve un bytearray ne prende possesso (niente copia), così wipe()
        # azzera proprio il buffer del chiamante. Da bytes immutabili invece
        # è obbligato a copiare, e l'originale non è azzerabile.
        self._buf = data if isinstance(data, bytearray) else bytearray(data)
        self._wiped = False

    @classmethod
    def from_str(cls, text: str) -> Self:
        """Crea un Secret dalla codifica UTF-8 di `text` (che resta in memoria)."""
        return cls(bytearray(text.encode("utf-8")))

    def view(self) -> memoryview:
        """Vista in sola lettura del contenuto, senza copiarlo.

        `cryptography` accetta direttamente un memoryview, quindi la chiave
        arriva alla libreria senza passare da un `bytes` intermedio.
        """
        if self._wiped:
            raise ValueError("Secret già azzerato")
        return memoryview(self._buf).toreadonly()

    def wipe(self) -> None:
        """Sovrascrive il buffer con zeri. Idempotente."""
        # Assegnazione a slice della stessa lunghezza: scrive nello stesso
        # buffer invece di riallocarne uno nuovo.
        self._buf[:] = bytes(len(self._buf))
        self._wiped = True

    def __len__(self) -> int:
        return len(self._buf)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        # Confronto a tempo costante: non rivela dopo quanti byte differiscono.
        return hmac.compare_digest(self._buf, other._buf)

    __hash__ = None  # type: ignore[assignment]  # mutabile: non usarlo come chiave

    def __repr__(self) -> str:
        return "<Secret redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: object) -> object:
        # pickle, copy.copy e copy.deepcopy passano tutti da qui.
        raise TypeError("Secret non può essere serializzato o copiato")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.wipe()

    # Volutamente nessun __del__ che azzeri il buffer: una view() può
    # sopravvivere al Secret da cui è nata (es. `bytes(derive().view())`),
    # e azzerarla alla distruzione trasformerebbe in silenzio una chiave in
    # 32 zeri. Si azzera solo esplicitamente, con wipe() o con `with`.
