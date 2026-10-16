"""Container for secrets (passwords, keys) that limits accidental leaks.

What it does:
- `repr`/`str`/f-strings never show the content, so a secret that ends up
  in a log, a debug print or a traceback stays hidden;
- the content lives in a (mutable) `bytearray`, which `wipe()` zeroes;
- it forbids pickle and copy, so copies in memory don't multiply.

What it CANNOT do: Python does not guarantee that memory is erased.
Every `bytes`/`str` created from the secret (for example the output of
`getpass` or of a decryption) is immutable and stays in memory until the
garbage collector frees it. `Secret` reduces the problem, it doesn't remove it.
"""

import hmac
from types import TracebackType
from typing import Self


class Secret:
    """Sensitive bytes with a redacted representation and explicit zeroing."""

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray) -> None:
        # Given a bytearray it takes ownership (no copy), so wipe() zeroes
        # the caller's own buffer. From immutable bytes, instead, it has to
        # copy, and the original cannot be zeroed.
        self._buf = data if isinstance(data, bytearray) else bytearray(data)
        self._wiped = False

    @classmethod
    def from_str(cls, text: str) -> Self:
        """Create a Secret from the UTF-8 encoding of `text` (which stays in memory)."""
        return cls(bytearray(text.encode("utf-8")))

    def view(self) -> memoryview:
        """Read-only view of the content, without copying it.

        `cryptography` accepts a memoryview directly, so the key reaches
        the library without going through an intermediate `bytes`.
        """
        if self._wiped:
            raise ValueError("Secret already wiped")
        return memoryview(self._buf).toreadonly()

    def wipe(self) -> None:
        """Overwrite the buffer with zeros. Idempotent."""
        # Slice assignment of the same length: writes into the same
        # buffer instead of allocating a new one.
        self._buf[:] = bytes(len(self._buf))
        self._wiped = True

    def __len__(self) -> int:
        return len(self._buf)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        # Constant-time comparison: doesn't reveal after how many bytes they differ.
        return hmac.compare_digest(self._buf, other._buf)

    __hash__ = None  # type: ignore[assignment]  # mutable: don't use it as a key

    def __repr__(self) -> str:
        return "<Secret redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, protocol: object) -> object:
        # pickle, copy.copy and copy.deepcopy all go through here.
        raise TypeError("Secret cannot be serialized or copied")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.wipe()

    # Deliberately no __del__ that zeroes the buffer: a view() can outlive
    # the Secret it came from (e.g. `bytes(derive().view())`), and zeroing
    # it on destruction would silently turn a key into 32 zeros. Zeroing
    # happens only explicitly, with wipe() or with `with`.
