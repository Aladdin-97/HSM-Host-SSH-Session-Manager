import copy
import pickle

import pytest

from hsm.secret import Secret


def test_repr_str_format_are_redacted() -> None:
    s = Secret(bytearray(b"hunter2"))
    for rendered in (repr(s), str(s), f"{s}", f"{s!r}"):
        assert "hunter2" not in rendered
        assert "redacted" in rendered


def test_redacted_inside_containers() -> None:
    # Nei traceback e nei debug print i Secret finiscono spesso dentro dict/list.
    rendered = repr({"pw": Secret(bytearray(b"hunter2"))})
    assert "hunter2" not in rendered


def test_view_exposes_content_read_only() -> None:
    s = Secret(bytearray(b"abc"))
    view = s.view()
    assert bytes(view) == b"abc"
    with pytest.raises(TypeError):
        view[0] = 0  # type: ignore[index]


def test_wipe_zeroes_the_buffer_it_owns() -> None:
    buf = bytearray(b"hunter2")
    s = Secret(buf)
    s.wipe()
    assert buf == bytearray(len(b"hunter2"))


def test_use_after_wipe_raises() -> None:
    s = Secret(bytearray(b"abc"))
    s.wipe()
    with pytest.raises(ValueError):
        s.view()


def test_context_manager_wipes_on_exit() -> None:
    buf = bytearray(b"abc")
    with Secret(buf) as s:
        assert bytes(s.view()) == b"abc"
    assert buf == bytearray(3)


def test_context_manager_wipes_on_exception() -> None:
    buf = bytearray(b"abc")
    with pytest.raises(RuntimeError):
        with Secret(buf):
            raise RuntimeError("boom")
    assert buf == bytearray(3)


def test_from_str_encodes_utf8() -> None:
    assert bytes(Secret.from_str("pàss").view()) == "pàss".encode()


def test_bytes_input_is_copied() -> None:
    s = Secret(b"abc")
    assert bytes(s.view()) == b"abc"


def test_cannot_be_pickled_or_copied() -> None:
    s = Secret(bytearray(b"abc"))
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(TypeError):
        copy.copy(s)
    with pytest.raises(TypeError):
        copy.deepcopy(s)


def test_equality_compares_content() -> None:
    assert Secret(b"abc") == Secret(b"abc")
    assert Secret(b"abc") != Secret(b"abd")
    assert Secret(b"abc") != b"abc"


def test_len() -> None:
    assert len(Secret(b"abcd")) == 4


def test_not_hashable() -> None:
    with pytest.raises(TypeError):
        hash(Secret(b"abc"))


def test_view_of_temporary_secret_keeps_its_content() -> None:
    # Regressione: __del__ azzerava il buffer quando il Secret temporaneo
    # veniva distrutto, mentre la sua view era ancora in uso. Risultato:
    # zeri al posto della chiave, senza nessun errore.
    def make() -> Secret:
        return Secret(bytearray(b"abc"))

    # Fuori dall'assert: la riscrittura degli assert di pytest tiene vivi i
    # valori intermedi e nasconderebbe il bug.
    content = bytes(make().view())
    assert content == b"abc"
