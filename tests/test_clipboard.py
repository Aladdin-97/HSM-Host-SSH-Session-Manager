import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import pytest

from hsm.clipboard import (
    CONCEALED_TYPE,
    STRING_TYPE,
    TRANSIENT_TYPE,
    Clipboard,
    clear_if_unchanged,
    main,
)
from hsm.errors import HsmError
from hsm.secret import Secret

NOW = 1_800_000_000.0


@dataclass
class FakePasteboard:
    """Imita NSPasteboard: tipi dichiarati, contenuti e changeCount."""

    count: int = 100
    contents: dict[str, str] = field(default_factory=dict)
    declared: list[str] = field(default_factory=list)

    def changeCount(self) -> int:  # noqa: N802
        return self.count

    def clearContents(self) -> int:  # noqa: N802
        self.contents = {}
        self.declared = []
        self.count += 1
        return self.count

    def declareTypes_owner_(self, types: list[str], owner: object) -> int:  # noqa: N802
        self.contents = {}
        self.declared = list(types)
        self.count += 1
        return self.count

    def setString_forType_(self, value: str, kind: str) -> bool:  # noqa: N802
        if kind not in self.declared:
            return False
        self.contents[kind] = value
        return True


@dataclass
class FakeSpawn:
    """Simula il watchdog: se `ready`, scrive il byte di conferma sul fd."""

    ready: bool = True
    raises: BaseException | None = None
    calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)

    def __call__(self, argv: list[str], **kwargs: Any) -> None:
        self.calls.append((argv, kwargs))
        if self.raises is not None:
            raise self.raises
        if self.ready:
            os.write(int(argv[argv.index("--ready-fd") + 1]), b"1")


@pytest.fixture
def pb() -> FakePasteboard:
    return FakePasteboard()


@pytest.fixture
def spawn() -> FakeSpawn:
    return FakeSpawn()


def _clip(pb: FakePasteboard, spawn: FakeSpawn, **kwargs: Any) -> Clipboard:
    return Clipboard(pasteboard=pb, spawn=spawn, clock=lambda: NOW, **kwargs)


# --- copia ------------------------------------------------------------------


def test_copies_text_and_marks_it_concealed_and_transient(pb: FakePasteboard, spawn: FakeSpawn) -> None:
    _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents[STRING_TYPE] == "s3cret"
    # Convenzione nspasteboard.org: i gestori di cronologia non la salvano.
    assert CONCEALED_TYPE in pb.declared and TRANSIENT_TYPE in pb.declared


def test_spawns_detached_watchdog_with_change_count_and_deadline(pb: FakePasteboard, spawn: FakeSpawn) -> None:
    _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"), seconds=30)
    argv, kwargs = spawn.calls[0]
    assert argv[:4] == [sys.executable, "-I", "-m", "hsm.clipboard"]
    assert argv[argv.index("--expect") + 1] == str(pb.count)
    # Scadenza assoluta su orologio reale: vale anche se il Mac va in stop.
    assert float(argv[argv.index("--deadline") + 1]) == NOW + 30
    # Al watchdog non arriva nulla del segreto: né il testo né un suo hash.
    assert not any("s3cret" in a for a in argv)
    assert kwargs["start_new_session"] is True
    assert kwargs["stdin"] is subprocess.DEVNULL
    ready_fd = int(argv[argv.index("--ready-fd") + 1])
    assert kwargs["pass_fds"] == (ready_fd,)


def test_ready_pipe_is_closed_in_parent(pb: FakePasteboard, spawn: FakeSpawn) -> None:
    _clip(pb, spawn).copy_with_autoclear(Secret(b"x"))
    ready_fd = int(spawn.calls[0][0][spawn.calls[0][0].index("--ready-fd") + 1])
    with pytest.raises(OSError):
        os.fstat(ready_fd)


def test_expected_count_is_the_one_returned_by_our_write(pb: FakePasteboard, spawn: FakeSpawn) -> None:
    _clip(pb, spawn).copy_with_autoclear(Secret(b"x"))
    argv = spawn.calls[0][0]
    assert int(argv[argv.index("--expect") + 1]) == 101  # da declareTypes, non letto dopo


def test_other_app_writing_during_copy_is_detected(
    pb: FakePasteboard, spawn: FakeSpawn, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = pb.setString_forType_

    def racing(value: str, kind: str) -> bool:
        ok = original(value, kind)
        pb.count += 1  # un'altra app scrive negli appunti proprio ora
        return ok

    monkeypatch.setattr(pb, "setString_forType_", racing)
    with pytest.raises(HsmError, match="altra app"):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"x"))
    assert spawn.calls == []


def test_watchdog_not_ready_clears_and_raises(pb: FakePasteboard) -> None:
    # Il processo è partito ma è morto all'avvio (es. import fallito):
    # nessuno cancellerebbe la password, quindi la togliamo subito.
    spawn = FakeSpawn(ready=False)
    with pytest.raises(HsmError, match="cancellazione"):
        _clip(pb, spawn, ready_timeout=0.05).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents == {}


def test_spawn_failure_clears_and_raises(pb: FakePasteboard) -> None:
    spawn = FakeSpawn(raises=OSError("fork fallita"))
    with pytest.raises(HsmError, match="cancellazione"):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents == {}


def test_ctrl_c_during_spawn_clears_and_propagates(pb: FakePasteboard) -> None:
    spawn = FakeSpawn(raises=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents == {}


def test_unexpected_error_clears_and_becomes_hsm_error(pb: FakePasteboard) -> None:
    spawn = FakeSpawn(raises=TypeError("sys.executable è None"))
    with pytest.raises(HsmError):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents == {}


def test_cleanup_does_not_wipe_a_newer_user_copy(pb: FakePasteboard) -> None:
    class UserCopiesThenFails(FakeSpawn):
        def __call__(self, argv: list[str], **kwargs: Any) -> None:
            pb.declareTypes_owner_([STRING_TYPE], None)
            pb.setString_forType_("copiato dall'utente", STRING_TYPE)
            raise OSError("fork fallita")

    with pytest.raises(HsmError):
        _clip(pb, UserCopiesThenFails()).copy_with_autoclear(Secret(b"s3cret"))
    assert pb.contents == {STRING_TYPE: "copiato dall'utente"}


def test_write_failure_is_clean_error(pb: FakePasteboard, spawn: FakeSpawn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pb, "setString_forType_", lambda value, kind: False)
    with pytest.raises(HsmError, match="appunti"):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"s3cret"))
    assert spawn.calls == []


@pytest.mark.parametrize("seconds", [0, -1, 601])
def test_seconds_bounds(pb: FakePasteboard, spawn: FakeSpawn, seconds: int) -> None:
    with pytest.raises(ValueError):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"x"), seconds=seconds)


def test_non_utf8_secret_is_clean_error(pb: FakePasteboard, spawn: FakeSpawn) -> None:
    with pytest.raises(HsmError, match="UTF-8"):
        _clip(pb, spawn).copy_with_autoclear(Secret(b"\xff"))
    assert pb.contents == {}


def test_missing_appkit_is_clean_error(spawn: FakeSpawn, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "AppKit", None)
    with pytest.raises(HsmError, match="pyobjc"):
        Clipboard(spawn=spawn).copy_with_autoclear(Secret(b"x"))


# --- watchdog ----------------------------------------------------------------


def test_clear_if_unchanged_clears_our_value(pb: FakePasteboard) -> None:
    pb.contents = {STRING_TYPE: "s3cret"}
    assert clear_if_unchanged(pb, expected=pb.count) is True
    assert pb.contents == {}


def test_clear_if_unchanged_respects_newer_copy(pb: FakePasteboard) -> None:
    expected = pb.count
    pb.count += 1
    pb.contents = {STRING_TYPE: "altro"}
    assert clear_if_unchanged(pb, expected=expected) is False
    assert pb.contents == {STRING_TYPE: "altro"}


def test_main_waits_on_wall_clock_in_short_steps(pb: FakePasteboard) -> None:
    # Simula 25 s di stop del Mac: l'orologio reale salta in avanti e il
    # watchdog se ne accorge al passo successivo, senza aspettare altri 30 s.
    now = [NOW]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds if len(slept) != 2 else 25

    pb.contents = {STRING_TYPE: "s3cret"}
    code = main(
        ["--expect", str(pb.count), "--deadline", str(NOW + 30)],
        pasteboard=pb,
        sleep=sleep,
        clock=lambda: now[0],
    )
    assert code == 0
    assert pb.contents == {}
    assert max(slept) <= 2
    assert len(slept) < 15


def test_main_signals_ready_after_setup(pb: FakePasteboard) -> None:
    r, w = os.pipe()
    try:
        main(
            ["--expect", "1", "--deadline", str(NOW), "--ready-fd", str(w)],
            pasteboard=pb,
            sleep=lambda _: None,
            clock=lambda: NOW,
        )
        assert os.read(r, 1) == b"1"
    finally:
        os.close(r)


@pytest.mark.parametrize("deadline", [NOW + 601, -1.0])
def test_main_rejects_deadline_out_of_range(pb: FakePasteboard, deadline: float) -> None:
    with pytest.raises(SystemExit):
        main(
            ["--expect", "1", "--deadline", str(deadline)],
            pasteboard=pb,
            sleep=lambda _: None,
            clock=lambda: NOW,
        )


def test_main_rejects_bad_arguments(pb: FakePasteboard) -> None:
    with pytest.raises(SystemExit):
        main(["--expect", "x", "--deadline", "1"], pasteboard=pb, sleep=lambda _: None)


def test_real_watchdog_process_signals_ready() -> None:
    # Il vero `python -I -m hsm.clipboard`, avviato dalla root del disco.
    # --expect -1 non coincide mai con il vero changeCount: gli appunti
    # vengono solo letti, mai toccati.
    r, w = os.pipe()
    try:
        proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "hsm.clipboard", "--expect", "-1",
             "--deadline", str(time.time()), "--ready-fd", str(w)],
            pass_fds=(w,),
            cwd="/",
            env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        )  # fmt: skip
        os.close(w)
        w = -1
        assert os.read(r, 1) == b"1"
        assert proc.wait(timeout=10) == 0
    finally:
        os.close(r)
        if w != -1:
            os.close(w)


@pytest.mark.skipif(
    os.environ.get("HSM_CLIPBOARD_TESTS") != "1",
    reason="sovrascrive gli appunti reali: abilita con HSM_CLIPBOARD_TESTS=1",
)
def test_real_pasteboard_autoclear() -> None:
    import AppKit

    real = AppKit.NSPasteboard.generalPasteboard()
    Clipboard().copy_with_autoclear(Secret(b"hsm-test"), seconds=2)
    assert real.stringForType_(STRING_TYPE) == "hsm-test"
    time.sleep(4)
    assert real.stringForType_(STRING_TYPE) is None
