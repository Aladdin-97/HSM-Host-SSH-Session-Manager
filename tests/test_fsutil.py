import fcntl
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from hsm.errors import HsmError, InsecurePermissionsError
from hsm.fsutil import atomic_write, check_private, ensure_private_dir, read_private


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def open_umask() -> Iterator[None]:
    # umask 0 è il caso peggiore: se il codice si affidasse all'umask,
    # i file uscirebbero 0666.
    old = os.umask(0)
    yield
    os.umask(old)


def test_atomic_write_creates_0600_even_with_open_umask(tmp_path: Path, open_umask: None) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"data")
    assert target.read_bytes() == b"data"
    assert _mode(target) == 0o600


def test_atomic_write_replaces_and_tightens_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"old")
    target.chmod(0o644)
    atomic_write(target, b"new")
    assert target.read_bytes() == b"new"
    assert _mode(target) == 0o600


def test_atomic_write_leaves_no_temp_files(tmp_path: Path) -> None:
    atomic_write(tmp_path / "f", b"data")
    assert [p.name for p in tmp_path.iterdir()] == ["f"]


def test_atomic_write_cleans_up_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(src: str, dst: str) -> None:
        raise OSError("disco pieno")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disco pieno"):
        atomic_write(tmp_path / "f", b"data")
    assert list(tmp_path.iterdir()) == []


def test_read_private_returns_content(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"data")
    assert read_private(target) == b"data"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_read_private_rejects_permissive_modes(tmp_path: Path, mode: int) -> None:
    target = tmp_path / "f"
    target.write_bytes(b"data")
    target.chmod(mode)
    with pytest.raises(InsecurePermissionsError, match="chmod 600"):
        read_private(target)


def test_read_private_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    atomic_write(real, b"data")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(InsecurePermissionsError, match="symlink"):
        read_private(link)


def test_read_private_rejects_foreign_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"data")
    monkeypatch.setattr(os, "getuid", lambda: os.stat(target).st_uid + 1)
    with pytest.raises(InsecurePermissionsError, match="proprietario"):
        read_private(target)


def test_read_private_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_private(tmp_path / "missing")


def test_check_private_accepts_0600_file_and_0700_dir(tmp_path: Path) -> None:
    f = tmp_path / "f"
    atomic_write(f, b"x")
    check_private(f)
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    check_private(d)


def test_check_private_rejects_0755_dir_with_hint(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o755)
    with pytest.raises(InsecurePermissionsError, match="chmod 700"):
        check_private(d)


def test_check_private_rejects_symlink(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(d)
    with pytest.raises(InsecurePermissionsError, match="symlink"):
        check_private(link)


def test_ensure_private_dir_creates_0700(tmp_path: Path, open_umask: None) -> None:
    d = tmp_path / "a" / "hsm"
    ensure_private_dir(d)
    assert _mode(d) == 0o700


def test_ensure_private_dir_rejects_existing_permissive_dir(tmp_path: Path) -> None:
    d = tmp_path / "hsm"
    d.mkdir()
    d.chmod(0o755)
    with pytest.raises(InsecurePermissionsError):
        ensure_private_dir(d)


# --- rilievi della security review --------------------------------------------


def test_read_private_rejects_permissive_parent_dir(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    atomic_write(d / "f", b"data")
    d.chmod(0o777)
    with pytest.raises(InsecurePermissionsError, match="chmod 700"):
        read_private(d / "f")


def test_atomic_write_rejects_permissive_parent_dir(tmp_path: Path) -> None:
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o755)
    with pytest.raises(InsecurePermissionsError):
        atomic_write(d / "f", b"data")
    assert list(d.iterdir()) == []


def test_read_private_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(InsecurePermissionsError, match="file regolare"):
        read_private(fifo)


def test_read_private_rejects_oversized_file(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"12345")
    with pytest.raises(HsmError, match="grande"):
        read_private(target, max_size=4)


def test_exclusive_write_refuses_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"old")
    with pytest.raises(FileExistsError):
        atomic_write(target, b"new", exclusive=True)
    assert target.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["f"]


def test_exclusive_write_creates_new_file(tmp_path: Path) -> None:
    target = tmp_path / "f"
    atomic_write(target, b"data", exclusive=True)
    assert target.read_bytes() == b"data"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["f"]


def test_falls_back_to_fsync_when_full_fsync_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsupported(fd: int, cmd: int) -> None:
        raise OSError("F_FULLFSYNC non supportato")

    monkeypatch.setattr(fcntl, "fcntl", unsupported)
    atomic_write(tmp_path / "f", b"data")
    assert (tmp_path / "f").read_bytes() == b"data"
