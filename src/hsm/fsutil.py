"""Operations on private files: permission checks and atomic writes.

Rule: hsm files are 0600, directories 0700, the owner is the current user
and they are not symlinks. If a condition doesn't hold we refuse to go on
and say how to fix it: we don't fix it ourselves, because a wrong
permission can be the sign of something worth understanding.
"""

import contextlib
import errno
import fcntl
import os
import stat
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from hsm.errors import HsmError, InsecurePermissionsError

# No hsm file comes close to this threshold: beyond it, something is wrong
# and we don't want to load it all into memory.
MAX_READ_SIZE = 16 * 1024 * 1024


def _verify(st: os.stat_result, path: Path) -> None:
    """Apply the permission rule to an already obtained stat result."""
    is_dir = stat.S_ISDIR(st.st_mode)
    if not (is_dir or stat.S_ISREG(st.st_mode)):
        # FIFO, socket, device: opening them can block or have side effects.
        raise InsecurePermissionsError(f"{path} is neither a regular file nor a directory.")
    if st.st_uid != os.getuid():
        raise InsecurePermissionsError(
            f"{path} has an owner other than the current user (uid {st.st_uid})."
        )
    mode = stat.S_IMODE(st.st_mode)
    # 0o077 = any bit for group or others: they must all be off.
    if mode & 0o077:
        wanted = "700" if is_dir else "600"
        raise InsecurePermissionsError(
            f"Permissions too open on {path} ({mode:03o}). "
            f"Fix with: chmod {wanted} {path}"
        )


def check_private(path: Path) -> None:
    """Check that `path` (file or directory) is private to the user.

    Uses lstat, so a symlink is rejected instead of followed: otherwise a
    link could make us read or write someone else's file.
    Raises FileNotFoundError if `path` doesn't exist.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise InsecurePermissionsError(f"{path} is a symlink: hsm requires a real file.")
    _verify(st, path)


def read_private(path: Path, max_size: int = MAX_READ_SIZE) -> bytes:
    """Read a private file after checking its permissions.

    Also checks the containing directory: a 0600 file in a directory
    writable by others can be renamed or replaced.
    The check on the file is done on the already open file descriptor
    (fstat), not on the name: this way there is no window between check and
    read in which the file could be swapped (TOCTOU race).
    """
    check_private(path.parent)
    # O_NOFOLLOW: fails if the last component is a symlink.
    # O_NONBLOCK: if there is a FIFO in place of the file, open() doesn't hang
    #   waiting for a writer; we reject it right after with fstat.
    # O_CLOEXEC: the descriptor is not inherited by ssh or other children.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InsecurePermissionsError(
                f"{path} is a symlink: hsm requires a real file."
            ) from None
        raise
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        _verify(st, path)
        if stat.S_ISDIR(st.st_mode):
            raise InsecurePermissionsError(f"{path} is a directory, not a file.")
        if st.st_size > max_size:
            raise HsmError(f"{path} is too large ({st.st_size} bytes): invalid file.")
        return f.read()


def ensure_private_dir(path: Path) -> None:
    """Create `path` with 0700 permissions if missing, then check its permissions."""
    # The mode passed to makedirs applies only to the last directory created;
    # the umask can only remove bits, so the result is at most 0700.
    os.makedirs(path, mode=0o700, exist_ok=True)
    check_private(path)


def _full_fsync(fd: int) -> None:
    # On macOS fsync() hands the data to the disk but doesn't force the disk
    # to flush its cache; F_FULLFSYNC does. For the vault, losing a write
    # means losing all passwords, so we pay the cost.
    full_fsync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_fsync is not None:
        try:
            fcntl.fcntl(fd, full_fsync)
            return
        except OSError:
            # Some filesystems (SMB, NFS, some external disks) don't
            # support it: we fall back to fsync, the best guarantee left.
            pass
    os.fsync(fd)


def atomic_write(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """Write `data` to `path` atomically and with 0600 permissions.

    A reader sees either the whole old file or the whole new one, never a
    half-written one, even if the process dies during the write:
    1. mkstemp creates a temporary file in the same directory with O_EXCL and
       0600 permissions from creation (no instant with loose permissions);
    2. we write and force the data to disk;
    3. we publish the file under its final name (an atomic operation on the
       same filesystem);
    4. we sync the directory, because it is what records the new name.

    With `exclusive=True` step 3 uses os.link, which fails with
    FileExistsError if `path` already exists: it ensures we never overwrite a
    file created in the meantime by another process.
    """
    directory = path.parent
    check_private(directory)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    tmp_renamed = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            _full_fsync(f.fileno())
        if exclusive:
            # Creates a second name for the same file; the temporary one is
            # removed in the finally, and only `path` remains.
            os.link(tmp_name, path)
        else:
            os.replace(tmp_name, path)
            tmp_renamed = True
    finally:
        if not tmp_renamed:
            # Error halfway through, or link succeeded: remove the temporary name.
            # Any original exception keeps propagating.
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        _full_fsync(dir_fd)
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def locked(path: Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Exclusive lock between hsm processes, held for the whole `with` block.

    It wraps read-modify-write of the vault: without it, two parallel
    `hsm pw set` would read the same file and the second save would erase
    the first one's change.
    flock is "advisory": it only protects against those using the same lock,
    i.e. other hsm processes, which is what we need. The lock goes away with
    the process, so a crash doesn't leave files locked.
    """
    check_private(path.parent)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InsecurePermissionsError(f"{path} is a symlink: hsm requires a real file.") from None
        raise
    try:
        _verify(os.fstat(fd), path)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise HsmError(
                        f"Another hsm is modifying the vault ({path}): try again shortly."
                    ) from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # closing the descriptor releases the lock
