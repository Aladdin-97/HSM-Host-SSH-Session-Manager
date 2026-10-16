"""Automatic ssh password via SSH_ASKPASS, without sshpass.

OpenSSH can ask an external program for the password instead of the
terminal: with SSH_ASKPASS=<program> and SSH_ASKPASS_REQUIRE=force, for every
question ssh runs `<program> "<question text>"` and reads the answer from its
stdout. The program here is `hsm-askpass` (the `main` function below).

    hsm connect ──► AskpassServer (private Unix socket, only during connect)
        │                    ▲
        └─► /usr/bin/ssh ──► hsm-askpass "admin@10.0.0.9's password: "
                                 │  token + question ──►  server
                                 │  ◄── password / "ask the user" / "no"
                                 └─► stdout ──► ssh

Why a socket: at startup ssh closes every file descriptor beyond
stdin/stdout/stderr, so a pipe passed down by hsm would never reach the
helper (which did work with sshpass).

The rules, all covered by tests:
- the password goes ONLY to the exact question "<user>@<host>'s password: "
  (or "(<user>@<host>) Password: ", keyboard-interactive) of the destination
  host, and ONLY to a helper that is a child of the main ssh process. The
  pid is checked by the kernel (LOCAL_PEERPID), not claimed by the helper.
  So the child ssh that ssh spawns for a jump host (-J) does not get it,
  even if that bastion had the same user@host on another port;
- everything else (host key confirmation, bastion password, OTP,
  passphrase) is relayed to you on the terminal. Confirming an unknown host
  key NEVER gets an automatic answer: an automatic "yes" would accept any
  server (verified: with SSH_ASKPASS_REQUIRE=force that question comes
  through here too);
- the question text can come from the server (keyboard-interactive): we
  strip control characters before showing it, and the answer is echoed
  while you type only for ssh's real host key question;
- the password is supplied once only: if ssh asks again, it was wrong, and
  you take over;
- no secrets in the environment: ssh and the helper get only the socket
  path and a random token, worthless without the running server;
- the socket lives in a 0700 directory created for the occasion and is
  removed when the connection ends.

Limitation: processes ssh runs on your behalf (ProxyCommand, LocalCommand,
`Match exec` in your ~/.ssh/config) are also children of ssh and inherit
token and socket: they could ask for the password in place of the helper.
They are commands you configured yourself, running as your user, i.e.
inside hsm's trust boundary (see THREAT_MODEL.md).
"""

import contextlib
import getpass
import hmac
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from types import FrameType, TracebackType
from typing import BinaryIO, Self

from hsm.errors import HsmError
from hsm.secret import Secret

ENV_SOCKET = "HSM_ASKPASS_SOCKET"
ENV_TOKEN = "HSM_ASKPASS_TOKEN"

# Server replies to the helper (one type byte, then any data).
_PASSWORD = b"P"
_ASK_USER = b"A"
_DENY = b"D"

_MAX_REQUEST = 16 * 1024
_IO_TIMEOUT = 5.0

# macOS: getsockopt(SOL_LOCAL, LOCAL_PEERPID) returns the pid of the
# process at the other end of a Unix socket, guaranteed by the kernel.
_SOL_LOCAL = 0
_LOCAL_PEERPID = 2

_HOST_KEY_QUESTION = re.compile(
    r"The authenticity of host [^\n]*\n.*"
    r"Are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)\? ",
    re.DOTALL,
)

Relay = Callable[[str], str | None]
Notify = Callable[[str], None]


def is_password_prompt(prompt: str, *, user: str, hostname: str) -> bool:
    """True only for the password question of `user@hostname`.

    Exact match on the whole string: a text that contains the question
    amid other text (or followed by another question) does not count.
    """
    target = f"{re.escape(user)}@{re.escape(hostname)}"
    # "password" authentication:       admin@10.0.0.9's password:
    # Keyboard-interactive (OpenSSH 8+): (admin@10.0.0.9) Password:
    pattern = rf"{target}'s password: |\({target}\) (?i:password): ?"
    return re.fullmatch(pattern, prompt) is not None


def is_host_key_question(prompt: str) -> bool:
    """True for ssh's question about an unknown host key.

    A server cannot imitate it: any keyboard-interactive text it chooses
    always arrives prefixed by ssh with "(user@host) ".
    """
    return _HOST_KEY_QUESTION.fullmatch(prompt) is not None


def _printable(text: str) -> str:
    """The text without control characters (ANSI sequences, BEL...), except newlines."""
    return "".join(c for c in text if c == "\n" or c.isprintable())


def _parent_pid(pid: int) -> int | None:
    try:
        result = subprocess.run(
            ["/bin/ps", "-o", "ppid=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=_IO_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = result.stdout.strip()
    return int(text) if result.returncode == 0 and text.isdigit() else None


class AskpassServer:
    """Serves the password to hsm-askpass for the duration of a `with`."""

    def __init__(
        self,
        password: Secret,
        *,
        user: str,
        hostname: str,
        aliases: Iterable[tuple[str, str]] = (),
        pid_wait: float = 2.0,
    ) -> None:
        view = password.view()
        if 0x0A in view or 0x0D in view or 0x00 in view:
            # ssh reads one line from the helper's stdout: a newline would
            # break it.
            raise ValueError("the password contains a newline or a null byte")
        self._password = Secret(bytearray(view))  # own copy, wiped in __exit__
        # The (user, host) pairs ssh may use in the question: the
        # inventory ones and the effective ones according to `ssh -G`.
        self._names = {(user, hostname), *aliases}
        self._token = secrets.token_hex(32)
        self._answered = False
        self._ssh_pid: int | None = None
        self._ssh_known = threading.Event()
        self._pid_wait = pid_wait
        self._stop = threading.Event()
        self._dir: Path | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        #: how many times ssh asked for the password again after receiving it
        self.rejected = 0

    def expect_ssh(self, pid: int) -> None:
        """The pid of the main ssh process: only its helpers receive the password."""
        self._ssh_pid = pid
        self._ssh_known.set()

    def __enter__(self) -> Self:
        # mkdtemp creates the directory with mode 0700: only we can even
        # see the socket. It lives in $TMPDIR, which on macOS is already
        # per-user (/var/folders/...).
        self._dir = Path(tempfile.mkdtemp(prefix="hsm-askpass-"))
        path = self._dir / "s"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(path))
            os.chmod(path, 0o600)
            sock.listen(8)
            sock.settimeout(0.2)  # so we can check _stop
        except OSError as exc:
            sock.close()
            self._cleanup()
            # The typical case: a path beyond the ~104 bytes allowed for a Unix socket.
            raise HsmError(
                f"Cannot create the password socket ({exc.strerror}). "
                "If TMPDIR is a very long path, use a shorter one."
            ) from None
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="hsm-askpass", daemon=True)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        if self._sock is not None:
            self._sock.close()
        self._cleanup()
        self._password.wipe()

    def env(self, helper: str) -> dict[str, str]:
        """The variables to add to ssh's environment. No secrets."""
        if self._dir is None:
            raise RuntimeError("AskpassServer must be used inside a `with`")
        return {
            "SSH_ASKPASS": helper,
            # force: use the helper even when there is a terminal (OpenSSH ≥ 8.4).
            "SSH_ASKPASS_REQUIRE": "force",
            ENV_SOCKET: str(self._dir / "s"),
            ENV_TOKEN: self._token,
        }

    def _cleanup(self) -> None:
        if self._dir is None:
            return
        (self._dir / "s").unlink(missing_ok=True)
        self._dir.rmdir()
        self._dir = None

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return  # socket closed
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    pass  # helper gone or slow: it simply gets nothing

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(_IO_TIMEOUT)
        token, sep, rest = _recv_all(conn).partition(b"\0")
        kind, sep2, raw_prompt = rest.partition(b"\0")
        if not (sep and sep2) or not hmac.compare_digest(token, self._token.encode()):
            conn.sendall(_DENY)
            return
        prompt = raw_prompt.decode("utf-8", errors="replace")
        # non-empty kind = confirmation or informational question
        # (SSH_ASKPASS_PROMPT): never a password.
        if kind or not any(
            is_password_prompt(prompt, user=u, hostname=h) for u, h in self._names
        ):
            conn.sendall(_ASK_USER)
            return
        if not self._from_main_ssh(conn):
            conn.sendall(_ASK_USER)
            return
        if self._answered:
            # ssh asks again: the one we gave was wrong.
            self.rejected += 1
            conn.sendall(_ASK_USER)
            return
        self._deliver(conn)
        # Only after a successful send: if the helper vanished midway, the
        # next request still gets the password.
        self._answered = True

    def _from_main_ssh(self, conn: socket.socket) -> bool:
        """Is the helper at the other end a child of the main ssh process?"""
        if not self._ssh_known.wait(self._pid_wait):
            return False
        try:
            peer = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERPID)
        except OSError:
            return False  # without the kernel's check, no password
        return _parent_pid(peer) == self._ssh_pid

    def _deliver(self, conn: socket.socket) -> None:
        conn.sendall(_PASSWORD)
        conn.sendall(self._password.view())


def _recv_all(conn: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size <= _MAX_REQUEST and (chunk := conn.recv(4096)):
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)[:_MAX_REQUEST]


def _request(path: str, token: str, kind: str, prompt: str) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(_IO_TIMEOUT)
        sock.connect(path)
        payload = b"\0".join(
            [token.encode(), kind.encode(), prompt.encode("utf-8", errors="replace")]
        )
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        return _recv_all(sock)


@contextlib.contextmanager
def _restore_tty_on_sigterm() -> Iterator[None]:
    # ssh may terminate the helper with SIGTERM while it waits for an answer.
    # The default would kill the process without running getpass's
    # `finally` blocks, leaving the terminal without echo: we turn it into
    # SystemExit.
    def stop(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    try:
        previous = signal.signal(signal.SIGTERM, stop)
    except ValueError:  # not in the main thread (e.g. in tests)
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _relay_to_tty(prompt: str) -> str | None:
    """Relays the question to the user on the terminal. None if there is no terminal."""
    shown = _printable(prompt)
    try:
        tty = open("/dev/tty", "r+", encoding="utf-8", errors="replace")  # noqa: SIM115
    except OSError:
        return None
    with tty:
        if is_host_key_question(prompt):
            # Host key confirmation: the answer is echoed while you type it.
            tty.write(shown)
            tty.flush()
            line = tty.readline()
            return line.rstrip("\n") if line else None
    try:
        with _restore_tty_on_sigterm():
            return getpass.getpass(shown)  # reads from /dev/tty without echo
    except EOFError:
        return None


def _notify_tty(text: str) -> None:
    with contextlib.suppress(OSError), open("/dev/tty", "w", encoding="utf-8") as tty:
        tty.write(_printable(text) + "\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdout: BinaryIO | None = None,
    relay: Relay | None = None,
    notify: Notify | None = None,
) -> int:
    """Entry point of `hsm-askpass`, run by ssh with the question as argument."""
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    out = stdout if stdout is not None else sys.stdout.buffer
    ask_user = relay if relay is not None else _relay_to_tty
    show = notify if notify is not None else _notify_tty
    prompt = argv[1] if len(argv) > 1 else ""
    kind = env.get("SSH_ASKPASS_PROMPT", "")

    if kind == "none":
        # Informational only (e.g. "touch your security key"): ssh expects
        # no answer and will close the helper when no longer needed.
        show(prompt)
        return 0

    reply: bytes | None = None
    path, token = env.get(ENV_SOCKET), env.get(ENV_TOKEN)
    if path and token:
        try:
            reply = _request(path, token, kind, prompt)
        except OSError:
            reply = None  # server unreachable: ask the user
    if reply is not None and reply.startswith(_PASSWORD):
        # `reply` is an immutable copy of the password: a known limitation,
        # it lives only until this process ends, which is right away.
        out.write(reply[len(_PASSWORD) :] + b"\n")
        out.flush()
        return 0
    if reply == _DENY:
        return 1
    answer = ask_user(prompt)
    if answer is None:
        return 1  # no answer: ssh treats it as "no"
    out.write(answer.encode("utf-8") + b"\n")
    out.flush()
    return 0
