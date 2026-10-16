"""Opens the session with /usr/bin/ssh, the system's native client.

The arguments are built from the host's fields, so `hsm connect` works
even if you never ran `hsm sync`:

    /usr/bin/ssh -l deploy -p 2222 -J jump@bastion:2200 \\
                 -i /Users/me/.ssh/id -o IdentitiesOnly=yes -- 10.0.0.1

The `--` before the destination tells ssh there are no more options after
it: even a hostname starting with "-" would never be parsed as an option
(Host already forbids it; this is a second line of defense).

The jump_host can be an inventory alias: we translate it into
`user@hostname:port` (and walk up the chain if the bastion has its own
jump). Limitation: the bastion's identity_file only applies after
`hsm sync`, because -J uses the ssh configuration for intermediate hops.

Password (secondary case: the default is the SSH key): ssh asks
`hsm-askpass` for it via SSH_ASKPASS, with no external programs (see
askpass.py). The password never goes through the arguments (visible with
`ps`) or the environment; it is given only to the exact question of the
destination host, once. Every other question (unknown host key, bastion
password, OTP) is shown to you on the terminal.
"""

import contextlib
import getpass
import ipaddress
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from hsm.askpass import AskpassServer
from hsm.errors import HsmError
from hsm.inventory import Host, Inventory
from hsm.secret import Secret

SSH = "/usr/bin/ssh"

# A password longer than this is certainly a mistake.
_MAX_PASSWORD = 4096

Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _run(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    """Runs the session in the current terminal and waits for it to end.

    During the session Ctrl-C must reach ssh, not us: if Python reacted,
    subprocess would kill ssh and leave the terminal in raw mode. So we
    ignore SIGINT, but only AFTER starting the child: SIG_IGN is inherited,
    and ssh could no longer be interrupted.
    """
    on_spawn = kwargs.pop("on_spawn", None)
    proc = subprocess.Popen(list(argv), **kwargs)
    if on_spawn is not None:
        on_spawn(proc.pid)
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        returncode = proc.wait()
    finally:
        signal.signal(signal.SIGINT, previous)
    return subprocess.CompletedProcess(list(argv), returncode)


def default_askpass_helper() -> Path:
    """`hsm-askpass` installed next to the interpreter running hsm.

    We look there and not in PATH: it is the console script of the same
    package, in the same virtualenv (or uv tool). A fake "hsm-askpass" in
    PATH would receive the password.
    """
    return Path(sys.executable).parent / "hsm-askpass"


def resolve_effective_names(argv: Sequence[str]) -> list[tuple[str, str]]:
    """Effective (user, host) according to `ssh -G` for these arguments.

    ~/.ssh/config can change HostName or User, and the password question
    uses those values. `ssh -G` prints the resolved configuration without
    connecting. If it fails it is not serious: you will be asked for the
    password.
    """
    try:
        result = subprocess.run(
            [SSH, "-G", *argv[1:]],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    values = dict(line.split(" ", 1) for line in result.stdout.splitlines() if " " in line)
    if "user" in values and "hostname" in values:
        return [(values["user"], values["hostname"])]
    return []


@contextlib.contextmanager
def _exit_on_termination() -> Iterator[None]:
    """SIGTERM/SIGHUP (e.g. terminal window closed) become SystemExit.

    The default would kill Python without running the `with` blocks: the
    socket would stay in $TMPDIR and the password would not be wiped.
    """

    def stop(signum: int, frame: FrameType | None) -> None:
        raise SystemExit(128 + signum)

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def build_argv(
    host: Host,
    inventory: Inventory,
    *,
    warn: Callable[[str], None] | None = None,
) -> list[str]:
    """The /usr/bin/ssh arguments for `host`."""
    argv = [SSH]
    if host.user is not None:
        argv += ["-l", host.user]
    argv += ["-p", str(host.port)]
    hops = _jump_chain(host, inventory, seen={host.alias.casefold()}, warn=warn)
    if hops:
        argv += ["-J", ",".join(hops)]
    if host.identity_file is not None:
        # IdentitiesOnly: without it, ssh first tries every agent key and
        # the server may close ("Too many authentication failures") before
        # reaching the given one.
        argv += ["-i", os.path.expanduser(host.identity_file), "-o", "IdentitiesOnly=yes"]
    argv += ["--", host.hostname]
    return argv


class Connector:
    """Runs ssh. External dependencies are injectable for tests."""

    def __init__(
        self,
        *,
        runner: Runner = _run,
        warn: Callable[[str], None],
        askpass_helper: Callable[[], Path] = default_askpass_helper,
        local_user: Callable[[], str] = getpass.getuser,
        resolve: Callable[[Sequence[str]], list[tuple[str, str]]] = resolve_effective_names,
    ) -> None:
        self._runner = runner
        self._warn = warn
        self._askpass_helper = askpass_helper
        self._local_user = local_user
        self._resolve = resolve

    def connect(self, host: Host, inventory: Inventory, *, password: Secret | None = None) -> int:
        """Opens the session and returns the exit code (shell style)."""
        argv = build_argv(host, inventory, warn=self._warn)
        if password is None:
            return self._spawn(argv)

        # A memoryview holds integers: `b"\n" in view` would always be False.
        view = password.view()
        if 0x0A in view or 0x0D in view or 0x00 in view:
            raise HsmError("The password contains a newline: ssh cannot receive it.")
        if len(password) > _MAX_PASSWORD:
            raise HsmError("The password is too long.")
        helper = self._askpass_helper()
        if not (helper.is_file() and os.access(helper, os.X_OK)):
            raise HsmError(
                f"{helper} not found: reinstall hsm (uv tool install --reinstall .) "
                "or, in the project, run uv sync."
            )
        if host.jump_host is not None:
            self._warn(
                f"The saved password applies only to {host.alias}: you enter the other "
                "prompts (e.g. the jump host) yourself."
            )

        # ssh uses the local user when `user` is not set: the question we
        # recognize must carry the same name.
        user = host.user if host.user is not None else self._local_user()
        server = AskpassServer(password, user=user, hostname=host.hostname, aliases=self._resolve(argv))
        with _exit_on_termination(), server:
            env = {**os.environ, **server.env(str(helper))}
            # on_spawn: the server must know ssh's pid to give the password
            # only to its helpers (not to the jump host's ssh).
            code = self._spawn(argv, env=env, on_spawn=server.expect_ssh)
        if server.rejected:
            self._warn(
                f"The server rejected the saved password for {host.alias}: "
                f"update it with hsm pw set {host.alias}."
            )
        return code

    def _spawn(self, argv: list[str], **kwargs: Any) -> int:
        try:
            code = self._runner(argv, **kwargs).returncode
        except FileNotFoundError:
            raise HsmError(f"{argv[0]} not found.") from None
        # Killed by a signal: subprocess gives -N, the shell would use 128+N.
        return 128 - code if code < 0 else code


def _find_alias(inventory: Inventory, name: str) -> Host | None:
    # ssh compares aliases case-insensitively, and the inventory keeps them
    # unique the same way: "Bastion" must find "bastion".
    folded = name.casefold()
    return next((h for h in inventory.hosts() if h.alias.casefold() == folded), None)


def _jump_chain(
    host: Host,
    inventory: Inventory,
    *,
    seen: set[str],
    warn: Callable[[str], None] | None,
) -> list[str]:
    """The hops to pass to -J, from outermost to innermost."""
    if host.jump_host is None:
        return []
    jump = _find_alias(inventory, host.jump_host)
    if jump is None:
        # Not an alias: literal value, already validated by Host.
        if warn is not None and _looks_like_alias(host.jump_host):
            warn(
                f"jump_host {host.jump_host!r} is not an inventory alias: "
                "using it as a host name (is it a typo?)."
            )
        return [host.jump_host]
    if jump.alias.casefold() in seen:
        raise HsmError(f"jump_host chain with a cycle: it goes through {jump.alias} twice.")
    return [*_jump_chain(jump, inventory, seen=seen | {jump.alias.casefold()}, warn=warn), _hop(jump)]


def _looks_like_alias(jump: str) -> bool:
    """A name without dots that is not an IP: more likely a mistyped alias."""
    host = jump.rpartition("@")[2]
    if host.startswith("["):
        return False
    host = host.partition(":")[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." not in host
    return False


def _hop(host: Host) -> str:
    if "%" in host.hostname:
        raise HsmError(
            f"{host.alias}: a jump host with an IPv6 zone ({host.hostname}) is not supported by -J."
        )
    # In -J an IPv6 address goes in square brackets, otherwise ":port" is ambiguous.
    address = f"[{host.hostname}]" if ":" in host.hostname else host.hostname
    user = f"{host.user}@" if host.user is not None else ""
    return f"{user}{address}:{host.port}"
