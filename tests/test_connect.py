import os
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from hsm.connect import SSH, Connector, build_argv
from hsm.errors import HsmError
from hsm.inventory import Host, Inventory
from hsm.secret import Secret

SSHPASS = "/opt/homebrew/bin/sshpass"


def inventory(tmp_path: Path, *hosts: Host) -> Inventory:
    inv = Inventory.load(tmp_path / "missing.toml")
    for h in hosts:
        inv.add(h)
    return inv


BASTION = Host(alias="bastion", hostname="bastion.example.com", user="jump", port=2200)
WEB01 = Host(
    alias="web01",
    hostname="10.0.0.1",
    user="deploy",
    port=2222,
    jump_host="bastion",
    identity_file="~/.ssh/id_ed25519",
)


@dataclass
class FakeRunner:
    """Registra la chiamata; legge subito dal fd passato, come farebbe sshpass."""

    returncode: int = 0
    raises: BaseException | None = None
    calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)
    fd_content: bytes | None = None

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        fds = kwargs.get("pass_fds") or ()
        if fds:
            chunks = []
            while chunk := os.read(fds[0], 4096):
                chunks.append(chunk)
            self.fd_content = b"".join(chunks)
        return subprocess.CompletedProcess(list(argv), self.returncode)


@dataclass
class Env:
    tmp_path: Path
    runner: FakeRunner = field(default_factory=FakeRunner)
    sshpass: str | None = SSHPASS
    warnings: list[str] = field(default_factory=list)
    copied: list[bytes] = field(default_factory=list)
    accept: bool = True
    questions: list[str] = field(default_factory=list)

    def confirm(self, question: str) -> bool:
        self.questions.append(question)
        return self.accept

    def connector(self, *, with_fallback: bool = True) -> Connector:
        return Connector(
            runner=self.runner,
            find_sshpass=lambda: self.sshpass,
            warn=self.warnings.append,
            clipboard_fallback=(lambda s: self.copied.append(bytes(s.view()))) if with_fallback else None,
            confirm=self.confirm,
        )


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


# --- build_argv -----------------------------------------------------------------


def test_full_argv(tmp_path: Path) -> None:
    argv = build_argv(WEB01, inventory(tmp_path, BASTION, WEB01))
    assert argv == [
        SSH,
        "-l", "deploy",
        "-p", "2222",
        "-J", "jump@bastion.example.com:2200",
        "-i", os.path.expanduser("~/.ssh/id_ed25519"),
        "-o", "IdentitiesOnly=yes",
        "--",
        "10.0.0.1",
    ]  # fmt: skip


def test_minimal_argv(tmp_path: Path) -> None:
    h = Host(alias="db", hostname="db.example.com")
    assert build_argv(h, inventory(tmp_path, h)) == [SSH, "-p", "22", "--", "db.example.com"]


def test_destination_always_after_double_dash(tmp_path: Path) -> None:
    # Difesa in profondità: anche se la validazione cambiasse, un hostname
    # che inizia con "-" non verrebbe mai letto come opzione.
    argv = build_argv(WEB01, inventory(tmp_path, BASTION, WEB01))
    assert argv[-2:] == ["--", "10.0.0.1"]


def test_literal_jump_host_passes_through(tmp_path: Path) -> None:
    h = Host(alias="x", hostname="x", jump_host="admin@gw.example.com:22")
    argv = build_argv(h, inventory(tmp_path, h))
    assert argv[argv.index("-J") + 1] == "admin@gw.example.com:22"


def test_jump_alias_with_ipv6_is_bracketed(tmp_path: Path) -> None:
    b6 = Host(alias="b6", hostname="2001:db8::1")
    h = Host(alias="x", hostname="x", jump_host="b6")
    argv = build_argv(h, inventory(tmp_path, b6, h))
    assert argv[argv.index("-J") + 1] == "[2001:db8::1]:22"


def test_jump_chain_is_resolved_outermost_first(tmp_path: Path) -> None:
    outer = Host(alias="outer", hostname="outer.example.com")
    inner = Host(alias="inner", hostname="inner.lan", jump_host="outer")
    h = Host(alias="x", hostname="x", jump_host="inner")
    argv = build_argv(h, inventory(tmp_path, outer, inner, h))
    # -J a,b: prima a, poi b, poi la destinazione.
    assert argv[argv.index("-J") + 1] == "outer.example.com:22,inner.lan:22"


def test_jump_cycle_is_an_error(tmp_path: Path) -> None:
    a = Host(alias="a", hostname="a", jump_host="b")
    b = Host(alias="b", hostname="b", jump_host="a")
    with pytest.raises(HsmError, match="ciclo"):
        build_argv(a, inventory(tmp_path, a, b))


def test_jump_alias_with_ipv6_zone_is_unsupported(tmp_path: Path) -> None:
    z = Host(alias="z", hostname="fe80::1%en0")
    h = Host(alias="x", hostname="x", jump_host="z")
    with pytest.raises(HsmError, match="zona"):
        build_argv(h, inventory(tmp_path, z, h))


# --- connect senza password (il caso normale) --------------------------------


def test_key_auth_runs_plain_ssh(env: Env) -> None:
    env.runner.returncode = 0
    code = env.connector().connect(WEB01, inventory(env.tmp_path, BASTION, WEB01))
    assert code == 0
    argv, kwargs = env.runner.calls[0]
    assert argv[0] == SSH
    assert not kwargs.get("pass_fds")


def test_exit_code_is_propagated(env: Env) -> None:
    env.runner.returncode = 255
    assert env.connector().connect(BASTION, inventory(env.tmp_path, BASTION)) == 255


def test_missing_ssh_is_clean_error(env: Env) -> None:
    env.runner.raises = FileNotFoundError(SSH)
    with pytest.raises(HsmError, match="ssh"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION))


# --- connect con password via sshpass ------------------------------------------


def test_password_goes_through_a_pipe_not_argv_nor_env(env: Env) -> None:
    pw = Secret(b"s3cret-pw")
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=pw)
    argv, kwargs = env.runner.calls[0]
    assert argv[:2] == [SSHPASS, "-d"]
    fd = int(argv[2])
    assert kwargs["pass_fds"] == (fd,)
    assert argv[3] == SSH
    # Il segreto non compare negli argomenti (visibili con ps) né nell'ambiente.
    assert not any("s3cret" in a for a in argv)
    assert "env" not in kwargs
    assert env.runner.fd_content == b"s3cret-pw"


def test_pipe_fds_are_closed_after_the_session(env: Env) -> None:
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    fd = int(env.runner.calls[0][0][2])
    with pytest.raises(OSError):
        os.fstat(fd)


def test_password_with_newline_is_rejected(env: Env) -> None:
    # sshpass legge una riga: il resto finirebbe perso o frainteso.
    with pytest.raises(HsmError, match="a capo"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"a\nb"))
    assert env.runner.calls == []


@pytest.mark.parametrize("code, hint", [(5, "rifiutata"), (6, "chiave dell'host")])
def test_sshpass_exit_codes_are_explained(env: Env, code: int, hint: str) -> None:
    env.runner.returncode = code
    assert env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw")) == code
    assert any(hint in w for w in env.warnings)


def test_password_with_jump_host_warns(env: Env) -> None:
    env.connector().connect(WEB01, inventory(env.tmp_path, BASTION, WEB01), password=Secret(b"pw"))
    assert any("jump" in w for w in env.warnings)


def test_missing_sshpass_offers_clipboard_and_connects(env: Env) -> None:
    env.sshpass = None
    code = env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    assert code == 0
    assert env.questions  # la copia negli appunti viene chiesta, non imposta
    assert env.copied == [b"pw"]
    argv, kwargs = env.runner.calls[0]
    assert argv[0] == SSH and not kwargs.get("pass_fds")
    assert any("sshpass" in w for w in env.warnings)


def test_missing_sshpass_declined_still_connects(env: Env) -> None:
    env.sshpass = None
    env.accept = False
    assert env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw")) == 0
    assert env.copied == []
    assert len(env.runner.calls) == 1


def test_missing_sshpass_without_fallback_still_connects(env: Env) -> None:
    # La spec: "senza fallire". Si collega e l'utente digita la password.
    env.sshpass = None
    code = env.connector(with_fallback=False).connect(
        BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw")
    )
    assert code == 0
    assert env.runner.calls[0][0][0] == SSH
    assert any("sshpass" in w for w in env.warnings)


# --- integrazione: pipe e pass_fds reali con un finto sshpass -------------------


def test_real_subprocess_receives_password_on_fd(tmp_path: Path) -> None:
    # Un finto sshpass: legge dal fd ricevuto con -d e lo salva su file.
    # Verifica il meccanismo vero (os.pipe + pass_fds + subprocess.run).
    scripts = tmp_path / "bin"
    scripts.mkdir()
    out = tmp_path / "received"
    fake = scripts / "sshpass"
    fake.write_text(f'#!/bin/sh\ncat <&"$2" > "{out}"\n')
    fake.chmod(stat.S_IRWXU)
    connector = Connector(find_sshpass=lambda: str(fake), warn=lambda _: None)
    code = connector.connect(BASTION, inventory(tmp_path, BASTION), password=Secret(b"real-pw"))
    assert code == 0
    assert out.read_bytes() == b"real-pw"


def test_password_with_carriage_return_is_rejected(env: Env) -> None:
    with pytest.raises(HsmError, match="a capo"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"a\rb"))


def test_oversized_password_is_rejected(env: Env) -> None:
    with pytest.raises(HsmError, match="lunga"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"x" * 5000))


# --- rilievi della security review --------------------------------------------


def test_password_mode_forces_password_prompt(env: Env) -> None:
    # Se la chiave SSH bastasse, sshpass non leggerebbe mai la pipe e la
    # password resterebbe lì, ereditata da ssh e dai suoi figli.
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    argv = env.runner.calls[0][0]
    i = argv.index("PreferredAuthentications=password,keyboard-interactive")
    assert argv[i - 1] == "-o"
    assert i < argv.index("--")


def test_key_mode_does_not_restrict_auth(env: Env) -> None:
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION))
    assert not any("PreferredAuthentications" in a for a in env.runner.calls[0][0])


def test_negative_returncode_becomes_shell_style(env: Env) -> None:
    env.runner.returncode = -9  # ucciso da SIGKILL
    assert env.connector().connect(BASTION, inventory(env.tmp_path, BASTION)) == 128 + 9


def test_jump_alias_lookup_is_case_insensitive(tmp_path: Path) -> None:
    h = Host(alias="x", hostname="x", jump_host="Bastion")
    argv = build_argv(h, inventory(tmp_path, BASTION, h))
    assert argv[argv.index("-J") + 1] == "jump@bastion.example.com:2200"


def test_unknown_bare_jump_label_warns(tmp_path: Path) -> None:
    h = Host(alias="x", hostname="x", jump_host="bastoin")  # refuso
    warnings: list[str] = []
    build_argv(h, inventory(tmp_path, h), warn=warnings.append)
    assert any("bastoin" in w for w in warnings)


# --- ricerca di sshpass --------------------------------------------------------


def _fake_bin(directory: Path, mode: int = 0o755) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    f = directory / "sshpass"
    f.write_text("#!/bin/sh\n")
    f.chmod(mode)
    return f


def test_find_sshpass_uses_only_fixed_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm.connect import find_sshpass

    # Un sshpass nel PATH ma fuori dalle directory note non viene usato.
    rogue = _fake_bin(tmp_path / "rogue")
    monkeypatch.setenv("PATH", str(rogue.parent))
    assert find_sshpass(dirs=[tmp_path / "empty"]) is None
    good = _fake_bin(tmp_path / "brew")
    assert find_sshpass(dirs=[tmp_path / "empty", tmp_path / "brew"]) == str(good)


def test_find_sshpass_rejects_writable_binary(tmp_path: Path) -> None:
    from hsm.connect import find_sshpass

    _fake_bin(tmp_path / "brew", mode=0o777)
    assert find_sshpass(dirs=[tmp_path / "brew"]) is None


def test_find_sshpass_rejects_writable_directory(tmp_path: Path) -> None:
    from hsm.connect import find_sshpass

    _fake_bin(tmp_path / "brew")
    (tmp_path / "brew").chmod(0o777)
    try:
        assert find_sshpass(dirs=[tmp_path / "brew"]) is None
    finally:
        (tmp_path / "brew").chmod(0o755)


def test_default_runner_ignores_sigint_in_parent_only(monkeypatch: pytest.MonkeyPatch) -> None:
    import signal

    from hsm import connect

    seen: list[object] = []

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            # Al momento del fork il padre NON deve ancora ignorare SIGINT:
            # SIG_IGN verrebbe ereditato da ssh.
            seen.append(signal.getsignal(signal.SIGINT))
            self.returncode = 0

        def wait(self) -> int:
            seen.append(signal.getsignal(signal.SIGINT))
            return 0

    before = signal.getsignal(signal.SIGINT)
    monkeypatch.setattr(connect.subprocess, "Popen", FakePopen)
    result = connect._run(["/usr/bin/true"])
    assert result.returncode == 0
    assert seen[0] is not signal.SIG_IGN
    assert seen[1] is signal.SIG_IGN  # durante la sessione Ctrl-C va a ssh
    assert signal.getsignal(signal.SIGINT) is before  # ripristinato


def test_find_sshpass_rejects_non_executable_or_directory(tmp_path: Path) -> None:
    from hsm.connect import find_sshpass

    _fake_bin(tmp_path / "a", mode=0o644)
    (tmp_path / "b" / "sshpass").mkdir(parents=True)
    assert find_sshpass(dirs=[tmp_path / "a", tmp_path / "b"]) is None


@pytest.mark.parametrize("jump", ["10.0.0.9", "[2001:db8::1]:22", "gw.example.com"])
def test_literal_ip_or_fqdn_jump_does_not_warn(tmp_path: Path, jump: str) -> None:
    h = Host(alias="x", hostname="x", jump_host=jump)
    warnings: list[str] = []
    build_argv(h, inventory(tmp_path, h), warn=warnings.append)
    assert warnings == []
