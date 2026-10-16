import io
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from hsm.askpass import (
    ENV_SOCKET,
    ENV_TOKEN,
    AskpassServer,
    is_host_key_question,
    is_password_prompt,
    main,
)
from hsm.errors import HsmError
from hsm.secret import Secret

USER, HOST = "admin", "10.0.0.9"
TARGET_PROMPT = "admin@10.0.0.9's password: "
HOSTKEY_PROMPT = (
    "The authenticity of host '10.0.0.9 (10.0.0.9)' can't be established.\n"
    "ED25519 key fingerprint is: SHA256:abc\n"
    "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
)


def server(password: bytes = b"s3cret") -> AskpassServer:
    return AskpassServer(Secret(password), user=USER, hostname=HOST)


# --- riconoscimento del prompt ----------------------------------------------------


@pytest.mark.parametrize(
    "prompt",
    [
        "admin@10.0.0.9's password: ",  # autenticazione "password"
        "(admin@10.0.0.9) Password: ",  # keyboard-interactive (OpenSSH recenti)
        "(admin@10.0.0.9) Password:",
    ],
)
def test_recognizes_target_password_prompt(prompt: str) -> None:
    assert is_password_prompt(prompt, user=USER, hostname=HOST)


@pytest.mark.parametrize(
    "prompt",
    [
        HOSTKEY_PROMPT,  # la conferma della chiave host: MAI risposta automatica
        "jump@bastion.example.com's password: ",  # un altro host (es. il bastion)
        "root@10.0.0.9's password: ",  # un altro utente
        "admin@10.0.0.99's password: ",
        "Enter passphrase for key '/Users/me/.ssh/id': ",
        "(admin@10.0.0.9) Verification code: ",  # OTP
        "evil text admin@10.0.0.9's password: ",  # prefisso: niente match parziali
        "admin@10.0.0.9's password: \nAre you sure (yes/no)? ",
    ],
)
def test_rejects_every_other_prompt(prompt: str) -> None:
    assert not is_password_prompt(prompt, user=USER, hostname=HOST)


# --- server -----------------------------------------------------------------------


def _ask(env: dict[str, str], prompt: str) -> tuple[int, bytes]:
    """Lancia l'helper vero (main) come farebbe ssh, catturando stdout."""
    out = io.BytesIO()
    code = main(["hsm-askpass", prompt], env=env, stdout=out, relay=lambda p: None)
    return code, out.getvalue()


def test_env_carries_no_secret() -> None:
    with server(b"UNIQUE-PW") as srv:
        srv.expect_ssh(os.getppid())
        env = srv.env("/path/to/hsm-askpass")
        assert env["SSH_ASKPASS"] == "/path/to/hsm-askpass"
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        assert not any("UNIQUE-PW" in v for v in env.values())
        assert len(env[ENV_TOKEN]) >= 64


def test_socket_lives_in_private_dir_and_is_removed() -> None:
    with server() as srv:
        srv.expect_ssh(os.getppid())
        sock = Path(srv.env("x")[ENV_SOCKET])
        assert stat.S_IMODE(sock.parent.stat().st_mode) == 0o700
        assert stat.S_ISSOCK(sock.stat().st_mode)
    assert not sock.exists() and not sock.parent.exists()


def test_answers_target_prompt_once() -> None:
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = srv.env("x")
        assert _ask(env, TARGET_PROMPT) == (0, b"s3cret\n")
        # Una seconda richiesta vuol dire password rifiutata: niente nuovo
        # invio automatico, la parola passa all'utente.
        code, out = _ask(env, TARGET_PROMPT)
        assert out == b""
        assert srv.rejected == 1


def test_never_answers_host_key_or_other_prompts() -> None:
    relayed: list[str] = []
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = srv.env("x")
        for prompt in (HOSTKEY_PROMPT, "jump@bastion's password: "):
            out = io.BytesIO()
            main(["hsm-askpass", prompt], env=env, stdout=out, relay=lambda p: relayed.append(p) or None)
            assert b"s3cret" not in out.getvalue()
    assert relayed == [HOSTKEY_PROMPT, "jump@bastion's password: "]


def test_wrong_token_gets_nothing() -> None:
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = {**srv.env("x"), ENV_TOKEN: "0" * 64}
        code, out = _ask(env, TARGET_PROMPT)
        assert code != 0 and out == b""
        # Il tentativo fallito non consuma la risposta per il token giusto.
        assert _ask(srv.env("x"), TARGET_PROMPT) == (0, b"s3cret\n")


def test_closed_server_gives_nothing() -> None:
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = srv.env("x")
    code, out = _ask(env, TARGET_PROMPT)
    assert out == b""


def test_password_with_newline_is_rejected() -> None:
    with pytest.raises(ValueError):
        AskpassServer(Secret(b"a\nb"), user=USER, hostname=HOST)


# --- helper: relay verso il terminale ---------------------------------------------


def test_relay_answer_goes_to_stdout() -> None:
    out = io.BytesIO()
    with server() as srv:
        srv.expect_ssh(os.getppid())
        code = main(["hsm-askpass", HOSTKEY_PROMPT], env=srv.env("x"), stdout=out, relay=lambda p: "yes")
    assert (code, out.getvalue()) == (0, b"yes\n")


def test_relay_without_terminal_fails_closed() -> None:
    # Nessun terminale: la conferma della chiave host vale "no".
    out = io.BytesIO()
    with server() as srv:
        srv.expect_ssh(os.getppid())
        code = main(["hsm-askpass", HOSTKEY_PROMPT], env=srv.env("x"), stdout=out, relay=lambda p: None)
    assert code != 0 and out.getvalue() == b""


def test_without_hsm_env_behaves_like_plain_askpass() -> None:
    out = io.BytesIO()
    assert main(["hsm-askpass", "Password: "], env={}, stdout=out, relay=lambda p: "typed") == 0
    assert out.getvalue() == b"typed\n"


# --- integrazione: l'eseguibile vero ----------------------------------------------


def test_installed_helper_executable_answers() -> None:
    helper = Path(sys.executable).parent / "hsm-askpass"
    assert helper.exists(), "manca la console script hsm-askpass: lancia `uv sync`"
    with server(b"real-pw") as srv:
        srv.expect_ssh(os.getpid())  # il padre dell'helper è questo processo
        result = subprocess.run(
            [str(helper), TARGET_PROMPT],
            env={**os.environ, **srv.env(str(helper))},
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=20,
        )
    assert result.returncode == 0, result.stderr
    assert result.stdout == b"real-pw\n"


@pytest.mark.skipif(
    os.environ.get("HSM_SSHD_TESTS") != "1",
    reason="avvia un sshd temporaneo su 127.0.0.1: abilita con HSM_SSHD_TESTS=1",
)
def test_with_real_ssh_and_sshd(tmp_path: Path) -> None:
    import getpass
    import socket
    import time

    srv_dir = tmp_path / "srv"
    srv_dir.mkdir()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(srv_dir / "hostkey")], check=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    (srv_dir / "sshd_config").write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {srv_dir / 'hostkey'}\n"
        f"PidFile {srv_dir / 'pid'}\nUsePAM no\nPasswordAuthentication yes\n"
        "KbdInteractiveAuthentication no\nPubkeyAuthentication no\nStrictModes no\n"
    )
    log = srv_dir / "sshd.log"
    sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(srv_dir / "sshd_config")], stderr=log.open("w"))
    try:
        time.sleep(1)
        user = getpass.getuser()
        known = tmp_path / "known_hosts"
        helper = Path(sys.executable).parent / "hsm-askpass"
        base = [
            "/usr/bin/ssh", "-F", "/dev/null", "-p", str(port), "-l", user,
            "-o", f"UserKnownHostsFile={known}", "-o", "PreferredAuthentications=password",
            "-o", "NumberOfPasswordPrompts=1", "--", "127.0.0.1", "true",
        ]  # fmt: skip

        # 1. Chiave host sconosciuta, nessun terminale: l'helper NON conferma.
        with AskpassServer(Secret(b"pw"), user=user, hostname="127.0.0.1") as srv:
            proc = subprocess.Popen(base, env={**os.environ, **srv.env(str(helper))},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # fmt: skip
            srv.expect_ssh(proc.pid)
            assert proc.wait(timeout=20) != 0
        assert not known.exists() or known.read_text() == ""

        # 2. Chiave host già nota: la password arriva al server da sola.
        keyscan = subprocess.run(["ssh-keyscan", "-p", str(port), "127.0.0.1"], capture_output=True, text=True)
        known.write_text(keyscan.stdout)
        with AskpassServer(Secret(b"pw-from-vault"), user=user, hostname="127.0.0.1") as srv:
            proc = subprocess.Popen(base, env={**os.environ, **srv.env(str(helper))},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # fmt: skip
            srv.expect_ssh(proc.pid)
            proc.wait(timeout=20)
        time.sleep(0.3)
        # Un sshd non-root non può verificare password: "Failed password"
        # dimostra che la password è arrivata fino al server.
        assert "Failed password" in log.read_text()
    finally:
        sshd.terminate()
        sshd.wait(timeout=5)


# --- relay verso /dev/tty (simulato) ----------------------------------------------


class FakeTty(io.StringIO):
    def __init__(self, typed: str) -> None:
        super().__init__(typed)
        self.shown: list[str] = []

    def write(self, text: str) -> int:
        self.shown.append(text)
        return len(text)


def test_relay_yes_no_reads_visible_line(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    tty = FakeTty("yes\n")
    monkeypatch.setattr(askpass, "open", lambda *a, **k: tty, raising=False)
    assert askpass._relay_to_tty(HOSTKEY_PROMPT) == "yes"
    assert tty.shown == [HOSTKEY_PROMPT]  # la domanda completa arriva a te


def test_relay_secret_prompt_uses_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    monkeypatch.setattr(askpass, "open", lambda *a, **k: FakeTty(""), raising=False)
    monkeypatch.setattr(askpass.getpass, "getpass", lambda prompt: "typed-secret")
    assert askpass._relay_to_tty("jump@bastion's password: ") == "typed-secret"


def test_relay_without_tty_or_on_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    def no_tty(*a: object, **k: object) -> None:
        raise OSError("no tty")

    monkeypatch.setattr(askpass, "open", no_tty, raising=False)
    assert askpass._relay_to_tty("x") is None
    monkeypatch.setattr(askpass, "open", lambda *a, **k: FakeTty(""), raising=False)
    assert askpass._relay_to_tty(HOSTKEY_PROMPT) is None  # EOF sulla conferma

    def eof(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr(askpass.getpass, "getpass", eof)
    assert askpass._relay_to_tty("Password: ") is None


def test_env_outside_with_is_an_error() -> None:  # noqa: D103
    with pytest.raises(RuntimeError):
        server().env("x")


def test_bind_failure_leaves_nothing_behind(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket as socket_mod
    import tempfile

    created: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def tracking_mkdtemp(*a: object, **k: object) -> str:
        path = real_mkdtemp(*a, **k)  # type: ignore[arg-type]
        created.append(path)
        return path

    def failing_bind(self: socket_mod.socket, address: object) -> None:
        raise OSError("bind fallita")

    monkeypatch.setattr(tempfile, "mkdtemp", tracking_mkdtemp)
    monkeypatch.setattr(socket_mod.socket, "bind", failing_bind)
    with pytest.raises(HsmError, match="TMPDIR"):
        with server():
            pass
    assert created and not Path(created[0]).exists()


def test_helper_that_disconnects_does_not_break_the_server() -> None:
    import socket as socket_mod

    with server() as srv:

        srv.expect_ssh(os.getppid())
        env = srv.env("x")
        with socket_mod.socket(socket_mod.AF_UNIX) as s:
            s.connect(env[ENV_SOCKET])  # si connette e se ne va senza dire nulla
        assert _ask(env, TARGET_PROMPT) == (0, b"s3cret\n")


# --- rilievi della security review ----------------------------------------------


def test_only_helpers_of_the_main_ssh_get_the_password() -> None:
    # Con -J, ssh lancia un ssh figlio per il bastion: anche lui usa l'helper.
    # Se il bastion avesse lo stesso user@host della destinazione (altra
    # porta), il suo prompt combacerebbe: il pid del padre lo esclude.
    relayed: list[str] = []
    with server() as srv:
        srv.expect_ssh(1)  # un altro processo, non il nostro padre
        out = io.BytesIO()
        main(["hsm-askpass", TARGET_PROMPT], env=srv.env("x"), stdout=out, relay=lambda p: relayed.append(p) or None)
    assert out.getvalue() == b""
    assert relayed == [TARGET_PROMPT]


def test_without_known_ssh_pid_nothing_is_released() -> None:
    with AskpassServer(Secret(b"s3cret"), user=USER, hostname=HOST, pid_wait=0.05) as srv:
        assert _ask(srv.env("x"), TARGET_PROMPT)[1] == b""


def test_informational_prompt_is_shown_not_answered() -> None:
    shown: list[str] = []
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = {**srv.env("x"), "SSH_ASKPASS_PROMPT": "none"}
        out = io.BytesIO()
        code = main(["hsm-askpass", "Confirm user presence for key"], env=env, stdout=out,
                    relay=lambda p: "x", notify=shown.append)  # fmt: skip
    assert (code, out.getvalue()) == (0, b"")
    assert shown == ["Confirm user presence for key"]


def test_confirm_kind_never_gets_the_password() -> None:
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = {**srv.env("x"), "SSH_ASKPASS_PROMPT": "confirm"}
        out = io.BytesIO()
        main(["hsm-askpass", TARGET_PROMPT], env=env, stdout=out, relay=lambda p: None)
    assert b"s3cret" not in out.getvalue()


def test_host_key_question_is_recognized_strictly() -> None:
    assert is_host_key_question(HOSTKEY_PROMPT)
    assert is_host_key_question(
        "The authenticity of host '[127.0.0.1]:22222 ([127.0.0.1]:22222)' can't be established.\n"
        "ED25519 key fingerprint is: SHA256:x\nThis key is not known by any other names.\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    )
    # Testo keyboard-interactive scelto dal server: ssh lo prefissa con
    # "(user@host) ", quindi non può spacciarsi per la domanda di ssh.
    assert not is_host_key_question("(evil@h) OTP (yes/no) Are you sure you want to continue connecting (yes/no/[fingerprint])? ")


def test_server_text_with_yes_no_does_not_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    monkeypatch.setattr(askpass, "open", lambda *a, **k: FakeTty(""), raising=False)
    monkeypatch.setattr(askpass.getpass, "getpass", lambda prompt: "hidden")
    # Un server che include "(yes/no" non deve poter far vedere un OTP sullo schermo.
    assert askpass._relay_to_tty("(u@h) Code (yes/no): ") == "hidden"


def test_control_characters_are_stripped_before_reaching_the_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    seen: list[str] = []
    monkeypatch.setattr(askpass, "open", lambda *a, **k: FakeTty(""), raising=False)
    monkeypatch.setattr(askpass.getpass, "getpass", lambda prompt: seen.append(prompt) or "x")
    askpass._relay_to_tty("(u@h) \x1b]0;evil\x07Password\x1b[2J: ")
    assert "\x1b" not in seen[0] and "\x07" not in seen[0]


def test_failed_delivery_does_not_consume_the_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import askpass

    calls = {"n": 0}
    original = askpass.AskpassServer._deliver

    def flaky(self: AskpassServer, conn: object) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("helper sparito")
        original(self, conn)  # type: ignore[arg-type]

    monkeypatch.setattr(askpass.AskpassServer, "_deliver", flaky)
    with server() as srv:
        srv.expect_ssh(os.getppid())
        env = srv.env("x")
        _ask(env, TARGET_PROMPT)
        assert _ask(env, TARGET_PROMPT) == (0, b"s3cret\n")
        assert srv.rejected == 0
