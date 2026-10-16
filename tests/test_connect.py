import io
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from hsm import askpass
from hsm.connect import SSH, Connector, build_argv
from hsm.errors import HsmError
from hsm.inventory import Host, Inventory
from hsm.secret import Secret

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
    """Fake ssh: records the call and, if SSH_ASKPASS is set, asks the real
    helper (askpass.main) the questions as ssh would, in the given order."""

    returncode: int = 0
    raises: BaseException | None = None
    prompts: list[str] = field(default_factory=list)
    calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)
    answers: list[tuple[int, bytes]] = field(default_factory=list)
    relayed: list[str] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        env = kwargs.get("env") or {}
        if "on_spawn" in kwargs:
            # The helper runs here, in-process: its "parent" is our parent.
            kwargs["on_spawn"](os.getppid())
        if "SSH_ASKPASS" in env:
            for prompt in self.prompts:
                out = io.BytesIO()
                code = askpass.main(
                    [env["SSH_ASKPASS"], prompt], env=env, stdout=out,
                    relay=lambda p: self.relayed.append(p) or None,
                )  # fmt: skip
                self.answers.append((code, out.getvalue()))
        return subprocess.CompletedProcess(list(argv), self.returncode)


@dataclass
class Env:
    tmp_path: Path
    runner: FakeRunner = field(default_factory=FakeRunner)
    warnings: list[str] = field(default_factory=list)

    def connector(self) -> Connector:
        helper = self.tmp_path / "hsm-askpass"
        if not helper.exists():
            helper.write_text("#!/bin/sh\n")
            helper.chmod(0o700)
        return Connector(
            runner=self.runner,
            warn=self.warnings.append,
            askpass_helper=lambda: helper,
            local_user=lambda: "localme",
            resolve=lambda argv: [],
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
    # Defense in depth: even if validation changed, a hostname starting
    # with "-" would never be read as an option.
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
    # -J a,b: first a, then b, then the destination.
    assert argv[argv.index("-J") + 1] == "outer.example.com:22,inner.lan:22"


def test_jump_cycle_is_an_error(tmp_path: Path) -> None:
    a = Host(alias="a", hostname="a", jump_host="b")
    b = Host(alias="b", hostname="b", jump_host="a")
    with pytest.raises(HsmError, match="cycle"):
        build_argv(a, inventory(tmp_path, a, b))


def test_jump_alias_with_ipv6_zone_is_unsupported(tmp_path: Path) -> None:
    z = Host(alias="z", hostname="fe80::1%en0")
    h = Host(alias="x", hostname="x", jump_host="z")
    with pytest.raises(HsmError, match="zone"):
        build_argv(h, inventory(tmp_path, z, h))


# --- connect without password (the normal case) -----------------------------


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


# --- connect with password via SSH_ASKPASS ------------------------------------

BASTION_PROMPT = "jump@bastion.example.com's password: "
HOSTKEY_PROMPT = "The authenticity of host ... Are you sure you want to continue connecting (yes/no/[fingerprint])? "


def test_password_reaches_ssh_via_askpass_not_argv_nor_env(env: Env) -> None:
    env.runner.prompts = ["jump@bastion.example.com's password: "]
    code = env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"s3cret-pw"))
    assert code == 0
    argv, kwargs = env.runner.calls[0]
    assert argv[0] == SSH
    assert not any("s3cret" in a for a in argv)
    assert not any("s3cret" in v for v in kwargs["env"].values())
    assert kwargs["env"]["SSH_ASKPASS_REQUIRE"] == "force"
    assert env.runner.answers == [(0, b"s3cret-pw\n")]


def test_host_key_and_other_prompts_are_never_answered(env: Env) -> None:
    env.runner.prompts = [HOSTKEY_PROMPT, "deploy@10.0.0.1's password: "]
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    assert all(b"pw" not in out for _, out in env.runner.answers)
    assert env.runner.relayed == env.runner.prompts


def test_default_user_is_the_local_one(env: Env) -> None:
    host = Host(alias="nouser", hostname="10.0.0.5")
    env.runner.prompts = ["localme@10.0.0.5's password: "]
    env.connector().connect(host, inventory(env.tmp_path, host), password=Secret(b"pw"))
    assert env.runner.answers == [(0, b"pw\n")]


def test_rejected_password_is_reported(env: Env) -> None:
    prompt = "jump@bastion.example.com's password: "
    env.runner.prompts = [prompt, prompt]  # ssh asks again: it was wrong
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    assert env.runner.answers[1] == (1, b"")
    assert any("hsm pw set bastion" in w for w in env.warnings)


def test_password_with_jump_host_warns(env: Env) -> None:
    env.connector().connect(WEB01, inventory(env.tmp_path, BASTION, WEB01), password=Secret(b"pw"))
    assert any("jump host" in w for w in env.warnings)


@pytest.mark.parametrize("bad", [b"a\nb", b"a\rb", b"a\x00b"])
def test_password_with_line_break_is_rejected(env: Env, bad: bytes) -> None:
    with pytest.raises(HsmError, match="newline"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(bad))
    assert env.runner.calls == []


def test_oversized_password_is_rejected(env: Env) -> None:
    with pytest.raises(HsmError, match="too long"):
        env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"x" * 5000))


def test_missing_helper_is_clean_error(env: Env, tmp_path: Path) -> None:
    connector = Connector(runner=env.runner, warn=env.warnings.append, askpass_helper=lambda: tmp_path / "nope")
    with pytest.raises(HsmError, match="reinstall"):
        connector.connect(BASTION, inventory(tmp_path, BASTION), password=Secret(b"pw"))
    assert env.runner.calls == []


def test_key_auth_does_not_set_askpass(env: Env) -> None:
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION))
    assert "env" not in env.runner.calls[0][1]


def test_negative_returncode_becomes_shell_style(env: Env) -> None:
    env.runner.returncode = -9  # killed by SIGKILL
    assert env.connector().connect(BASTION, inventory(env.tmp_path, BASTION)) == 128 + 9


def test_default_helper_sits_next_to_the_interpreter() -> None:
    from hsm.connect import default_askpass_helper

    assert default_askpass_helper() == Path(sys.executable).parent / "hsm-askpass"


def test_default_runner_ignores_sigint_in_parent_only(monkeypatch: pytest.MonkeyPatch) -> None:
    import signal

    from hsm import connect

    seen: list[object] = []

    class FakePopen:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            # At fork time the parent must NOT be ignoring SIGINT yet:
            # SIG_IGN would be inherited by ssh.
            seen.append(signal.getsignal(signal.SIGINT))

        def wait(self) -> int:
            seen.append(signal.getsignal(signal.SIGINT))
            return 0

    before = signal.getsignal(signal.SIGINT)
    monkeypatch.setattr(connect.subprocess, "Popen", FakePopen)
    assert connect._run(["/usr/bin/true"]).returncode == 0
    assert seen[0] is not signal.SIG_IGN
    assert seen[1] is signal.SIG_IGN
    assert signal.getsignal(signal.SIGINT) is before


# --- jump host -------------------------------------------------------------------


def test_jump_alias_lookup_is_case_insensitive(tmp_path: Path) -> None:
    h = Host(alias="x", hostname="x", jump_host="Bastion")
    argv = build_argv(h, inventory(tmp_path, BASTION, h))
    assert argv[argv.index("-J") + 1] == "jump@bastion.example.com:2200"


def test_unknown_bare_jump_label_warns(tmp_path: Path) -> None:
    h = Host(alias="x", hostname="x", jump_host="bastoin")  # typo
    warnings: list[str] = []
    build_argv(h, inventory(tmp_path, h), warn=warnings.append)
    assert any("bastoin" in w for w in warnings)


@pytest.mark.parametrize("jump", ["10.0.0.9", "[2001:db8::1]:22", "gw.example.com"])
def test_literal_ip_or_fqdn_jump_does_not_warn(tmp_path: Path, jump: str) -> None:
    h = Host(alias="x", hostname="x", jump_host=jump)
    warnings: list[str] = []
    build_argv(h, inventory(tmp_path, h), warn=warnings.append)
    assert warnings == []


def test_effective_names_from_ssh_config_are_recognized(env: Env) -> None:
    # If ~/.ssh/config changes HostName/User, the prompt uses those values.
    connector = Connector(
        runner=env.runner, warn=env.warnings.append, askpass_helper=env.connector()._askpass_helper,
        local_user=lambda: "localme", resolve=lambda argv: [("realuser", "real.example.com")],
    )  # fmt: skip
    env.runner.prompts = ["realuser@real.example.com's password: "]
    connector.connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    assert env.runner.answers == [(0, b"pw\n")]


def test_ssh_g_resolution_parses_user_and_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import connect

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert argv[:2] == [SSH, "-G"]
        return subprocess.CompletedProcess(argv, 0, "user realuser\nhostname real.example.com\nport 22\n", "")

    monkeypatch.setattr(connect.subprocess, "run", fake_run)
    assert connect.resolve_effective_names([SSH, "-p", "22", "--", "x"]) == [("realuser", "real.example.com")]


def test_ssh_g_failure_resolves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from hsm import connect

    monkeypatch.setattr(connect.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 255, "", "err"))
    assert connect.resolve_effective_names([SSH, "--", "x"]) == []


def test_sigterm_during_password_session_cleans_up(env: Env) -> None:
    import signal

    seen: dict[str, object] = {}

    class Inspect(FakeRunner):
        def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
            seen["handler"] = signal.getsignal(signal.SIGTERM)
            seen["socket"] = kwargs["env"]["HSM_ASKPASS_SOCKET"]
            return super().__call__(argv, **kwargs)

    env.runner = Inspect()
    before = signal.getsignal(signal.SIGTERM)
    env.connector().connect(BASTION, inventory(env.tmp_path, BASTION), password=Secret(b"pw"))
    assert seen["handler"] not in (signal.SIG_DFL, before)
    assert signal.getsignal(signal.SIGTERM) is before
    assert not Path(str(seen["socket"])).exists()


def test_real_ssh_g_runs_without_network(tmp_path: Path) -> None:
    from hsm import connect

    names = connect.resolve_effective_names(build_argv(BASTION, inventory(tmp_path, BASTION)))
    assert ("jump", "bastion.example.com") in names
