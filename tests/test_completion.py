import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hsm.cli import build_parser
from hsm.completion import bash_script

BASHES = [b for b in ("/bin/bash", "/opt/homebrew/bin/bash") if os.path.exists(b)]
HSM = Path(sys.executable).parent / "hsm"


# --- the generated script --------------------------------------------------------


def test_script_registers_the_function() -> None:
    script = bash_script(build_parser())
    assert "complete -F _hsm hsm" in script
    assert "_hsm()" in script


def test_script_knows_every_visible_command() -> None:
    script = bash_script(build_parser())
    for command in ("add", "edit", "ls", "rm", "connect", "pw", "vault", "sync", "paths", "completion"):
        assert command in script


def test_hidden_command_is_not_offered() -> None:
    script = bash_script(build_parser())
    commands_line = next(line for line in script.splitlines() if "_hsm_commands=" in line)
    assert "__complete" not in commands_line


def test_script_is_valid_bash() -> None:
    for bash in BASHES:
        result = subprocess.run([bash, "-n"], input=bash_script(build_parser()), text=True, capture_output=True)
        assert result.returncode == 0, (bash, result.stderr)


# --- behaviour in a real bash ------------------------------------------------------


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A HOME with a small inventory, used by `hsm __complete`."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    env = {**os.environ, "HOME": str(home)}
    for args in (
        ["add", "bastion", "--ip", "b.example.com", "--tag", "infra"],
        ["add", "web01", "--ip", "10.0.0.1", "--tag", "prod", "--tag", "web"],
        ["add", "web02", "--ip", "10.0.0.2", "--tag", "prod"],
    ):
        subprocess.run([str(HSM), *args], env=env, check=True, capture_output=True)
    return home


def complete(bash: str, home: Path, line: str) -> list[str]:
    """Simulate typing `line` and pressing TAB: returns COMPREPLY."""
    words = line.split(" ")  # a trailing space means "new empty word"
    script = bash_script(build_parser())
    driver = (
        f"{script}\n"
        f"COMP_WORDS=({' '.join(repr(w) if w else repr('') for w in words)})\n"
        f"COMP_CWORD={len(words) - 1}\n"
        "_hsm\n"
        'printf "%s\\n" "${COMPREPLY[@]}"\n'
    )
    env = {**os.environ, "HOME": str(home), "PATH": f"{HSM.parent}:{os.environ['PATH']}"}
    result = subprocess.run([bash, "-c", driver], env=env, text=True, capture_output=True, check=True)
    return [w for w in result.stdout.splitlines() if w]


@pytest.fixture(params=BASHES)
def bash(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def test_completes_commands(bash: str, home: Path) -> None:
    assert set(complete(bash, home, "hsm ")) >= {"add", "connect", "pw", "paths", "completion"}
    assert complete(bash, home, "hsm con") == ["connect"]
    assert "__complete" not in complete(bash, home, "hsm ")


def test_completes_aliases_where_an_alias_is_expected(bash: str, home: Path) -> None:
    assert complete(bash, home, "hsm connect w") == ["web01", "web02"]
    assert complete(bash, home, "hsm rm ") == ["bastion", "web01", "web02"]
    assert complete(bash, home, "hsm edit b") == ["bastion"]
    assert complete(bash, home, "hsm --debug connect web0") == ["web01", "web02"]


def test_new_alias_in_add_is_not_completed(bash: str, home: Path) -> None:
    assert complete(bash, home, "hsm add ") == []


def test_only_one_alias_per_command(bash: str, home: Path) -> None:
    assert complete(bash, home, "hsm connect web01 ") == []


def test_completes_nested_actions(bash: str, home: Path) -> None:
    assert complete(bash, home, "hsm pw ") == ["get", "rm", "set"]
    assert complete(bash, home, "hsm pw get w") == ["web01", "web02"]
    assert complete(bash, home, "hsm vault ") == ["rekey"]
    assert complete(bash, home, "hsm completion ") == ["bash"]


def test_completes_options_of_the_current_command(bash: str, home: Path) -> None:
    options = complete(bash, home, "hsm add web03 --")
    assert {"--ip", "--hostname", "--password", "--dry-run", "--tag"} <= set(options)
    assert "--alias" not in options  # only for edit
    assert "--alias" in complete(bash, home, "hsm edit web01 --")


def test_option_values_are_not_mistaken_for_positionals(bash: str, home: Path) -> None:
    # "10.0.0.3" is the value of --ip, not a second positional.
    assert "--password" in complete(bash, home, "hsm add web03 --ip 10.0.0.3 --")


def test_completes_option_values(bash: str, home: Path) -> None:
    assert complete(bash, home, "hsm ls --sort ") == ["alias", "recent", "tag"]
    assert complete(bash, home, "hsm ls --tag p") == ["prod"]
    assert complete(bash, home, "hsm edit web01 --jump b") == ["bastion"]
    assert complete(bash, home, "hsm edit web01 --port ") == []  # free value: nothing to suggest


def test_identity_completes_files(bash: str, home: Path) -> None:
    (home / "id_test").write_text("")
    replies = complete(bash, home, f"hsm edit web01 --identity {home}/id_")
    assert replies == [f"{home}/id_test"]


def test_broken_inventory_completes_silently(bash: str, home: Path) -> None:
    (home / ".config" / "hsm" / "hosts.toml").chmod(0o644)  # hsm would refuse to start
    assert complete(bash, home, "hsm connect ") == []


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_completion_command_prints_the_script(home: Path) -> None:
    out = subprocess.run(
        [str(HSM), "completion", "bash"],
        env={**os.environ, "HOME": str(home)},
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out == bash_script(build_parser())
