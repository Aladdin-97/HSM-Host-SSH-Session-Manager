import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hsm.errors import InsecurePermissionsError
from hsm.fsutil import atomic_write
from hsm.inventory import Host
from hsm.sshconfig import BEGIN, END, SshConfigError, apply, render

NOW = datetime(2026, 10, 16, 10, 0, 0, tzinfo=UTC)
SSH = "/usr/bin/ssh"

WEB01 = Host(
    alias="web01",
    hostname="10.0.0.1",
    user="deploy",
    port=2222,
    jump_host="bastion",
    identity_file="~/.ssh/id_ed25519",
)
BASTION = Host(alias="bastion", hostname="bastion.example.com")


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    d = tmp_path / ".ssh"
    d.mkdir(mode=0o700)
    return d / "config"


def _write(path: Path, text: str) -> None:
    atomic_write(path, text.encode())


def _backups(path: Path) -> list[Path]:
    return sorted(path.parent.glob(f"{path.name}.hsm-backup-*"))


# --- render -------------------------------------------------------------------


def test_render_full_host() -> None:
    block = render([WEB01])
    assert block.startswith(BEGIN + "\n")
    assert block.endswith(END + "\n")
    assert (
        "Host web01\n"
        "    HostName 10.0.0.1\n"
        "    User deploy\n"
        "    Port 2222\n"
        "    ProxyJump bastion\n"
        '    IdentityFile "~/.ssh/id_ed25519"\n'
    ) in block


def test_render_minimal_host_writes_port_but_not_user() -> None:
    block = render([BASTION])
    assert "Host bastion\n    HostName bastion.example.com\n    Port 22\n" in block
    assert "User" not in block


def test_render_sorts_hosts() -> None:
    block = render([WEB01, BASTION])
    assert block.index("Host bastion") < block.index("Host web01")


def test_render_doubles_percent_in_hostname() -> None:
    # In HostName ssh expands %h, %%...: a single "%" makes ssh fail.
    block = render([Host(alias="ll", hostname="fe80::1%en0")])
    assert "HostName fe80::1%%en0" in block


def test_render_closes_with_host_star() -> None:
    # Lines after the block must return to global scope (see the ssh -G tests).
    lines = render([WEB01]).splitlines()
    assert lines[-2] == "Host *"


def test_render_is_deterministic() -> None:
    assert render([WEB01, BASTION]) == render([BASTION, WEB01])


def test_render_empty() -> None:
    block = render([])
    assert block.startswith(BEGIN) and block.endswith(END + "\n")
    assert "HostName" not in block


# --- apply ------------------------------------------------------------------


def test_creates_missing_file_without_backup(cfg: Path) -> None:
    result = apply(cfg, render([WEB01]), now=NOW)
    assert result.changed
    assert result.backup is None
    assert cfg.read_text() == render([WEB01])
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600


def test_inserts_block_at_top_and_keeps_rest_byte_for_byte(cfg: Path) -> None:
    original = "# my hosts\nHost old\n    HostName old.example.com\n"
    _write(cfg, original)
    apply(cfg, render([WEB01]), now=NOW)
    text = cfg.read_text()
    assert text.startswith(BEGIN)
    assert text.endswith(original)


def test_replaces_only_between_markers(cfg: Path) -> None:
    before = "Host a\n    User x\n\n"
    after = "\nHost z\n    Port 99\n"
    _write(cfg, before + render([BASTION]) + after)
    apply(cfg, render([WEB01]), now=NOW)
    assert cfg.read_text() == before + render([WEB01]) + after


def test_idempotent(cfg: Path) -> None:
    _write(cfg, "Host a\n    User x\n")
    first = apply(cfg, render([WEB01]), now=NOW)
    content = cfg.read_bytes()
    second = apply(cfg, render([WEB01]), now=NOW)
    assert first.changed and not second.changed
    assert cfg.read_bytes() == content
    assert len(_backups(cfg)) == 1


def test_backup_has_original_content_and_is_private(cfg: Path) -> None:
    original = "Host a\n    User x\n"
    _write(cfg, original)
    result = apply(cfg, render([WEB01]), now=NOW)
    assert result.backup is not None
    assert result.backup.read_text() == original
    assert stat.S_IMODE(result.backup.stat().st_mode) == 0o600
    assert "20261016T100000" in result.backup.name


def test_two_backups_in_same_second_do_not_collide(cfg: Path) -> None:
    _write(cfg, "Host a\n")
    first = apply(cfg, render([WEB01]), now=NOW)
    second = apply(cfg, render([BASTION]), now=NOW)
    assert first.backup != second.backup
    assert len(_backups(cfg)) == 2


def test_dry_run_writes_nothing_and_shows_diff(cfg: Path) -> None:
    _write(cfg, "Host a\n")
    result = apply(cfg, render([WEB01]), dry_run=True, now=NOW)
    assert result.changed
    assert cfg.read_text() == "Host a\n"
    assert _backups(cfg) == []
    assert "+Host web01" in result.diff()


def test_dry_run_on_missing_file_creates_nothing(cfg: Path) -> None:
    apply(cfg, render([WEB01]), dry_run=True, now=NOW)
    assert not cfg.exists()


def test_file_without_trailing_newline_is_preserved(cfg: Path) -> None:
    _write(cfg, "Host a\n    User x")
    apply(cfg, render([WEB01]), now=NOW)
    assert cfg.read_text().endswith("Host a\n    User x")


@pytest.mark.parametrize(
    "text",
    [
        f"{BEGIN}\nHost x\n",  # begin without end
        f"Host x\n{END}\n",  # end without begin
        f"{END}\n{BEGIN}\n",  # swapped order
        f"{BEGIN}\n{END}\n{BEGIN}\n{END}\n",  # two blocks
    ],
)
def test_malformed_markers_refuse_and_leave_file_untouched(cfg: Path, text: str) -> None:
    _write(cfg, text)
    with pytest.raises(SshConfigError, match="marker"):
        apply(cfg, render([WEB01]), now=NOW)
    assert cfg.read_text() == text
    assert _backups(cfg) == []


def test_refuses_permissive_config(cfg: Path) -> None:
    _write(cfg, "Host a\n")
    cfg.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        apply(cfg, render([WEB01]), now=NOW)


def test_refuses_symlinked_config(cfg: Path, tmp_path: Path) -> None:
    real = cfg.parent / "real_config"
    _write(real, "Host a\n")
    cfg.symlink_to(real)
    with pytest.raises(InsecurePermissionsError, match="symlink"):
        apply(cfg, render([WEB01]), now=NOW)


def test_rejects_block_without_markers(cfg: Path) -> None:
    with pytest.raises(ValueError):
        apply(cfg, "Host x\n", now=NOW)


def test_non_utf8_config_is_clean_error(cfg: Path) -> None:
    atomic_write(cfg, b"Host \xff\n")
    with pytest.raises(SshConfigError):
        apply(cfg, render([WEB01]), now=NOW)


# --- check against the real ssh (ssh -G does not connect) -------------------

needs_ssh = pytest.mark.skipif(not os.path.exists(SSH), reason="ssh not available")


def _ssh_g(cfg: Path, target: str) -> dict[str, str]:
    out = subprocess.run(
        [SSH, "-G", "-F", str(cfg), "--", target],
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


@needs_ssh
def test_ssh_sees_hsm_values(cfg: Path) -> None:
    apply(cfg, render([WEB01, BASTION]), now=NOW)
    resolved = _ssh_g(cfg, "web01")
    assert resolved["hostname"] == "10.0.0.1"
    assert resolved["user"] == "deploy"
    assert resolved["port"] == "2222"
    assert resolved["proxyjump"] == "bastion"


@needs_ssh
def test_ssh_resolves_ipv6_zone(cfg: Path) -> None:
    apply(cfg, render([Host(alias="ll", hostname="fe80::1%en0")]), now=NOW)
    assert _ssh_g(cfg, "ll")["hostname"] == "fe80::1%en0"


@needs_ssh
def test_user_global_options_stay_global(cfg: Path) -> None:
    # The case that motivated "Host *": a global option at the top of the
    # user's file must still apply to everyone after the block is inserted.
    _write(cfg, "ServerAliveInterval 42\n")
    apply(cfg, render([WEB01]), now=NOW)
    assert _ssh_g(cfg, "other.example.com")["serveraliveinterval"] == "42"
    assert _ssh_g(cfg, "web01")["serveraliveinterval"] == "42"


def test_value_guard_rejects_newlines() -> None:
    from hsm.sshconfig import _value

    with pytest.raises(SshConfigError):
        _value("x\nProxyCommand evil")


def test_gives_up_after_too_many_backups_in_one_second(cfg: Path) -> None:
    from hsm.sshconfig import _MAX_BACKUP_SUFFIX

    _write(cfg, "Host a\n")
    stamp = "20261016T100000"
    for n in range(_MAX_BACKUP_SUFFIX):
        suffix = stamp if n == 0 else f"{stamp}-{n}"
        _write(cfg.with_name(f"config.hsm-backup-{suffix}"), "x")
    with pytest.raises(SshConfigError, match="backup"):
        apply(cfg, render([WEB01]), now=NOW)
    assert cfg.read_text() == "Host a\n"


# --- security review findings ------------------------------------------------


@pytest.mark.parametrize("bad", ["a b", 'a"b', "a#b", "a\\b", "a$b", "a=b"])
def test_unquoted_value_guard(bad: str) -> None:
    from hsm.sshconfig import _value

    with pytest.raises(SshConfigError):
        _value(bad)


def test_quoted_value_guard_allows_spaces_but_not_quotes() -> None:
    from hsm.sshconfig import _value

    assert _value("~/My Keys/id", quoted=True) == "~/My Keys/id"
    with pytest.raises(SshConfigError):
        _value('a"b', quoted=True)


@pytest.mark.parametrize(
    "marker_begin, marker_end",
    [(BEGIN + " ", END), ("  " + BEGIN, END), (BEGIN, END + "\t"), (BEGIN + "\r", END + "\r")],
)
def test_markers_tolerate_surrounding_whitespace(cfg: Path, marker_begin: str, marker_end: str) -> None:
    # Editors add whitespace: an "almost equal" marker must not spawn a
    # second block while leaving the old one active.
    before, after = "Host a\n", "Host z\n"
    _write(cfg, f"{before}{marker_begin}\nHost stale\n{marker_end}\n{after}")
    apply(cfg, render([WEB01]), now=NOW)
    text = cfg.read_text()
    assert text == before + render([WEB01]) + after
    assert "stale" not in text


def test_only_newline_splits_lines_like_ssh(cfg: Path) -> None:
    # For ssh a form feed is not a line break: this line is a comment, not a marker.
    original = f"# note\x0c{BEGIN}\nHost a\n"
    _write(cfg, original)
    apply(cfg, render([WEB01]), now=NOW)
    assert cfg.read_text().endswith(original)


def test_concurrent_edit_is_detected_and_not_overwritten(
    cfg: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hsm import sshconfig

    _write(cfg, "Host a\n")
    real_backup = sshconfig._backup

    def backup_then_someone_edits(path: Path, content: bytes, now: datetime) -> Path:
        result = real_backup(path, content, now)
        _write(cfg, "Host a\nHost edited-meanwhile\n")  # an editor saves now
        return result

    monkeypatch.setattr(sshconfig, "_backup", backup_then_someone_edits)
    with pytest.raises(SshConfigError, match="modified"):
        apply(cfg, render([WEB01]), now=NOW)
    assert "edited-meanwhile" in cfg.read_text()


def test_identity_file_comes_with_identities_only() -> None:
    # Without it, ssh first tries all the agent's keys and the server may
    # disconnect with "Too many authentication failures" before reaching -i.
    assert '    IdentityFile "~/.ssh/id_ed25519"\n    IdentitiesOnly yes\n' in render([WEB01])


# --- per-folder sections ----------------------------------------------------------


def test_render_groups_hosts_by_folder_with_section_comments() -> None:
    hosts = [
        Host(alias="web02", hostname="10.0.0.2", group="prod/eu/web"),
        Host(alias="laptop", hostname="laptop.lan"),
        Host(alias="db01", hostname="10.0.0.3", group="prod/eu/db"),
        Host(alias="web01", hostname="10.0.0.1", group="prod/eu/web"),
    ]
    lines = render(hosts).splitlines()
    headers = [line for line in lines if line.startswith("# --- ")]
    assert headers == ["# --- (no folder) ---", "# --- prod/eu/db ---", "# --- prod/eu/web ---"]
    order = [line.split()[1] for line in lines if line.startswith("Host ") and line != "Host *"]
    assert order == ["laptop", "db01", "web01", "web02"]


def test_render_without_folders_has_no_section_comments() -> None:
    assert "# --- " not in render([WEB01, BASTION])


@needs_ssh
def test_ssh_still_reads_a_sectioned_block(cfg: Path) -> None:
    hosts = [Host(alias="a", hostname="10.0.0.1", group="x/y"), Host(alias="b", hostname="10.0.0.2")]
    apply(cfg, render(hosts), now=NOW)
    assert _ssh_g(cfg, "a")["hostname"] == "10.0.0.1"
    assert _ssh_g(cfg, "b")["hostname"] == "10.0.0.2"
