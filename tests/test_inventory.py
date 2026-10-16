import stat
from pathlib import Path

import pytest

from hsm.errors import InsecurePermissionsError
from hsm.fsutil import atomic_write
from hsm.inventory import (
    DEFAULT_PORT,
    Host,
    HostExistsError,
    HostNotFound,
    InvalidHostError,
    Inventory,
    InventoryError,
)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    d = tmp_path / "hsm"
    d.mkdir(mode=0o700)
    return d / "hosts.toml"


def _write(path: Path, text: str) -> None:
    atomic_write(path, text.encode())


def web01(**overrides: object) -> Host:
    fields: dict[str, object] = {
        "alias": "web01",
        "hostname": "10.0.0.1",
        "user": "deploy",
        "port": 2222,
        "tags": ("prod", "web"),
        "jump_host": "bastion",
        "identity_file": "~/.ssh/id_ed25519",
        "note": "main frontend",
    }
    fields.update(overrides)
    return Host(**fields)  # type: ignore[arg-type]


# --- Host: defaults and validation ------------------------------------------


def test_host_defaults() -> None:
    h = Host(alias="db", hostname="db.example.com")
    assert (h.user, h.port, h.tags, h.jump_host, h.identity_file, h.note) == (
        None,
        DEFAULT_PORT,
        (),
        None,
        None,
        None,
    )


@pytest.mark.parametrize("alias", ["", "web 01", "web*", "-web", "a/b", "x" * 65, "web\n"])
def test_invalid_alias(alias: str) -> None:
    with pytest.raises(InvalidHostError, match="alias"):
        web01(alias=alias)


@pytest.mark.parametrize(
    "hostname",
    [
        "-oProxyCommand=touch /tmp/pwned",  # would be read by ssh as an option
        "",
        "host name",
        "host\nProxyCommand evil",  # injection into ~/.ssh/config
        "host#comment",
        "user@host",
    ],
)
def test_invalid_hostname(hostname: str) -> None:
    with pytest.raises(InvalidHostError, match="hostname"):
        web01(hostname=hostname)


@pytest.mark.parametrize("hostname", ["example.com", "10.0.0.1", "fe80::1", "fe80::1%en0", "my_host"])
def test_valid_hostname(hostname: str) -> None:
    assert web01(hostname=hostname).hostname == hostname


@pytest.mark.parametrize("user", ["-l", "a b", "root@x", "", "a\nb"])
def test_invalid_user(user: str) -> None:
    with pytest.raises(InvalidHostError, match="user"):
        web01(user=user)


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_invalid_port(port: int) -> None:
    with pytest.raises(InvalidHostError, match="port"):
        web01(port=port)


def test_port_must_be_int_not_bool() -> None:
    with pytest.raises(InvalidHostError, match="port"):
        web01(port=True)


@pytest.mark.parametrize("tag", ["", "a b", "-x", "a,b"])
def test_invalid_tag(tag: str) -> None:
    with pytest.raises(InvalidHostError, match="tag"):
        web01(tags=(tag,))


def test_tags_are_normalized_sorted_and_unique() -> None:
    assert web01(tags=("web", "prod", "web")).tags == ("prod", "web")


@pytest.mark.parametrize("jump", ["-J", "a,b", "a b", "a\nb", ""])
def test_invalid_jump_host(jump: str) -> None:
    with pytest.raises(InvalidHostError, match="jump_host"):
        web01(jump_host=jump)


@pytest.mark.parametrize("jump", ["bastion", "admin@bastion.example.com:2222", "10.0.0.9"])
def test_valid_jump_host(jump: str) -> None:
    assert web01(jump_host=jump).jump_host == jump


@pytest.mark.parametrize("ident", ["a\nb", 'a"b', "", "-i"])
def test_invalid_identity_file(ident: str) -> None:
    with pytest.raises(InvalidHostError, match="identity_file"):
        web01(identity_file=ident)


def test_identity_file_may_contain_spaces() -> None:
    assert web01(identity_file="~/My Keys/id").identity_file == "~/My Keys/id"


def test_note_rejects_control_characters() -> None:
    with pytest.raises(InvalidHostError, match="note"):
        web01(note="line\x1b[31m")


# --- load ---------------------------------------------------------------------


def test_missing_file_is_empty_inventory(path: Path) -> None:
    assert Inventory.load(path).hosts() == []


def test_load_parses_all_fields(path: Path) -> None:
    _write(
        path,
        """
[hosts.web01]
hostname = "10.0.0.1"
user = "deploy"
port = 2222
tags = ["web", "prod"]
jump_host = "bastion"
identity_file = "~/.ssh/id_ed25519"
note = "main frontend"

[hosts.db]
hostname = "db.example.com"
""",
    )
    inv = Inventory.load(path)
    assert inv.get("web01") == web01()
    assert inv.get("db") == Host(alias="db", hostname="db.example.com")


def test_hosts_sorted_by_alias(path: Path) -> None:
    _write(path, '[hosts.zeta]\nhostname = "z"\n[hosts.alpha]\nhostname = "a"\n')
    assert [h.alias for h in Inventory.load(path).hosts()] == ["alpha", "zeta"]


def test_filter_by_tag(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.add(Host(alias="db", hostname="db", tags=("prod",)))
    inv.add(Host(alias="lab", hostname="lab"))
    assert [h.alias for h in inv.hosts(tag="prod")] == ["db", "web01"]
    assert [h.alias for h in inv.hosts(tag="web")] == ["web01"]


def test_invalid_toml_reports_location(path: Path) -> None:
    _write(path, "[hosts.web01\nhostname = 1\n")
    with pytest.raises(InventoryError, match="line 1"):
        Inventory.load(path)


def test_unknown_field_is_rejected_with_alias(path: Path) -> None:
    _write(path, '[hosts.web01]\nhostnam = "x"\n')
    with pytest.raises(InventoryError, match="web01.*hostnam"):
        Inventory.load(path)


@pytest.mark.parametrize(
    "body",
    ['hostname = "x"\nport = "22"', 'hostname = "x"\ntags = "prod"', "hostname = 5", "port = 22"],
)
def test_wrong_types_or_missing_hostname(path: Path, body: str) -> None:
    _write(path, f"[hosts.web01]\n{body}\n")
    with pytest.raises(InventoryError, match="web01"):
        Inventory.load(path)


def test_invalid_value_in_file_names_the_host(path: Path) -> None:
    _write(path, '[hosts.web01]\nhostname = "-oProxyCommand=x"\n')
    with pytest.raises(InventoryError, match="web01"):
        Inventory.load(path)


def test_hosts_must_be_a_table(path: Path) -> None:
    _write(path, 'hosts = "nope"\n')
    with pytest.raises(InventoryError, match="hosts"):
        Inventory.load(path)


def test_permissive_file_is_refused(path: Path) -> None:
    _write(path, "")
    path.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        Inventory.load(path)


# --- editing and saving ------------------------------------------------------


def test_add_save_load_roundtrip(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.save()
    assert Inventory.load(path).get("web01") == web01()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_add_duplicate_is_rejected(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    with pytest.raises(HostExistsError):
        inv.add(web01(hostname="other"))


def test_get_missing(path: Path) -> None:
    with pytest.raises(HostNotFound, match="nope"):
        Inventory.load(path).get("nope")


def test_remove(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.save()
    inv = Inventory.load(path)
    assert inv.remove("web01") == web01()
    inv.save()
    assert Inventory.load(path).hosts() == []


def test_remove_missing(path: Path) -> None:
    with pytest.raises(HostNotFound):
        Inventory.load(path).remove("nope")


def test_update_replaces_fields_and_clears_none(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.update(web01(user=None, note=None, port=DEFAULT_PORT))
    inv.save()
    text = path.read_text()
    assert "user" not in text and "note" not in text
    assert "port" not in text  # the default is not written
    assert Inventory.load(path).get("web01") == web01(user=None, note=None, port=DEFAULT_PORT)


def test_update_missing(path: Path) -> None:
    with pytest.raises(HostNotFound):
        Inventory.load(path).update(web01())


def test_edits_preserve_user_comments(path: Path) -> None:
    _write(
        path,
        """# My servers — do not hand-edit the lab block
[hosts.web01]
hostname = "10.0.0.1"  # internal IP
port = 2222

[hosts.db]
hostname = "db"
""",
    )
    inv = Inventory.load(path)
    inv.update(Host(alias="web01", hostname="10.0.0.2", port=2222))
    inv.remove("db")
    inv.add(Host(alias="lab", hostname="lab"))
    inv.save()
    text = path.read_text()
    assert "# My servers — do not hand-edit the lab block" in text
    assert '"10.0.0.2"' in text


def test_dry_run_returns_text_without_writing(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    rendered = inv.save(dry_run=True)
    assert "[hosts.web01]" in rendered
    assert not path.exists()


def test_save_creates_private_dir(tmp_path: Path) -> None:
    p = tmp_path / "new" / "hosts.toml"
    inv = Inventory.load(p)
    inv.add(web01())
    inv.save()
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700


def test_referenced_by(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="bastion", hostname="b"))
    inv.add(web01())
    inv.add(Host(alias="db", hostname="db", jump_host="bastion"))
    assert inv.referenced_by("bastion") == ["db", "web01"]
    assert inv.referenced_by("web01") == []


def test_secrets_never_stored(path: Path) -> None:
    # hosts.toml can be version-controlled: Host has no password field.
    assert not any("pass" in f for f in Host.__dataclass_fields__)


def test_non_string_tag_in_file_is_rejected(path: Path) -> None:
    _write(path, '[hosts.web01]\nhostname = "x"\ntags = ["ok", 5]\n')
    with pytest.raises(InventoryError, match="web01"):
        Inventory.load(path)


# --- security review findings ------------------------------------------------


@pytest.mark.parametrize("jump", ["none", "None", "NONE", "admin@none"])
def test_jump_none_would_silently_skip_the_bastion(jump: str) -> None:
    # `ProxyJump none` / `-J none` mean "no hop": rejected.
    with pytest.raises(InvalidHostError, match="jump_host"):
        web01(jump_host=jump)


@pytest.mark.parametrize(
    "jump",
    ["bastion:99999", "bastion:abc", "bastion:0", "::::", "[", "[::1", "a:b:c", "host%x", "a..b", "-x@b"],
)
def test_jump_host_format_is_parsed_strictly(jump: str) -> None:
    with pytest.raises(InvalidHostError, match="jump_host"):
        web01(jump_host=jump)


@pytest.mark.parametrize("jump", ["[fe80::1]:2222", "admin@[2001:db8::1]", "bastion:22"])
def test_jump_host_valid_forms(jump: str) -> None:
    assert web01(jump_host=jump).jump_host == jump


@pytest.mark.parametrize("hostname", ["a:b", ":", "[", "[::", "a..b", ".a", "a.", "a%hb", "-a.b", "a_b-"])
def test_hostname_is_ip_or_dns_name(hostname: str) -> None:
    with pytest.raises(InvalidHostError, match="hostname"):
        web01(hostname=hostname)


@pytest.mark.parametrize("hostname", ["::1", "2001:db8::1", "fe80::1%en0", "host-1.example.com", "a"])
def test_hostname_valid_forms(hostname: str) -> None:
    assert web01(hostname=hostname).hostname == hostname


@pytest.mark.parametrize("ident", ["key\\", "~/.ssh/%h", "   "])
def test_identity_file_rejects_backslash_percent_blank(ident: str) -> None:
    # Inside ssh_config quotes "\" escapes and "%x" is expanded.
    with pytest.raises(InvalidHostError, match="identity_file"):
        web01(identity_file=ident)


def test_tags_must_be_a_sequence_not_a_string() -> None:
    with pytest.raises(InvalidHostError, match="tags"):
        web01(tags="web")  # type: ignore[arg-type]


def test_alias_unique_case_insensitively(path: Path) -> None:
    # ssh matches Host patterns case-insensitively.
    inv = Inventory.load(path)
    inv.add(web01())
    with pytest.raises(HostExistsError):
        inv.add(web01(alias="WEB01"))


def test_alias_case_duplicate_in_file_is_rejected(path: Path) -> None:
    _write(path, '[hosts.web01]\nhostname = "a"\n[hosts.Web01]\nhostname = "b"\n')
    with pytest.raises(InventoryError, match="web01"):
        Inventory.load(path)


def test_alias_cannot_shadow_another_hosts_hostname(path: Path) -> None:
    # "Host 10.0.0.1" would capture anyone typing `ssh 10.0.0.1` and send
    # them to a different HostName/User/IdentityFile.
    inv = Inventory.load(path)
    inv.add(Host(alias="db", hostname="10.0.0.1"))
    with pytest.raises(InventoryError, match="10.0.0.1"):
        inv.add(Host(alias="10.0.0.1", hostname="10.0.0.2"))
    with pytest.raises(InventoryError, match="db"):
        inv.add(Host(alias="other", hostname="db"))


def test_alias_equal_to_own_hostname_is_fine(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="web01.example.com", hostname="web01.example.com"))


def test_remove_referenced_jump_host_requires_force(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="bastion", hostname="b"))
    inv.add(web01())
    with pytest.raises(InventoryError, match="web01"):
        inv.remove("bastion")
    assert inv.remove("bastion", force=True).alias == "bastion"


@pytest.mark.parametrize("jump", ["[::1]x", "[::1]:", 5])
def test_jump_host_odd_shapes(jump: object) -> None:
    with pytest.raises(InvalidHostError, match="jump_host"):
        web01(jump_host=jump)


def test_host_entry_must_be_a_table(path: Path) -> None:
    _write(path, '[hosts]\nweb01 = "10.0.0.1"\n')
    with pytest.raises(InventoryError, match="web01.*table"):
        Inventory.load(path)


@pytest.mark.parametrize(
    "hostname", ["fe80::1%a b", 'fe80::1%"x', "fe80::1%a#b", "fe80::1%a\\b", "fe80::1%${HOME}", "fe80::1%-o"]
)
def test_ipv6_zone_is_restricted(hostname: str) -> None:
    # ipaddress accepts any zone; in ssh_config a space or a quote
    # there would make the whole file invalid.
    with pytest.raises(InvalidHostError, match="hostname"):
        web01(hostname=hostname)


def test_identity_file_rejects_dollar() -> None:
    # OpenSSH expands ${VAR} in IdentityFile.
    with pytest.raises(InvalidHostError, match="identity_file"):
        web01(identity_file="${HOME}/.ssh/id")


def test_identity_file_must_be_absolute_or_home_relative() -> None:
    # A relative path would depend on the current directory.
    with pytest.raises(InvalidHostError, match="identity_file"):
        web01(identity_file="keys/id_ed25519")
    assert web01(identity_file="/etc/ssh/id").identity_file == "/etc/ssh/id"


# --- auth field -----------------------------------------------------------------


def test_auth_defaults_to_key_and_is_not_written(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="a", hostname="a"))
    assert inv.get("a").auth == "key"
    assert "auth" not in inv.save(dry_run=True)


def test_auth_password_roundtrip(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="a", hostname="a", auth="password"))
    inv.save()
    assert 'auth = "password"' in path.read_text()
    assert Inventory.load(path).get("a").auth == "password"


@pytest.mark.parametrize("bad", ["", "Password", "keyboard", "none"])
def test_auth_rejects_unknown_values(bad: str) -> None:
    with pytest.raises(InvalidHostError, match="auth"):
        web01(auth=bad)


# --- rename -----------------------------------------------------------------------


def test_rename_moves_host_and_keeps_fields(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.rename("web01", "web02")
    with pytest.raises(HostNotFound):
        inv.get("web01")
    assert inv.get("web02") == web01(alias="web02")
    inv.save()
    assert Inventory.load(path).get("web02") == web01(alias="web02")


def test_rename_updates_jump_host_of_other_hosts(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(Host(alias="bastion", hostname="b"))
    inv.add(web01())  # jump_host = "bastion"
    inv.add(Host(alias="db", hostname="db", jump_host="Bastion"))  # ssh is case-insensitive
    assert inv.rename("bastion", "gw") == ["db", "web01"]
    assert inv.get("web01").jump_host == "gw"
    assert inv.get("db").jump_host == "gw"


def test_rename_conflicts(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.add(Host(alias="db", hostname="db.example.com"))
    with pytest.raises(HostExistsError):
        inv.rename("web01", "DB")
    with pytest.raises(InventoryError, match="db.example.com"):
        inv.rename("web01", "db.example.com")  # another host's hostname
    with pytest.raises(InvalidHostError, match="alias"):
        inv.rename("web01", "bad alias")
    with pytest.raises(HostNotFound):
        inv.rename("nope", "x")
    assert inv.get("web01") == web01()  # nothing changed


def test_rename_case_only(path: Path) -> None:
    inv = Inventory.load(path)
    inv.add(web01())
    inv.rename("web01", "Web01")
    assert inv.get("Web01").hostname == "10.0.0.1"


def test_rename_preserves_comments(path: Path) -> None:
    _write(
        path,
        """# My servers
[hosts.web01]
hostname = "10.0.0.1"  # internal IP
port = 2222
""",
    )
    inv = Inventory.load(path)
    inv.rename("web01", "web02")
    inv.save()
    text = path.read_text()
    assert "# My servers" in text and "# internal IP" in text
    assert "[hosts.web02]" in text and "web01" not in text
