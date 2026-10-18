"""Host inventory in ~/.config/hsm/hosts.toml (plaintext, no secrets).

Format, one table per host:

    [hosts.web01]
    hostname = "10.0.0.1"
    user = "deploy"
    port = 2222                      # omitted if 22
    tags = ["prod", "web"]
    jump_host = "bastion"            # hsm alias or [user@]host[:port]
    identity_file = "~/.ssh/id_ed25519"
    note = "main frontend"
    auth = "password"                # omitted if "key" (the default)

`auth` only says HOW to authenticate, never with what: `hsm connect` uses it
to know whether to open the vault, so it doesn't ask for Touch ID for hosts
that use an SSH key. It is set by `hsm pw set` / `hsm pw rm`.

Choices that matter:

- Strict validation of every field. hostname, user and jump_host end up
  in ssh arguments and in ~/.ssh/config: a hostname like
  "-oProxyCommand=..." would be read by ssh as an option and run a
  command; a newline in a value would add arbitrary lines to
  ssh_config; `jump_host = "none"` would silently disable the bastion.
  That is why hosts are parsed (IP address via `ipaddress`, or DNS name
  label by label) instead of just being filtered by character. The check
  lives in Host, so it applies both to values read from the file and to
  those passed on the command line.

- Aliases are unique case-insensitively (as ssh does with Host patterns)
  and cannot match another host's hostname: "Host 10.0.0.1" would capture
  anyone typing `ssh 10.0.0.1`.

- tomlkit instead of tomllib: tomllib can only read, and rewriting the file
  with an arbitrary serializer would erase hand-written comments.
  tomlkit edits the document in place and preserves everything else.
"""

import dataclasses
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.toml_document import TOMLDocument

from hsm.errors import HsmError
from hsm.fsutil import atomic_write, ensure_private_dir, read_private

DEFAULT_PORT = 22
AUTH_METHODS = ("key", "password")

# Alias: ends up in the "Host <alias>" line of ssh_config, where spaces and
# wildcards (*, ?, !) would change its meaning.
_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# A DNS label: no "-" at the start or end. "_" is allowed because it
# appears in real internal names, even though it isn't standard.
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,31}")
# A folder is a path of segments like "prod/eu/web". Each segment follows
# almost the alias rules: no leading "-", so "." and ".." are impossible too,
# and no spaces or other characters that would need quoting in a shell or in
# fzf. The depth limit only guards against absurd values.
_GROUP_SEGMENT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
MAX_GROUP_DEPTH = 16
_PORT_RE = re.compile(r"[0-9]{1,5}")
# IPv6 zone (an interface name, e.g. en0). ipaddress accepts any;
# we only accept characters that ssh_config reads without surprises.
_ZONE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")


def is_valid_alias(alias: object) -> bool:
    """True if `alias` can be used as an hsm alias (and as Host in ssh_config)."""
    return isinstance(alias, str) and _ALIAS_RE.fullmatch(alias) is not None


class InventoryError(HsmError):
    """Invalid hosts.toml or impossible operation on the inventory."""


class InvalidHostError(InventoryError):
    """A host field does not satisfy the validation rules."""


class HostNotFound(InventoryError):
    """No host with this alias."""


class HostExistsError(InventoryError):
    """A host with this alias already exists."""


@dataclass(frozen=True)
class Host:
    """An inventory host. Validation happens at construction."""

    alias: str
    hostname: str
    user: str | None = None
    port: int = DEFAULT_PORT
    tags: tuple[str, ...] = ()
    group: str | None = None
    jump_host: str | None = None
    identity_file: str | None = None
    note: str | None = None
    auth: str = "key"

    def __post_init__(self) -> None:
        if not is_valid_alias(self.alias):
            raise InvalidHostError(
                f"invalid alias: {self.alias!r} (letters, digits, '.', '_', '-'; "
                "must start with a letter or digit)"
            )
        # The IPv6 zone (fe80::1%en0) is allowed only here; whoever writes
        # ssh_config must double the "%", which is expanded there.
        if not isinstance(self.hostname, str) or not (
            _is_ip(self.hostname, allow_zone=True) or _is_dns_name(self.hostname)
        ):
            self._fail("hostname", self.hostname)
        if self.user is not None:
            self._check("user", _USER_RE, self.user)
        # bool is a subclass of int: True would mean port 1.
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            self._fail("port", self.port)
        # A string is iterable: tuple("web") would give ("w", "e", "b").
        if not isinstance(self.tags, (list, tuple)):
            self._fail("tags", self.tags)
        tags = tuple(self.tags)
        for tag in tags:
            self._check("tag", _TAG_RE, tag)
        # Sorted and deduplicated: stable comparisons and output.
        object.__setattr__(self, "tags", tuple(sorted(set(tags))))
        if self.jump_host is not None and not _is_jump(self.jump_host):
            self._fail("jump_host", self.jump_host)
        if self.identity_file is not None:
            ident = self.identity_file
            if (
                not isinstance(ident, str)
                or not ident
                or not ident.strip()
                # Absolute or relative to home: a relative path would
                # depend on the directory hsm is launched from.
                or not ident.startswith(("/", "~"))
                # In ssh_config we write it in quotes: there '"' closes,
                # "\" escapes, "%x" and "${VAR}" are expanded.
                or any(c in ident for c in '"\\%$')
                or not ident.isprintable()
            ):
                self._fail("identity_file", ident)
        if self.note is not None and (not isinstance(self.note, str) or not self.note.isprintable()):
            # isprintable() rules out newlines and terminal escape sequences.
            self._fail("note", self.note)
        try:
            object.__setattr__(self, "group", normalize_group(self.group))
        except ValueError:
            self._fail("group", self.group)
        if self.auth not in AUTH_METHODS:
            self._fail("auth", self.auth)

    def _check(self, field: str, pattern: re.Pattern[str], value: object) -> None:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            self._fail(field, value)

    def _fail(self, field: str, value: object) -> None:
        raise InvalidHostError(f"Host {self.alias}: invalid {field}: {value!r}")


def _is_ip(value: str, *, allow_zone: bool) -> bool:
    if "%" in value:
        _, _, zone = value.partition("%")
        if not allow_zone or not _ZONE_RE.fullmatch(zone):
            return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_dns_name(value: str) -> bool:
    if not 0 < len(value) <= 253:
        return False
    return all(_DNS_LABEL_RE.fullmatch(label) for label in value.split("."))


def _is_jump(value: object) -> bool:
    """Validate a single `[user@]host[:port]` hop, with IPv6 inside [ ]."""
    if not isinstance(value, str):
        return False
    user, at, rest = value.partition("@")
    if not at:
        rest = value
    elif not _USER_RE.fullmatch(user):
        return False
    port: str | None
    if rest.startswith("["):
        host, bracket, tail = rest[1:].partition("]")
        if not bracket or not _is_ip(host, allow_zone=False) or ":" not in host:
            return False
        if tail == "":
            port = None
        elif tail.startswith(":"):
            port = tail[1:]
        else:
            return False
    else:
        host, colon, port_text = rest.partition(":")
        port = port_text if colon else None
        # An unbracketed IPv6 is ambiguous with ":port": it must be written inside [ ].
        if not (_is_ip(host, allow_zone=False) and ":" not in host) and not _is_dns_name(host):
            return False
        # "none" has a special meaning for ProxyJump/-J: no hop.
        if host.lower() == "none":
            return False
    if port is not None and not (_PORT_RE.fullmatch(port) and 1 <= int(port) <= 65535):
        return False
    return True


_FIELDS = tuple(f.name for f in fields(Host))
# Expected type in hosts.toml for each field, for clear error messages.
_FILE_TYPES: dict[str, tuple[type, str]] = {
    "hostname": (str, "a string"),
    "user": (str, "a string"),
    "port": (int, "an integer"),
    "tags": (list, "a list of strings"),
    "jump_host": (str, "a string"),
    "identity_file": (str, "a string"),
    "note": (str, "a string"),
    "auth": (str, '"key" or "password"'),
    "group": (str, 'a folder path like "prod/eu"'),
}


class Inventory:
    """The inventory loaded from a file, editable and saveable."""

    def __init__(self, path: Path, doc: TOMLDocument, hosts: dict[str, Host]) -> None:
        self._path = path
        self._doc = doc
        self._hosts = hosts

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        """Read and validate `path`. If the file doesn't exist, empty inventory."""
        try:
            raw = read_private(path)
        except FileNotFoundError:
            return cls(path, tomlkit.document(), {})
        try:
            doc = tomlkit.parse(raw.decode("utf-8"))
        except (TOMLKitError, UnicodeDecodeError) as exc:
            raise InventoryError(f"{path}: invalid TOML ({exc})") from None
        section = doc.get("hosts")
        if section is None:
            return cls(path, doc, {})
        if not isinstance(section, Mapping):
            raise InventoryError(f"{path}: 'hosts' must be a table")
        hosts: dict[str, Host] = {}
        for alias, data in section.unwrap().items():
            host = _host_from_file(str(alias), data)
            _check_conflicts(host, hosts, replacing=None)
            hosts[host.alias] = host
        return cls(path, doc, hosts)

    def hosts(self, tag: str | None = None) -> list[Host]:
        """Hosts sorted by alias, optionally filtered by tag."""
        return [
            h for _, h in sorted(self._hosts.items()) if tag is None or tag in h.tags
        ]

    def get(self, alias: str) -> Host:
        try:
            return self._hosts[alias]
        except KeyError:
            raise HostNotFound(f"No host with alias {alias!r}.") from None

    def add(self, host: Host) -> None:
        _check_conflicts(host, self._hosts, replacing=None)
        if "hosts" not in self._doc:
            # Super-table: only [hosts.<alias>] appears in the file, without
            # an empty [hosts] above it.
            self._doc["hosts"] = tomlkit.table(is_super_table=True)
        table = tomlkit.table()
        for key, value in _to_file(host).items():
            if value is not None:
                table[key] = value
        self._doc["hosts"][host.alias] = table  # type: ignore[index]
        self._hosts[host.alias] = host

    def update(self, host: Host) -> None:
        """Replace the fields of an existing host, preserving comments."""
        self.get(host.alias)
        _check_conflicts(host, self._hosts, replacing=host.alias)
        table = self._doc["hosts"][host.alias]  # type: ignore[index]
        # Edit key by key instead of replacing the table: this way comments
        # and the order of untouched lines stay where they are.
        for key, value in _to_file(host).items():
            if value is None:
                if key in table:
                    del table[key]
            elif key not in table or table[key] != value:
                table[key] = value
        self._hosts[host.alias] = host

    def rename(self, old: str, new: str) -> list[str]:
        """Change a host's alias. Return the hosts whose jump_host was updated.

        Hosts that used `old` as jump_host are updated: leaving them as they
        are would make them resolve via DNS, possibly to another machine.
        The comparison ignores case, as jump resolution does.
        All checks happen before anything is modified.
        """
        host = self.get(old)
        renamed = dataclasses.replace(host, alias=new)  # revalidates the new alias
        _check_conflicts(renamed, self._hosts, replacing=old)
        dependents = sorted(
            h.alias
            for h in self._hosts.values()
            if h.alias != old and h.jump_host is not None and h.jump_host.casefold() == old.casefold()
        )
        # The table is moved, not recreated: the comments inside it are
        # kept. In the file it ends up at the bottom of the [hosts] section.
        section = self._doc["hosts"]
        table = section[old]  # type: ignore[index]
        del section[old]  # type: ignore[union-attr]
        section[new] = table  # type: ignore[index]
        del self._hosts[old]
        self._hosts[new] = renamed
        for alias in dependents:
            self.update(dataclasses.replace(self._hosts[alias], jump_host=new))
        return dependents

    def remove(self, alias: str, *, force: bool = False) -> Host:
        """Remove a host. If others use it as jump_host, `force` is required.

        Without the "Host <alias>" block in ssh_config, an orphaned jump_host
        would be resolved via DNS: possibly to a different machine.
        """
        host = self.get(alias)
        users = self.referenced_by(alias)
        if users and not force:
            raise InventoryError(
                f"{alias} is the jump_host of: {', '.join(users)}. "
                "Update those hosts or force the removal."
            )
        del self._doc["hosts"][alias]  # type: ignore[union-attr]
        del self._hosts[alias]
        return host

    def groups(self) -> dict[str, int]:
        """Every folder, with how many hosts it contains (sub-folders included).

        A host in "prod/eu/web" counts for "prod", "prod/eu" and "prod/eu/web":
        that is what a tree view shows next to each folder.
        """
        counts: dict[str, int] = {}
        for host in self._hosts.values():
            if host.group is None:
                continue
            parts = host.group.split("/")
            for depth in range(1, len(parts) + 1):
                prefix = "/".join(parts[:depth])
                counts[prefix] = counts.get(prefix, 0) + 1
        return dict(sorted(counts.items()))

    def move_group(self, old: str, new: str) -> list[str]:
        """Move a folder (and its sub-folders) under a new path; "" means the root.

        Returns the aliases of the moved hosts. Every new Host is built (and
        so validated) before anything changes: an invalid target leaves the
        inventory untouched instead of half-moved.
        """
        source = _group_or_error(old)
        target = _group_or_error(new)
        if source is None:
            raise InventoryError("Cannot move the root: name a folder.")
        if target == source:
            return []
        if target is not None and target.startswith(source + "/"):
            raise InventoryError(f"Cannot move {source!r} inside itself ({target!r}).")
        moved: list[Host] = []
        for host in self._hosts.values():
            # Exact folder or a real sub-folder: "prod/eu" must not catch "prod/europe".
            if host.group != source and not (host.group or "").startswith(source + "/"):
                continue
            rest = host.group[len(source) :].lstrip("/") if host.group else ""
            new_group = "/".join(part for part in (target, rest) if part) or None
            moved.append(dataclasses.replace(host, group=new_group))
        if not moved:
            raise InventoryError(f"No folder {old!r}.")
        for host in moved:
            self.update(host)
        return sorted(h.alias for h in moved)

    def referenced_by(self, alias: str) -> list[str]:
        """Aliases of the hosts that use `alias` as jump_host."""
        return sorted(h.alias for h in self._hosts.values() if h.jump_host == alias)

    def save(self, *, dry_run: bool = False) -> str:
        """Write the file (0600, atomic) and return the text produced.

        With `dry_run` nothing is written: the caller can show the text.
        """
        text = tomlkit.dumps(self._doc)
        if not dry_run:
            ensure_private_dir(self._path.parent)
            atomic_write(self._path, text.encode("utf-8"))
        return text


def _group_or_error(value: str) -> str | None:
    try:
        return normalize_group(value)
    except ValueError:
        raise InvalidHostError(f"invalid group: {value!r}") from None


def normalize_group(value: object) -> str | None:
    """A folder path in canonical form: no surrounding "/", None for the root.

    Raises ValueError if the value is not a valid path.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("group must be a string")
    path = value.strip("/")
    if not path:
        return None
    parts = path.split("/")
    if len(parts) > MAX_GROUP_DEPTH or not all(_GROUP_SEGMENT_RE.fullmatch(p) for p in parts):
        raise ValueError(f"invalid group: {value!r}")
    return path


def _check_conflicts(host: Host, hosts: dict[str, Host], *, replacing: str | None) -> None:
    """Aliases unique case-insensitively, and never equal to another host's hostname."""
    alias = host.alias.casefold()
    for other in hosts.values():
        if other.alias == replacing:
            continue
        if other.alias.casefold() == alias:
            raise HostExistsError(
                f"A host with alias {other.alias!r} already exists "
                f"(ssh is case-insensitive: {host.alias!r} would collide)."
            )
        if other.hostname.casefold() == alias:
            raise InventoryError(
                f"Alias {host.alias!r} matches the hostname of {other.alias!r}: "
                f"`ssh {other.hostname}` would end up on {host.hostname}."
            )
        if other.alias.casefold() == host.hostname.casefold():
            raise InventoryError(
                f"Hostname {host.hostname!r} matches the alias {other.alias!r}: "
                "ssh would apply that host's settings."
            )


def _host_from_file(alias: str, data: Any) -> Host:
    if not isinstance(data, Mapping):
        raise InventoryError(f"Host {alias}: must be a table")
    unknown = sorted(set(data) - set(_FIELDS))
    if unknown:
        raise InventoryError(f"Host {alias}: unknown field {', '.join(unknown)}")
    if "hostname" not in data:
        raise InventoryError(f"Host {alias}: missing hostname")
    for key, value in data.items():
        expected, description = _FILE_TYPES[key]
        if not isinstance(value, expected) or isinstance(value, bool):
            raise InventoryError(f"Host {alias}: {key} must be {description}")
    try:
        return Host(alias=alias, **{k: _from_toml(k, v) for k, v in data.items()})
    except InvalidHostError as exc:
        raise InventoryError(str(exc)) from None


def _from_toml(key: str, value: Any) -> Any:
    return tuple(value) if key == "tags" else value


def _to_file(host: Host) -> dict[str, Any]:
    """The fields to write; None means "key absent from the file"."""
    return {
        "hostname": host.hostname,
        "user": host.user,
        "port": host.port if host.port != DEFAULT_PORT else None,
        "group": host.group,
        "tags": list(host.tags) if host.tags else None,
        "jump_host": host.jump_host,
        "identity_file": host.identity_file,
        "note": host.note,
        "auth": host.auth if host.auth != "key" else None,
    }
