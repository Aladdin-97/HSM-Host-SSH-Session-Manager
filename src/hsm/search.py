"""Search over the inventory, for `hsm ls`, the picker and fzf's initial query.

Syntax (words are separated by spaces; quote a phrase that contains spaces):

    prod web 03         every word must appear somewhere: alias, hostname,
                        user, folder, tags, note or jump host (case-insensitive)
    tag:nginx           has exactly this tag
    group:prod/eu       is in this folder or below it ("prod/eu" does not
                        include "prod/europe": the match is per segment)
    group:/             is at the root (no folder)
    user:admin          exactly this user
    auth:password       authentication method ("key" or "password")
    host:10.1.          substring of the hostname
    alias:web           substring of the alias
    jump:bastion        substring of the jump host
    -tag:legacy  -test  a leading "-" excludes
    "main frontend"     a phrase, e.g. from a note

A prefix counts as a field only if it is one of the names above: "fe80::1"
stays a free-text search for an IPv6 address.

Ranking: an alias equal to a searched word first, then aliases starting with
it, then aliases containing it; within each tier the most recently used
hosts first, then alphabetical. With hundreds of hosts the one you want is
usually at the top after a word or two.
"""

import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from hsm.errors import HsmError
from hsm.inventory import AUTH_METHODS, Host, normalize_group

FIELDS = ("alias", "auth", "group", "host", "jump", "tag", "user")

_ROOT = "/"  # value of group:/ after parsing: hosts without a folder


class SearchError(HsmError):
    """The search text cannot be parsed."""


@dataclass(frozen=True)
class Filter:
    field: str
    value: str
    negated: bool = False


@dataclass(frozen=True)
class Query:
    """A parsed search: free words (casefolded) and field filters."""

    terms: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()
    filters: tuple[Filter, ...] = ()


def parse(text: str) -> Query:
    """Turn the search text into a Query. Raises SearchError if it is invalid."""
    try:
        # shlex: quotes group a phrase with spaces, like in a shell.
        tokens = shlex.split(text)
    except ValueError:
        raise SearchError("Unbalanced quotes in the search.") from None
    terms: list[str] = []
    excluded: list[str] = []
    filters: list[Filter] = []
    for token in tokens:
        negated = token.startswith("-") and len(token) > 1
        body = token[1:] if negated else token
        name, colon, value = body.partition(":")
        field = name.casefold()
        if colon and field in FIELDS:
            filters.append(Filter(field, _filter_value(field, value), negated))
        elif body:
            (excluded if negated else terms).append(body.casefold())
    return Query(tuple(terms), tuple(excluded), tuple(filters))


def _filter_value(field: str, value: str) -> str:
    if not value:
        raise SearchError(f"Empty value for {field}: in the search.")
    if field == "auth":
        if value.casefold() not in AUTH_METHODS:
            raise SearchError(f"auth: must be one of {', '.join(AUTH_METHODS)}.")
        return value.casefold()
    if field == "group":
        try:
            folder = normalize_group(value)
        except ValueError:
            raise SearchError(f"Invalid folder in the search: {value!r}") from None
        return _ROOT if folder is None else folder
    return value.casefold()


def matches(host: Host, query: Query) -> bool:
    """True if `host` satisfies every word and filter of `query`."""
    haystack = _haystack(host)
    if not all(term in haystack for term in query.terms):
        return False
    if any(term in haystack for term in query.excluded):
        return False
    return all(_check(host, f) != f.negated for f in query.filters)


def search(
    hosts: Iterable[Host],
    text: str,
    *,
    last_used: Mapping[str, datetime] | None = None,
) -> list[Host]:
    """The hosts matching `text`, best first (see the module docstring)."""
    query = parse(text)
    used = last_used or {}

    def rank(host: Host) -> tuple[int, float, str]:
        when = used.get(host.alias)
        # Negative timestamp: more recent sorts first; never used goes last.
        recency = -when.timestamp() if when is not None else float("inf")
        return (_alias_tier(host.alias.casefold(), query.terms), recency, host.alias)

    return sorted((h for h in hosts if matches(h, query)), key=rank)


def _alias_tier(alias: str, terms: tuple[str, ...]) -> int:
    best = 3
    for term in terms:
        if alias == term:
            return 0
        if alias.startswith(term):
            best = min(best, 1)
        elif term in alias:
            best = min(best, 2)
    return best


def _haystack(host: Host) -> str:
    # Joined with newlines so a word cannot match across two fields.
    parts = [host.alias, host.hostname, host.user, host.group, host.note, host.jump_host, *host.tags]
    return "\n".join(p for p in parts if p).casefold()


def _check(host: Host, f: Filter) -> bool:
    match f.field:
        case "tag":
            return f.value in {t.casefold() for t in host.tags}
        case "group":
            if f.value == _ROOT:
                return host.group is None
            return host.group is not None and (host.group == f.value or host.group.startswith(f.value + "/"))
        case "user":
            return (host.user or "").casefold() == f.value
        case "auth":
            return host.auth == f.value
        case "host":
            return f.value in host.hostname.casefold()
        case "alias":
            return f.value in host.alias.casefold()
        case "jump":
            return f.value in (host.jump_host or "").casefold()
    raise AssertionError(f"unknown field {f.field}")  # pragma: no cover - FIELDS is closed
