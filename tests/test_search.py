from datetime import UTC, datetime

import pytest

from hsm.inventory import Host
from hsm.search import SearchError, parse, search

WEB01 = Host(
    alias="web01",
    hostname="10.1.0.1",
    user="deploy",
    group="prod/eu/web",
    tags=("nginx", "prod"),
    note="main frontend",
    jump_host="bastion-eu",
)
WEB02 = Host(alias="web02", hostname="10.1.0.2", user="deploy", group="prod/eu/web", tags=("nginx",))
DB = Host(alias="db-eu", hostname="db.eu.example.com", user="postgres", group="prod/eu/db", auth="password")
OLD = Host(alias="web-old", hostname="10.9.0.1", group="prod/europe-old", tags=("legacy",))
LAB = Host(alias="lab", hostname="fe80::1", user="admin")
HOSTS = [WEB01, WEB02, DB, OLD, LAB]


def aliases(query: str, **kwargs: object) -> list[str]:
    return [h.alias for h in search(HOSTS, query, **kwargs)]  # type: ignore[arg-type]


# --- free text ----------------------------------------------------------------------


def test_empty_query_returns_everything_alphabetically() -> None:
    assert aliases("") == ["db-eu", "lab", "web-old", "web01", "web02"]


@pytest.mark.parametrize(
    "term, expected",
    [
        ("10.1.0", ["web01", "web02"]),  # hostname
        ("postgres", ["db-eu"]),  # user
        ("europe", ["web-old"]),  # folder
        ("legacy", ["web-old"]),  # tag
        ("frontend", ["web01"]),  # note
        ("bastion", ["web01"]),  # jump host
        ("WEB0", ["web01", "web02"]),  # case-insensitive
    ],
)
def test_term_matches_any_field(term: str, expected: list[str]) -> None:
    assert aliases(term) == expected


def test_every_term_must_match() -> None:
    assert aliases("prod nginx 02") == ["web02"]
    assert aliases("prod lab") == []


def test_quoted_phrase_keeps_spaces() -> None:
    assert aliases('"main frontend"') == ["web01"]
    assert aliases('"frontend main"') == []


def test_ipv6_and_unknown_prefixes_are_free_text() -> None:
    # "fe80" is not a field name: the colon is part of the text.
    assert aliases("fe80::1") == ["lab"]
    assert aliases("nofield:x") == []


# --- field filters --------------------------------------------------------------------


def test_tag_is_exact() -> None:
    assert aliases("tag:nginx") == ["web01", "web02"]
    assert aliases("tag:ngin") == []
    assert aliases("tag:NGINX") == ["web01", "web02"]


def test_group_is_segment_aware() -> None:
    assert aliases("group:prod/eu") == ["db-eu", "web01", "web02"]  # not prod/europe-old
    assert aliases("group:prod") == ["db-eu", "web-old", "web01", "web02"]
    assert aliases("group:/prod/eu/") == ["db-eu", "web01", "web02"]  # normalized


def test_group_root() -> None:
    assert aliases("group:/") == ["lab"]


def test_user_and_auth_are_exact() -> None:
    assert aliases("user:deploy") == ["web01", "web02"]
    assert aliases("user:dep") == []
    assert aliases("auth:password") == ["db-eu"]
    assert aliases("auth:key prod") == ["web-old", "web01", "web02"]


def test_substring_fields() -> None:
    assert aliases("host:10.1.") == ["web01", "web02"]
    assert aliases("alias:old") == ["web-old"]
    assert aliases("jump:bastion") == ["web01"]


def test_negation() -> None:
    assert aliases("prod -tag:legacy") == ["db-eu", "web01", "web02"]
    assert aliases("web -old") == ["web01", "web02"]


def test_filters_and_terms_combine() -> None:
    assert aliases("group:prod/eu web 01") == ["web01"]


# --- ranking ---------------------------------------------------------------------------


def test_exact_alias_comes_first_then_prefix_then_the_rest() -> None:
    hosts = [
        Host(alias="xweb", hostname="a"),
        Host(alias="web", hostname="b"),
        Host(alias="webby", hostname="c"),
    ]
    assert [h.alias for h in search(hosts, "web")] == ["web", "webby", "xweb"]


def test_recent_hosts_come_before_others() -> None:
    last_used = {"web02": datetime(2026, 10, 17, tzinfo=UTC), "web01": datetime(2026, 10, 1, tzinfo=UTC)}
    assert aliases("nginx", last_used=last_used) == ["web02", "web01"]
    assert aliases("", last_used=last_used)[:2] == ["web02", "web01"]


def test_exact_alias_beats_recency() -> None:
    last_used = {"web02": datetime(2026, 10, 17, tzinfo=UTC)}
    assert aliases("web01", last_used=last_used)[0] == "web01"


# --- errors ------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["tag:", "auth:maybe", '"unclosed', 'group:"bad name"'])
def test_invalid_queries_are_clean_errors(bad: str) -> None:
    with pytest.raises(SearchError):
        parse(bad)


def test_search_error_is_an_hsm_error() -> None:
    from hsm.errors import HsmError

    assert issubclass(SearchError, HsmError)
