import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from hsm.errors import InsecurePermissionsError
from hsm.fsutil import atomic_write
from hsm.state import State, StateError

T0 = datetime(2026, 10, 16, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    d = tmp_path / "hsm"
    d.mkdir(mode=0o700)
    return d / "state.toml"


def _write(path: Path, text: str) -> None:
    atomic_write(path, text.encode())


def test_missing_file_is_empty(path: Path) -> None:
    assert State.load(path).last_used("web01") is None


def test_touch_save_load_roundtrip(path: Path) -> None:
    s = State.load(path)
    s.touch("web01", T0)
    s.save()
    assert State.load(path).last_used("web01") == T0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_touch_defaults_to_now_utc(path: Path) -> None:
    s = State.load(path)
    s.touch("web01")
    used = s.last_used("web01")
    assert used is not None and used.tzinfo is not None
    assert abs(datetime.now(UTC) - used) < timedelta(seconds=5)


def test_touch_truncates_to_seconds_and_normalizes_to_utc(path: Path) -> None:
    rome = timezone(timedelta(hours=2))
    s = State.load(path)
    s.touch("web01", datetime(2026, 10, 16, 12, 0, 0, 123456, tzinfo=rome))
    s.save()
    assert State.load(path).last_used("web01") == T0


def test_touch_rejects_naive_datetime(path: Path) -> None:
    # Without a timezone we couldn't compare uses made in different timezones.
    with pytest.raises(ValueError):
        State.load(path).touch("web01", datetime(2026, 10, 16, 10, 0, 0))


def test_touch_rejects_invalid_alias(path: Path) -> None:
    with pytest.raises(ValueError):
        State.load(path).touch("bad alias", T0)


def test_forget(path: Path) -> None:
    s = State.load(path)
    s.touch("web01", T0)
    s.forget("web01")
    s.forget("never-seen")  # idempotent
    assert s.last_used("web01") is None


def test_prune_keeps_only_known_aliases(path: Path) -> None:
    s = State.load(path)
    s.touch("web01", T0)
    s.touch("gone", T0)
    s.prune({"web01", "db"})
    assert s.last_used("web01") == T0
    assert s.last_used("gone") is None


def test_recent_orders_by_last_use_then_alias(path: Path) -> None:
    s = State.load(path)
    s.touch("old", T0)
    s.touch("new", T0 + timedelta(hours=1))
    assert s.recent(["zeta", "old", "alpha", "new"]) == ["new", "old", "alpha", "zeta"]


def test_save_is_deterministic_with_header(path: Path) -> None:
    s = State.load(path)
    s.touch("zeta", T0)
    s.touch("alpha", T0)
    text = s.save()
    assert text.startswith("# ")
    assert text.index("alpha") < text.index("zeta")
    assert s.save() == text


def test_dry_run_does_not_write(path: Path) -> None:
    s = State.load(path)
    s.touch("web01", T0)
    assert "web01" in s.save(dry_run=True)
    assert not path.exists()


def test_save_creates_private_dir(tmp_path: Path) -> None:
    p = tmp_path / "new" / "state.toml"
    s = State.load(p)
    s.touch("web01", T0)
    s.save()
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700


# --- invalid file ------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "[last_used\n",  # broken TOML
        'last_used = "x"\n',  # not a table
        '[last_used]\nweb01 = "yesterday"\n',  # not a date
        "[last_used]\nweb01 = 2026-10-16T10:00:00\n",  # no timezone
        '[last_used]\n"bad alias" = 2026-10-16T10:00:00Z\n',
        "[last_used]\nweb01 = 2026-10-16\n",  # date only
    ],
)
def test_invalid_file_is_state_error_naming_the_path(path: Path, text: str) -> None:
    _write(path, text)
    with pytest.raises(StateError, match="state.toml"):
        State.load(path)


def test_unknown_top_level_keys_are_ignored(path: Path) -> None:
    # Room for future versions: unknown keys don't block hsm.
    _write(path, "future = 1\n[last_used]\nweb01 = 2026-10-16T10:00:00Z\n")
    assert State.load(path).last_used("web01") == T0


def test_permissive_file_is_refused(path: Path) -> None:
    _write(path, "")
    path.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        State.load(path)


def test_alias_with_dot_roundtrips(path: Path) -> None:
    # In TOML a dot in a key separates tables: it must be quoted.
    s = State.load(path)
    s.touch("web.prod", T0)
    s.save()
    assert State.load(path).last_used("web.prod") == T0


# --- review findings -----------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"]
)
def test_extreme_dates_are_state_error_not_overflow(path: Path, value: str) -> None:
    _write(path, f"[last_used]\nweb01 = {value}\n")
    with pytest.raises(StateError, match="state.toml"):
        State.load(path)


def test_deep_nesting_is_state_error(path: Path) -> None:
    _write(path, "[last_used]\nweb01 = " + "[" * 100_000 + "\n")
    with pytest.raises(StateError):
        State.load(path)


def test_unreadable_file_is_state_error(path: Path) -> None:
    _write(path, "")
    path.chmod(0o000)
    try:
        with pytest.raises(StateError, match="state.toml"):
            State.load(path)
    finally:
        path.chmod(0o600)


def test_load_truncates_to_seconds(path: Path) -> None:
    _write(path, "[last_used]\nweb01 = 2026-10-16T10:00:00.5Z\n")
    assert State.load(path).last_used("web01") == T0


def test_touch_extreme_date_is_value_error(path: Path) -> None:
    with pytest.raises(ValueError):
        State.load(path).touch("web01", datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5))))


def test_load_or_empty_degrades_with_warning(path: Path) -> None:
    # The state is convenience data: a broken file must not block connect.
    _write(path, "[last_used\n")
    warnings: list[str] = []
    s = State.load_or_empty(path, warnings.append)
    assert s.last_used("web01") is None
    assert warnings and "state.toml" in warnings[0]


def test_load_or_empty_still_refuses_permissive_file(path: Path) -> None:
    # Permissions remain a hard requirement, as for the other hsm files.
    _write(path, "")
    path.chmod(0o644)
    with pytest.raises(InsecurePermissionsError):
        State.load_or_empty(path, lambda _: None)


def test_rename_moves_last_use(path: Path) -> None:
    s = State.load(path)
    s.touch("web01", T0)
    s.rename("web01", "web02")
    assert s.last_used("web01") is None
    assert s.last_used("web02") == T0
    s.rename("never-seen", "x")  # no error
    with pytest.raises(ValueError):
        s.rename("web02", "bad alias")
