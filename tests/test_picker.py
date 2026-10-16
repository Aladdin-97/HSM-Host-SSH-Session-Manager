import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from hsm.errors import HsmError
from hsm.inventory import Host
from hsm.picker import Picker, format_line

FZF = "/opt/homebrew/bin/fzf"

WEB01 = Host(alias="web01", hostname="10.0.0.1", user="deploy", port=2222, tags=("prod", "web"), note="frontend")
DB = Host(alias="db", hostname="db.example.com", tags=("prod",))
LAB = Host(alias="lab", hostname="lab.local")
HOSTS = [WEB01, DB, LAB]  # already sorted (e.g. by last use)


@dataclass
class FakeFzf:
    returncode: int = 0
    stdout: str = ""
    raises: BaseException | None = None
    calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(list(argv), self.returncode, self.stdout, "")


@dataclass
class Console:
    answers: list[str] = field(default_factory=list)
    printed: list[str] = field(default_factory=list)

    def input(self, prompt: str) -> str:
        self.printed.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def output(self, text: str) -> None:
        self.printed.append(text)


def fzf_picker(fake: FakeFzf, console: Console | None = None) -> Picker:
    console = console or Console()
    return Picker(which=lambda name: FZF, runner=fake, input=console.input, output=console.output)


def list_picker(console: Console) -> Picker:
    return Picker(which=lambda name: None, input=console.input, output=console.output)


# --- format --------------------------------------------------------------------


def test_format_line_fields_are_tab_separated() -> None:
    line = format_line(WEB01)
    assert line.split("\t") == ["web01", "deploy@10.0.0.1:2222", "#prod #web", "frontend"]


def test_format_line_minimal_host() -> None:
    assert format_line(LAB).split("\t") == ["lab", "lab.local", "", ""]


def test_format_line_never_contains_newlines() -> None:
    host = Host(alias="n", hostname="n", note="note with spaces, commas and — dashes")
    line = format_line(host)
    assert "\n" not in line and line.count("\t") == 3


# --- fzf -------------------------------------------------------------------------


def test_fzf_receives_numbered_hosts_in_order_and_returns_choice() -> None:
    # Each line starts with a hidden index (--with-nth=2..): the choice is
    # derived from that number, not from text fzf might print differently.
    fake = FakeFzf(stdout="2\t" + format_line(DB) + "\n")
    assert fzf_picker(fake).choose(HOSTS) == DB
    argv, kwargs = fake.calls[0]
    assert argv[0] == FZF
    assert kwargs["input"] == "".join(f"{i}\t{format_line(h)}\n" for i, h in enumerate(HOSTS, 1))
    assert kwargs["stdout"] is subprocess.PIPE
    assert "--with-nth=2.." in argv and "--delimiter=\t" in argv and "--no-multi" in argv


def test_fzf_ignores_user_default_options(monkeypatch: pytest.MonkeyPatch) -> None:
    # FZF_DEFAULT_OPTS could add --print-query, --expect, etc. and change
    # the output format: we remove it from fzf's environment.
    monkeypatch.setenv("FZF_DEFAULT_OPTS", "--print-query")
    monkeypatch.setenv("FZF_DEFAULT_OPTS_FILE", "/tmp/x")
    fake = FakeFzf(stdout="1\t" + format_line(WEB01) + "\n")
    fzf_picker(fake).choose(HOSTS)
    env = fake.calls[0][1]["env"]
    assert "FZF_DEFAULT_OPTS" not in env and "FZF_DEFAULT_OPTS_FILE" not in env
    assert "PATH" in env


@pytest.mark.parametrize(
    "stdout",
    ["query\n1\tweb01\n", "1\tweb01\r\n", "\n", "9\tx\n", "web01\tx\n", "0\tx\n"],
)
def test_fzf_unexpected_output_fails_closed(stdout: str) -> None:
    with pytest.raises(HsmError):
        fzf_picker(FakeFzf(stdout=stdout)).choose(HOSTS)


def test_relative_fzf_path_is_not_used() -> None:
    # A "./fzf" in the current directory (PATH with an empty entry or ".") is not used.
    console = Console(answers=["1"])
    picker = Picker(which=lambda name: "fzf", runner=FakeFzf(), input=console.input, output=console.output)
    assert picker.choose(HOSTS) == WEB01


@pytest.mark.parametrize("code", [1, 130])
def test_fzf_no_match_or_cancel_returns_none(code: int) -> None:
    assert fzf_picker(FakeFzf(returncode=code)).choose(HOSTS) is None


def test_fzf_error_is_clean_error() -> None:
    with pytest.raises(HsmError, match="fzf"):
        fzf_picker(FakeFzf(returncode=2)).choose(HOSTS)




def test_fzf_vanished_falls_back_to_list() -> None:
    console = Console(answers=["2"])
    picker = Picker(
        which=lambda name: FZF,
        runner=FakeFzf(raises=FileNotFoundError(FZF)),
        input=console.input,
        output=console.output,
    )
    assert picker.choose(HOSTS) == DB


# --- numbered list (without fzf) -------------------------------------------------


def test_list_shows_numbered_hosts_and_selects_by_number() -> None:
    console = Console(answers=["1"])
    assert list_picker(console).choose(HOSTS) == WEB01
    text = "\n".join(console.printed)
    assert "1" in text and "web01" in text and "lab" in text


def test_list_filter_then_number() -> None:
    console = Console(answers=["prod", "2"])
    assert list_picker(console).choose(HOSTS) == DB


def test_list_exact_alias_selects_it() -> None:
    console = Console(answers=["LAB"])  # case-insensitive
    assert list_picker(console).choose(HOSTS) == LAB


def test_list_single_non_alias_match_still_needs_confirmation() -> None:
    # A filter with a single result does NOT connect on its own: a typo
    # would take you to some random host (maybe with the password).
    console = Console(answers=["db.example"])  # then EOF
    assert list_picker(console).choose(HOSTS) is None
    assert list_picker(Console(answers=["db.example", "1"])).choose(HOSTS) == DB


def test_list_filter_matches_hostname_tags_and_note() -> None:
    assert list_picker(Console(answers=["db.example", "1"])).choose(HOSTS) == DB
    assert list_picker(Console(answers=["frontend", "1"])).choose(HOSTS) == WEB01


@pytest.mark.parametrize("weird", ["²", "①", "٣", "１", "9" * 5000])
def test_non_ascii_or_huge_digits_are_filters_not_indexes(weird: str) -> None:
    # '²'.isdigit() is True but int('²') raises: no crash, it's a filter.
    console = Console(answers=[weird, "2"])
    assert list_picker(console).choose(HOSTS) == DB


def test_list_filter_without_matches_shows_message_and_retries() -> None:
    console = Console(answers=["zzz", "3"])
    assert list_picker(console).choose(HOSTS) == LAB
    assert any("No host" in p for p in console.printed)


@pytest.mark.parametrize("bad", ["0", "4", "-1"])
def test_list_out_of_range_number_retries(bad: str) -> None:
    console = Console(answers=[bad, "1"])
    assert list_picker(console).choose(HOSTS) == WEB01


@pytest.mark.parametrize("answers", [[""], []])
def test_list_empty_answer_or_eof_returns_none(answers: list[str]) -> None:
    assert list_picker(Console(answers=answers)).choose(HOSTS) is None


def test_empty_inventory_is_clean_error() -> None:
    with pytest.raises(HsmError, match="hsm add"):
        list_picker(Console()).choose([])


def test_format_line_brackets_ipv6_only_with_port() -> None:
    assert format_line(Host(alias="v6", hostname="2001:db8::1", port=2200)).split("\t")[1] == "[2001:db8::1]:2200"
    assert format_line(Host(alias="v6", hostname="2001:db8::1")).split("\t")[1] == "2001:db8::1"
