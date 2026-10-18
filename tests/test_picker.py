import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from hsm.errors import HsmError
from hsm.inventory import Host
from hsm.picker import Picker, Selection, format_line

FZF = "/opt/homebrew/bin/fzf"

WEB01 = Host(alias="web01", hostname="10.0.0.1", user="deploy", group="prod/eu/web", tags=("nginx",))
WEB02 = Host(alias="web02", hostname="10.0.0.2", user="deploy", group="prod/eu/web")
DB = Host(alias="db01", hostname="db.example.com", group="prod/eu/db")
BASTION = Host(alias="bastion-eu", hostname="10.0.0.9", group="prod/eu", note="entry point")
API = Host(alias="api01", hostname="10.2.0.1", group="prod/us")
LAPTOP = Host(alias="laptop", hostname="laptop.lan")
HOSTS = [WEB01, WEB02, DB, BASTION, API, LAPTOP]  # order given by the caller (e.g. recency)


@dataclass
class FakeFzf:
    """Answers each fzf run with the next scripted (returncode, stdout)."""

    script: list[tuple[int, str]] = field(default_factory=list)
    calls: list[tuple[list[str], dict[str, Any]]] = field(default_factory=list)
    raises: BaseException | None = None

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        code, out = self.script.pop(0) if self.script else (130, "")
        return subprocess.CompletedProcess(list(argv), code, out, "")

    def lines(self, call: int = -1) -> list[str]:
        return self.calls[call][1]["input"].splitlines()

    def header(self, call: int = -1) -> str:
        return next(a for a in self.calls[call][0] if a.startswith("--header=")).removeprefix("--header=")


def row(fake: FakeFzf, call: int, entry_id: str) -> str:
    """The input line fzf received for `entry_id` (what fzf prints back on Enter)."""
    return next(line for line in fake.lines(call) if line.split("\t")[1] == entry_id)


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

    def text(self) -> str:
        return "\n".join(self.printed)


def fzf_picker(fake: FakeFzf, preview: str | None = None) -> Picker:
    console = Console()
    return Picker(which=lambda name: FZF, runner=fake, input=console.input, output=console.output, preview=preview)


def list_picker(console: Console) -> Picker:
    return Picker(which=lambda name: None, input=console.input, output=console.output)


# --- format_line (used by hsm ls too) ---------------------------------------------


def test_format_line_fields_are_tab_separated() -> None:
    assert format_line(WEB01).split("\t") == ["web01", "deploy@10.0.0.1", "#nginx", ""]


def test_format_line_brackets_ipv6_only_with_port() -> None:
    assert format_line(Host(alias="v6", hostname="2001:db8::1", port=2200)).split("\t")[1] == "[2001:db8::1]:2200"
    assert format_line(Host(alias="v6", hostname="2001:db8::1")).split("\t")[1] == "2001:db8::1"


# --- fzf: what each screen contains -------------------------------------------------


def test_root_screen_lists_folders_then_hosts_of_the_whole_tree() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS)
    shown = [line.split("\t")[:2] for line in fake.lines()]
    assert shown[0] == ["folder", "prod"]
    # Then every host, folders' hosts included, so typing searches everything.
    assert ["host", "laptop"] in shown and ["host", "web01"] in shown
    assert len([s for s in shown if s[0] == "host"]) == len(HOSTS)


def test_hosts_in_subfolders_show_their_relative_path() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS)
    assert "prod/eu/web/web01" in row(fake, 0, "web01")
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS, start="prod/eu")
    assert "web/web01" in row(fake, 0, "web01") and "prod/eu/web" not in row(fake, 0, "web01")


def test_folder_rows_show_their_host_count() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS)
    assert "5 hosts" in row(fake, 0, "prod")


def test_hosts_keep_the_given_order() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse([API, WEB01, LAPTOP])
    hosts = [line.split("\t")[1] for line in fake.lines() if line.startswith("host")]
    assert hosts == ["api01", "web01", "laptop"]


def test_header_shows_the_current_folder_and_the_keys() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS, start="prod/eu")
    header = fake.header()
    assert "prod/eu" in header and "ctrl-e" in header and "ctrl-y" in header


def test_full_screen_with_expected_keys_and_strict_output() -> None:
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS)
    argv, kwargs = fake.calls[0]
    assert argv[0] == FZF
    assert "--expect=ctrl-e,ctrl-y" in argv
    assert "--bind=backward-eof:print(..)+accept" not in argv  # at the root there is no "up"
    assert not any(a.startswith("--height") for a in argv)  # full screen, like k9s
    assert "FZF_DEFAULT_OPTS" not in kwargs["env"]


def test_preview_uses_the_given_command() -> None:
    fake = FakeFzf()
    fzf_picker(fake, preview="/x/hsm __preview {1} {2}").browse(HOSTS)
    assert "--preview=/x/hsm __preview {1} {2}" in fake.calls[0][0]
    fake = FakeFzf()
    fzf_picker(fake).browse(HOSTS)
    assert not any(a.startswith("--preview") for a in fake.calls[0][0])


def test_initial_query_only_on_the_first_screen() -> None:
    fake = FakeFzf(script=[(0, "\nfolder\tprod\tprod/  5 hosts\n")])
    fzf_picker(fake).browse(HOSTS, query="web")
    assert "--query=web" in fake.calls[0][0]
    assert not any(a.startswith("--query") for a in fake.calls[1][0])


# --- fzf: navigation and actions -----------------------------------------------------


def test_enter_on_a_folder_opens_it() -> None:
    fake = FakeFzf()
    picker = fzf_picker(fake)
    fake.script = [(0, "\nfolder\tprod\tprod/ 5 hosts\n")]
    picker.browse(HOSTS)
    assert "prod" in fake.header(1)
    assert [line.split("\t")[1] for line in fake.lines(1) if line.startswith("folder")] == ["prod/eu", "prod/us"]


def test_enter_on_a_host_connects() -> None:
    fake = FakeFzf(script=[(0, "\nhost\tweb02\tprod/eu/web/web02\n")])
    assert fzf_picker(fake).browse(HOSTS) == Selection("connect", WEB02)


@pytest.mark.parametrize("key, action", [("ctrl-e", "edit"), ("ctrl-y", "copy")])
def test_shortcuts_return_their_action(key: str, action: str) -> None:
    fake = FakeFzf(script=[(0, f"{key}\nhost\tdb01\tprod/eu/db/db01\n")])
    assert fzf_picker(fake).browse(HOSTS) == Selection(action, DB)


def test_shortcut_on_a_folder_just_opens_it() -> None:
    fake = FakeFzf(script=[(0, "ctrl-e\nfolder\tprod\tprod/\n")])
    fzf_picker(fake).browse(HOSTS)
    assert "prod" in fake.header(1)


def test_backspace_on_empty_query_goes_up() -> None:
    fake = FakeFzf(script=[(0, "\n..\nhost\tweb01\tweb/web01\n")])
    fzf_picker(fake).browse(HOSTS, start="prod/eu")
    header = fake.header(1)
    assert "prod" in header and "prod/eu" not in header


def test_going_up_at_the_root_stays_at_the_root() -> None:
    fake = FakeFzf(script=[(0, "\n..\nfolder\tprod\tprod/\n")])
    fzf_picker(fake).browse(HOSTS)
    assert len(fake.calls) == 2
    assert fake.lines(1) == fake.lines(0)


def test_esc_quits() -> None:
    assert fzf_picker(FakeFzf(script=[(130, "")])).browse(HOSTS) is None


def test_enter_without_matches_stays_on_the_screen() -> None:
    # fzf exits 1 on Enter with no match: like k9s, we stay in the folder.
    fake = FakeFzf(script=[(1, ""), (0, "\nhost\tweb01\tx\n")])
    assert fzf_picker(fake).browse(HOSTS, start="prod/eu") == Selection("connect", WEB01)
    assert "prod/eu" in fake.header(1)


def test_repeated_no_match_exits_eventually() -> None:
    fake = FakeFzf(script=[(1, "")] * 200)
    assert fzf_picker(fake).browse(HOSTS) is None
    assert len(fake.calls) < 200


def test_up_binding_only_below_the_root() -> None:
    fake = FakeFzf(script=[(0, "\nfolder\tprod\tprod/\n")])
    fzf_picker(fake).browse(HOSTS)
    assert "--bind=backward-eof:print(..)+accept" not in fake.calls[0][0]
    assert "--bind=backward-eof:print(..)+accept" in fake.calls[1][0]


@pytest.mark.parametrize(
    "stdout",
    [
        "\nhost\tghost\tghost\n",  # unknown host
        "\nfolder\tnope\tnope/\n",  # unknown folder
        "\nwhat\tweb01\tx\n",  # unknown kind
        "ctrl-x\nhost\tweb01\tx\n",  # unexpected key
        "\nhost\tweb01\tx\nhost\tweb02\tx\n",  # two lines
        "garbage",
    ],
)
def test_unexpected_fzf_output_fails_closed(stdout: str) -> None:
    with pytest.raises(HsmError):
        fzf_picker(FakeFzf(script=[(0, stdout)])).browse(HOSTS)


def test_fzf_error_code_is_clean_error() -> None:
    with pytest.raises(HsmError, match="fzf"):
        fzf_picker(FakeFzf(script=[(2, "")])).browse(HOSTS)


def test_unknown_start_folder_is_an_error() -> None:
    with pytest.raises(HsmError, match="nope"):
        fzf_picker(FakeFzf()).browse(HOSTS, start="nope")


def test_relative_fzf_path_falls_back_to_the_list() -> None:
    console = Console(answers=["laptop"])
    picker = Picker(which=lambda name: "fzf", runner=FakeFzf(), input=console.input, output=console.output)
    assert picker.browse(HOSTS) == Selection("connect", LAPTOP)


def test_vanished_fzf_falls_back_to_the_list() -> None:
    console = Console(answers=["laptop"])
    picker = Picker(
        which=lambda name: FZF, runner=FakeFzf(raises=FileNotFoundError(FZF)), input=console.input, output=console.output
    )
    assert picker.browse(HOSTS) == Selection("connect", LAPTOP)


def test_choose_is_browse_restricted_to_connect() -> None:
    assert fzf_picker(FakeFzf(script=[(0, "\nhost\tweb01\tx\n")])).choose(HOSTS) == WEB01
    assert fzf_picker(FakeFzf(script=[(0, "ctrl-e\nhost\tweb01\tx\n")])).choose(HOSTS) is None


# --- numbered list (no fzf) ------------------------------------------------------------


def test_list_root_shows_folders_with_counts_and_root_hosts() -> None:
    console = Console()
    list_picker(console).browse(HOSTS)
    text = console.text()
    assert "prod/" in text and "5 hosts" in text and "laptop" in text
    assert "web01" not in text  # inside a folder: not listed until you open it or search


def test_list_number_opens_a_folder_and_selects_a_host() -> None:
    console = Console(answers=["1", "1", "3"])  # prod/ -> eu/ -> bastion-eu (after db/, web/)
    assert list_picker(console).browse(HOSTS) == Selection("connect", BASTION)
    assert "prod/eu" in console.text()


def test_list_dot_dot_goes_up() -> None:
    console = Console(answers=["..", "2"])  # from prod/eu up to prod, then into us/, then EOF
    list_picker(console).browse(HOSTS, start="prod/eu")
    headers = [line for line in console.printed if line.startswith("hsm › ")]
    assert headers == ["hsm › prod/eu", "hsm › prod", "hsm › prod/us"]


def test_list_search_uses_the_full_syntax_on_the_subtree() -> None:
    console = Console(answers=["tag:nginx", "1"])
    assert list_picker(console).browse(HOSTS) == Selection("connect", WEB01)
    console = Console(answers=["group:prod/eu web", "2"])
    assert list_picker(console).browse(HOSTS) == Selection("connect", WEB02)


def test_list_search_is_limited_to_the_current_folder() -> None:
    console = Console(answers=["api"])
    list_picker(console).browse(HOSTS, start="prod/eu")
    assert "No host matches" in console.text()


def test_list_exact_alias_selects_it() -> None:
    assert list_picker(Console(answers=["LAPTOP"])).browse(HOSTS) == Selection("connect", LAPTOP)


def test_list_single_non_alias_match_still_needs_confirmation() -> None:
    assert list_picker(Console(answers=["entry point"])).browse(HOSTS) is None
    assert list_picker(Console(answers=['"entry point"', "1"])).browse(HOSTS) == Selection("connect", BASTION)


def test_list_long_results_are_truncated_with_a_hint() -> None:
    many = [Host(alias=f"h{i:03d}", hostname=f"10.0.1.{i}", group="big") for i in range(100)]
    console = Console(answers=["h0"])
    list_picker(console).browse(many)
    text = console.text()
    assert "h029" in text and "h031" not in text
    assert "more" in text


def test_list_invalid_search_is_reported_not_raised() -> None:
    console = Console(answers=["auth:maybe", "laptop"])
    assert list_picker(console).browse(HOSTS) == Selection("connect", LAPTOP)
    assert "auth:" in console.text()


@pytest.mark.parametrize("weird", ["²", "①", "٣", "9" * 5000])
def test_list_non_ascii_or_huge_digits_are_searches_not_indexes(weird: str) -> None:
    console = Console(answers=[weird, "laptop"])
    assert list_picker(console).browse(HOSTS) == Selection("connect", LAPTOP)


def test_list_out_of_range_number_without_such_alias() -> None:
    console = Console(answers=["99", "laptop"])
    assert list_picker(console).browse(HOSTS) == Selection("connect", LAPTOP)
    assert "No host matches" in console.text()


@pytest.mark.parametrize("answers", [[""], []])
def test_list_empty_answer_or_eof_quits(answers: list[str]) -> None:
    assert list_picker(Console(answers=answers)).browse(HOSTS) is None


def test_empty_inventory_is_clean_error() -> None:
    with pytest.raises(HsmError, match="hsm add"):
        list_picker(Console()).browse([])


def test_invalid_start_folder_is_an_error() -> None:
    with pytest.raises(HsmError, match="bad name"):
        fzf_picker(FakeFzf()).browse(HOSTS, start="bad name")


def test_list_numeric_alias_out_of_range_is_searched() -> None:
    hosts = [*HOSTS, Host(alias="2024", hostname="10.9.9.9")]
    assert list_picker(Console(answers=["2024"])).browse(hosts) == Selection("connect", hosts[-1])
