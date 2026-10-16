"""Host picker for `hsm` without arguments: fzf if available, otherwise a list.

Returns only the chosen host (or None): the CLI does the connect.

With fzf each host is a tab-separated line, preceded by an index that fzf
does not show (--with-nth=2..):

    2   web01   deploy@10.0.0.1:2222   #prod #web   frontend

fzf draws its interface on /dev/tty and reads the lines from stdin; it
writes the chosen line to stdout, and from that index we get the host. If
the output is not exactly one "<index>\t..." line, we stop: better an
error than connecting to the wrong host. For the same reason we remove
FZF_DEFAULT_OPTS from fzf's environment: options like --print-query or
--expect would change the output format.
Lines come in the order received (usually: recently used first) and
`--tiebreak=index` keeps that order on equal scores.

fzf receives no secrets, so we look it up in PATH like any command, but
only if the path is absolute (no "./fzf"). The fields shown are already
validated by Host (no tabs, newlines or escape sequences), so they cannot
tamper with the terminal.

Without fzf: a numbered list. Type a number to choose, or some text to
filter (alias, host, tags, notes; case-insensitive). The filter picks on
its own only if the text is exactly an alias: otherwise, even with a
single result, the number is required, so a typo does not take you to
some random host. Empty Enter quits.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from hsm.errors import HsmError
from hsm.inventory import DEFAULT_PORT, Host

# fzf exit codes: 1 = no match, 130 = Esc or Ctrl-C.
_FZF_NO_MATCH = 1
_FZF_INTERRUPTED = 130

# ASCII digits only, and not too many: '²'.isdigit() is True but int('²')
# fails, and int() rejects strings of more than 4300 digits.
_INDEX_RE = re.compile(r"[0-9]{1,6}")
_FZF_CHOICE_RE = re.compile(r"([0-9]{1,6})\t[^\r\n]*\n?")
_FZF_ENV_DROP = ("FZF_DEFAULT_OPTS", "FZF_DEFAULT_OPTS_FILE")

_FZF_OPTIONS = [
    "--delimiter=\t",
    "--with-nth=2..",
    "--no-multi",
    "--reverse",
    "--height=40%",
    "--tiebreak=index",
    "--prompt=hsm> ",
]


def format_line(host: Host) -> str:
    """alias, [user@]host[:port], #tags, note — tab-separated."""
    address = f"[{host.hostname}]" if ":" in host.hostname and host.port != DEFAULT_PORT else host.hostname
    target = (f"{host.user}@" if host.user else "") + address
    if host.port != DEFAULT_PORT:
        target += f":{host.port}"
    tags = " ".join(f"#{t}" for t in host.tags)
    return "\t".join([host.alias, target, tags, host.note or ""])


class Picker:
    """Picks a host interactively. External dependencies are injectable."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        input: Callable[[str], str] = input,  # noqa: A002 - same name as the default builtin
        output: Callable[[str], None] = print,
    ) -> None:
        self._which = which
        self._runner = runner
        self._input = input
        self._output = output

    def choose(self, hosts: Sequence[Host]) -> Host | None:
        """The chosen host, or None if the user gives up."""
        if not hosts:
            raise HsmError("Inventory is empty: add a host with hsm add <alias>.")
        fzf = self._which("fzf")
        if fzf is not None and os.path.isabs(fzf):
            try:
                return self._choose_fzf(fzf, hosts)
            except FileNotFoundError:
                pass  # gone between which and execution: use the list
        return self._choose_from_list(hosts)

    def _choose_fzf(self, fzf: str, hosts: Sequence[Host]) -> Host | None:
        result: Any = self._runner(
            [fzf, *_FZF_OPTIONS],
            input="".join(f"{i}\t{format_line(h)}\n" for i, h in enumerate(hosts, start=1)),
            stdout=subprocess.PIPE,
            text=True,
            check=False,
            env={k: v for k, v in os.environ.items() if k not in _FZF_ENV_DROP},
        )
        if result.returncode in (_FZF_NO_MATCH, _FZF_INTERRUPTED):
            return None
        if result.returncode != 0:
            raise HsmError(f"fzf exited with an error (code {result.returncode}).")
        match = _FZF_CHOICE_RE.fullmatch(result.stdout)
        index = int(match.group(1)) if match else 0
        if not 1 <= index <= len(hosts):
            raise HsmError("fzf returned a choice in an unexpected format: not connecting.")
        return hosts[index - 1]

    def _choose_from_list(self, hosts: Sequence[Host]) -> Host | None:
        current = list(hosts)
        while True:
            self._show(current)
            try:
                answer = self._input("Number or filter (Enter to quit): ").strip()
            except EOFError:
                return None
            if not answer:
                return None
            if _INDEX_RE.fullmatch(answer):
                index = int(answer)
                if 1 <= index <= len(current):
                    return current[index - 1]
                self._output(f"Number out of range (1-{len(current)}).")
                continue
            needle = answer.casefold()
            # The filter always starts from the full list: a second filter
            # replaces the first instead of narrowing it further.
            matches = [h for h in hosts if needle in format_line(h).casefold()]
            if not matches:
                self._output(f"No host matches {answer!r}.")
                continue
            exact = [h for h in matches if h.alias.casefold() == needle]
            if exact:
                return exact[0]
            current = matches

    def _show(self, hosts: Sequence[Host]) -> None:
        width = max(len(h.alias) for h in hosts)
        for i, host in enumerate(hosts, start=1):
            alias, target, tags, note = format_line(host).split("\t")
            columns = [f"{i:>3}", alias.ljust(width), target, tags, note]
            self._output("  ".join(c for c in columns if c).rstrip())
