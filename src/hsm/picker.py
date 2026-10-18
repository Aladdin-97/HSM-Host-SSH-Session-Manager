"""Host picker for `hsm` without arguments, browsing folders like k9s.

With fzf (the "k9s-like" mode) every folder is a full-screen fzf screen:

    hsm › prod/eu  ·  140 hosts
    enter open/connect · ⌫ up · ctrl-e edit · ctrl-y copy password · esc quit
    > web 03
      db/                         12 hosts
      web/                       128 hosts
      bastion-eu                  jump@10.1.0.1      #infra
      web/web03                   deploy@10.1.2.3    #nginx

- sub-folders first, with their host count; then EVERY host below the
  current folder, with its relative path, so typing searches the whole
  sub-tree while Enter on a folder narrows it;
- Enter opens a folder or picks a host; Backspace on an empty query goes up
  (fzf's backward-eof prints ".."); ctrl-e / ctrl-y pick the host for
  editing or for copying its password; Esc quits;
- an optional preview command (given by the CLI) fills the right pane.

Each line is "kind<TAB>id<TAB>what you see": fzf shows only the third part
(--with-nth=3..) and prints the whole line back. If the output is not
exactly what we expect (known key, one line, a folder or host that is on
this screen), we stop: better an error than connecting to the wrong host.
For the same reason FZF_DEFAULT_OPTS is removed from fzf's environment.
fzf receives no secrets; it is looked up in PATH, but only if the path is
absolute. The fields shown are validated by Host (no tabs, newlines or
escape sequences), so they cannot tamper with the terminal.

Without fzf: a numbered list per folder (sub-folders and the hosts directly
in it). A number opens a folder or picks a host, ".." goes up, any other text
is a search (search.py syntax: words, tag:, group:...) over the current
folder and below, showing at most 30 results. A search picks on its own only
if the text is exactly an alias: otherwise the number is required, so a typo
does not take you to some random host.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from hsm.errors import HsmError
from hsm.inventory import DEFAULT_PORT, Host, normalize_group
from hsm.search import SearchError, search

# fzf exit codes: 1 = no match, 130 = Esc or Ctrl-C.
_FZF_NO_MATCH = 1
_FZF_INTERRUPTED = 130
_FZF_ENV_DROP = ("FZF_DEFAULT_OPTS", "FZF_DEFAULT_OPTS_FILE")
# Key printed by --expect (empty for Enter) -> action returned to the CLI.
_ACTIONS = {"": "connect", "ctrl-e": "edit", "ctrl-y": "copy"}
_UP = ".."
_FZF_OPTIONS = [
    "--delimiter=\t",
    "--with-nth=3..",
    "--no-multi",
    "--layout=reverse",
    "--tiebreak=index",
    "--prompt=hsm> ",
    "--expect=ctrl-e,ctrl-y",
]
# Backspace on an empty query: print ".." and accept, i.e. "go up".
# Not bound at the root, where there is nothing above.
_FZF_UP = "--bind=backward-eof:print(..)+accept"
_KEYS_HELP = "enter open/connect · ⌫ up · ctrl-e edit · ctrl-y copy password · esc quit"

# ASCII digits only, and not too many: '²'.isdigit() is True but int('²')
# fails, and int() rejects strings of more than 4300 digits.
_INDEX_RE = re.compile(r"[0-9]{1,6}")
_MAX_LIST_ROWS = 30
# fzf exits 1 when Enter is pressed with no match: we redraw the same folder.
# Each redraw needs a keypress, but a cap guarantees we never spin.
_MAX_NO_MATCH = 50


@dataclass(frozen=True)
class Selection:
    """What the user picked: an action ("connect", "edit", "copy") on a host."""

    action: str
    host: Host


@dataclass(frozen=True)
class _Folder:
    path: str  # full path, e.g. "prod/eu"
    name: str  # last segment, e.g. "eu"
    count: int  # hosts inside, sub-folders included


@dataclass(frozen=True)
class _View:
    folders: list[_Folder]  # direct sub-folders, alphabetical
    hosts: list[tuple[Host, str]]  # every host below, with its path relative to the folder


def format_line(host: Host) -> str:
    """alias, [user@]host[:port], #tags, note — tab-separated."""
    address = f"[{host.hostname}]" if ":" in host.hostname and host.port != DEFAULT_PORT else host.hostname
    target = (f"{host.user}@" if host.user else "") + address
    if host.port != DEFAULT_PORT:
        target += f":{host.port}"
    tags = " ".join(f"#{t}" for t in host.tags)
    return "\t".join([host.alias, target, tags, host.note or ""])


def _view(hosts: Sequence[Host], folder: str) -> _View:
    counts: dict[str, int] = {}
    below: list[tuple[Host, str]] = []
    for host in hosts:
        group = host.group or ""
        if folder and group != folder and not group.startswith(folder + "/"):
            continue
        relative = group[len(folder) :].lstrip("/") if folder else group
        below.append((host, relative))
        if relative:
            first = relative.split("/")[0]
            counts[first] = counts.get(first, 0) + 1
    folders = [
        _Folder(path=f"{folder}/{name}" if folder else name, name=name, count=counts[name])
        for name in sorted(counts)
    ]
    return _View(folders, below)


def _parent(folder: str) -> str:
    return folder.rpartition("/")[0]


def _plural(count: int) -> str:
    return f"{count} host" if count == 1 else f"{count} hosts"


class Picker:
    """Picks a host interactively. External dependencies are injectable."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        input: Callable[[str], str] = input,  # noqa: A002 - same name as the default builtin
        output: Callable[[str], None] = print,
        preview: str | None = None,
    ) -> None:
        self._which = which
        self._runner = runner
        self._input = input
        self._output = output
        self._preview = preview

    def choose(self, hosts: Sequence[Host]) -> Host | None:
        """The host to connect to, or None (any other action counts as giving up)."""
        selection = self.browse(hosts)
        return selection.host if selection is not None and selection.action == "connect" else None

    def browse(self, hosts: Sequence[Host], *, start: str = "", query: str = "") -> Selection | None:
        """Browse folders and pick a host; None if the user quits.

        `hosts` keeps its order (the CLI passes them most recent first);
        `start` is the initial folder, `query` the initial fzf query.
        """
        if not hosts:
            raise HsmError("Inventory is empty: add a host with hsm add <alias>.")
        try:
            folder = normalize_group(start) or ""
        except ValueError:
            folder = None
        if folder is None or (folder and not _view(hosts, folder).hosts):
            raise HsmError(f"No folder {start!r}.")
        fzf = self._which("fzf")
        if fzf is not None and os.path.isabs(fzf):
            try:
                return self._browse_fzf(fzf, hosts, folder, query)
            except FileNotFoundError:
                pass  # gone between which and execution: use the list
        return self._browse_list(hosts, folder)

    # --- fzf -----------------------------------------------------------------

    def _browse_fzf(self, fzf: str, hosts: Sequence[Host], folder: str, query: str) -> Selection | None:
        first = True
        no_match = 0
        while True:
            view = _view(hosts, folder)
            argv = [fzf, *_FZF_OPTIONS, f"--header={self._header(folder, view)}"]
            if folder:
                argv.append(_FZF_UP)
            if first and query:
                argv.append(f"--query={query}")
            if self._preview is not None:
                argv += [f"--preview={self._preview}", "--preview-window=right,50%,wrap"]
            first = False
            result: Any = self._runner(
                argv,
                input="".join(line + "\n" for line in self._fzf_lines(view)),
                stdout=subprocess.PIPE,
                text=True,
                check=False,
                env={k: v for k, v in os.environ.items() if k not in _FZF_ENV_DROP},
            )
            if result.returncode == _FZF_NO_MATCH:
                no_match += 1
                if no_match >= _MAX_NO_MATCH:
                    return None
                continue  # Enter with nothing matching: stay here, like k9s
            if result.returncode == _FZF_INTERRUPTED:
                return None
            if result.returncode != 0:
                raise HsmError(f"fzf exited with an error (code {result.returncode}).")
            key, up, line = self._parse(result.stdout)
            if up:
                folder = _parent(folder)
                continue
            kind, _, rest = line.partition("\t")
            entry = rest.split("\t", 1)[0]
            if kind == "folder" and entry in {f.path for f in view.folders}:
                folder = entry  # a shortcut on a folder just opens it
                continue
            hosts_here = {host.alias: host for host, _ in view.hosts}
            if kind == "host" and entry in hosts_here:
                return Selection(_ACTIONS[key], hosts_here[entry])
            raise HsmError("fzf returned a choice that is not on screen: not connecting.")

    @staticmethod
    def _header(folder: str, view: _View) -> str:
        return f"hsm › {folder or '/'}  ·  {_plural(len(view.hosts))}\n{_KEYS_HELP}"

    @staticmethod
    def _fzf_lines(view: _View) -> list[str]:
        paths = [f"{rel}/{h.alias}" if rel else h.alias for h, rel in view.hosts]
        width = max([len(f.name) + 1 for f in view.folders] + [len(p) for p in paths] + [1])
        targets = [format_line(h).split("\t") for h, _ in view.hosts]
        target_width = max([len(t[1]) for t in targets] + [1])
        lines = [f"folder\t{f.path}\t{(f.name + '/').ljust(width)}  {_plural(f.count)}" for f in view.folders]
        for (host, _), path, (_, target, tags, note) in zip(view.hosts, paths, targets, strict=True):
            shown = "  ".join(c for c in (path.ljust(width), target.ljust(target_width), tags, note) if c)
            lines.append(f"host\t{host.alias}\t{shown.rstrip()}")
        return lines

    @staticmethod
    def _parse(stdout: str) -> tuple[str, bool, str]:
        """(key, went_up, chosen line) from fzf's output, or an error."""
        if not stdout.endswith("\n"):
            raise HsmError("fzf returned a choice in an unexpected format: not connecting.")
        key, *rest = stdout[:-1].split("\n")
        up = bool(rest) and rest[0] == _UP
        if up:
            rest = rest[1:]
        if key not in _ACTIONS or len(rest) != 1:
            raise HsmError("fzf returned a choice in an unexpected format: not connecting.")
        return key, up, rest[0]

    # --- numbered list ---------------------------------------------------------

    def _browse_list(self, hosts: Sequence[Host], folder: str) -> Selection | None:
        results: list[Host] | None = None  # None = browsing the folder, else search results
        while True:
            view = _view(hosts, folder)
            if results is None:
                self._output(f"hsm › {folder or '/'}")
                entries: list[_Folder | Host] = [*view.folders, *(h for h, rel in view.hosts if not rel)]
            else:
                entries = list(results)
            self._show(entries)
            try:
                answer = self._input("Number, search, .. to go up, Enter to quit: ").strip()
            except EOFError:
                return None
            if not answer:
                return None
            if answer == _UP:
                folder, results = _parent(folder), None
                continue
            rows = min(len(entries), _MAX_LIST_ROWS)
            # A number within the rows on screen picks that row; any other
            # number is searched, so an alias like "2024" stays reachable.
            if _INDEX_RE.fullmatch(answer) and 1 <= int(answer) <= rows:
                chosen = entries[int(answer) - 1]
                if isinstance(chosen, _Folder):
                    folder, results = chosen.path, None
                    continue
                return Selection("connect", chosen)
            try:
                found = search([h for h, _ in view.hosts], answer)
            except SearchError as exc:
                self._output(str(exc))
                continue
            if not found:
                self._output(f"No host matches {answer!r}.")
                continue
            exact = [h for h in found if h.alias.casefold() == answer.casefold()]
            if exact:
                return Selection("connect", exact[0])
            results = found

    def _show(self, entries: Sequence["_Folder | Host"]) -> None:
        shown = list(entries[:_MAX_LIST_ROWS])
        width = max([len(e.name) + 1 if isinstance(e, _Folder) else len(e.alias) for e in shown] + [1])
        for i, entry in enumerate(shown, start=1):
            if isinstance(entry, _Folder):
                self._output(f"{i:>3}  {(entry.name + '/').ljust(width)}  {_plural(entry.count)}")
            else:
                alias, target, tags, note = format_line(entry).split("\t")
                columns = [f"{i:>3}", alias.ljust(width), target, tags, note]
                self._output("  ".join(c for c in columns if c).rstrip())
        if len(entries) > _MAX_LIST_ROWS:
            self._output(f"  … {len(entries) - _MAX_LIST_ROWS} more: refine the search")
