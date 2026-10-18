"""Tree view of the inventory folders, for `hsm ls --tree`.

    prod/          5
    ├── eu/        4
    │   ├── db/    1
    │   └── web/   2
    └── us/        1
    lab/           1
    (no folder)    2

Each folder shows how many hosts it contains, sub-folders included, so a
collapsed folder still tells you how big it is. Options:
- `root`: look inside one folder ("prod/eu");
- `depth`: how many folder levels to open below the starting point;
  deeper folders stay closed but are counted;
- `show_hosts`: also list the hosts, after the sub-folders of each folder.

It works on any list of hosts: given the result of a search, it answers
"where are the hosts that match?".
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from hsm.errors import HsmError
from hsm.inventory import Host, normalize_group

_NO_FOLDER = "(no folder)"


@dataclass
class _Folder:
    name: str
    path: str
    folders: dict[str, "_Folder"] = field(default_factory=dict)
    hosts: list[Host] = field(default_factory=list)
    count: int = 0  # hosts here and below


def _build(hosts: list[Host]) -> _Folder:
    root = _Folder(name="", path="")
    for host in hosts:
        node = root
        node.count += 1
        if host.group is None:
            node.hosts.append(host)
            continue
        for part in host.group.split("/"):
            child_path = f"{node.path}/{part}" if node.path else part
            node = node.folders.setdefault(part, _Folder(name=part, path=child_path))
            node.count += 1
        node.hosts.append(host)
    return root


def render_tree(
    hosts: Iterable[Host],
    *,
    root: str | None = None,
    depth: int | None = None,
    show_hosts: bool = False,
    label: Callable[[Host], str] = lambda host: host.alias,
) -> list[str]:
    """The tree as lines of text (no trailing newline)."""
    tree = _build(list(hosts))
    rows: list[tuple[str, int | None]] = []

    def expand(node: _Folder, prefix: str, level: int) -> None:
        # `level` is the depth of the items being listed; deeper ones stay closed.
        if depth is not None and level > depth:
            return
        items: list[_Folder | Host] = [node.folders[name] for name in sorted(node.folders)]
        if show_hosts:
            items += sorted(node.hosts, key=lambda h: h.alias)
        for index, item in enumerate(items):
            last = index == len(items) - 1
            branch = "└── " if last else "├── "
            if isinstance(item, _Folder):
                rows.append((f"{prefix}{branch}{item.name}/", item.count))
                expand(item, prefix + ("    " if last else "│   "), level + 1)
            else:
                rows.append((f"{prefix}{branch}{label(item)}", None))

    if root is not None:
        node = _find(tree, root)
        rows.append((f"{node.path}/", node.count))
        expand(node, "", 1)
    else:
        # Several top-level folders: each is a root line, like `tree a b c`.
        for name in sorted(tree.folders):
            folder = tree.folders[name]
            rows.append((f"{folder.name}/", folder.count))
            expand(folder, "", 2)
        if show_hosts:
            rows += [(label(h), None) for h in sorted(tree.hosts, key=lambda h: h.alias)]
        elif tree.hosts:
            rows.append((_NO_FOLDER, len(tree.hosts)))

    counted = [(text, count) for text, count in rows if count is not None]
    width = max((len(text) for text, _ in counted), default=0) + 2
    digits = max((len(str(count)) for _, count in counted), default=0)
    return [text if count is None else text.ljust(width) + str(count).rjust(digits) for text, count in rows]


def _find(tree: _Folder, root: str) -> _Folder:
    try:
        path = normalize_group(root)
    except ValueError:
        path = None
    node: _Folder | None = None
    if path is not None:
        node = tree
        for part in path.split("/"):
            node = node.folders.get(part)
            if node is None:
                break
    if node is None:
        raise HsmError(f"No folder {root!r}.")
    return node
