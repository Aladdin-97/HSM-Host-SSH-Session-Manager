import pytest

from hsm.errors import HsmError
from hsm.inventory import Host
from hsm.tree import render_tree


def h(alias: str, group: str | None = None) -> Host:
    return Host(alias=alias, hostname=f"{alias}.lan", group=group)


FLEET = [
    h("web01", "prod/eu/web"),
    h("web02", "prod/eu/web"),
    h("db01", "prod/eu/db"),
    h("bastion-eu", "prod/eu"),
    h("api01", "prod/us"),
    h("lab1", "lab"),
    h("laptop"),
    h("nas"),
]


def tree(**kwargs: object) -> str:
    return "\n".join(render_tree(FLEET, **kwargs))  # type: ignore[arg-type]


def test_folders_with_counts() -> None:
    # Folders in alphabetical order; counts include sub-folders.
    assert tree() == (
        "lab/          1\n"
        "prod/         5\n"
        "├── eu/       4\n"
        "│   ├── db/   1\n"
        "│   └── web/  2\n"
        "└── us/       1\n"
        "(no folder)   2"
    )


def test_depth_collapses_deeper_folders_but_keeps_counts() -> None:
    assert tree(depth=1) == (
        "lab/         1\n"
        "prod/        5\n"
        "(no folder)  2"
    )
    assert tree(depth=2).splitlines()[1:4] == ["prod/        5", "├── eu/      4", "└── us/      1"]


def test_show_hosts_lists_them_after_the_folders() -> None:
    assert tree(show_hosts=True) == (
        "lab/          1\n"
        "└── lab1\n"
        "prod/         5\n"
        "├── eu/       4\n"
        "│   ├── db/   1\n"
        "│   │   └── db01\n"
        "│   ├── web/  2\n"
        "│   │   ├── web01\n"
        "│   │   └── web02\n"
        "│   └── bastion-eu\n"
        "└── us/       1\n"
        "    └── api01\n"
        "laptop\n"
        "nas"
    )


def test_custom_host_label() -> None:
    lines = render_tree([h("web01", "prod")], show_hosts=True, label=lambda host: f"{host.alias}  {host.hostname}")
    assert lines == ["prod/  1", "└── web01  web01.lan"]


def test_root_shows_a_single_folder() -> None:
    assert "\n".join(render_tree(FLEET, root="prod/eu")) == (
        "prod/eu/  4\n"
        "├── db/   1\n"
        "└── web/  2"
    )


def test_root_with_hosts() -> None:
    lines = render_tree(FLEET, root="/prod/eu/", show_hosts=True)  # normalized
    assert lines[0].startswith("prod/eu/")
    assert lines[-1] == "└── bastion-eu"


def test_root_and_depth_together() -> None:
    assert render_tree(FLEET, root="prod", depth=1) == ["prod/    5", "├── eu/  4", "└── us/  1"]


def test_unknown_root_is_an_error() -> None:
    with pytest.raises(HsmError, match="nope"):
        render_tree(FLEET, root="nope")
    with pytest.raises(HsmError, match="prod/xx"):
        render_tree(FLEET, root="prod/xx")
    with pytest.raises(HsmError):
        render_tree(FLEET, root="bad name")
    with pytest.raises(HsmError):
        render_tree(FLEET, root="/")


def test_empty_list_renders_nothing() -> None:
    assert render_tree([]) == []


def test_only_hosts_without_folder() -> None:
    assert render_tree([h("a"), h("b")]) == ["(no folder)  2"]
    assert render_tree([h("a"), h("b")], show_hosts=True) == ["a", "b"]


def test_counts_match_inventory_groups(tmp_path: object) -> None:
    from pathlib import Path

    from hsm.inventory import Inventory

    inv = Inventory.load(Path(str(tmp_path)) / "hosts.toml")
    for host in FLEET:
        inv.add(host)
    groups = inv.groups()
    for line in render_tree(FLEET):
        name, count = line.rsplit(maxsplit=1)
        folder = name.lstrip("│├└─ ").rstrip("/")
        if folder != "(no folder)":
            assert any(g.endswith(folder) and groups[g] == int(count) for g in groups), line
