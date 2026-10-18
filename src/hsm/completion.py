"""Bash completion for hsm, generated from the argparse parser.

`hsm completion bash` prints a script that registers `_hsm` with `complete`.
Commands, sub-actions and options are read from the parser at generation
time, so the completion cannot drift from the real CLI. Values that depend
on your data (aliases, tags) are fetched at TAB time with the hidden
command `hsm __complete aliases|tags`, which only reads hosts.toml and
prints nothing on any problem: a TAB must never flood the terminal.

The script sticks to bash 3.2 features (macOS /bin/bash) so it also works
there, not only with Homebrew's bash 5.

What gets completed:
- commands and nested actions (`pw get`, `vault rekey`, `completion bash`);
- options of the command being typed (`hsm add web03 --<TAB>`);
- an existing alias wherever one is expected (`connect`, `edit`, `rm`,
  `show`, `pw set|get|rm`, `--jump`), but not the new alias of `add`;
- folders for `--group`, `ls <folder>` and `group mv FOLDER TARGET`;
- tags for `--tag`, files for `--identity`, fixed choices such as `--sort`.
"""

import argparse
from dataclasses import dataclass, field

# Option -> dynamic values fetched at TAB time ("files" uses bash's own file completion).
_DYNAMIC_VALUES = {"--jump": "aliases", "--tag": "tags", "--group": "groups", "--identity": "files"}
# Positionals that take a folder: `ls [query]` (one word) and `group mv FOLDER TARGET`.
_GROUP_POSITIONALS = {"query": "one", "folder": "many", "target": "many"}
# Commands whose `alias` positional is a NEW name: nothing to suggest.
_NEW_ALIAS_COMMANDS = {"add"}


@dataclass
class _Spec:
    """What the parser tree says, flattened for the bash `case` statements."""

    commands: list[str] = field(default_factory=list)
    global_options: list[str] = field(default_factory=list)
    # "pw get" -> options of that (sub)command
    options: dict[str, list[str]] = field(default_factory=dict)
    # "pw" -> ["get", "rm", "set"]; "" -> commands
    choices: dict[str, list[str]] = field(default_factory=dict)
    # paths where an existing alias is expected, e.g. "connect", "pw get"
    alias_paths: list[str] = field(default_factory=list)
    # bash `case` patterns where a folder is expected, e.g. '"ls"', '"group mv "*'
    group_patterns: list[str] = field(default_factory=list)
    value_options: set[str] = field(default_factory=set)
    option_choices: dict[str, list[str]] = field(default_factory=dict)


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction | None:  # type: ignore[type-arg]
    for action in parser._actions:  # noqa: SLF001 - argparse has no public API for this
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return action
    return None


def _visible(name: str) -> bool:
    # Hidden helpers (e.g. `__complete`) start with an underscore.
    return not name.startswith("_")


def _collect(parser: argparse.ArgumentParser, path: str, spec: _Spec) -> None:
    options: list[str] = []
    for action in parser._actions:  # noqa: SLF001
        if action.option_strings:
            options += action.option_strings
            if action.nargs != 0:  # store_true/help take no value
                spec.value_options.update(action.option_strings)
                if action.choices:
                    for opt in action.option_strings:
                        spec.option_choices[opt] = sorted(str(c) for c in action.choices)
        elif action.dest == "alias" and path not in _NEW_ALIAS_COMMANDS:
            spec.alias_paths.append(path)
        elif action.dest in _GROUP_POSITIONALS:
            patterns = [f'"{path}"']
            if _GROUP_POSITIONALS[action.dest] == "many":
                patterns.append(f'"{path} "*')  # second folder of `group mv` too
            spec.group_patterns += [p for p in patterns if p not in spec.group_patterns]
        elif action.choices and not isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            # A positional with fixed choices, e.g. `completion bash`.
            spec.choices[path] = sorted(str(c) for c in action.choices)
    if path:
        spec.options[path] = sorted(options)
    else:
        spec.global_options = sorted(options)

    sub = _subparsers(parser)
    if sub is None:
        return
    names = sorted(name for name in sub.choices if _visible(name))
    spec.choices[path] = names
    for name in names:
        _collect(sub.choices[name], f"{path} {name}".strip(), spec)


def _words(items: list[str]) -> str:
    return " ".join(items)


def bash_script(parser: argparse.ArgumentParser) -> str:
    """The bash completion script for `parser` (the `hsm` parser)."""
    spec = _Spec()
    _collect(parser, "", spec)

    value_cases = []
    for opt in sorted(spec.value_options):
        if opt in _DYNAMIC_VALUES:
            kind = _DYNAMIC_VALUES[opt]
            reply = (
                'COMPREPLY=($(compgen -f -- "$cur"))'
                if kind == "files"
                else f'COMPREPLY=($(compgen -W "$(_hsm_dynamic {kind})" -- "$cur"))'
            )
        elif opt in spec.option_choices:
            reply = f'COMPREPLY=($(compgen -W "{_words(spec.option_choices[opt])}" -- "$cur"))'
        else:
            reply = ":"  # free value (hostname, port, ...): nothing to suggest
        value_cases.append(f"        {opt}) {reply}; return 0 ;;")

    # Deepest paths first, so "pw get" wins over "pw".
    option_cases = [
        f'            "{path}"|"{path} "*) opts="{_words(opts)}" ;;'
        for path, opts in sorted(spec.options.items(), key=lambda kv: -kv[0].count(" "))
    ]
    choice_cases = [
        f'        "{path}") COMPREPLY=($(compgen -W "{_words(names)}" -- "$cur")) ;;'
        for path, names in sorted(spec.choices.items())
        if path
    ]
    alias_pattern = "|".join(f'"{p}"' for p in sorted(spec.alias_paths))
    group_pattern = "|".join(spec.group_patterns)

    return f"""\
# bash completion for hsm. Generated by `hsm completion bash`: do not edit,
# regenerate it after updating hsm.

_hsm_commands="{_words(spec.choices[""])}"
_hsm_value_opts=" {_words(sorted(spec.value_options))} "

# Aliases and tags come from your inventory, read at TAB time. Errors are
# silenced: completion must never print anything but candidates.
_hsm_dynamic() {{
    command hsm __complete "$1" 2>/dev/null
}}

_hsm() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}" prev="" word key opts i
    local -a pos=()
    COMPREPLY=()
    if (( COMP_CWORD > 0 )); then
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    fi

    # Positional words typed so far (command, action, alias...), skipping
    # options and the values of options that take one.
    for (( i = 1; i < COMP_CWORD; i++ )); do
        word="${{COMP_WORDS[i]}}"
        if [[ $_hsm_value_opts == *" $word "* ]]; then
            (( i++ ))
        elif [[ $word != -* ]]; then
            pos+=("$word")
        fi
    done
    key="${{pos[*]}}"

    # The value of an option.
    case "$prev" in
{chr(10).join(value_cases)}
    esac

    # An option of the current (sub)command.
    if [[ $cur == -* ]]; then
        case "$key" in
{chr(10).join(option_cases)}
            *) opts="{_words(spec.global_options)}" ;;
        esac
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
        return 0
    fi

    # A command, a nested action, or an existing alias.
    case "$key" in
        "") COMPREPLY=($(compgen -W "$_hsm_commands" -- "$cur")) ;;
{chr(10).join(choice_cases)}
        {alias_pattern}) COMPREPLY=($(compgen -W "$(_hsm_dynamic aliases)" -- "$cur")) ;;
        {group_pattern}) COMPREPLY=($(compgen -W "$(_hsm_dynamic groups)" -- "$cur")) ;;
    esac
    return 0
}}

complete -F _hsm hsm
"""
