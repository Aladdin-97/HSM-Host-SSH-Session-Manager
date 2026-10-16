"""Selettore di host per `hsm` senza argomenti: fzf se c'è, altrimenti una lista.

Restituisce solo l'host scelto (o None): il connect lo fa la CLI.

Con fzf ogni host è una riga separata da tab, preceduta da un indice che
fzf non mostra (--with-nth=2..):

    2   web01   deploy@10.0.0.1:2222   #prod #web   frontend

fzf disegna la sua interfaccia su /dev/tty e legge le righe da stdin;
scrive su stdout la riga scelta, e da quell'indice ricaviamo l'host. Se
l'output non è esattamente una riga "<indice>\t...", ci fermiamo: meglio
un errore che collegarsi all'host sbagliato. Per lo stesso motivo togliamo
FZF_DEFAULT_OPTS dall'ambiente di fzf: opzioni come --print-query o
--expect cambierebbero il formato dell'output.
Le righe arrivano nell'ordine ricevuto (di solito: usati di recente prima)
e `--tiebreak=index` lo conserva a parità di punteggio.

fzf non riceve segreti, quindi lo cerchiamo nel PATH come qualsiasi
comando, ma solo se il percorso è assoluto (niente "./fzf"). I campi
mostrati sono già validati da Host (niente tab, a capo o sequenze di
escape), quindi non possono alterare il terminale.

Senza fzf: lista numerata. Si digita un numero per scegliere, oppure un
testo per filtrare (alias, host, tag, note; senza maiuscole). Il filtro
sceglie da solo solo se il testo è esattamente un alias: altrimenti anche
con un solo risultato serve il numero, perché un refuso non porti su un
host qualsiasi. Invio a vuoto esce.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from hsm.errors import HsmError
from hsm.inventory import DEFAULT_PORT, Host

# Codici d'uscita di fzf: 1 = nessuna corrispondenza, 130 = Esc o Ctrl-C.
_FZF_NO_MATCH = 1
_FZF_INTERRUPTED = 130

# Solo cifre ASCII e non troppe: '²'.isdigit() è True ma int('²') fallisce,
# e int() rifiuta stringhe di oltre 4300 cifre.
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
    """alias, [user@]host[:porta], #tag, nota — separati da tab."""
    address = f"[{host.hostname}]" if ":" in host.hostname and host.port != DEFAULT_PORT else host.hostname
    target = (f"{host.user}@" if host.user else "") + address
    if host.port != DEFAULT_PORT:
        target += f":{host.port}"
    tags = " ".join(f"#{t}" for t in host.tags)
    return "\t".join([host.alias, target, tags, host.note or ""])


class Picker:
    """Sceglie un host in modo interattivo. Dipendenze esterne iniettabili."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        input: Callable[[str], str] = input,  # noqa: A002 - stesso nome della builtin di default
        output: Callable[[str], None] = print,
    ) -> None:
        self._which = which
        self._runner = runner
        self._input = input
        self._output = output

    def choose(self, hosts: Sequence[Host]) -> Host | None:
        """L'host scelto, o None se l'utente rinuncia."""
        if not hosts:
            raise HsmError("Inventario vuoto: aggiungi un host con hsm add <alias>.")
        fzf = self._which("fzf")
        if fzf is not None and os.path.isabs(fzf):
            try:
                return self._choose_fzf(fzf, hosts)
            except FileNotFoundError:
                pass  # sparito tra which e l'esecuzione: si usa la lista
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
            raise HsmError(f"fzf è terminato con errore (codice {result.returncode}).")
        match = _FZF_CHOICE_RE.fullmatch(result.stdout)
        index = int(match.group(1)) if match else 0
        if not 1 <= index <= len(hosts):
            raise HsmError("fzf ha restituito una scelta in un formato inatteso: non mi collego.")
        return hosts[index - 1]

    def _choose_from_list(self, hosts: Sequence[Host]) -> Host | None:
        current = list(hosts)
        while True:
            self._show(current)
            try:
                answer = self._input("Numero o filtro (invio per uscire): ").strip()
            except EOFError:
                return None
            if not answer:
                return None
            if _INDEX_RE.fullmatch(answer):
                index = int(answer)
                if 1 <= index <= len(current):
                    return current[index - 1]
                self._output(f"Numero fuori intervallo (1-{len(current)}).")
                continue
            needle = answer.casefold()
            # Il filtro parte sempre dall'elenco completo: un secondo filtro
            # sostituisce il primo invece di restringerlo ancora.
            matches = [h for h in hosts if needle in format_line(h).casefold()]
            if not matches:
                self._output(f"Nessun host corrisponde a {answer!r}.")
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
