# hsm

Un CLI per gestire un inventario di host SSH su macOS, pensato per
sostituire l'albero sessioni di MobaXterm.

- **Salva gli host** in un file TOML leggibile e versionabile, senza segreti.
- **Li organizza** con tag e li cerca, anche con un selettore interattivo.
- **Salva le password** in un vault cifrato (AES-256-GCM, chiave da
  Argon2id), sbloccato con Touch ID.
- **Si collega** con l'`ssh` nativo del sistema (`/usr/bin/ssh`). Non
  reimplementa SSH.
- **Genera un blocco** in `~/.ssh/config`, così `ssh <alias>` funziona anche
  senza hsm.

La chiave SSH è il caso normale: la password è il caso secondario, per gli
host che non lasciano scelta.

> Prima di affidargli password vere, leggi
> [THREAT_MODEL.md](THREAT_MODEL.md): da cosa hsm protegge e da cosa no.

---

## Indice

- [Requisiti](#requisiti)
- [Installazione](#installazione)
- [Primi passi](#primi-passi)
- [Comandi](#comandi)
- [Il file hosts.toml](#il-file-hoststoml)
- [Password e vault](#password-e-vault)
- [Connessione](#connessione)
- [Sync verso ~/.ssh/config](#sync-verso-sshconfig)
- [File e permessi](#file-e-permessi)
- [Sicurezza in breve](#sicurezza-in-breve)
- [Problemi comuni](#problemi-comuni)
- [Sviluppo](#sviluppo)
- [Disinstallazione](#disinstallazione)

---

## Requisiti

| Cosa | Necessario? | Note |
|---|---|---|
| macOS (Apple Silicon) | sì | Usa Keychain, Touch ID e NSPasteboard |
| Python 3.12+ | sì | `uv` lo scarica da solo se manca |
| [uv](https://docs.astral.sh/uv/) | consigliato | Per installare e per lo sviluppo |
| `/usr/bin/ssh` | sì | Già presente su macOS |
| `sshpass` | opzionale | Solo per collegarsi in automatico agli host con password. Senza, hsm copia la password negli appunti e la incolli tu |
| `fzf` | opzionale | Per il selettore fuzzy. Senza, c'è una lista numerata |

Per installare gli strumenti opzionali con Homebrew:

```bash
brew install fzf
```

```bash
brew install hudochenkov/sshpass/sshpass
```

`sshpass` non è nel repository principale di Homebrew: quello sopra è un tap
di terze parti molto usato. Valuta tu se fidarti.

### Dipendenze Python

| Pacchetto | Perché |
|---|---|
| `cryptography` ≥ 44 | AES-256-GCM e Argon2id. Contiene Argon2 nativo, quindi niente `argon2-cffi` |
| `tomlkit` | Riscrive `hosts.toml` conservando i commenti scritti a mano |
| `pyobjc-framework-LocalAuthentication` | Prompt Touch ID: non esiste un comando di sistema equivalente |
| `pyobjc-framework-Cocoa` | Appunti con i tipi "da non salvare in cronologia", cosa che `pbcopy` non permette. È già richiesto dal pacchetto precedente |

La riga di comando usa `argparse` e non `typer`: typer, di default, mostra le
variabili locali nei traceback, e lì potrebbe finire una password.

---

## Installazione

Dalla cartella del progetto:

```bash
uv tool install .
```

Il comando `hsm` finisce in `~/.local/bin`. Se la shell non lo trova,
aggiungi quella directory al `PATH`:

```bash
uv tool update-shell
```

Per aggiornare dopo un `git pull`:

```bash
uv tool install --reinstall .
```

Per usarlo senza installarlo, dalla cartella del progetto:

```bash
uv sync
```

```bash
.venv/bin/hsm --help
```

---

## Primi passi

```bash
# 1. Aggiungi un bastion e un host che passa da lì
hsm add bastion --hostname bastion.example.com --user jump --port 2200
hsm add web01 --hostname 10.0.0.1 --user deploy --tag prod --tag web --jump bastion

# 2. Guarda l'inventario
hsm ls

# 3. Collegati (chiave SSH: nessun prompt di hsm)
hsm connect web01

# 4. Oppure scegli dal selettore e premi invio
hsm

# 5. Fai funzionare anche `ssh web01` da qualsiasi terminale
hsm sync --dry-run      # prima guarda cosa cambierebbe
hsm sync
```

Per un host che accetta solo la password:

```bash
hsm add legacy01 --hostname 10.0.0.9 --user admin
hsm pw set legacy01     # la prima volta crea il vault e chiede una master password
hsm connect legacy01    # Touch ID → sshpass (oppure appunti, se manca sshpass)
```

Senza flag, `hsm add <alias>` fa le domande una per una:

```text
$ hsm add db
Hostname: db.example.com
Utente (invio = default di ssh): postgres
Porta [22]:
Tag (separati da spazi): prod db
Jump host:
Chiave SSH (identity_file): ~/.ssh/id_db
Nota: il database principale
Aggiunto db.
```

---

## Comandi

| Comando | Cosa fa |
|---|---|
| `hsm` | Selettore interattivo; invio = connect |
| `hsm add <alias> [flag]` | Aggiunge un host, con i flag o con le domande |
| `hsm edit <alias> [flag]` | Modifica un host, con i flag o con le domande |
| `hsm ls [--tag X] [--sort alias\|tag\|recent]` | Elenca gli host |
| `hsm rm <alias> [--force]` | Rimuove un host (e la sua password, se ne ha una) |
| `hsm connect <alias>` | Apre la sessione ssh |
| `hsm pw set <alias>` | Salva la password dell'host nel vault |
| `hsm pw get <alias>` | Copia la password negli appunti; si cancella dopo 30 s |
| `hsm pw rm <alias>` | Toglie la password dal vault |
| `hsm vault rekey` | Cambia la master password |
| `hsm sync` | Rigenera il blocco hsm in `~/.ssh/config` |

**Opzioni globali**
- `--debug`: in caso di errore mostra il traceback completo, che non
  contiene mai le variabili locali.

**`--dry-run`** (su `add`, `edit`, `rm`, `sync`)
- Mostra il diff di quello che cambierebbe e non scrive nulla.

**Flag di `add` ed `edit`**

| Flag | Campo |
|---|---|
| `--hostname` | `hostname` (obbligatorio in `add` se usi i flag) |
| `--user` | `user` |
| `--port` | `port` |
| `--tag` | `tags`, ripetibile: `--tag prod --tag web` |
| `--jump` | `jump_host` |
| `--identity` | `identity_file` |
| `--note` | `note` |

**Due dettagli pratici**
- **Un valore che inizia con `-` va passato con `=`**, altrimenti argparse lo
  scambia per un'opzione: `--note=-da-rivedere`.
- **Per cancellare un campo** usa `hsm edit <alias>` senza flag e rispondi
  `-` alla domanda; invio lascia il valore com'è. Con i flag si possono solo
  impostare valori, non cancellarli.

**Ordinamento di `hsm ls`**
- `alias` (default), `tag` (per primo tag, gli host senza tag in fondo),
  `recent` (prima i più usati di recente).

```text
$ hsm ls --sort recent
ALIAS     HOST                           TAG         AUTH      ULTIMO USO
web01     deploy@10.0.0.1                #prod #web  key       2026-10-16 14:02
legacy01  admin@10.0.0.9                 -           password  2026-10-15 09:30
bastion   jump@bastion.example.com:2200  -           key       mai
```

**Selettore (`hsm` senza argomenti)**
- **Con fzf:** filtro fuzzy, invio per scegliere, Esc per uscire.
- **Senza fzf:** lista numerata. Digiti un numero per scegliere, oppure un
  testo per filtrare (cerca in alias, host, tag e note).
  - Il filtro sceglie da solo solo se il testo è **esattamente un alias**;
    altrimenti serve il numero, così un refuso non ti collega a un host
    qualsiasi.
  - Un filtro fatto solo di cifre viene sempre letto come numero di riga.

**`hsm rm` di un host usato come jump**
- Se l'host è il `jump_host` di altri host, serve `--force`. Altrimenti
  quegli host risolverebbero il bastion via DNS, magari verso una macchina
  diversa.

---

## Il file hosts.toml

Vive in `~/.config/hsm/hosts.toml`. Una tabella per host:

```toml
# I miei server: i commenti restano anche dopo hsm add/edit.

[hosts.web01]
hostname = "10.0.0.1"
user = "deploy"
port = 2222                      # omesso se 22
tags = ["prod", "web"]
jump_host = "bastion"            # alias hsm, oppure [user@]host[:port]
identity_file = "~/.ssh/id_ed25519"
note = "frontend principale"

[hosts.legacy01]
hostname = "10.0.0.9"
user = "admin"
auth = "password"                # impostato da `hsm pw set`, omesso se "key"
```

| Campo | Obbligatorio | Regole |
|---|---|---|
| alias (nome della tabella) | sì | Lettere, cifre, `.`, `_`, `-`; inizia con lettera o cifra; max 64. Unico **senza distinguere maiuscole** (come fa ssh) e mai uguale all'hostname di un altro host |
| `hostname` | sì | Un IP (IPv4, IPv6, anche con zona come `fe80::1%en0`) o un nome DNS valido. Mai un `-` iniziale |
| `user` | no | Lettere, cifre, `.`, `_`, `-`; niente `@` |
| `port` | no | 1–65535, default 22 |
| `tags` | no | Lista di parole: lettere, cifre, `_`, `-` |
| `jump_host` | no | Un alias dell'inventario oppure `[user@]host[:port]`, con IPv6 tra `[ ]`. **Mai `none`**: per ssh significherebbe "nessun bastion" |
| `identity_file` | no | Assoluto o che inizia con `~`. Spazi ammessi; vietati `"`, `\`, `%` e `$`, che ssh_config espanderebbe |
| `note` | no | Testo libero su una riga, senza caratteri di controllo |
| `auth` | no | `"key"` (default) oppure `"password"`. Lo gestiscono `hsm pw set` e `hsm pw rm` |

`auth` dice solo **come** ci si autentica, mai con cosa. Serve perché
`hsm connect` sappia se aprire il vault: per gli host a chiave non c'è
nessun Touch ID e nessuna master password.

Le regole sono strette perché questi valori finiscono negli argomenti di
ssh e in `~/.ssh/config`. Per esempio un hostname `-oProxyCommand=…`
verrebbe eseguito da ssh come un comando. Un errore nel file dice quale host
e quale campo correggere:

```text
hsm: Host web01: hostname non valido: '-oProxyCommand=touch /tmp/x'
```

**Versionarlo con git** va bene: non contiene segreti, ma è una mappa della
tua infrastruttura, quindi niente repository pubblici. git non conserva i
permessi 0600: dopo un clone hsm si rifiuta di partire e ti dice il `chmod`
da lanciare.

---

## Password e vault

### Come funziona lo sblocco

```text
hsm connect legacy01
   │
   ├─ Touch ID ──ok──► chiave dal Keychain ──apre il vault?──sì──► sshpass
   │                         │                     │
   └─ annullato / non        └─ assente            └─ no: la rimuove
      disponibile                │                     │
      (es. via SSH)              ▼                     ▼
                       ──────────► master password (3 tentativi)
                                   └─► salva la chiave nel Keychain
```

- **La prima volta** (`hsm pw set` senza vault) hsm crea il vault e ti
  chiede una **master password nuova**, due volte, di almeno 12 caratteri.
- **Dopo il primo sblocco**, la chiave derivata (non la master password) va
  nel login keychain e gli sblocchi successivi passano dal Touch ID. Se
  Touch ID non è disponibile (Mac via SSH, coperchio chiuso senza Apple
  Watch) hsm chiede la master password. Non ripiega mai su "niente
  cifratura".
- **`hsm vault rekey`** cambia la master password. Chiede **la vecchia
  digitata**: il Touch ID non basta. Rigenera salt e chiave e aggiorna
  l'item nel Keychain.

### Formato di vault.enc

| Byte | Campo |
|---|---|
| 0–3 | `HSMV` |
| 4 | versione del formato (1) |
| 5 | KDF (1 = Argon2id) |
| 6–9, 10–13, 14 | memoria (KiB), passate, parallelismo |
| 15–31 | lunghezza (16) e salt |
| 32–44 | lunghezza (12) e nonce |
| 45– | testo cifrato + tag GCM |

Le scelte crittografiche sono spiegate nei commenti di
[src/hsm/vault.py](src/hsm/vault.py):
- **AES-256-GCM:** cifratura autenticata, quindi rileva le manomissioni.
- **Argon2id** con 256 MiB, 3 passate e 4 lane: rende costoso il brute
  force.
- **Nonce di 96 bit** casuale a ogni scrittura, mai riusato.
- **Salt di 128 bit** generato una volta e salvato in chiaro.
- **Header autenticato** come AAD: nessuno può abbassare i parametri senza
  che la decifratura fallisca.

### Cose da sapere

- **Non c'è recupero.** Senza master password e senza item nel Keychain il
  vault è perso.
- **Il rekey non cambia le copie vecchie del vault** che stanno nei backup:
  quelle si aprono ancora con la vecchia master password.

---

## Connessione

`hsm connect` costruisce la riga di comando di ssh dai campi dell'host, e
funziona anche senza aver mai fatto `hsm sync`:

```text
/usr/bin/ssh -l deploy -p 2222 -J jump@bastion.example.com:2200 \
             -i /Users/tu/.ssh/id_ed25519 -o IdentitiesOnly=yes -- 10.0.0.1
```

- **`--`** impedisce che la destinazione venga letta come opzione.
- **`-J`**: se `jump_host` è un alias dell'inventario viene tradotto in
  `user@host:porta`, risalendo la catena se anche il bastion ha un jump.
  L'`identity_file` del bastion vale solo dopo `hsm sync`.
- **`IdentitiesOnly=yes`** accanto a `-i` evita "Too many authentication
  failures" quando l'agent ha molte chiavi.
- **Ctrl-C durante la sessione arriva a ssh**, non a hsm.
- **Il codice d'uscita di `hsm connect` è quello di ssh.**

**Con `auth = "password"`**
- La password arriva a `sshpass -d <fd>` tramite una pipe anonima, mai
  negli argomenti (visibili con `ps`) né nell'ambiente.
- L'autenticazione a password è forzata.
- `sshpass` viene cercato solo in `/opt/homebrew/bin`, `/usr/local/bin` e
  `/usr/bin`, mai nel `PATH`.
- Durante la sessione restano in memoria solo quella password e nient'altro
  del vault.
- **Senza sshpass**, hsm lo dice, propone di copiare la password negli
  appunti (cancellata dopo 30 s) e si collega comunque: la incolli al
  prompt.
- **Due limiti:**
  - `sshpass` risponde a un solo prompt, quindi il bastion deve accettare
    la tua chiave SSH;
  - non sa accettare una chiave host nuova, quindi la prima connessione va
    fatta senza password (vedi [Problemi comuni](#problemi-comuni)).

---

## Sync verso ~/.ssh/config

```bash
hsm sync --dry-run    # mostra il diff
hsm sync
```

Scrive solo tra due marker:

```text
# >>> hsm begin
# Generato da `hsm sync`: le modifiche qui dentro verranno sovrascritte.

Host web01
    HostName 10.0.0.1
    User deploy
    Port 2222
    ProxyJump bastion
    IdentityFile "~/.ssh/id_ed25519"
    IdentitiesOnly yes

# Riporta lo scope a globale per le righe che seguono il blocco.
Host *
# <<< hsm end
```

**Le regole**
- **Tutto ciò che sta fuori dai marker resta identico, byte per byte.**
- **Se i marker non ci sono, il blocco va in cima al file.** In ssh_config
  vince il primo valore trovato, quindi in cima i valori di hsm non vengono
  scavalcati da un `Host *` scritto più in basso.
- **Il `Host *` finale serve a non rompere le tue opzioni globali.** In
  ssh_config un'opzione appartiene al blocco `Host` sopra di lei: senza
  quella riga, un `ServerAliveInterval` che avevi in cima al file finirebbe
  dentro l'ultimo host di hsm. È verificato con `ssh -G`.
- **Prima di scrivere c'è un backup 0600**,
  `~/.ssh/config.hsm-backup-AAAAMMGGTHHMMSS`, ma solo se qualcosa cambia.
  I backup non vengono mai cancellati: ripuliscili a mano ogni tanto.
- **È idempotente:** due sync di fila producono lo stesso file e nessun
  secondo backup.
- **hsm non tocca il file in tre casi:** marker malformati (uno solo,
  invertiti, doppi), file modificato da un editor durante la sync, file che
  non è testo UTF-8. In tutti e tre ti dice cosa correggere.

---

## File e permessi

| Percorso | Contenuto | Permessi |
|---|---|---|
| `~/.config/hsm/` | directory di hsm | 0700 |
| `~/.config/hsm/hosts.toml` | inventario, in chiaro | 0600 |
| `~/.config/hsm/vault.enc` | password, cifrate | 0600 |
| `~/.config/hsm/state.toml` | ultimo uso per host | 0600 |
| `~/.config/hsm/vault.lock` | lock tra processi hsm (vuoto) | 0600 |
| `~/.ssh/config` | blocco generato da `hsm sync` | 0600 (`~/.ssh` 0700) |
| login keychain, item `hsm` | chiave del vault | gestito da macOS |

**I controlli all'avvio**
- Directory e file devono appartenere a te, non essere symlink e non essere
  accessibili a gruppo o altri.
- Se qualcosa non torna, hsm **si rifiuta di partire** e stampa il `chmod`
  da lanciare. Non corregge da solo: un permesso sbagliato può essere il
  segno di qualcosa da capire.
- I permessi di `~/.ssh/config` vengono controllati da `hsm sync`, non a
  ogni comando.

**Come vengono scritti i file**
- Tutte le scritture sono atomiche (file temporaneo 0600, poi rename) e
  forzate su disco.
- Le modifiche a `hosts.toml` e al vault avvengono sotto un lock: due hsm
  in parallelo non si cancellano le modifiche a vicenda.

**Lo stato**
- `state.toml` è un dato di comodo: se si rompe, hsm avvisa e lo riscrive.
  Non blocca mai un connect.

---

## Sicurezza in breve

**Protegge da**
- chi ottiene una copia di `vault.enc` (backup, disco perso, dotfile
  pubblicati);
- altri utenti dello stesso Mac;
- valori malevoli in `hosts.toml` che proverebbero a iniettare opzioni o
  righe di configurazione.

**Non protegge da**
- codice malevolo che gira come il tuo utente: può leggere la chiave dal
  Keychain senza prompt;
- root;
- chi ha il tuo Mac sbloccato e sa usare il terminale;
- il server che riceve la password quando ti autentichi con password.

Il Touch ID di hsm è un controllo d'interfaccia, non una barriera
crittografica. Python non garantisce di poter azzerare la memoria: hsm
riduce le copie in chiaro, ma non può eliminarle tutte.

I dettagli, i limiti per componente e i consigli sono in
**[THREAT_MODEL.md](THREAT_MODEL.md)**.

---

## Problemi comuni

**`Permessi troppo aperti su … Correggi con: chmod 600 …`**
Lancia il comando suggerito. Succede spesso dopo aver clonato `hosts.toml`
da git, o con un `~/.ssh/config` creato con i permessi di default (0644).

**`hsm sync`: `~/.ssh/config è un symlink`**
hsm non scrive attraverso un symlink. Succede spesso se gestisci i dotfile
con un repository. Ci sono due strade:
- sostituisci il symlink con un file vero e aggiungi una riga
  `Include ~/dotfiles/ssh_config` che punti al tuo file;
- oppure non usare `hsm sync` e collegati con `hsm connect`.

**`sshpass ha restituito 6`**
È la prima connessione a quell'host e sshpass non sa accettare la sua
chiave. Collegati una volta senza sshpass e verifica l'impronta della
chiave quando ssh la mostra:

```bash
ssh -l admin 10.0.0.9
```

Poi `hsm connect` funziona.

**`sshpass ha restituito 5`**
Probabilmente la password è cambiata sul server. Aggiornala:

```bash
hsm pw set legacy01
```

**`Touch ID non disponibile: inserisci la master password`**
Normale se sei collegato al Mac via SSH o se il coperchio è chiuso senza
Apple Watch.

**`Un altro hsm sta modificando il vault`**
Un altro comando hsm sta aspettando una password o il Touch ID. Completalo
o chiudilo, poi riprova.

**`jump_host 'xyz' non è un alias dell'inventario`**
Probabilmente è un refuso nel nome del bastion. Se invece è davvero un nome
host senza dominio, l'avviso si può ignorare.

**`argument --note: expected one argument`**
Il valore inizia con `-`: scrivilo come `--note=-valore`.

**Qualcosa non torna e vuoi più dettagli**

```bash
hsm --debug <comando>
```

---

## Sviluppo

```bash
uv sync
```

```bash
.venv/bin/pytest
```

```bash
.venv/bin/pytest --cov=hsm --cov-report=term-missing
```

### Test che toccano il sistema reale (opzionali)

Sono saltati per default. Vanno abilitati uno alla volta:

| Variabile | Cosa fa |
|---|---|
| `HSM_KEYCHAIN_TESTS=1` | Crea, legge e cancella un item `hsm-test` nel login keychain |
| `HSM_TOUCHID_TESTS=1` | Mostra un vero prompt Touch ID (aggiungi `-s` per vedere i messaggi) |
| `HSM_CLIPBOARD_TESTS=1` | **Sovrascrive i tuoi appunti** per circa 4 secondi |

```bash
HSM_KEYCHAIN_TESTS=1 .venv/bin/pytest tests/test_keychain.py -k real
```

Altri test usano strumenti veri senza rischi:
- `ssh -G`, che risolve la configurazione senza collegarsi;
- un finto `sshpass`, per il passaggio della password via pipe;
- il watchdog degli appunti avviato davvero, che legge soltanto.

### Struttura

```text
src/hsm/
├── errors.py      errori di dominio, excepthook senza variabili locali
├── secret.py      contenitore per segreti: repr redatto, azzeramento esplicito
├── fsutil.py      permessi 0600/0700, scrittura atomica, lock tra processi
├── vault.py       formato di vault.enc, Argon2id, AES-256-GCM, rekey
├── keychain.py    chiave del vault nel login keychain via `security -i`
├── touchid.py     controllo di presenza con LocalAuthentication
├── unlock.py      Touch ID + Keychain, oppure master password
├── inventory.py   hosts.toml: modello Host e validazione dei campi
├── state.py       state.toml: ultimo uso per host
├── sshconfig.py   blocco tra i marker in ~/.ssh/config
├── connect.py     argomenti di ssh, ProxyJump, sshpass via pipe
├── clipboard.py   appunti con cancellazione automatica (watchdog staccato)
├── picker.py      selettore: fzf o lista numerata
└── cli.py         riga di comando: collega i moduli
```

Le dipendenze vanno in una sola direzione, dal basso verso l'alto.
`vault.py` non sa nulla di Keychain o prompt: riceve una password e
restituisce una chiave, oppure riceve una chiave e legge o scrive.

### Regole del progetto

- **Un modulo alla volta, in TDD:** prima i test, che devono fallire, poi il
  codice.
- **Ogni scelta crittografica ha un commento** che spiega perché.
- **Mai crittografia fatta a mano:** solo `cryptography`.
- **Mai `except` generici che silenziano gli errori;** mai password in
  chiaro su disco, nemmeno temporaneamente.
- **Nessuna chiamata di rete** fuori da ssh; nessuna GUI, TUI o web server.

Le specifiche originali sono in [SPEC.md](SPEC.md).

---

## Disinstallazione

```bash
uv tool uninstall hsm
```

Per togliere anche i dati, prima rimuovi la chiave dal Keychain:

```bash
security delete-generic-password -s hsm
```

Poi cancella la directory di hsm, **dopo aver controllato** che non ti
servano più le password che contiene:

```bash
rm -r ~/.config/hsm
```

Infine togli a mano da `~/.ssh/config` il blocco tra `# >>> hsm begin` e
`# <<< hsm end`, e se vuoi i file `~/.ssh/config.hsm-backup-*`.
