# hsm — Limiti noti e modello di minaccia

Questo documento dice **da cosa hsm ti protegge e da cosa no**. Vale per la
versione su `feat/core-modules` (ottobre 2026), macOS su Apple Silicon, uso
personale da parte di un solo utente.

In una frase: hsm protegge bene le password **a riposo** (il file del vault
copiato, rubato, finito in un backup) e non lascia segreti in posti ovvi
(argomenti dei processi, variabili d'ambiente, log, file temporanei). **Non**
protegge da chi esegue codice come il tuo utente sul Mac sbloccato.

---

## Cosa c'è da proteggere

| Bene | Dove vive | Sensibilità |
|---|---|---|
| Password degli host | `~/.config/hsm/vault.enc`, cifrate | Alta |
| Chiave del vault (32 byte, derivata dalla master password) | login keychain, item `hsm` | Alta: apre il vault senza master password |
| Master password | solo nella tua testa; in memoria per un attimo durante l'unlock | Alta |
| Inventario (hostname, utenti, bastion, tag, note) | `~/.config/hsm/hosts.toml`, in chiaro | Media: è una mappa della tua infrastruttura |
| Ultimo uso degli host | `~/.config/hsm/state.toml`, in chiaro | Bassa: dice cosa usi e quando |
| Blocco generato | `~/.ssh/config` tra i marker, più i backup `config.hsm-backup-*` | Media, come l'inventario |

---

## Chi può attaccare, e cosa ottiene

### ✅ Chi ottiene una copia di `vault.enc`

È il caso per cui hsm è progettato: un backup su Time Machine o in cloud, un
disco smarrito, un repository di dotfile pubblicato per errore.

- **Il vault è cifrato con AES-256-GCM.** Senza la chiave non si legge
  nulla, nemmeno quali alias hanno una password: si cifra l'intero payload.
- **La chiave viene da Argon2id** con 256 MiB di memoria, 3 passate e 4
  lane. Ogni tentativo di indovinare la master password costa 256 MiB di
  RAM e circa 0,15 s su un Apple Silicon. Le GPU, che hanno tanta potenza
  di calcolo ma poca memoria per core, non danno un grande vantaggio.
- **Manomissioni:** il tag GCM autentica anche l'header. Un file alterato,
  compresi i parametri di Argon2 portati più in basso, viene rifiutato, mai
  decifrato male.
- **Limite:** la protezione vale quanto la master password. Il minimo è 12
  caratteri, ma una password corta o riusata altrove si indovina comunque.

### ✅ Altri utenti dello stesso Mac (non amministratori)

- I file e le directory di hsm sono 0600 e 0700, appartengono a te e non
  possono essere symlink. All'avvio hsm controlla tutto questo e **si
  rifiuta di partire** se qualcosa non torna. I controlli sono fatti sul
  file già aperto (`fstat`), così il file non può essere scambiato tra il
  controllo e la lettura.
- **La password di un host non compare mai negli argomenti dei processi**
  (visibili a tutti con `ps`) **né in una variabile d'ambiente.** A sshpass
  arriva tramite una pipe anonima che solo il processo figlio eredita.
- **La chiave del vault viene passata a `security` su stdin** (`security
  -i`), mai come argomento.
- **Il processo che svuota gli appunti riceve solo un contatore e una
  scadenza:** niente password e niente hash da attaccare offline.

### ✅ Un `hosts.toml` scritto male o manipolato

Per esempio un file condiviso in un repository di team, o modificato da uno
script.

- **Ogni campo viene analizzato, non solo filtrato:** IP con `ipaddress`,
  nomi DNS etichetta per etichetta, jump host scomposto in
  `[user@]host[:port]`. Un hostname come `-oProxyCommand=…` (che ssh
  eseguirebbe come comando) viene rifiutato. In più c'è sempre `--` prima
  della destinazione.
- **Nessun valore può aggiungere righe a `~/.ssh/config`.** A capo,
  virgolette, `#`, `\`, `$` e `%` non espanso vengono rifiutati, con un
  secondo controllo al momento della scrittura. Un valore sbagliato
  romperebbe l'intero file, per tutti gli host.
- **`jump_host = "none"` è vietato:** farebbe saltare il bastion in silenzio.
- **Alias:** unici senza distinguere maiuscole, e mai uguali all'hostname
  di un altro host. `Host 10.0.0.1` dirotterebbe chi digita `ssh 10.0.0.1`.
- **Limite:** hsm controlla la *forma* dei valori, non la *fiducia*. Se il
  file dice che `prod-db` è `attacker.example.com`, hsm ti collega lì, e con
  `auth = "password"` manda lì la password. Un `hosts.toml` condiviso va
  trattato come codice: va letto prima di usarlo.

### ⚠️ Qualcuno con il tuo Mac sbloccato tra le mani

- `hsm connect` e `hsm pw get` chiedono il Touch ID, e il cambio della
  master password richiede la vecchia password digitata. Questo ferma chi
  trova il portatile aperto e lancia `hsm`.
- **Ma il Touch ID è un controllo d'interfaccia, non un vincolo
  crittografico.** La policy accetta anche la password di macOS. Soprattutto,
  chi è seduto al tuo Mac sbloccato può aprire un terminale e leggere
  l'item del Keychain direttamente:
  `security find-generic-password -s hsm -w`.
  Un vincolo biometrico vero richiederebbe un binario firmato con
  entitlement Apple (opzione (b) scartata in fase di piano).

### ❌ Codice malevolo che gira come il tuo utente

Per esempio un malware, una dipendenza npm o pip compromessa, o un'estensione
dell'editor.

**hsm non protegge da questo.** Un processo con il tuo utente può:

- leggere la chiave del vault dal Keychain senza nessun prompt, e con quella
  decifrare il vault;
- leggere gli appunti nei 30 secondi in cui contengono una password;
- registrare quello che digiti, master password compresa;
- sostituire i file del virtualenv o del sorgente di hsm, che sono
  scrivibili dal tuo utente e quindi hanno lo stesso livello di fiducia di
  hsm stesso;
- modificare `hosts.toml`, perché i permessi 0600 non fermano il
  proprietario.

È la stessa situazione di un `~/.ssh/id_ed25519` senza passphrase: sul tuo
utente compromesso nessuno strumento in user space resiste.

### ❌ root / amministratore, o il Mac compromesso a livello di sistema

Fuori portata: può leggere la memoria di qualsiasi processo, il Keychain
sbloccato, tutto.

### ❌ Il server a cui ti colleghi con password

Con l'autenticazione a password la password **arriva al server**: è come
funziona quel metodo. Un server compromesso, o uno falso con una chiave host
accettata per errore, la riceve. Usa le chiavi SSH ogni volta che puoi:
in hsm sono il default, e la password è il caso secondario.

---

## Limiti noti, componente per componente

### Memoria

- **Python non garantisce di poter azzerare la memoria.** `Secret` tiene i
  segreti in un `bytearray` che viene azzerato, ma ogni `str` o `bytes`
  creato lungo la strada è immutabile e resta in memoria finché il garbage
  collector non lo libera. Succede con l'output di `getpass`, con il testo
  decifrato del vault, con l'output di `security` e con l'NSString degli
  appunti. È una mitigazione, non una garanzia.
- **Mitigazioni attive:**
  - i core dump sono disattivati (`RLIMIT_CORE = 0`);
  - i traceback non mostrano mai le variabili locali (argparse al posto di
    typer per questo motivo);
  - `repr` e `str` dei segreti sono redatti;
  - durante una sessione ssh restano in memoria solo la password necessaria
    e nient'altro del vault.
- macOS cifra lo swap, quindi le pagine scritte su disco non sono in chiaro.

### Keychain e Touch ID

- Nel Keychain sta la **chiave derivata**, non la master password. Chi la
  ruba apre questo vault, ma non scopre una password che potresti riusare
  altrove.
- Conseguenza: **finché l'item esiste nel Keychain, il vault si apre anche
  senza la master password.** Utile se la dimentichi, pericoloso se il
  Keychain è esposto.
- Dopo `hsm vault rekey` il salt cambia: l'item vecchio viene cancellato e
  la chiave vecchia non apre più il file nuovo.

### Vault e backup

- **`hsm vault rekey` non cambia i vault vecchi nei backup.** Una copia su
  Time Machine di prima del rekey si apre ancora con la vecchia master
  password. Se cambi la master password perché pensi sia compromessa,
  considera compromesse anche quelle copie.
- **Nessun recupero:** senza master password e senza item nel Keychain, il
  vault è perso. È voluto.
- Le scritture sono atomiche e forzate su disco (`F_FULLFSYNC`): un crash
  lascia il vault vecchio o quello nuovo, mai uno a metà.
- Il lock (`flock`) protegge solo da altri processi hsm. Un editor che
  modifica `hosts.toml` mentre hsm lavora può ancora perdere una modifica
  (la sync di `~/.ssh/config` invece se ne accorge e si ferma).

### Connessione con password (sshpass)

- `sshpass` risponde a **un solo prompt**: con un jump host, il bastion deve
  accettare la tua chiave SSH.
- `sshpass` **non sa accettare una chiave host nuova** (esce con codice 6).
  La prima connessione va fatta senza password, e la chiave va verificata
  a mano. hsm non cambia mai `StrictHostKeyChecking`.
- Il processo `sshpass` tiene la password in memoria per tutta la sessione.
- `sshpass` viene cercato solo in `/opt/homebrew/bin`, `/usr/local/bin` e
  `/usr/bin`, e scartato se è scrivibile da altri. Uno `sshpass` finto nel
  `PATH` non riceve la password.
- **Senza sshpass** (come su questo Mac oggi), hsm propone di copiare la
  password negli appunti e ti collega comunque: la incolli tu.

### Appunti

- Per 30 secondi **qualsiasi app** può leggere la password dagli appunti.
- I tipi `Concealed` e `Transient` chiedono ai gestori di cronologia (Maccy,
  Raycast, Paste…) di non salvarla. Un gestore che li ignora la salva
  comunque.
- **Appunti universali (Handoff):** macOS può sincronizzare gli appunti con
  i tuoi altri dispositivi Apple vicini. Non ho verificato se rispetta il
  tipo `Transient`. Se ti preoccupa, disattiva Handoff oppure non usare
  `pw get` con altri dispositivi vicini.
- Se il processo che svuota gli appunti viene ucciso, la password resta
  negli appunti fino al logout. La scadenza è su orologio reale, quindi
  regge lo stop del Mac.

### File in chiaro

- **`hosts.toml`, il blocco in `~/.ssh/config` e i suoi backup sono una
  mappa della tua infrastruttura:** hostname interni, utenti, bastion, note.
  Non contengono segreti, ma in un repository pubblico sono materiale da
  ricognizione per un attaccante.
- **git non conserva i permessi 0600.** Dopo un clone, hsm si rifiuta di
  partire finché non lanci il `chmod` che ti indica.
- **I backup di `~/.ssh/config` si accumulano**, uno per ogni sync che
  cambia qualcosa. Sono 0600, ma vanno ripuliti a mano.
- **`hsm sync` rifiuta un `~/.ssh/config` symlink** (comune con i dotfile) o
  con permessi 0644.

### Rete

- hsm non fa chiamate di rete: l'unico traffico è quello di `/usr/bin/ssh`,
  che lanci tu.

---

## Cosa conviene fare

1. **Master password lunga e unica**, possibilmente una passphrase di più
   parole. È l'unica difesa del vault copiato.
2. **FileVault attivo:** protegge Keychain, swap e file di hsm a Mac spento.
3. **Chiavi SSH ovunque possibile.** `auth = "password"` solo per gli host
   che non ti lasciano scelta.
4. **Blocca lo schermo** quando ti allontani: il Touch ID di hsm non basta.
5. **Leggi gli `hosts.toml` che non hai scritto tu** prima di usarli.
6. **Dopo un rekey "di emergenza"**, considera compromessi i vault vecchi
   nei backup, e cambia le password degli host che contenevano.

---

## Verificato e non verificato

**Verificato con test automatici (540, copertura 99%):** cifratura e
manomissioni del vault, permessi e symlink, Keychain reale (roundtrip con un
item di test), passaggio della password via pipe con un vero processo
figlio, configurazione risolta da `ssh -G` (OpenSSH 10.3), avvio reale del
watchdog degli appunti, comando `hsm` reale in una HOME temporanea.

**Non verificato in automatico, da provare a mano:**

- prompt Touch ID reale (provato da te durante lo sviluppo di `touchid.py`);
- scrittura e cancellazione degli appunti reali:
  `HSM_CLIPBOARD_TESTS=1 .venv/bin/pytest tests/test_clipboard.py -k real_pasteboard`;
- `hsm pw set` e `hsm connect` verso un host vero, con e senza sshpass;
- comportamento degli appunti universali con il tipo `Transient`.
