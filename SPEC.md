Costruiamo insieme un CLI Python per gestire un inventario di host SSH.
Non scrivere ancora codice: prima leggi tutto e dimmi le assunzioni che fai.

OBIETTIVO
Un tool da riga di comando che sostituisca l'albero sessioni di MobaXterm:
salva macchine, le organizza con tag, le cerca, salva le password cifrate,
e lancia la connessione usando l'ssh nativo del sistema.

CONTESTO
- macOS (Apple Silicon), Python 3.12, uso personale su decine di host
- Utente: infrastructure engineer, conosce Python ma vuole CAPIRE il codice,
  non solo eseguirlo. Spiega le scelte non ovvie con commenti brevi.
- Motore di connessione: /usr/bin/ssh nativo. Non implementare SSH in Python,
  non usare paramiko.

MODELLO DATI
- Inventario in ~/.config/hsm/hosts.toml (leggibile e versionabile, SENZA segreti)
- Campi host: alias, hostname, user, port, tag[], jump_host, identity_file, note
- Il vault dei segreti è un file separato e cifrato: ~/.config/hsm/vault.enc

SICUREZZA (la parte che conta — leggi con attenzione)
- Vault cifrato con AES-256-GCM. Chiave derivata dalla master password con
  Argon2id (parametri espliciti e commentati, non default della libreria).
- La master password NON viene chiesta a ogni comando: dopo il primo unlock
  viene memorizzata nel Keychain macOS come item protetto da biometria, così
  gli unlock successivi passano da Touch ID. Usa il comando `security` o
  una libreria equivalente; spiega nel codice cosa stai facendo e perché.
- Se il Keychain non è disponibile, fallback al prompt della master password.
  Mai fallire in modo silenzioso verso "nessuna cifratura".
- Nonce casuale per ogni cifratura, mai riusato. Salt generato una volta e
  salvato in chiaro nell'header del vault.
- La password in chiaro deve vivere il meno possibile in memoria: niente log,
  niente stacktrace che la contengano, niente repr degli oggetti che la
  tengono.
- Permessi 0600 su vault e config. Verificali all'avvio e rifiuta di partire
  se sono più permissivi.

COMANDI
  hsm add <alias>      aggiunge un host (flag o prompt interattivo)
  hsm ls [--tag X]     lista, ordinabile per alias/tag/ultimo uso
  hsm rm <alias>
  hsm edit <alias>
  hsm connect <alias>  apre la sessione ssh
  hsm                  senza argomenti: selettore fuzzy, invio = connect
  hsm pw set <alias>   salva la password nel vault
  hsm pw get <alias>   copia in clipboard con auto-clear dopo 30s
  hsm sync             rigenera un blocco delimitato in ~/.ssh/config

CONNESSIONE
- Default: chiave SSH. La password è il caso secondario, non il primo.
- Con password: usa sshpass passandola via file descriptor o fifo con
  permessi 0600, MAI come argomento di command line (visibile in ps) e
  mai in una variabile d'ambiente esportata.
- Se sshpass non è installato, dillo e offri il fallback "copia in clipboard
  e connetti", senza fallire.
- Supporta ProxyJump dal campo jump_host.

SYNC VERSO SSH_CONFIG
- Scrive solo tra marker "# >>> hsm begin" / "# <<< hsm end"
- Non tocca una riga fuori da quel blocco
- Fa un backup prima di scrivere
- Idempotente: due sync di fila producono lo stesso file

NON FUNZIONALI
- Dipendenze minime: typer (o argparse), cryptography, argon2-cffi, tomlkit.
  Giustifica ogni dipendenza aggiunta oltre queste.
- Type hints ovunque, docstring sulle funzioni pubbliche
- Errori con messaggi utili all'utente, non stacktrace nudi
- --dry-run su add/rm/edit/sync
- Nessuna chiamata di rete fuori da ssh

VINCOLI
- Non reimplementare crittografia a mano: usa `cryptography`, non costruzioni
  artigianali con hashlib.
- Non scrivere mai la password in chiaro su disco, nemmeno temporaneamente.
- Non silenziare eccezioni con except generici.
- Non aggiungere una GUI, un TUI o un web server.

OUTPUT
1. Prima: assunzioni, domande aperte e lo schema del vault (header + payload).
2. Poi, su mio ok: struttura dei moduli, poi il codice un modulo alla volta,
   partendo da vault.py (la parte critica), così posso leggerlo prima di
   proseguire.
3. Per ogni scelta crittografica, due righe di spiegazione del PERCHÉ.
4. Chiudi con una sezione "Limiti noti e modello di minaccia": da cosa questo
   tool protegge e da cosa NON protegge.

Non generare tutto in un colpo. Procedi a moduli e fermati tra uno e l'altro.
