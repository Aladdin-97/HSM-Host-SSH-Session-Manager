# hsm

A CLI to manage an inventory of SSH hosts on macOS, built to replace
MobaXterm's session tree.

- **Saves hosts** in a readable, versionable TOML file, with no secrets.
- **Organizes them** with tags and searches them, including with an
  interactive picker.
- **Stores passwords** in an encrypted vault (AES-256-GCM, key from
  Argon2id), unlocked with Touch ID.
- **Connects** with the system's native `ssh` (`/usr/bin/ssh`). For
  password hosts it types the password itself, with no external programs.
- **Generates a block** in `~/.ssh/config`, so `ssh <alias>` works even
  without hsm.

The SSH key is the normal case: the password is the secondary case, for
hosts that leave no choice.

> Before trusting it with real passwords, read
> [THREAT_MODEL.md](THREAT_MODEL.md): what hsm protects against and what it
> does not.

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Getting started](#getting-started)
- [Commands](#commands)
- [The hosts.toml file](#the-hoststoml-file)
- [Passwords and vault](#passwords-and-vault)
- [Connection](#connection)
- [Sync to ~/.ssh/config](#sync-to-sshconfig)
- [Files and permissions](#files-and-permissions)
- [Security in brief](#security-in-brief)
- [Common problems](#common-problems)
- [Development](#development)
- [Uninstalling](#uninstalling)

---

## Requirements

| What | Required? | Notes |
|---|---|---|
| macOS (Apple Silicon) | yes | Uses Keychain, Touch ID and NSPasteboard |
| Python 3.12+ | yes | `uv` downloads it if missing |
| [uv](https://docs.astral.sh/uv/) | recommended | For installing and for development |
| `/usr/bin/ssh` (OpenSSH ≥ 8.4) | yes | Already on macOS. 8.4 is needed for `SSH_ASKPASS_REQUIRE` |
| `fzf` | optional | For the fuzzy picker. Without it, there is a numbered list |

**`sshpass` is not needed.** For password hosts, ssh asks for the password
from a small hsm helper (`hsm-askpass`), which is installed together with
`hsm` (see [Connection](#connection)).

To install fzf with Homebrew:

```bash
brew install fzf
```

### Python dependencies

| Package | Why |
|---|---|
| `cryptography` ≥ 44 | AES-256-GCM and Argon2id. It includes native Argon2, so no `argon2-cffi` |
| `tomlkit` | Rewrites `hosts.toml` keeping hand-written comments |
| `pyobjc-framework-LocalAuthentication` | Touch ID prompt: there is no equivalent system command |
| `pyobjc-framework-Cocoa` | `hsm pw get`: clipboard with the "do not save in history" types, which `pbcopy` does not allow. Already required by the previous package |

The command line uses `argparse`, not `typer`: by default typer shows local
variables in tracebacks, and a password could end up there.

---

## Installation

From the project folder:

```bash
uv tool install .
```

This installs two commands in `~/.local/bin`:
- `hsm`, the one you use;
- `hsm-askpass`, the helper used by ssh. You never need to run it by hand.

If the shell cannot find `hsm`, add that directory to your `PATH`:

```bash
uv tool update-shell
```

To update after a `git pull`:

```bash
uv tool install --reinstall .
```

To use it without installing it, from the project folder:

```bash
uv sync
```

```bash
.venv/bin/hsm --help
```

To check that everything is in place:

```bash
hsm paths
```

---

## Getting started

```bash
# 1. Add a bastion and a host reached through it
hsm add bastion --ip bastion.example.com --user jump --port 2200
hsm add web01 --ip 10.0.0.1 --user deploy --tag prod --tag web --jump bastion

# 2. Look at the inventory
hsm ls

# 3. Connect (SSH key: no hsm prompt)
hsm connect web01

# 4. Or choose from the picker and press Enter
hsm

# 5. Make `ssh web01` work from any terminal too
hsm sync --dry-run      # first see what would change
hsm sync
```

For a host that only accepts a password, you set it right in `add`:

```bash
hsm add legacy01 --ip 10.0.0.9 --user admin --password
hsm connect legacy01    # Touch ID → the password reaches ssh on its own
```

`--password` takes no value: it starts a hidden prompt. The first time, the
vault is created too, with its master password. For an existing host, use
`hsm pw set <alias>`.

Without flags, `hsm add <alias>` asks the questions one by one:

```text
$ hsm add db
Hostname or IP: db.example.com
User (Enter = ssh default): postgres
Port [22]:
Tags (space-separated): prod db
Jump host:
SSH key (identity_file): ~/.ssh/id_db
Note: the main database
Use a password for this host (stored in the vault)? [y/N]
Added db.
```

---

## Commands

| Command | What it does |
|---|---|
| `hsm` | Interactive picker; Enter = connect |
| `hsm add <alias> [flags]` | Adds a host, with flags or with questions |
| `hsm edit <alias> [flags]` | Edits a host, including its alias |
| `hsm ls [--tag X] [--sort alias\|tag\|recent]` | Lists the hosts |
| `hsm rm <alias> [--force]` | Removes a host (and its password, if it has one) |
| `hsm connect <alias>` | Opens the ssh session |
| `hsm pw set <alias>` | Stores the host's password in the vault |
| `hsm pw get <alias>` | Copies the password to the clipboard; cleared after 30 s |
| `hsm pw rm <alias>` | Removes the password from the vault |
| `hsm vault rekey` | Changes the master password |
| `hsm sync` | Regenerates the hsm block in `~/.ssh/config` |
| `hsm paths` | Shows every file and program used, with its status |

**Global options**
- `--debug`: on error, shows the full traceback, which never contains local
  variables.

**`--dry-run`** (on `add`, `edit`, `rm`, `sync`)
- Shows the diff of what would change and writes nothing. It does not even
  ask for passwords.

**`add` and `edit` flags**

| Flag | Field | Where |
|---|---|---|
| `--ip`, `--hostname` | `hostname`: DNS name or IP address (required in `add` if you use flags) | add, edit |
| `--user` | `user` | add, edit |
| `--port` | `port` | add, edit |
| `--tag` | `tags`, repeatable: `--tag prod --tag web` | add, edit |
| `--jump` | `jump_host` | add, edit |
| `--identity` | `identity_file` | add, edit |
| `--note` | `note` | add, edit |
| `--password` | asks for the password (hidden) and stores it in the vault | add only |
| `--alias NEW` | renames the host | edit only |

**Three practical details**
- **The password is never passed as a value.** `--password s3cret` is
  rejected, because it would end up in the shell history and in the
  arguments visible with `ps`. If it happens, delete the line from the
  history and consider the password exposed.
- **A value starting with `-` must be passed with `=`**, otherwise argparse
  takes it for an option: `--note=-to-review`.
- **To clear a field**, use `hsm edit <alias>` without flags and answer `-`
  to the question; Enter leaves the value as it is. Flags can only set
  values, not clear them.

**Renaming a host**

```bash
hsm edit bastion --alias gw
```

In interactive mode the first question is `Alias [bastion]`. The rename
also updates:
- the hosts that used that alias as `jump_host`;
- the password in the vault, if the host has one (unlocking is required);
- the last use.

`~/.ssh/config` is not updated: run `hsm sync` again. In `hosts.toml` the
renamed table moves to the end; the comments inside it are kept.

**`hsm ls` sorting**
- `alias` (default), `tag` (by first tag, hosts without tags last),
  `recent` (most recently used first).

```text
$ hsm ls --sort recent
ALIAS     HOST                           TAG         AUTH      LAST USED
web01     deploy@10.0.0.1                #prod #web  key       2026-10-16 14:02
legacy01  admin@10.0.0.9                 -           password  2026-10-15 09:30
bastion   jump@bastion.example.com:2200  -           key       never
```

**Picker (`hsm` without arguments)**
- **With fzf:** fuzzy filter, Enter to choose, Esc to quit.
- **Without fzf:** numbered list. Type a number to choose, or some text to
  filter (it searches alias, host, tags and notes).
  - The filter chooses on its own only if the text is **exactly an alias**;
    otherwise you need the number, so a typo does not connect you to some
    random host.
  - A filter made only of digits is always read as a line number.

**`hsm rm` of a host used as a jump**
- If the host is the `jump_host` of other hosts, `--force` is required.
  Otherwise those hosts would resolve the bastion via DNS, possibly to a
  different machine.

**`hsm paths`**

```text
$ hsm paths
WHAT               PATH                                         STATUS
Config dir         ~/.config/hsm                                ok (700)
Inventory          ~/.config/hsm/hosts.toml                     ok (600)
Vault              ~/.config/hsm/vault.enc                      ok (600)
State              ~/.config/hsm/state.toml                     ok (600)
Lock               ~/.config/hsm/vault.lock                     ok (600)
SSH config         ~/.ssh/config                                ok (600), hsm block present
Backup SSH config  ~/.ssh/config.hsm-backup-*                   2 file(s), latest config.hsm-backup-20261016T141034
Keychain           login keychain, service hsm, account 3f2a…   present (unlock with Touch ID)
ssh                /usr/bin/ssh                                 ok
hsm-askpass        ~/.local/share/uv/tools/hsm/bin/hsm-askpass  ok (automatic password for ssh)
fzf                -                                            not installed: numbered list
Python             ~/.local/share/uv/tools/hsm/bin/python       runs hsm and the clipboard watchdog
```

- It is the only command that **runs even with wrong permissions**,
  precisely to show them to you together with the `chmod` to run.
- It is read-only: it creates no files, does not open the vault and reads
  no secrets. For the Keychain it only checks that the item exists.

---

## The hosts.toml file

It lives in `~/.config/hsm/hosts.toml`. One table per host:

```toml
# My servers: comments are kept even after hsm add/edit.

[hosts.web01]
hostname = "10.0.0.1"
user = "deploy"
port = 2222                      # omitted if 22
tags = ["prod", "web"]
jump_host = "bastion"            # hsm alias, or [user@]host[:port]
identity_file = "~/.ssh/id_ed25519"
note = "main frontend"

[hosts.legacy01]
hostname = "10.0.0.9"
user = "admin"
auth = "password"                # set by `hsm add --password` / `hsm pw set`
```

| Field | Required | Rules |
|---|---|---|
| alias (table name) | yes | Letters, digits, `.`, `_`, `-`; starts with a letter or digit; max 64. Unique **case-insensitively** (as ssh does) and never equal to another host's hostname |
| `hostname` | yes | DNS name or IP address (IPv4, IPv6, also with a zone such as `fe80::1%en0`). Never a leading `-` |
| `user` | no | Letters, digits, `.`, `_`, `-`; no `@` |
| `port` | no | 1–65535, default 22 |
| `tags` | no | List of words: letters, digits, `_`, `-` |
| `jump_host` | no | An inventory alias or `[user@]host[:port]`, with IPv6 in `[ ]`. **Never `none`**: to ssh it would mean "no bastion" |
| `identity_file` | no | Absolute or starting with `~`. Spaces allowed; `"`, `\`, `%` and `$`, which ssh_config would expand, are forbidden |
| `note` | no | Free text on one line, without control characters |
| `auth` | no | `"key"` (default, omitted from the file) or `"password"` |

In the file the field is called `hostname`, like ssh's `HostName`, but it
accepts either a name or an IP; that is why the flag also has the `--ip`
form.

`auth` only says **how** you authenticate, never with what. It lets
`hsm connect` know whether to open the vault: for key hosts there is no
Touch ID and no master password. It is set by `hsm add --password` and
`hsm pw set`, and removed by `hsm pw rm`.

The rules are strict because these values end up in ssh's arguments and in
`~/.ssh/config`. For example a hostname `-oProxyCommand=…` would be run by
ssh as a command. An error in the file says which host and which field to
fix:

```text
hsm: Host web01: invalid hostname: '-oProxyCommand=touch /tmp/x'
```

**Versioning it with git** is fine: it contains no secrets, but it is a map
of your infrastructure, so no public repositories. git does not preserve
0600 permissions: after a clone hsm refuses to start and tells you the
`chmod` to run.

---

## Passwords and vault

### How unlocking works

```text
hsm connect legacy01
   │
   ├─ Touch ID ──ok──► key from Keychain ──opens the vault?──yes──► ssh (automatic password)
   │                         │                     │
   └─ cancelled / not        └─ missing            └─ no: removes it
      available                  │                     │
      (e.g. over SSH)            ▼                     ▼
                       ──────────► master password (3 attempts)
                                   └─► saves the key in the Keychain
```

- **The first time** (`hsm add --password` or `hsm pw set` with no vault)
  hsm creates the vault and asks you for a **new master password**, twice,
  of at least 12 characters.
- **After the first unlock**, the derived key (not the master password) goes
  into the login keychain and later unlocks go through Touch ID. If Touch ID
  is not available (Mac over SSH, lid closed without an Apple Watch) hsm
  asks for the master password. It never falls back to "no encryption".
- **`hsm vault rekey`** changes the master password. It asks for **the old
  one, typed**: Touch ID is not enough. It regenerates salt and key and
  updates the Keychain item.

### vault.enc format

| Bytes | Field |
|---|---|
| 0–3 | `HSMV` |
| 4 | format version (1) |
| 5 | KDF (1 = Argon2id) |
| 6–9, 10–13, 14 | memory (KiB), passes, parallelism |
| 15–31 | length (16) and salt |
| 32–44 | length (12) and nonce |
| 45– | ciphertext + GCM tag |

The cryptographic choices are explained in the comments of
[src/hsm/vault.py](src/hsm/vault.py):
- **AES-256-GCM:** authenticated encryption, so it detects tampering.
- **Argon2id** with 256 MiB, 3 passes and 4 lanes: makes brute force
  expensive.
- **96-bit nonce**, random on every write, never reused.
- **128-bit salt**, generated once and stored in clear.
- **Header authenticated** as AAD: nobody can lower the parameters without
  decryption failing.

### Things to know

- **There is no recovery.** Without the master password and without the
  Keychain item, the vault is lost.
- **Rekey does not change old copies of the vault** sitting in backups:
  those still open with the old master password.

---

## Connection

`hsm connect` builds the ssh command line from the host's fields, and works
even if you have never run `hsm sync`:

```text
/usr/bin/ssh -l deploy -p 2222 -J jump@bastion.example.com:2200 \
             -i /Users/you/.ssh/id_ed25519 -o IdentitiesOnly=yes -- 10.0.0.1
```

- **`--`** prevents the destination from being read as an option.
- **`-J`**: if `jump_host` is an inventory alias it is translated to
  `user@host:port`, following the chain if the bastion has a jump too.
  The bastion's `identity_file` applies only after `hsm sync`.
- **`IdentitiesOnly=yes`** next to `-i` avoids "Too many authentication
  failures" when the agent holds many keys.
- **Ctrl-C during the session goes to ssh**, not to hsm.
- **The exit code of `hsm connect` is ssh's.**

### Hosts with `auth = "password"`

OpenSSH can ask an external program for the password instead of the
terminal (`SSH_ASKPASS`, with `SSH_ASKPASS_REQUIRE=force`). hsm uses this
with its helper `hsm-askpass`:

```text
hsm connect legacy01
  → Touch ID → password from the vault
  → ssh: "admin@10.0.0.9's password: " → hsm-askpass → the password arrives on its own
```

**When the password is handed over.** Only if all these conditions hold:
1. the question is **exactly** `user@host's password: ` (or the
   keyboard-interactive variant) of the destination host. The effective
   names according to `ssh -G` count too, if your `~/.ssh/config` changes
   `HostName` or `User`;
2. the one asking is a helper that is a **child of the main ssh process**.
   The kernel verifies this, the helper does not just claim it. This is
   what rules out the jump host's ssh, even when the bastion has the same
   `user@host` on another port;
3. it is **the first time**. If ssh asks again it means the password was
   wrong: the question goes to you, and at the end hsm tells you to update
   it with `hsm pw set`.

**You answer everything else in the terminal**: confirming an unknown host
key, the bastion's password, OTP codes, passphrases.
- The host key confirmation **never** gets an automatic answer: an
  automatic "yes" would accept any server.
- The answer is visible while you type it only for that question; for all
  the others it stays hidden.
- Control characters are stripped from the question text, which can come
  from the server, before it is shown.

**How the password travels.** Never in the arguments (visible with `ps`) or
in the environment. For the duration of the connect hsm opens a Unix socket
in a private directory (0700), and passes ssh only its path and a random
token. When the connection ends, even with SIGTERM or the window closed,
the socket is removed and the password wiped.

---

## Sync to ~/.ssh/config

```bash
hsm sync --dry-run    # shows the diff
hsm sync
```

It writes only between two markers:

```text
# >>> hsm begin
# Generated by `hsm sync`: changes inside this block will be overwritten.

Host web01
    HostName 10.0.0.1
    User deploy
    Port 2222
    ProxyJump bastion
    IdentityFile "~/.ssh/id_ed25519"
    IdentitiesOnly yes

# Resets the scope to global for the lines after this block.
Host *
# <<< hsm end
```

**The rules**
- **Everything outside the markers stays identical, byte for byte.**
- **If the markers are missing, the block goes at the top of the file.** In
  ssh_config the first value found wins, so at the top hsm's values are not
  overridden by a `Host *` written further down.
- **The final `Host *` keeps your global options from breaking.** In
  ssh_config an option belongs to the `Host` block above it: without that
  line, a `ServerAliveInterval` you had at the top of the file would end up
  inside hsm's last host. This is verified with `ssh -G`.
- **Before writing there is a 0600 backup**,
  `~/.ssh/config.hsm-backup-YYYYMMDDTHHMMSS`, but only if something
  changes. Backups are never deleted: clean them up by hand from time to
  time.
- **It is idempotent:** two syncs in a row produce the same file and no
  second backup.
- **hsm does not touch the file in three cases:** malformed markers (only
  one, swapped, duplicated), file modified by an editor during the sync,
  file that is not UTF-8 text. In all three it tells you what to fix.
- **After a rename** (`hsm edit --alias`) the block still has the old name
  until you run `hsm sync` again.

The password never goes into the block: `ssh <alias>` from a normal
terminal asks you for it. The automatic password exists only with
`hsm connect`.

---

## Files and permissions

| Path | Contents | Permissions |
|---|---|---|
| `~/.config/hsm/` | hsm directory | 0700 |
| `~/.config/hsm/hosts.toml` | inventory, in clear | 0600 |
| `~/.config/hsm/vault.enc` | passwords, encrypted | 0600 |
| `~/.config/hsm/state.toml` | last use per host | 0600 |
| `~/.config/hsm/vault.lock` | lock between hsm processes (empty) | 0600 |
| `~/.ssh/config` | block generated by `hsm sync` | 0600 (`~/.ssh` 0700) |
| `$TMPDIR/hsm-askpass-*/s` | password socket, only during a connect | 0700 / 0600 |
| login keychain, item `hsm` | vault key | managed by macOS |

`hsm paths` shows them all, with their status.

**Startup checks**
- Directories and files must belong to you, must not be symlinks and must
  not be accessible to group or others.
- If something is off, hsm **refuses to start** and prints the `chmod` to
  run. It does not fix things on its own: a wrong permission may be the
  sign of something worth understanding.
- The exception is `hsm paths`, whose job is precisely to show these
  problems.
- The permissions of `~/.ssh/config` are checked by `hsm sync`, not on
  every command.

**How files are written**
- All writes are atomic (0600 temporary file, then rename) and forced to
  disk.
- Changes to `hosts.toml` and to the vault happen under a lock: two hsm
  processes in parallel do not overwrite each other's changes.

**State**
- `state.toml` is convenience data: if it breaks, hsm warns and rewrites
  it. It never blocks a connect.

---

## Security in brief

**Protects against**
- anyone who gets a copy of `vault.enc` (backups, lost disk, published
  dotfiles);
- other users on the same Mac;
- malicious values in `hosts.toml` that would try to inject options or
  configuration lines;
- a server or bastion trying to get another host's password, or to get its
  host key accepted without confirmation.

**Does not protect against**
- malicious code running as your user: it can read the key from the
  Keychain without a prompt;
- root;
- someone who has your unlocked Mac and knows how to use the terminal;
- the server that receives the password when you authenticate with a
  password;
- the commands your `~/.ssh/config` makes ssh run (`ProxyCommand`,
  `LocalCommand`, `Match exec`): they are children of ssh and could ask for
  the password just like the helper.

hsm's Touch ID is an interface check, not a cryptographic barrier. Python
does not guarantee that memory can be wiped: hsm reduces plaintext copies,
but cannot eliminate them all.

Details, per-component limits and recommendations are in
**[THREAT_MODEL.md](THREAT_MODEL.md)**.

---

## Common problems

**`Permissions too open on … Fix with: chmod 600 …`**
Run the suggested command. It often happens after cloning `hosts.toml`
from git, or with a `~/.ssh/config` created with default permissions
(0644). `hsm paths` shows every file with a problem at once.

**`hsm sync`: `~/.ssh/config is a symlink`**
hsm does not write through a symlink. This often happens if you manage your
dotfiles with a repository. There are two ways out:
- replace the symlink with a real file and add an
  `Include ~/dotfiles/ssh_config` line pointing to your file;
- or do not use `hsm sync` and connect with `hsm connect`.

**On the first connection ssh asks you to confirm the host key**
This is intended: hsm never answers that question on its own. Verify the
fingerprint (with the server's administrator, or through a trusted channel)
and answer `yes` in the terminal.

**`The server rejected the saved password for …`**
It has probably changed on the server. Update it:

```bash
hsm pw set legacy01
```

**`… hsm-askpass not found: reinstall hsm`**
The helper must sit next to hsm's interpreter. Reinstall:

```bash
uv tool install --reinstall .
```

**The password is not typed automatically and ssh asks you for it**
Usually your `~/.ssh/config` changes `HostName` or `User` in a way hsm
could not resolve, or the server uses an unusual prompt. There is no risk:
you simply type it yourself. `ssh -G <host>` shows the effective values.

**`Touch ID unavailable: enter the master password.`**
Normal if you are connected to the Mac over SSH or the lid is closed
without an Apple Watch.

**`Another hsm is modifying the vault`**
Another hsm command is waiting for a password or Touch ID. Finish it or
close it, then try again.

**`jump_host 'xyz' is not an inventory alias`**
Probably a typo in the bastion's name. If it really is a host name without
a domain, the warning can be ignored.

**`argument --note: expected one argument`**
The value starts with `-`: write it as `--note=-value`.

**Something is off and you want more details**

```bash
hsm --debug <command>
```

---

## Development

```bash
uv sync
```

```bash
.venv/bin/pytest
```

```bash
.venv/bin/pytest --cov=hsm --cov-report=term-missing
```

### Tests that touch the real system (optional)

They are skipped by default. Enable them one at a time:

| Variable | What it does |
|---|---|
| `HSM_KEYCHAIN_TESTS=1` | Creates, reads and deletes an `hsm-test` item in the login keychain |
| `HSM_TOUCHID_TESTS=1` | Shows a real Touch ID prompt (add `-s` to see the messages) |
| `HSM_CLIPBOARD_TESTS=1` | **Overwrites your clipboard** for about 4 seconds |
| `HSM_SSHD_TESTS=1` | Starts a temporary `sshd` as a normal user on `127.0.0.1` and checks the password path with the real ssh |

```bash
HSM_SSHD_TESTS=1 .venv/bin/pytest tests/test_askpass.py -k real_ssh
```

Other tests use real tools with no risk:
- `ssh -G`, which resolves the configuration without connecting;
- the installed `hsm-askpass` helper, launched the way ssh would launch it;
- the clipboard watchdog actually started, which only reads.

### Layout

```text
src/hsm/
├── errors.py      domain errors, excepthook without local variables
├── secret.py      container for secrets: redacted repr, explicit wipe
├── fsutil.py      0600/0700 permissions, atomic writes, inter-process lock
├── vault.py       vault.enc format, Argon2id, AES-256-GCM, rekey
├── keychain.py    vault key in the login keychain via `security -i`
├── touchid.py     presence check with LocalAuthentication
├── unlock.py      Touch ID + Keychain, or master password
├── inventory.py   hosts.toml: Host model, validation, rename
├── state.py       state.toml: last use per host
├── sshconfig.py   block between the markers in ~/.ssh/config
├── askpass.py     password for ssh via SSH_ASKPASS (server + hsm-askpass helper)
├── connect.py     ssh arguments, ProxyJump, session with askpass
├── clipboard.py   clipboard with automatic clearing (hsm pw get)
├── picker.py      picker: fzf or numbered list
└── cli.py         command line: wires the modules together
```

Dependencies go in one direction only, from the bottom up. `vault.py`
knows nothing about Keychain or prompts: it receives a password and returns
a key, or receives a key and reads or writes.

### Project rules

- **One module at a time, with TDD:** tests first, which must fail, then
  the code.
- **Every cryptographic choice has a comment** explaining why.
- **Never hand-made cryptography:** only `cryptography`.
- **Never generic `except`s that silence errors;** never plaintext
  passwords on disk, not even temporarily.
- **No network calls** outside ssh; no GUI, TUI or web server.

The original specification is in [SPEC.md](SPEC.md). Compared to it, hsm
uses `SSH_ASKPASS` instead of `sshpass` and adds the `auth` field to
`hosts.toml`: two choices discussed and approved during development.

---

## Uninstalling

```bash
uv tool uninstall hsm
```

To remove the data too, first remove the key from the Keychain:

```bash
security delete-generic-password -s hsm
```

Then delete the hsm directory, **after checking** that you no longer need
the passwords it contains:

```bash
rm -r ~/.config/hsm
```

Finally, remove by hand from `~/.ssh/config` the block between
`# >>> hsm begin` and `# <<< hsm end`, and if you like the
`~/.ssh/config.hsm-backup-*` files.
