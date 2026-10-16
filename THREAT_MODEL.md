# hsm — Known limits and threat model

This document says **what hsm protects you from and what it does not**. It
applies to the version on `feat/core-modules` (October 2026), macOS on Apple
Silicon, personal use by a single user.

In one sentence: hsm protects passwords well **at rest** (the vault file
copied, stolen, left in a backup) and does not leave secrets in obvious
places (process arguments, environment variables, logs, temporary files).
It does **not** protect against someone running code as your user on the
unlocked Mac.

---

## What needs protecting

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Host passwords | `~/.config/hsm/vault.enc`, encrypted | High |
| Vault key (32 bytes, derived from the master password) | login keychain, item `hsm` | High: opens the vault without the master password |
| Master password | only in your head; in memory for a moment during unlock | High |
| Inventory (hostnames, users, bastions, tags, notes) | `~/.config/hsm/hosts.toml`, in clear | Medium: it is a map of your infrastructure |
| Hosts' last use | `~/.config/hsm/state.toml`, in clear | Low: tells what you use and when |
| Generated block | `~/.ssh/config` between the markers, plus the `config.hsm-backup-*` backups | Medium, like the inventory |

---

## Who can attack, and what they get

### ✅ Someone who gets a copy of `vault.enc`

This is the case hsm is designed for: a Time Machine or cloud backup, a lost
disk, a dotfiles repository published by mistake.

- **The vault is encrypted with AES-256-GCM.** Without the key nothing can
  be read, not even which aliases have a password: the whole payload is
  encrypted.
- **The key comes from Argon2id** with 256 MiB of memory, 3 passes and 4
  lanes. Each attempt to guess the master password costs 256 MiB of RAM and
  about 0.15 s on Apple Silicon. GPUs, which have lots of compute but little
  memory per core, do not gain much.
- **Tampering:** the GCM tag also authenticates the header. An altered file,
  including Argon2 parameters lowered, is rejected, never decrypted wrongly.
- **Limit:** the protection is only as good as the master password. The
  minimum is 12 characters, but a short password or one reused elsewhere
  can still be guessed.

### ✅ Other users on the same Mac (non-administrators)

- hsm's files and directories are 0600 and 0700, belong to you and cannot
  be symlinks. At startup hsm checks all of this and **refuses to start**
  if something is off. The checks are made on the already opened file
  (`fstat`), so the file cannot be swapped between the check and the read.
- **A host's password never appears in process arguments** (visible to
  everyone with `ps`) **or in an environment variable.** ssh gets it from
  `hsm-askpass`, which receives it from hsm over a Unix socket in a 0700
  directory created for that connect, with a random token. Another user
  cannot even see the socket.
- **The vault key is passed to `security` on stdin** (`security -i`), never
  as an argument.
- **The process that clears the clipboard receives only a counter and a
  deadline:** no password and no hash to attack offline.

### ✅ A badly written or tampered `hosts.toml`

For example a file shared in a team repository, or modified by a script.

- **Every field is parsed, not just filtered:** IPs with `ipaddress`, DNS
  names label by label, jump host split into `[user@]host[:port]`. A
  hostname like `-oProxyCommand=…` (which ssh would run as a command) is
  rejected. On top of that there is always `--` before the destination.
- **No value can add lines to `~/.ssh/config`.** Newlines, quotes, `#`,
  `\`, `$` and unexpanded `%` are rejected, with a second check at write
  time. A bad value would break the whole file, for every host.
- **`jump_host = "none"` is forbidden:** it would silently skip the bastion.
- **Aliases:** unique case-insensitively, and never equal to another host's
  hostname. `Host 10.0.0.1` would hijack anyone typing `ssh 10.0.0.1`.
- **Limit:** hsm checks the *shape* of values, not *trust*. If the file
  says `prod-db` is `attacker.example.com`, hsm connects you there, and with
  `auth = "password"` sends the password there. A shared `hosts.toml` must
  be treated like code: read it before using it.

### ✅ A malicious server or bastion trying to get the password

The case: you connect to `legacy01` through a bastion, and the bastion (or a
fake server) tries to obtain `legacy01`'s password, or to get itself
accepted without you checking its key.

- **The password goes only to the exact question of the destination host**,
  `user@host's password: ` or the keyboard-interactive variant, and only
  once.
- **A server cannot imitate that question.** The keyboard-interactive text
  is chosen by the server, but ssh always prefixes it with `(user@host)` of
  the host it is really talking to. A bastion's question therefore cannot
  pass itself off as the destination's.
- **The jump host's ssh does not receive the password**, not even if the
  bastion has the same `user@host` as the destination on another port (a
  NAT, a bastion on the same machine). hsm hands it only to a helper that is
  a child of the main ssh process, and the pid is verified by the kernel
  (`LOCAL_PEERPID`), not claimed by the helper. Verified with two real sshd
  on the same machine.
- **Confirming an unknown host key never gets an automatic answer.** With
  `SSH_ASKPASS_REQUIRE=force` that question also goes through the helper:
  an automatic "yes" would accept any server (verified with a test helper,
  which did exactly that). hsm passes it to you.
- **The question text is cleaned** of control characters before reaching
  the terminal, and the answer is visible while you type it only for ssh's
  real host key question: a server cannot make a typed OTP show up on
  screen.

### ⚠️ Someone with your unlocked Mac in their hands

- `hsm connect` and `hsm pw get` ask for Touch ID, and changing the master
  password requires typing the old one. This stops someone who finds the
  laptop open and runs `hsm`.
- **But Touch ID is an interface check, not a cryptographic constraint.**
  The policy also accepts the macOS password. Above all, whoever sits at
  your unlocked Mac can open a terminal and read the Keychain item directly:
  `security find-generic-password -s hsm -w`.
  A true biometric constraint would require a binary signed with Apple
  entitlements (option (b), discarded during planning).

### ❌ Malicious code running as your user

For example malware, a compromised npm or pip dependency, or an editor
extension.

**hsm does not protect against this.** A process running as your user can:

- read the vault key from the Keychain without any prompt, and decrypt the
  vault with it;
- read the clipboard during the 30 seconds it holds a password;
- record what you type, master password included;
- replace the files of hsm's virtualenv or source, which are writable by
  your user and therefore have the same trust level as hsm itself;
- modify `hosts.toml`, because 0600 permissions do not stop the owner;
- during an `hsm connect`, read the socket token and path from ssh's
  environment and ask for the password in place of the helper.

A special case of the same boundary: the commands your `~/.ssh/config`
makes ssh run (`ProxyCommand`, `LocalCommand`, `Match exec`) are children
of ssh just like the helper, inherit token and socket, and could obtain the
password. They are commands you configured: if you include them from files
you do not control (a shared `Include`), treat them as code with access to
your passwords.

It is the same situation as a `~/.ssh/id_ed25519` without a passphrase: on
your compromised user account no user-space tool holds up.

### ❌ root / administrator, or the Mac compromised at system level

Out of scope: it can read the memory of any process, the unlocked Keychain,
everything.

### ❌ The server you connect to with a password

With password authentication the password **reaches the server**: that is
how the method works. A compromised server, or a fake one with a host key
accepted by mistake, receives it. Use SSH keys whenever you can: in hsm
they are the default, and the password is the secondary case.

---

## Known limits, component by component

### Memory

- **Python does not guarantee that memory can be wiped.** `Secret` holds
  secrets in a `bytearray` that gets wiped, but every `str` or `bytes`
  created along the way is immutable and stays in memory until the garbage
  collector frees it. This happens with the output of `getpass`, the
  decrypted vault text, the output of `security` and the clipboard
  NSString. It is a mitigation, not a guarantee.
- **Active mitigations:**
  - core dumps are disabled (`RLIMIT_CORE = 0`);
  - tracebacks never show local variables (argparse instead of typer for
    this reason);
  - `repr` and `str` of secrets are redacted;
  - during an ssh session only the needed password stays in memory, and
    nothing else from the vault.
- macOS encrypts swap, so pages written to disk are not in clear.

### Keychain and Touch ID

- The Keychain holds the **derived key**, not the master password. Whoever
  steals it opens this vault, but does not learn a password you might reuse
  elsewhere.
- Consequence: **as long as the item exists in the Keychain, the vault
  opens even without the master password.** Useful if you forget it,
  dangerous if the Keychain is exposed.
- After `hsm vault rekey` the salt changes: the old item is deleted and the
  old key no longer opens the new file.

### Vault and backups

- **`hsm vault rekey` does not change old vaults in backups.** A Time
  Machine copy from before the rekey still opens with the old master
  password. If you change the master password because you think it is
  compromised, consider those copies compromised too.
- **No recovery:** without the master password and without the Keychain
  item, the vault is lost. This is intended.
- Writes are atomic and forced to disk (`F_FULLFSYNC`): a crash leaves the
  old vault or the new one, never a half-written one.
- The lock (`flock`) only protects against other hsm processes. An editor
  modifying `hosts.toml` while hsm is working can still lose a change (the
  sync of `~/.ssh/config`, on the other hand, notices and stops).

### Password connection (SSH_ASKPASS)

- **No external programs.** ssh asks `hsm-askpass` for the password; the
  helper sits next to hsm's Python interpreter and is not looked up in the
  `PATH`: a fake helper in the `PATH` would receive nothing. Requires
  OpenSSH ≥ 8.4 (`SSH_ASKPASS_REQUIRE`).
- **The socket exists only during the connect** and is removed at the end,
  even with SIGTERM or SIGHUP (terminal window closed). With a `kill -9` an
  empty directory with a dead socket is left in `$TMPDIR`: no secrets on
  disk.
- **A single delivery.** If the server rejects the password, ssh asks
  again and the question goes to you. At the end hsm tells you to update it.
- **Fragile matching, but it fails safe.** If your `~/.ssh/config` changes
  `HostName` or `User`, hsm tries to follow them with `ssh -G`; if the
  prompt still does not match (name canonicalization, servers with unusual
  prompts), the password is not handed over and you type it yourself.
- **The bastion's password is not automatic:** if the jump host asks for
  it, you type it. The vault holds the destination's password.
- **During the session** only the needed password stays in memory: the
  vault key and other entries are already wiped. The helper lives only as
  long as it takes to answer.
- **`ssh <alias>` from a normal terminal** (after `hsm sync`) does not use
  hsm: there you type the password yourself. Automatic delivery exists only
  with `hsm connect`.

### Clipboard (`hsm pw get`)

- It is only for copying a password by hand: `hsm connect` no longer uses
  it.
- For 30 seconds **any app** can read the password from the clipboard.
- The `Concealed` and `Transient` types ask clipboard history managers
  (Maccy, Raycast, Paste…) not to save it. A manager that ignores them
  saves it anyway.
- **Universal Clipboard (Handoff):** macOS can sync the clipboard with your
  other nearby Apple devices. I have not verified whether it honors the
  `Transient` type. If this worries you, turn off Handoff or do not use
  `pw get` with other devices nearby.
- If the process that clears the clipboard is killed, the password stays in
  the clipboard until logout. The deadline is on wall-clock time, so it
  survives the Mac sleeping.

### Plaintext files

- **`hosts.toml`, the block in `~/.ssh/config` and its backups are a map of
  your infrastructure:** internal hostnames, users, bastions, notes. They
  contain no secrets, but in a public repository they are reconnaissance
  material for an attacker.
- **git does not preserve 0600 permissions.** After a clone, hsm refuses to
  start until you run the `chmod` it tells you.
- **`~/.ssh/config` backups pile up**, one for every sync that changes
  something. They are 0600, but must be cleaned up by hand.
- **`hsm sync` rejects a `~/.ssh/config` that is a symlink** (common with
  dotfiles) or has 0644 permissions.

### Network

- hsm makes no network calls: the only traffic is that of `/usr/bin/ssh`,
  which you launch.

---

## Recommendations

1. **A long, unique master password**, ideally a multi-word passphrase. It
   is the only defense of a copied vault.
2. **FileVault on:** it protects the Keychain, swap and hsm's files while
   the Mac is off.
3. **SSH keys wherever possible.** `auth = "password"` only for hosts that
   leave you no choice.
4. **Lock the screen** when you step away: hsm's Touch ID is not enough.
5. **Read any `hosts.toml` you did not write** before using it.
6. **After an "emergency" rekey**, consider old vaults in backups
   compromised, and change the passwords of the hosts they contained.

---

## Verified and not verified

**Verified with automated tests (over 600, 98% coverage):**
- vault encryption and tampering, permissions and symlinks;
- real Keychain (roundtrip with a test item);
- configuration resolved by `ssh -G` (OpenSSH 10.3);
- installed `hsm-askpass` helper, launched the way ssh launches it;
- real start of the clipboard watchdog;
- real `hsm` command in a temporary HOME.

**Verified with the real ssh and temporary `sshd` on 127.0.0.1**
(`HSM_SSHD_TESTS=1`):
- the vault password reaches the destination server without intervention;
- an unknown host key is not accepted;
- a jump host with the same `user@host` as the destination does not receive
  the password (manual test with two sshd).

An sshd started as a normal user cannot verify passwords, so these tests go
as far as "password received by the server", not a successful login.

**Not verified automatically, to be tried by hand:**
- real Touch ID prompt (tried by you while developing `touchid.py`);
- writing and clearing the real clipboard:
  `HSM_CLIPBOARD_TESTS=1 .venv/bin/pytest tests/test_clipboard.py -k real_pasteboard`;
- `hsm add --password` and `hsm connect` to a real host, up to a successful
  login, including through a bastion;
- servers with keyboard-interactive (PAM) authentication, where the
  question format comes from the OpenSSH documentation and not from a test;
- Universal Clipboard behavior with the `Transient` type.
