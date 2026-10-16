Let's build together a Python CLI to manage an inventory of SSH hosts.
Don't write any code yet: first read everything and tell me the assumptions you make.

GOAL
A command-line tool that replaces MobaXterm's session tree:
it saves machines, organizes them with tags, searches them, stores encrypted
passwords, and launches the connection using the system's native ssh.

CONTEXT
- macOS (Apple Silicon), Python 3.12, personal use on dozens of hosts
- User: infrastructure engineer, knows Python but wants to UNDERSTAND the code,
  not just run it. Explain non-obvious choices with short comments.
- Connection engine: native /usr/bin/ssh. Do not implement SSH in Python,
  do not use paramiko.

DATA MODEL
- Inventory in ~/.config/hsm/hosts.toml (readable and versionable, WITHOUT secrets)
- Host fields: alias, hostname, user, port, tag[], jump_host, identity_file, note
- The secrets vault is a separate, encrypted file: ~/.config/hsm/vault.enc

SECURITY (the part that matters — read carefully)
- Vault encrypted with AES-256-GCM. Key derived from the master password with
  Argon2id (explicit, commented parameters, not the library defaults).
- The master password is NOT asked for on every command: after the first unlock
  it is stored in the macOS Keychain as a biometry-protected item, so
  later unlocks go through Touch ID. Use the `security` command or
  an equivalent library; explain in the code what you are doing and why.
- If the Keychain is not available, fall back to the master password prompt.
  Never fail silently towards "no encryption".
- Random nonce for every encryption, never reused. Salt generated once and
  stored in clear in the vault header.
- The plaintext password must live in memory as briefly as possible: no logs,
  no stack traces containing it, no repr of the objects that
  hold it.
- 0600 permissions on vault and config. Check them at startup and refuse to
  start if they are more permissive.

COMMANDS
  hsm add <alias>      adds a host (flags or interactive prompt)
  hsm ls [--tag X]     list, sortable by alias/tag/last use
  hsm rm <alias>
  hsm edit <alias>
  hsm connect <alias>  opens the ssh session
  hsm                  without arguments: fuzzy picker, enter = connect
  hsm pw set <alias>   stores the password in the vault
  hsm pw get <alias>   copies to the clipboard with auto-clear after 30s
  hsm sync             regenerates a delimited block in ~/.ssh/config

CONNECTION
- Default: SSH key. The password is the secondary case, not the first.
- With a password: use sshpass, passing it via a file descriptor or a fifo with
  0600 permissions, NEVER as a command-line argument (visible in ps) and
  never in an exported environment variable.
- If sshpass is not installed, say so and offer the "copy to clipboard
  and connect" fallback, without failing.
- Support ProxyJump from the jump_host field.

SYNC TO SSH_CONFIG
- Writes only between the markers "# >>> hsm begin" / "# <<< hsm end"
- Does not touch a single line outside that block
- Makes a backup before writing
- Idempotent: two syncs in a row produce the same file

NON-FUNCTIONAL
- Minimal dependencies: typer (or argparse), cryptography, argon2-cffi, tomlkit.
  Justify every dependency added beyond these.
- Type hints everywhere, docstrings on public functions
- Errors with messages useful to the user, not bare stack traces
- --dry-run on add/rm/edit/sync
- No network calls outside ssh

CONSTRAINTS
- Do not reimplement cryptography by hand: use `cryptography`, not homemade
  constructions with hashlib.
- Never write the plaintext password to disk, not even temporarily.
- Do not silence exceptions with generic excepts.
- Do not add a GUI, a TUI or a web server.

OUTPUT
1. First: assumptions, open questions and the vault schema (header + payload).
2. Then, on my ok: the module structure, then the code one module at a time,
   starting from vault.py (the critical part), so I can read it before
   moving on.
3. For every cryptographic choice, two lines explaining WHY.
4. Close with a "Known limits and threat model" section: what this
   tool protects against and what it does NOT protect against.

Don't generate everything in one go. Proceed module by module and stop between one and the next.
