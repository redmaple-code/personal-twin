# personal-twin

A local-first, single-file vault for the personal facts and credentials you need
to *use* — and a set of commands that let an AI agent work with them **without
ever seeing the values**.

```text
$ twin list
group     title      type        primary          secrets
--------  ---------  ----------  ---------------  -------
Personal  home       person      a***@example.com  1
Work      ci-token   credential  -                 1
2 record(s)

$ twin inject ci-token -- gh api /user        # token goes to gh via stdin
$ twin show home                              # masked detail for an agent
```

Everything lives in one KeePass-compatible `.kdbx` file. No server, no cloud, no
account, no telemetry.

---

## Why

Personal records are useful to an assistant only if the assistant can *see*
something. Handing it your password manager is not an option; keeping the
information in a chat log is worse. `personal-twin` splits the two:

| Layer | Who sees it | How |
|---|---|---|
| Record names, groups, types | you and agents | `list`, `show`, `export` |
| Identifying values (email, phone, username) | you see it; agents see a mask (`a***@example.com`) | masked rendering |
| Secrets (passwords, API keys, tokens) | nobody but the target process | `inject` / `form` / `reveal` |

Three properties follow:

1. **Records** — one store for personal facts and credentials, with an explicit
   sensitivity level per field.
2. **Masked injection** — agents get the shape of a record, and a secret goes
   straight into the child process that needs it.
3. **No direct AI read** — there is no `get` command. The only path that prints a
   secret is `reveal`, which requires a real terminal, an opt-in policy flag, and
   refuses to run when `TWIN_AGENT` is set.

---

## Install

Requires Python 3.11+.

```bash
pip install personal-twin          # from PyPI, once published
# or, from source:
git clone https://github.com/redmaple-code/personal-twin
cd personal-twin
pip install -e .
```

Optional: KeePassXC, if you want to open the same `.kdbx` file in a GUI.

## Quick start

```bash
# 1. create the vault (owner-only permissions where the platform supports them)
twin init

# 2. add a record. Secrets never go on the command line:
twin add work-mail --type person \
  --field username=alice@example.com \
  --field phone=+1-415-555-0100 \
  --secret-field recovery_code
#    -> prompts for the recovery_code value

# 3. look at it the way an agent would
twin list
twin show work-mail
twin export --format json

# 4. use a secret without printing it
twin inject work-mail --field recovery_code -- ./some-tool --login

# 5. let the human type a secret into a one-time browser form
twin form github-token --field token=Token:secret --group Work
```

---

## Commands

| Command | What it does |
|---|---|
| `twin init [--force]` | Create the vault. Prompts for the master password. |
| `twin unlock [--ttl N]` | Cache the master password in a DPAPI-protected session (Windows). |
| `twin lock` | Drop the session. |
| `twin autounlock on\|off\|status` | Opt in/out of passwordless access for the current OS user. |
| `twin list [--group G] [--json]` | Masked table of records. |
| `twin show TITLE [--json]` | Masked detail of one record. |
| `twin export [--format md\|json]` | Masked dump of everything (the agent-friendly view). |
| `twin add TITLE [--type ...] [--group ...] [--field ...] [--secret-field NAME]` | Add a record. |
| `twin set TITLE [--field ...] [--secret-field ...] [--remove NAME]` | Update fields. |
| `twin rm TITLE [--yes]` | Delete a record. |
| `twin reveal TITLE --field F` | Print one secret. Interactive terminal only. |
| `twin inject TITLE --field F [--env VAR] -- CMD...` | Hand a secret to a child process. |
| `twin form TITLE [--mode single\|batch]` | One-time local web form for hand entry. |
| `twin audit [--path DIR] [--detectors FILE] [--from-vault]` | Find stored values leaking into plaintext files. |
| `twin backup [--out DIR] [--include PATH]` | Copy the vault; optionally encrypt extra files. |
| `twin restore SOURCE [--dest FILE] [--extras DIR]` | Restore from a backup. |
| `twin doctor` | Print the effective configuration and security posture. |

### Field syntax

```bash
--field NAME=VALUE                 # sensitivity inferred from the name
--field NAME=VALUE:public          # explicit sensitivity
--field NAME=VALUE:identifying     # masked as a***@example.com / 138***8000
--field NAME=VALUE:secret          # refused: use --secret-field
--secret-field NAME                # read from TTY prompt or stdin
--sensitivity NAME=LEVEL           # change a level without touching the value
```

`--field password=...` is deliberately rejected. Argument vectors are visible in
shell history, process listings and agent transcripts; a secret must arrive via
a prompt, stdin, or the browser form.

### Injection

```bash
twin inject ci-token -- gh api /user                 # stdin (default)
twin inject ci-token --env GITHUB_TOKEN -- gh api /user   # environment variable
```

stdin is the default because environments are observable by other processes
running as the same user and are frequently captured in crash reports.
`--env` keeps only a minimal environment (`PATH`, `SYSTEMROOT`, `HOME`, ...) so
unrelated parent variables cannot leak into the child. `--inherit-env` opts out.

The value is never printed by `twin`, but the child still controls its own
stdout — a command that echoes its input can disclose it.

### The web form

`twin form` starts a server on `127.0.0.1:<port>` with a random URL:

```bash
twin form github-token --group Work --field token=Token:secret
[form] http://127.0.0.1:8340/f/<random-token>
[form] open this URL in a browser within 600s; values are not returned here
{"ok": true, "entry": "github-token"}
```

The human types the secret into the browser; the process only receives an entry
name and a status. Hardening: loopback bind, CSP nonce, all interpolated values
escaped, JSON-only POST with a custom header (forces a CORS preflight), `Host`
pinned to loopback, body/field limits, one submission, bounded lifetime, and a
cap on wrong master-password attempts.

`--mode batch` shows several rows on one page. Both modes accept the master
password in the form unless `autounlock` is on.

---

## Sensitivity levels

| Level | Default for | Rendering |
|---|---|---|
| `public` | — | shown as-is |
| `identifying` | `username`, `email`, `phone`, `notes`, `url`, custom fields | partial mask; URL query/fragment stripped |
| `secret` | `password`, `*_key`, `*_token`, `*_secret`, anything entered via `--secret-field`/`form` | `[hidden]` |

Custom fields marked `secret` are stored in KeePass' protected stream.

The masking layer is lossy by construction; there is no unmask function. Every
output path also passes through a redactor built from the vault's secret values,
so a secret pasted into a title or note still does not reach the transcript.

---

## Configuration

Default policy file: `%APPDATA%\twin\policy.toml` (Windows) or
`~/.config/twin/policy.toml` (POSIX). Override with `--config` or `TWIN_CONFIG`.

```toml
[vault]
path = "secrets.kdbx"          # relative to the data dir

[backup]
dir = "backups"                # relative to the data dir

[security]
allow_reveal = false           # keep false unless a human needs `twin reveal`
session_ttl = 900
allow_env_password = false     # TWIN_PASSWORD is off by default
allow_env_inject = true
block_agents = true            # refuse reveal when TWIN_AGENT is set
form_max_attempts = 5

[audit]
roots = []
detectors = ""
```

Data dir defaults to `%LOCALAPPDATA%\twin` / `~/.local/share/twin`; override with
`TWIN_HOME`. `TWIN_VAULT` and `TWIN_BACKUP_DIR` override the paths directly.

---

## Using it from an agent

The intended contract:

1. Agent runs `twin list` / `twin show` / `twin export` — masked output only.
2. Agent runs `twin inject ... -- <command>` — the secret reaches the tool, not the model.
3. If a secret is missing, the agent runs `twin form ...` and asks the human to
   type it into the browser. The agent never handles the value.
4. Agent never runs `twin reveal`, and the environment sets `TWIN_AGENT=1`.

`skills/personal-twin/SKILL.md` contains a ready-to-use skill document for that
contract.

---

## Security model

Read [SECURITY.md](SECURITY.md) before trusting this with anything important. The
short version:

- The vault is a KeePass database; the master password is the real boundary.
- Agents are kept away from values by *interface design*, not by a sandbox. A
  process that can run code as your OS user can open the vault directly.
- `reveal` is a policy gate (TTY + `allow_reveal` + `TWIN_AGENT` check). It slows
  an agent down; it does not stop a determined one.
- Use full-disk encryption and a dedicated OS account if you need a real
  boundary.

## Non-goals

- Not a password-manager replacement for browser autofill.
- Not a sync service. Copy the `.kdbx` (or `twin backup`) yourself.
- Not a sandbox. It cannot make an untrusted program safe.

## License

MIT — see [LICENSE](LICENSE).
