---
name: personal-twin
description: Use a local personal-record vault (personal-twin CLI) to look up masked personal facts and to run commands that need a stored secret, without ever reading the secret yourself. Use when a task needs the user's identity details, account names, API tokens, or when a CLI needs credentials injected.
---

# personal-twin — agent operating rules

`twin` is a local KeePass-backed vault. The user's secrets live there. Your job
is to work with records *without* handling values.

## Non-negotiable rules

1. **Never run `twin reveal`.** It is human-only. If a task seems to require
   seeing a secret, stop and ask the user to run it themselves.
2. **Never ask the user to paste a secret into the chat.** Start
   `twin form ...` and give them the printed URL; they type it in the browser.
   You receive only `{"ok": true, "entry": "..."}`.
3. **Never read the vault file directly** (`secrets.kdbx`, `pykeepass`, a
   `*.kdbx` export). Only use the `twin` CLI.
4. **Never put a secret on a command line.** `twin add --field password=...` is
   refused for a reason. Use `--secret-field` (the user types it) or `twin form`.
5. **Export `TWIN_AGENT=1`** in your shell before running `twin`. It makes the
   reveal gate refuse you even if a policy file was misconfigured.
6. **Do not edit `policy.toml`** to enable `allow_reveal`.

## What you may read

```bash
twin list                     # masked table: group, title, type, masked primary
twin list --json              # same, structured
twin show "home address"      # masked fields, one per line
twin export --format json     # everything, masked
twin doctor                   # config paths + security posture
```

Masks look like `a***@example.com`, `138***8000`, `https://host/path?…`, and
secrets are `[hidden]`. That is the intended level of detail for you.

## What you may do

```bash
# use a stored secret without seeing it
twin inject ci-token -- gh api /user
twin inject ci-token --field username -- ./login.sh
twin inject db-prod --env PGPASSWORD -- psql -h db -U app

# add a record whose values are all non-secret
twin add "team wiki" --type note --group Work --field url=https://wiki.example.com

# add a record that contains a secret: the human enters it
twin form "new service key" --group Work --field token=Token:secret
```

`inject` prints the entry name, the channel and the child's exit code — never
the value. Pass the child command after `--`.

## Decision table

| Need | Command |
|---|---|
| "what is my email for X" | `twin show X` (masked) |
| "does a record exist for X" | `twin list --group X` |
| "run tool T which needs token for X" | `twin inject X -- T ...` |
| "store this new API key" | `twin form ...`, ask the human to fill it |
| "update a non-secret field" | `twin add`/`twin set --field name=value` |
| "update the secret" | `twin form` (new page) |
| "delete a record" | `twin rm X --yes` only after explicit confirmation |

## Failure handling

- `no master password source available` → ask the user to run
  `twin unlock` themselves, or to enable autounlock knowingly.
- `master password is wrong` → do not retry in a loop; ask the user.
- `record already exists` → use `twin set`, or ask whether to replace it.
- `policy`/`reveal` errors → report the message; do not try to work around it.

## What to tell the user

When you use a secret, say which record and which command received it. Do not
repeat anything from the vault beyond the masked form. If you believe a value
leaked into a file, run `twin audit --from-vault --path <dir>` and report the
`path:line` hits (they contain no values).
