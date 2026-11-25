# Security model, audit, and residual risk

This document is written for someone who is about to put real personal data in
this tool and let a language model drive it. It states plainly what is
protected, what is not, and which gaps existed in the design this project was
extracted from.

**Bottom line:** the vault is a KeePass database. Its master password is the real
boundary. Everything else in this project is interface design that keeps values
out of AI context and out of logs. That is useful and hard to get right, but it
is not a sandbox.

---

## 1. Assets and threat model

**Assets**

- A: the plaintext contents of the vault (personal records, passwords, tokens).
- B: the master password.
- C: metadata (titles, group names, which services exist, the fact that a record
  has a secret).
- D: derived material: unlock sessions, autounlock blobs, backups, exports, the
  local form page in a browser.

**Adversaries considered**

| # | Adversary | Capability |
|---|---|---|
| T1 | AI agent / tool-using model | can run `twin` commands, read stdout/stderr, read files in its workspace |
| T2 | Another local process as the same OS user | can read files the user can read, inspect `/proc`, attach debuggers |
| T3 | A web page open in the same browser | can make requests to `127.0.0.1` |
| T4 | A stolen laptop/backup | has the vault file and backups offline |
| T5 | A malicious or careless child process started by `twin inject` | receives a secret, controls its own stdout |

**Out of scope:** a compromised OS, malware with admin/debug privileges, a
malicious Python interpreter, hardware attacks, and an agent that has been given
permission to edit the policy file *and* a real terminal (see §5).

---

## 2. What each command exposes

| Command | Reads | Writes | Output contains |
|---|---|---|---|
| `list`, `show`, `export` | vault | — | masked values only; secrets are `[hidden]` |
| `inject` | one field | — | entry name, channel, child exit code |
| `form` | vault (on submit) | vault | entry names + per-row status |
| `add`, `set`, `rm` | vault | vault | field **names** only |
| `reveal` | one field | — | the value (TTY + policy + `TWIN_AGENT` gate) |
| `audit` | configured dirs | optional report | file paths + detector index; never values |
| `backup`, `restore` | vault | backup dir | file names |
| `doctor` | config, filesystem | — | paths, booleans |

All masked output additionally passes through a redactor built from the vault's
secret values, so a secret pasted into a title, note or group name is replaced
with `[hidden]` before printing.

---

## 3. Audit of the original design (and what changed here)

The project was extracted from a single-file personal CLI. That version was
functional but had the following gaps. Each is listed with the control that
replaces it.

| # | Finding in the original | Severity | Status here |
|---|---|---|---|
| F1 | `twin get` printed any field, including passwords, with no caller check. Any agent with shell access could read every secret. | **High** | `get` removed. `show`/`list`/`export` are masked. Only `reveal` prints a value. |
| F2 | `register --token <literal>` accepted detector values on the command line, exposing them via shell history, process listings and agent transcripts. | **High** | Option removed entirely. Detectors live in a file or are derived from the vault. |
| F3 | `register` wrote a personal ledger file, appended audit tokens, ran audit, and triggered a backup — four implicit side effects from a "create record" command. | Medium | `add`/`set` only touch the vault. Audit, backup and export are separate commands. |
| F4 | `TWIN_PW` was consulted silently as a password source. | Medium | Off by default (`allow_env_password = false`). Environment variables are the easiest thing for an agent to read. |
| F5 | `inject --env` passed the full parent environment, and env injection was the documented first choice. | Medium | stdin is the default; `--env` uses a minimal environment unless `--inherit-env` is given. |
| F6 | The form interpolated titles and field labels into HTML and JavaScript, and rendered server responses with `innerHTML` in a page that handles secrets. | **High** (XSS on a secret-entry page) | All interpolation HTML-escaped or JSON-encoded; DOM built with `textContent`; per-response CSP nonce; `img-src 'none'`. |
| F7 | The form accepted any POST to the token URL: no `Origin`/`Host`/content-type check, so a web page in the same browser could post into it. | **High** | `Host` pinned to loopback; requires `Content-Type: application/json` **and** `X-Twin-Form: 1`, which forces a CORS preflight a foreign page cannot satisfy; one submission only. |
| F8 | No request size or field caps. | Medium | 64 KiB body, 50 rows, 32 fields, 4 KiB per value, title truncated. |
| F9 | Unlimited master-password attempts against the form — a local brute-force oracle. | Medium | Attempt cap (default 5) then shutdown; requests serialized under a lock. |
| F10 | Backup encrypted with `openssl enc -aes-256-cbc -pbkdf2` — unauthenticated ciphertext, malleable, and the "roundtrip check" only inspected a 4-byte prefix. | **High** | AES-256-GCM with scrypt-derived keys; tampering fails closed. The vault copy is validated by opening it *before* the destination is touched. |
| F11 | Audit used a fixed personal token list and personal scan roots, and wrote its report into the repo. | Medium | Detectors and roots are explicit; report JSON contains paths and detector indices, never values; 0600 permissions. |
| F12 | `check` required `profile.md`, `contacts.md`, `accounts.md`, a git repo and a `contacts.md.enc` backup — it failed on a fresh machine and encoded one person's layout. | Low | `doctor` reports config and posture only, with no personal-file assumptions. |
| F13 | `list` masked email-shaped and Chinese-mobile-shaped usernames only; every other identifier printed verbatim. | Medium | Sensitivity is explicit per field; the mask is chosen by level, not by guessing the format. |
| F14 | `chmod 600` was applied on Windows where it is effectively a no-op, giving a false sense of protection. | Low | Documented: on Windows the boundary is the profile ACL + DPAPI + BitLocker, not `chmod`. |
| F15 | An unexpected exception printed a full traceback, which can contain data or paths. | Low | CLI catches everything and prints only the exception type; `TWIN_DEBUG=1` opts into a traceback. |
| F16 | `add`/`register` accepted `--password`-style values on argv. | **High** | `--field password=...` is refused; secrets require `--secret-field`, a prompt, stdin, or the browser form. |
| F17 | Backup manifest had no integrity data for the copies. | Low | SHA-256 per file in `manifest.json`. |
| F18 | Extras archive was extracted without path validation. | Medium | Member paths checked against the destination, plus `tarfile` `filter="data"`. |
| F19 | `lock` cleared the session but left `autounlock` active without saying so. | Medium | `lock` warns; `autounlock status` states the reduced boundary. |
| F20 | One 950-line file mixed vault operations, personal ledger, backups, SSH packaging, git commits and web forms. | Medium | Split into `model` / `masking` / `vault` / `auth` / `inject` / `forms` / `backup` / `leakscan`; each has tests. |

---

## 4. Controls in this implementation

**Storage**

- KeePass KDBX (Argon2/AES per the pykeepass/KeePass defaults for the file's
  version) with a master password.
- Custom fields at `secret` sensitivity are written to the protected stream, not
  as plain string fields.
- Vault, session and autounlock files are created with owner-only permissions
  where the platform enforces them.

**Master password**

- Sources, in order: `--pw-stdin`, DPAPI session, DPAPI autounlock, opt-in
  `TWIN_PASSWORD`, TTY prompt. Nothing is consulted silently.
- No password is ever accepted from `argv`.

**Sessions and autounlock**

- Windows DPAPI (`CryptProtectData`) binds the blob to the current user and
  machine; a copied file is useless elsewhere.
- Autounlock is opt-in and lowers the boundary to "any process running as this
  user". `lock` and `autounlock off` are separate on purpose.
- On non-Windows platforms both features refuse to run instead of falling back to
  a weaker store.

**Injection**

- Value → stdin by default; minimal child environment; `subprocess.run` with an
  argument list, never `shell=True`.
- `twin` prints the entry name and channel, never the value.

**Local form**

- Loopback bind, 24-byte URL token compared with `compare_digest`, one use,
  bounded lifetime.
- CSP with nonce, `frame-ancestors 'none'`, `no-store`, `nosniff`,
  `no-referrer`, `Cross-Origin-Resource-Policy: same-origin`.
- JSON + custom header requirement, Host pinning, size/field caps, attempt cap.
- Responses contain entry names and status only; error strings never echo
  submitted data.

**Reveal gate**

- Requires `allow_reveal = true`, a TTY on stdin **and** stdout, `TWIN_AGENT`
  unset, and typing `REVEAL`. Blocked before the vault is even opened.

**Backups**

- Vault copied as-is (already encrypted); extra files tarred and sealed with
  AES-256-GCM under a scrypt-derived key.
- Restore validates the backup with the master password before writing anything.

**Leak scanning**

- Detectors from a file or derived from the vault; scan skips VCS, dependency and
  cache directories, binaries, and files over the size cap.
- Findings are `path:line` plus a detector index — never the value or a prefix.

---

## 5. Residual risk (read this)

These are known and accepted. If any of them is unacceptable, use a different
threat model (separate OS account, hardware token, dedicated machine).

1. **Same-user processes can read the vault.** Possession of the master password
   (or an unlocked session/autounlock blob) is all that is required. T2 wins.
2. **The reveal gate is a speed bump, not a sandbox.** An agent that controls a
   real PTY, can edit `policy.toml`, and can unset `TWIN_AGENT` can pass it. The
   `TWIN_AGENT` check only works if the harness sets the variable.
3. **Python cannot reliably zero memory.** Secrets exist as `str` objects, may be
   copied by the allocator, and can reach swap, hibernation files or crash dumps.
   Full-disk encryption and a short autounlock/session TTL reduce exposure.
4. **The child process is trusted with the value.** If it logs, echoes, or
   crashes with the value in a message, that is outside this tool's control.
5. **Anything the agent can read, the model provider can see.** `list`/`show`
   expose names, groups and masked identifiers. If a record title is itself
   sensitive, use a neutral title.
6. **The browser is part of the trust boundary.** Extensions, autofill engines and
   password managers may capture form contents. The page disables autofill
   hints, but a browser extension is out of scope.
7. **The form URL is printed to stdout.** A process that can read the agent's
   output could open it first. Lifetime and single-use limit the window; the
   trade-off is usability.
8. **No local action log.** The original wrote `audit.log` with entry names. This
   version keeps no trail, which protects metadata but removes tamper evidence.
9. **Metadata is not encrypted inside an unlocked vault.** Titles, group names and
   non-secret fields are plain text once decrypted — that is how KeePass works.
10. **No password-strength enforcement.** A weak master password defeats all of
    the above; there is no way to verify strength offline.
11. **KDF parameters come from the file/serializer.** If you create the database
    with a tool that uses weak settings, this project will not detect it.
12. **Windows file permissions are coarse.** `chmod` is mostly cosmetic there;
    rely on the user-profile ACL, DPAPI and disk encryption.

---

## 6. Recommended deployment for a real AI workflow

1. Run the agent and the vault under a **dedicated OS account**; keep the master
   password out of that account's reachable stores if you need a hard boundary.
2. Set `TWIN_AGENT=1` in every agent environment and leave `allow_reveal = false`.
   Turn it on only in a human shell, temporarily.
3. Keep `autounlock` off unless you accept "any process as this user".
4. Prefer `twin form` for entering secrets, `twin inject` for using them, and
   `twin list`/`show`/`export` for anything the model needs to reason about.
5. Back up with `twin backup --include <files>`, keep backups encrypted, and test
   `twin restore` before you need it.
6. Run `twin audit --from-vault --path <dir>` before sharing a directory, syncing
   it, or committing it.
7. Full-disk encryption on every machine that holds the vault or a backup.

---

## 7. Reporting

Open a GitHub issue for design questions and hardening ideas. For a vulnerability
that would expose a user's data, use a private security advisory instead of a
public issue.
