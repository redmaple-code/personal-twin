"""One-time local web form for entering a secret by hand.

Why a browser form: it keeps the value out of the terminal transcript, out of
shell history and out of an AI conversation. The agent starts the form, tells
the human the URL, and only ever receives ``{"ok": true, "entry": ...}``.

Hardening applied here (see SECURITY.md for the reasoning):

* binds to 127.0.0.1 only, random 32-byte URL token compared in constant time;
* derives a per-page CSP nonce, so injected markup cannot run;
* every interpolated value is HTML-escaped and JSON-encoded, never concatenated
  into JavaScript or ``innerHTML``;
* POSTs require ``Content-Type: application/json`` plus a custom header, which
  browsers must preflight, so a foreign page cannot post into the form;
* ``Host`` header pinned to loopback, body size / field count / field length caps;
* one submission only, bounded lifetime, and a cap on wrong master-password
  attempts before the server shuts itself down.
"""

from __future__ import annotations

import html
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .errors import TwinError

MAX_BODY = 64 * 1024
MAX_ITEMS = 50
MAX_FIELDS = 32
MAX_NAME = 64
MAX_VALUE = 4096
FORM_HEADER = "X-Twin-Form"


@dataclass
class FormField:
    name: str
    label: str
    secret: bool = False
    sensitivity: str = "identifying"

    def __post_init__(self) -> None:
        # A masked input is a secret, not merely a pretty field.
        if self.secret:
            self.sensitivity = "secret"


@dataclass
class FormResult:
    ok: bool
    entry: str | None = None
    error: str | None = None
    results: list[dict] = field(default_factory=list)

    def as_json(self) -> dict:
        out: dict = {"ok": self.ok}
        if self.entry:
            out["entry"] = self.entry
        if self.error:
            out["error"] = self.error
        if self.results:
            out["results"] = self.results
        return out


_STYLE = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
 background:#0d1117;color:#e6edf3;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
.card{width:min(560px,100%);background:#161b22;border:1px solid #30363d;border-radius:14px;padding:28px}
h1{margin:0 0 6px;font-size:17px;font-weight:600}
.sub{margin:0 0 20px;color:#8b949e;font-size:12px}
.row{border:1px solid #21262d;border-radius:10px;padding:14px;margin-bottom:12px;position:relative}
.row .num{position:absolute;top:-9px;left:12px;background:#21262d;color:#8b949e;font-size:11px;
 border-radius:6px;padding:1px 8px}
label{display:block;font-size:12px;color:#9da7b3;margin:10px 0 5px}
input{width:100%;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:8px;
 padding:9px 11px;font-size:14px}
input:focus{outline:none;border-color:#388bfd}
button{width:100%;border:0;border-radius:8px;padding:11px;font-size:14px;cursor:pointer;margin-top:8px}
.primary{background:#238636;color:#fff}
.add{background:none;border:1px dashed #3d444d;color:#8b949e}
.del{position:absolute;top:8px;right:8px;background:none;border:0;color:#6e7681;width:auto;
 padding:2px 6px;margin:0;font-size:14px}
.err{color:#f85149;font-size:13px;min-height:18px;margin-top:8px}
.ok{color:#3fb950}
.meta{color:#6e7681;font-size:11px;margin-top:14px;line-height:1.7}
.results div{padding:7px 10px;border-radius:7px;margin-top:6px;background:#0d1117;font-size:13px}
.results .r-ok{color:#3fb950}
.results .r-bad{color:#f85149}
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _input_html(f: FormField) -> str:
    typ = "password" if f.secret else "text"
    ac = "new-password" if f.secret else "off"
    return (
        f'<label for="{_esc(f.name)}">{_esc(f.label)}</label>'
        f'<input id="{_esc(f.name)}" name="{_esc(f.name)}" type="{typ}" '
        f'data-name="{_esc(f.name)}" autocomplete="{ac}" spellcheck="false">'
    )


def render_single(title: str, fields: list[FormField], group: str, needs_master: bool, nonce: str) -> str:
    inputs = "\n".join(_input_html(f) for f in fields)
    master = ""
    if needs_master:
        master = (
            '<label for="__master__">Vault master password</label>'
            '<input id="__master__" name="__master__" type="password" '
            'autocomplete="off" spellcheck="false">'
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>twin · add record</title>
<style nonce="{nonce}">{_STYLE}</style></head>
<body><main class="card">
<h1>{_esc(title)}</h1>
<p class="sub">Add a record. Values go straight into the encrypted vault and are never echoed back.</p>
<form id="f" autocomplete="off">
{inputs}
{master}
<div class="err" id="err" role="alert"></div>
<button class="primary" type="submit">Save encrypted</button>
<p class="meta">One-time page, bound to this machine's loopback interface.
It closes after a single submission and the submitted values are not returned
to the caller.</p>
</form></main>
<script nonce="{nonce}">
const GROUP = {json.dumps(group)};
const F = document.getElementById('f');
F.addEventListener('submit', async (ev) => {{
  ev.preventDefault();
  const err = document.getElementById('err');
  err.textContent = '';
  const data = {{}};
  for (const input of F.querySelectorAll('input')) {{
    if (input.dataset.name) data[input.dataset.name] = input.value;
    if (input.name === '__master__') data.__master__ = input.value;
  }}
  try {{
    const res = await fetch(location.href, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json', '{FORM_HEADER}': '1'}},
      body: JSON.stringify(data)
    }});
    const j = await res.json();
    if (j.ok) {{
      const el = document.createElement('div');
      el.className = 'ok';
      el.textContent = 'Saved to group ' + GROUP + '. You can close this page.';
      F.replaceChildren(el);
    }} else {{
      err.textContent = j.error || 'Save failed';
    }}
  }} catch (e) {{
    err.textContent = 'Request failed';
  }}
}});
</script></body></html>"""


def render_batch(title: str, fields: list[FormField], group: str, needs_master: bool, nonce: str) -> str:
    master = ""
    if needs_master:
        master = (
            '<label for="__master__">Vault master password</label>'
            '<input id="__master__" name="__master__" type="password" autocomplete="off">'
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>twin · add records</title>
<style nonce="{nonce}">{_STYLE}</style></head>
<body><main class="card">
<h1>{_esc(title)}</h1>
<p class="sub">Add records. All rows are saved in one submission and values are never echoed back.</p>
<div id="rows"></div>
<button class="add" type="button" id="add">+ Add row</button>
{master}
<div class="err" id="err" role="alert"></div>
<button class="primary" type="button" id="go">Save encrypted</button>
<div class="results" id="results"></div>
<p class="meta">One-time page on loopback. The caller only receives entry names and
per-row status.</p>
</main>
<script nonce="{nonce}">
const FIELD_DEFS = {json.dumps([{"name": f.name, "label": f.label, "secret": f.secret} for f in fields])};
const GROUP = {json.dumps(group)};
const rowsEl = document.getElementById('rows');
const errEl = document.getElementById('err');
const resEl = document.getElementById('results');

function addRow() {{
  const row = document.createElement('div');
  row.className = 'row';
  const num = document.createElement('span');
  num.className = 'num';
  row.appendChild(num);
  const del = document.createElement('button');
  del.className = 'del';
  del.type = 'button';
  del.textContent = '✕';
  del.addEventListener('click', () => {{ row.remove(); renumber(); }});
  row.appendChild(del);
  for (const def of FIELD_DEFS) {{
    const label = document.createElement('label');
    label.textContent = def.label;
    const input = document.createElement('input');
    input.id = 'fld-' + Math.random().toString(36).slice(2);
    input.type = def.secret ? 'password' : 'text';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.dataset.name = def.name;
    label.setAttribute('for', input.id);
    row.appendChild(label);
    row.appendChild(input);
  }}
  rowsEl.appendChild(row);
  renumber();
}}
function renumber() {{
  rowsEl.querySelectorAll('.row .num').forEach((n, i) => {{ n.textContent = String(i + 1); }});
}}
document.getElementById('add').addEventListener('click', addRow);
document.getElementById('go').addEventListener('click', async () => {{
  errEl.textContent = '';
  const items = [];
  for (const row of rowsEl.querySelectorAll('.row')) {{
    const item = {{}};
    for (const input of row.querySelectorAll('input')) {{
      if (input.dataset.name) item[input.dataset.name] = input.value.trim();
    }}
    if (Object.values(item).some(v => v !== '')) items.push(item);
  }}
  if (!items.length) {{ errEl.textContent = 'Fill at least one row'; return; }}
  const masterEl = document.getElementById('__master__');
  const payload = {{items: items}};
  if (masterEl) payload.__master__ = masterEl.value;
  const res = await fetch(location.href, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', '{FORM_HEADER}': '1'}},
    body: JSON.stringify(payload)
  }});
  const j = await res.json();
  if (!j.results) {{ errEl.textContent = j.error || 'Save failed'; return; }}
  resEl.replaceChildren();
  let allOk = true;
  j.results.forEach((r, i) => {{
    const div = document.createElement('div');
    div.className = r.ok ? 'r-ok' : 'r-bad';
    div.textContent = (r.ok ? 'Saved: ' : 'Failed: ') + (r.msg || ('row ' + (i + 1)));
    if (!r.ok) allOk = false;
    resEl.appendChild(div);
  }});
  if (allOk) {{
    rowsEl.replaceChildren();
    document.getElementById('go').disabled = true;
    document.getElementById('add').disabled = true;
  }}
}});
addRow();
</script></body></html>"""


class FormSession:
    def __init__(
        self,
        *,
        title: str,
        group: str,
        fields: list[FormField],
        mode: str,
        open_vault: Callable[[str], object],
        resolve_password: Callable[[], str | None],
        port: int = 8340,
        wait: int = 600,
        max_attempts: int = 5,
    ):
        self.title = title
        self.group = group
        self.fields = fields
        self.mode = mode
        self.open_vault = open_vault
        self.resolve_password = resolve_password
        self.wait_seconds = wait
        self.max_attempts = max_attempts

        self.token = secrets.token_urlsafe(24)
        self.result: FormResult | None = None
        self._attempts = 0
        self._lock = threading.Lock()
        self._done = threading.Event()

        handler = self._make_handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/f/{self.token}"

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> str:
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def wait(self, timeout: float | None = None) -> FormResult:
        deadline = time.time() + (self.wait_seconds if timeout is None else timeout)
        while time.time() < deadline:
            if self._done.wait(0.2):
                break
        self.stop()
        return self.result or FormResult(ok=False, error="timeout")

    def stop(self) -> None:
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass

    # -- request handling --------------------------------------------------
    def _make_handler(session):
        class Handler(BaseHTTPRequestHandler):
            server_version = "twin"
            sys_version = ""

            def log_message(self, *args):  # never log request paths/bodies
                pass

            # -- helpers --
            def _headers(self, code: int, ctype: str, length: int, nonce: str | None = None) -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cross-Origin-Resource-Policy", "same-origin")
                self.send_header("Cross-Origin-Opener-Policy", "same-origin")
                csp = (
                    "default-src 'none'; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'; connect-src 'self'; img-src 'none'; "
                    f"style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'"
                ) if nonce else (
                    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
                )
                self.send_header("Content-Security-Policy", csp)
                self.end_headers()

            def _send_json(self, code: int, payload: dict) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._headers(code, "application/json; charset=utf-8", len(body))
                self.wfile.write(body)

            def _host_ok(self) -> bool:
                host = (self.headers.get("Host") or "").strip().lower()
                return host in {
                    f"127.0.0.1:{session.port}",
                    f"localhost:{session.port}",
                }

            def _path_ok(self) -> bool:
                return secrets.compare_digest(self.path, f"/f/{session.token}")

            # -- verbs --
            def do_GET(self):
                if not (self._host_ok() and self._path_ok()):
                    self._send_json(404, {"error": "not found"})
                    return
                if session._done.is_set():
                    self._send_json(410, {"error": "already used"})
                    return
                nonce = secrets.token_urlsafe(16)
                if session.mode == "batch":
                    page = render_batch(session.title, session.fields, session.group,
                                        session.resolve_password() is None, nonce)
                else:
                    page = render_single(session.title, session.fields, session.group,
                                         session.resolve_password() is None, nonce)
                body = page.encode("utf-8")
                self._headers(200, "text/html; charset=utf-8", len(body), nonce)
                self.wfile.write(body)

            def do_POST(self):
                if not (self._host_ok() and self._path_ok()):
                    self._send_json(404, {"error": "not found"})
                    return
                if session._done.is_set():
                    self._send_json(410, {"error": "already used"})
                    return
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if ctype != "application/json" or self.headers.get(FORM_HEADER) != "1":
                    self._send_json(415, {"error": "unsupported request"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self._send_json(400, {"error": "bad request"})
                    return
                if length <= 0 or length > MAX_BODY:
                    self._send_json(413, {"error": "payload too large"})
                    return
                try:
                    data = json.loads(self.rfile.read(length).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(400, {"error": "bad json"})
                    return
                if not isinstance(data, dict):
                    self._send_json(400, {"error": "bad json"})
                    return

                with session._lock:
                    if session._done.is_set():
                        self._send_json(410, {"error": "already used"})
                        return
                    password = (data.pop("__master__", "") or "").strip() or session.resolve_password() or ""
                    if not password:
                        self._send_json(200, {"ok": False, "error": "master password required"})
                        return
                    try:
                        vault = session.open_vault(password)
                    except TwinError:
                        session._attempts += 1
                        if session._attempts >= session.max_attempts:
                            session.result = FormResult(ok=False, error="too many attempts")
                            session._done.set()
                            self._send_json(429, {"ok": False, "error": "too many attempts"})
                            return
                        self._send_json(200, {"ok": False, "error": "master password wrong"})
                        return

                    try:
                        if session.mode == "batch":
                            result = _save_batch(session, vault, data)
                        else:
                            result = _save_single(session, vault, data)
                    except TwinError as exc:
                        self._send_json(200, {"ok": False, "error": str(exc)})
                        return

                    session.result = result
                    if result.ok:
                        session._done.set()
                    self._send_json(200, result.as_json())

        return Handler


def _clean_value(raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, (str, int, float)):
        raise TwinError("invalid field value")
    value = str(raw).strip()
    if len(value) > MAX_VALUE:
        raise TwinError("field value too long")
    return value


def _collect_fields(session: FormSession, data: dict) -> dict[str, str]:
    values: dict[str, str] = {}
    allowed = {f.name for f in session.fields}
    for name, raw in data.items():
        if name not in allowed or not isinstance(name, str) or len(name) > MAX_NAME:
            continue
        value = _clean_value(raw)
        if value:
            values[name] = value
    return values


def _sens_map(session: FormSession) -> dict[str, str]:
    return {f.name: f.sensitivity for f in session.fields}


def _save_error(exc: TwinError) -> str:
    """Never echo submitted data back: a title could itself be a secret."""
    return "record already exists" if "already exists" in str(exc) else "save failed"


def _save_single(session: FormSession, vault, data: dict) -> FormResult:
    title = (data.pop("title", "") or session.title).strip()[:120]
    if not title:
        return FormResult(ok=False, error="title required")
    values = _collect_fields(session, data)
    # A field named like a credential maps onto the native password slot.
    for alias in ("password", "pass", "secret", "token", "apikey", "api_key", "key"):
        if alias in values and "password" not in values:
            values["password"] = values.pop(alias)
    try:
        vault.add(title=title, group=session.group, values=values,
                  sensitivities=_sens_map(session))
    except TwinError as exc:
        return FormResult(ok=False, error=_save_error(exc))
    return FormResult(ok=True, entry=title)


def _save_batch(session: FormSession, vault, data: dict) -> FormResult:
    items = data.get("items")
    if not isinstance(items, list) or not items:
        return FormResult(ok=False, error="no items")
    if len(items) > MAX_ITEMS:
        return FormResult(ok=False, error="too many items")
    results: list[dict] = []
    sens = _sens_map(session)
    any_ok = False
    for item in items:
        if not isinstance(item, dict):
            results.append({"ok": False, "msg": "invalid row"})
            continue
        title = (item.pop("title", "") or "").strip()[:120]
        if not title:
            results.append({"ok": False, "msg": "title required"})
            continue
        values = _collect_fields(session, item)
        for alias in ("password", "pass", "secret", "token", "apikey", "api_key", "key"):
            if alias in values and "password" not in values:
                values["password"] = values.pop(alias)
        try:
            vault.add(title=title, group=session.group, values=values, sensitivities=sens)
        except TwinError as exc:
            results.append({"ok": False, "msg": _save_error(exc)})
            continue
        any_ok = True
        results.append({"ok": True, "msg": f"saved in group {session.group}"})
    return FormResult(ok=any_ok, results=results)
