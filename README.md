# Safe-Paste

**The lightweight, local-first clipboard sanitizer middleware.**

Copy secrets out of your IDE / server logs, hit a hotkey, paste clean
placeholders into ChatGPT/Claude, get your fix back, hit another hotkey, paste
real identifiers back into the IDE. No dashboard. No network. No disk.

```
   IDE / terminal                LLM chat
 ┌──────────────┐  Ctrl+Shift+S ┌──────────────┐  Ctrl+Shift+R ┌──────────────┐
 │ copy secret  │ ────────────► │ [IP_1] [KEY_1]│ ────────────► │ paste into   │
 │ code / logs  │   sanitize    │  safe to send │   restore     │ your IDE     │
 └──────────────┘               └──────────────┘               └──────────────┘
                ◄──── in-RAM bidirectional map (never persisted) ────►
```

## Quick start (Phase 1 — zero dependencies, stdlib only)

```bash
python3 -m safepaste demo          # full offline end-to-end test
python3 -m safepaste repl          # interactive session; the RAM map persists
                                   # between commands (this IS the workflow)
python3 -m safepaste sanitize      # clipboard -> sanitized -> clipboard
python3 -m safepaste sanitize -f examples/sample_server_log.txt
python3 -m safepaste map --reveal  # inspect the (in-RAM, per-process) map
python3 -m safepaste words add "acme_corp" --group CLIENT
python3 -m safepaste allow add "8.8.8.8"    # never redact public values
```

`sanitize` + `restore` in **two separate one-shot processes cannot share the
map** — RAM-only state dies with the process *by design*; there is no
"persist the secrets to disk" flag to turn off. For the real two-hotkey
workflow, use `repl` (one process) or the desktop daemon (below).

Tests:

```bash
python3 -m unittest discover -s tests -v    # 40 tests, no external deps
```

## Custom dictionary, allowlist, optional NER

Copy `config.example.json` to `safepaste.config.json`:

```json
{
  "groups": {
    "CLIENT":   ["Acme Corp", "acme_corp", "Globex Industries"],
    "DB_TABLE": ["users_prod_v2_table", "billing_events"],
    "HOST":     ["db-prod-01", "jenkins.internal"]
  },
  "allowlist": ["8.8.8.8", "10.0.0.0/8", "https://localhost*", "*@docs.public.io"],
  "word_file": null,
  "disabled_categories": [],
  "case_sensitive_words": false,
  "ner": { "enabled": false, "model": "en_core_web_sm", "labels": ["PERSON", "ORG"] }
}
```

- **`allowlist`** — values that must *never* be redacted. Entries are exact
  strings, fnmatch globs (case-insensitive), IPs or CIDRs (matched against
  any IP-shaped finding, IPv4+IPv6), optionally category-scoped
  (`"IP:1.1.1.1"` allows that literal only as an IP finding — the same text
  inside a connection string stays hidden). Checked *after* detection but
  *before* the RAM map, so allowed values are never stored at all. Manage via
  `safepaste allow list|add|rm`, quotes protect globs from your shell.
- **`ner`** — Tier 3. With `enabled: true` (and `pip install spacy &&
  python -m spacy download en_core_web_sm`, ~13 MB model), person/org names
  regex can't know — "Jane Cooper", "Northwind Traders" — also get
  `[PERSON_1]`/`[ORG_1]`, deterministically, over only the text Tiers 1–2
  didn't claim. The model lazy-loads on first sanitize (daemon startup stays
  instant, RSS grows only if enabled); any NER failure degrades to
  "regex-only" for that call — it can never break the hotkey. Off by default:
  it's the one tier with a runtime cost.

- Each group becomes its own placeholder namespace with **letters**:
  `[CLIENT_A]`, `[DB_TABLE_B]`, … (regex categories use numbers: `[IP_1]`).
- Words match case-insensitively at identifier boundaries
  (`(?<!\w)word(?!\w)`), so `users_prod_v2_table` never matches inside
  `users`. Restore rewrites every variant back to the config spelling.
- `word_file`: plain `words.txt`, one term per line → `CUSTOM` group.
- `disabled_categories`: e.g. `["URL"]` if redacting URLs is too noisy.

## Desktop daemon (Phase 2 — invisible UI)

```bash
pip install -r requirements-desktop.txt   # pystray + pynput + plyer + Pillow
python -m safepaste.desktop_app
```

| Trigger | Action |
|---|---|
| `Ctrl+Shift+S` | sanitize clipboard → toast `🔒 Sanitized: 3 IPs, 1 API Key, 2 Clients.` |
| `Ctrl+Shift+R` | restore placeholders → toast `🔓 Restored 13 original values to clipboard.` |
| `Ctrl+Shift+X` | **panic**: wipe the RAM map, clipboard untouched |
| tray icon | grey = empty map · green = holding secrets; right-click: map count / Edit Words / Clear / Quit |

macOS: grant *Input Monitoring* permission for global hotkeys. Clipboard
backends: `wl-clipboard`/`xclip`/`xsel` (Linux), `pbcopy` (macOS),
PowerShell/`pyperclip` (Windows).

## Architecture

```
safepaste/
├── detectors.py    Tier 1: 11 pure-regex detectors + overlap PRIORITY table
├── allowlist.py    public-value exemptions (exact / glob / IP / CIDR, scoped)
├── ner.py          Tier 3 (optional): lazy-loaded spaCy pass over residual text
├── engine.py       scan → overlap resolution → allowlist → replace/restore
├── secure_map.py   RAM-only bidirectional dict (O(1) both directions)
├── config.py       custom word groups / toggles (keywords only, no secrets)
├── clipboard.py    native OS clipboard via subprocess, zero hard deps
│                   (Windows: base64 shuttle + -EncodedCommand = Unicode-safe)
├── cli.py          demo / repl / sanitize / restore / map / words / allow
└── desktop_app.py  tray + hotkeys + toasts (optional deps), crash-proofed
```

**Why placeholders, not noise:** a secret appearing 4× always becomes the same
`[IP_1]`, so the LLM still sees "these two log lines share a host" / "this
variable is used three times" — relational logic survives redaction, which is
the whole point vs. `sed`.

**Tiered detection, single claimed-span pass:**

1. Tier 1 regex finds candidate spans.
2. Tier 2 dictionary words are matched; anything overlapping an accepted
   regex span is dropped (a table name *inside* a connection string does not
   get double-redacted).
3. All findings are sorted `(start, −length, −priority)` and accepted
   greedily — the longest, most-specific span wins a region; a `-----BEGIN
   PRIVATE KEY-----` block, its inner base64, and everything inside a
   `postgres://` URL collapse into exactly one placeholder.
4. Replacement runs over accepted spans, so spans can never shift out of
   sync; placeholders are minted by `SecureMap.get_or_create()` — dedup by
   `(category, value)` makes repeats O(1) and deterministic.

**Restore is tolerant:** `[ip_1]`, `[ IP_1 ]` all resolve (LLMs like to
reformat). Tokens that *look* like ours but aren't in the map (`[IP_9]`
hallucinated) are left untouched and reported. Placeholder tokens that
already existed in your source text are excluded from allocation so
Safe-Paste never clobbers them.

## Security notes (honesty section)

- **RAM is not scrubbed on clear.** CPython strings are immutable; `clear()`
  drops references (memory is reclaimed and gone at process exit), but GC
  timing is not a guarantee of byte erasure. If you need `zeroize`-style
  wiping, port the engine to Rust; the architecture is designed for it.
- No network I/O anywhere in the core (stdlib-only). Nothing in
  `secure_map.py` may ever touch disk. Toasts and `map` output show masked
  values unless you pass `--reveal`.
- Threat model: this protects against *accidental* exfil when pasting into
  LLMs. It is **not** a DLP boundary — anything you paste into a cloud LLM
  must be assumed disclosed; placeholders leak structure (counts, lengths).
  Never assume it catches *everything* (see known gaps).
- Keep `safepaste.config.json` out of git (already ignored) — client/table
  names in the dictionary are themselves company-sensitive.

## Known gaps & roadmap

- IPv4 vs semver (`1.2.3.4`) is inherently ambiguous — guarded by
  lookarounds (`v1.2.3.4` is safe), but a bare version quad may redact.
  Mitigations: `disabled_categories: ["IP"]` per-case, or add your version
  constants to the allowlist globs.
- Person/org names are Tier 3 and off by default — enable `ner` in the
  config if client names show up in your logs without being dictionary words.
- Windows: PowerShell backend is Unicode-safe via a base64 shuttle (no temp
  files); pyperclip (if installed) remains a fallback. Long clipboard writes
  stay well under PS's stdin limits because the payload never rides the
  command line.
- Phase 3 ideas: per-app rules (only sanitize when the front window is
  chatgpt.com), macOS Services-menu item, tray HUD near the cursor, and a
  Rust/Go core (same Finding/priority contract) for a single ~2 MB binary
  with true `zeroize` memory wiping.
