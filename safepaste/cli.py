"""Safe-Paste CLI — the Phase-1 "test it in my terminal immediately" surface.

Commands
--------
  demo                 self-contained end-to-end test (no clipboard needed)
  repl                 interactive session; the RAM map persists between cmds
  sanitize  [-f FILE | TEXT] [--copy]   clipboard/text -> sanitized -> clip
  restore   [-f FILE | TEXT] [--copy]   placeholders -> originals -> clip
  map       [--reveal]                  inspect the in-RAM mapping
  clear                                 panic: wipe the map (Ctrl+Shift+X)
  words     list|add|rm                 manage the custom dictionary
  allow     list|add|rm                 manage the never-redact allowlist
  config    path|edit                   where the config lives / open it

One-shot note: ``sanitize`` then ``restore`` in two separate processes cannot
share the map (it is RAM-only by design — nothing is written to disk). Use
``repl`` (or the desktop daemon) for the real two-hotkey workflow, or pipe
both directions in one call: ``sanitize --copy`` ... paste ... ``restore
--copy`` inside ``repl``.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .clipboard import ClipboardUnavailable, detect_backend
from .config import DEFAULT_FILENAME, Config
from .engine import SafePasteEngine
from .secure_map import SecureMap


# --------------------------------------------------------------------------
# wiring
# --------------------------------------------------------------------------


class Session:
    """Engine + clipboard for one interactive process."""

    def __init__(self, config_path: Optional[str], no_clipboard: bool = False) -> None:
        self.config = Config.load(config_path)
        self.secure_map = SecureMap()
        self.engine = SafePasteEngine.from_config(self.config, self.secure_map)
        self.clipboard = None
        if not no_clipboard:
            try:
                self.clipboard = detect_backend()
            except ClipboardUnavailable:
                pass

    def read_text(self, args) -> str:
        if getattr(args, "file", None):
            return Path(args.file).read_text(encoding="utf-8")
        if getattr(args, "text", None):
            return args.text
        if self.clipboard is not None:
            return self.clipboard.get_text()
        data = sys.stdin.read()
        if not data:
            raise SystemExit("nothing to sanitize: no --text/--file and no clipboard")
        return data

    def emit(self, text: str, args) -> None:
        if getattr(args, "copy", False) and self.clipboard is not None:
            self.clipboard.set_text(text)
            print("(result copied to clipboard)")
        else:
            print(text)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_sanitize(session: Session, args) -> None:
    text = session.read_text(args)
    result = session.engine.sanitize(text)
    print(result.notification(), file=sys.stderr)
    session.emit(result.text, args)


def cmd_restore(session: Session, args) -> None:
    text = session.read_text(args)
    result = session.engine.restore(text)
    print(result.notification(), file=sys.stderr)
    if not result.changed and session.clipboard is not None and not getattr(args, "file", None):
        # restore targets the clipboard itself: leave it untouched
        print("(clipboard left as-is)")
        return
    session.emit(result.text, args)


def cmd_map(session: Session, args) -> None:
    rows = session.secure_map.snapshot(reveal=args.reveal)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    if not rows:
        print("map is empty — memory clean (grey icon state)")
        return
    width = max(len(r["placeholder"]) for r in rows)
    for r in rows:
        print(
            f"  {r['placeholder']:<{width}}  ×{r['occurrences']:<2} "
            f"{r['category']:<12} {r['value']}"
        )
    print(f"  → {len(rows)} unique secret(s), {session.secure_map.total_occurrences} occurrence(s)")


def cmd_clear(session: Session, args) -> None:
    session.secure_map.clear()
    print("🧹 Memory wiped. Clipboard untouched. (Ctrl+Shift+X equivalent)")


def cmd_words(session: Session, args) -> None:
    cfg = session.config
    if args.action == "list":
        if not cfg.groups:
            print("no custom words configured")
        for cat, words in sorted(cfg.groups.items()):
            print(f"[{cat}]")
            for w in words:
                print(f"  - {w}")
        if cfg.source_path:
            print(f"(config: {cfg.source_path})")
        return
    if args.action == "add":
        if not args.word:
            raise SystemExit("words add requires WORD")
        cfg.add_word(args.word, args.group)
        path = cfg.save()
        print(f"added {args.word!r} to [{args.group}] → {path}")
        print("note: restart repl / daemon to load the new dictionary")
        return
    if args.action == "rm":
        if cfg.remove_word(args.word or ""):
            cfg.save()
            print(f"removed {args.word!r}")
        else:
            print(f"{args.word!r} not found")


def cmd_allow(session: Session, args) -> None:
    cfg = session.config
    if args.action == "list":
        if not cfg.allowlist:
            print("allowlist empty — every detected secret is redacted")
        for entry in cfg.allowlist:
            print(f"  - {entry}")
        return
    if args.action == "add":
        if not args.pattern:
            raise SystemExit("allow add requires PATTERN (IP, CIDR, glob, or CAT:pattern)")
        cfg.add_allow(args.pattern)
        path = cfg.save()
        print(f"allowed {args.pattern!r} → {path}")
        print("note: restart repl / daemon to apply")
        return
    if args.action == "rm":
        if cfg.remove_allow(args.pattern or ""):
            cfg.save()
            print(f"removed {args.pattern!r}")
        else:
            print(f"{args.pattern!r} not in allowlist")


def cmd_config(session: Session, args) -> None:
    path = session.config.source_path or Path(DEFAULT_FILENAME)
    if args.action == "edit":
        editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
        if not path.exists():
            path.write_text(
                json.dumps(
                    {"groups": {"CLIENT": [], "DB_TABLE": []},
                     "disabled_categories": [],
                     "case_sensitive_words": False},
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        if editor:
            # quote the path so spaces/metacharacters cannot break the command
            quoted = (
                subprocess.list2cmdline([str(path)])
                if os.name == "nt"
                else shlex.quote(str(path))
            )
            subprocess.call(f"{editor} {quoted}", shell=True)
        else:
            print(f"no $EDITOR set; edit {path} manually")
    else:
        print(path)


# --------------------------------------------------------------------------
# demo (fully offline, proves the whole loop)
# --------------------------------------------------------------------------

DEMO_INPUT = """\
[2026-11-12 09:14:02] INFO  api-gw 10.42.7.19 -> POST /v1/billing/invoices
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
[2026-11-12 09:14:02] ERROR db-01 (db-prod-01) connection failed: postgresql://svc_ro:Tr0ub4dor&x@10.42.7.55:5432/billing_events
    retry 1/3 against 192.168.1.50:5432 ... still failing (192.168.1.50 is the same host as 10.42.7.55)
[2026-11-12 09:14:03] WARN  stripe webhook key sk_live_TESTONLYFAKEKEY1234 rotated; contact dev@acme-corp.io (client Acme Corp)
[2026-11-12 09:14:03] DEBUG cache GET users_prod_v2_table:v17 key=abc123 from 192.168.1.50
[2026-11-12 09:14:04] INFO  version pinned: app v1.2.3.4 on host db-prod-01 — helper x[::2] untouched, semver 1.2.3 untouched
"""

DEMO_WORDS = {"CLIENT": ["Acme Corp"], "DB_TABLE": ["users_prod_v2_table", "billing_events"], "HOST": ["db-prod-01"]}


def cmd_demo(session: Session, args) -> None:
    engine, smap = session.engine, session.secure_map
    # inject the demo dictionary (kept separate from the user's real config)
    engine.map.configure_letter_categories(DEMO_WORDS.keys())
    engine.word_rules = engine._compile_word_rules(DEMO_WORDS)

    print("─" * 72)
    print("RAW INPUT (what you just copied — contains secrets):")
    print("─" * 72)
    print(DEMO_INPUT)

    res = engine.sanitize(DEMO_INPUT)
    print("─" * 72)
    print("SANITIZED (safe to paste into ChatGPT/Claude) — Ctrl+Shift+S result:")
    print("─" * 72)
    print(res.text)
    print("─" * 72)
    print("TOAST:", res.notification())

    print()
    print("MAP (RAM only — never written to disk):")
    for r in smap.snapshot(reveal=True):
        print(f"  {r['placeholder']:<16} ×{r['occurrences']}  {r['category']:<10} {r['value']!r}")

    # Simulate the LLM lowercasing a placeholder, then restore.
    llm_answer = res.text.replace("[IP_1]", "[ip_1]")  # case-mangled by model
    rest = engine.restore(llm_answer)
    ok = rest.text == DEMO_INPUT
    print()
    print("─" * 72)
    print("RESTORED (paste back into IDE) — Ctrl+Shift+R result:")
    print("─" * 72)
    print(rest.text)
    print("TOAST:", rest.notification())
    print("ROUND-TRIP BYTE-EXACT (even with [ip_1] case-mangling):", "✅ PASS" if ok else "❌ FAIL")

    engine.sanitize("")  # no-op safety check
    smap.clear()
    print("After clear(): map size =", len(smap), "(grey-tray state reached)")


# --------------------------------------------------------------------------
# REPL — the real two-hotkey workflow inside one process
# --------------------------------------------------------------------------


def cmd_repl(session: Session, args) -> None:
    print("Safe-Paste REPL — commands: sanitize [-c], restore [-c], map [--reveal], clear, words, put, quit")
    print("(no args -> clipboard; paste text directly after 'put')")
    while True:
        try:
            line = input("safe-paste> ").strip()
        except EOFError:
            break
        if not line:
            continue
        parts = line.split()
        cmd, flags = parts[0], parts[1:]
        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "put":
            if session.clipboard is None:
                print("no clipboard backend — use: sanitize <text>")
                continue
            buf: List[str] = []
            print("paste text, end with a single '.' on its own line:")
            while True:
                try:
                    ln = input()
                except EOFError:
                    break
                if ln == ".":
                    break
                buf.append(ln)
            session.clipboard.set_text("\n".join(buf))
            print("clipboard set.")
        elif cmd in ("sanitize", "restore"):
            if len(parts) > 1:
                text = " ".join(parts[1:]).strip("'\"")
            elif session.clipboard is not None:
                text = session.clipboard.get_text()
            else:
                buf2: List[str] = []
                print("paste text, end with a single '.' on its own line:")
                while True:
                    try:
                        ln = input()
                    except EOFError:
                        break
                    if ln == ".":
                        break
                    buf2.append(ln)
                text = "\n".join(buf2)
            fn = session.engine.sanitize if cmd == "sanitize" else session.engine.restore
            res = fn(text)
            print(res.notification())
            if "-c" in flags and session.clipboard:
                session.clipboard.set_text(res.text)
                print("(copied result to clipboard)")
            else:
                print("─" * 60)
                print(res.text)
                print("─" * 60)
        elif cmd == "map":
            ns = argparse.Namespace(reveal="--reveal" in flags, json=False)
            cmd_map(session, ns)
        elif cmd == "clear":
            cmd_clear(session, args)
        elif cmd == "words":
            ns = argparse.Namespace(action="list", word=None, group=None)
            cmd_words(session, ns)
        else:
            print("unknown command:", cmd)
    print("bye — RAM map dies with the process (by design).")


# --------------------------------------------------------------------------
# argparse
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safepaste",
        description="Safe-Paste: sanitize clipboard before pasting into an LLM; restore after.",
    )
    p.add_argument("--version", action="version", version=f"safepaste {__version__}")
    p.add_argument("--config", help=f"config path (default: ./{DEFAULT_FILENAME} if present)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def io_opts(sp):
        sp.add_argument("text", nargs="?", help="explicit input text (default: clipboard)")
        sp.add_argument("-f", "--file", help="read input from FILE instead")
        sp.add_argument("-c", "--copy", action="store_true", help="write result back to clipboard")

    io_opts(sub.add_parser("sanitize", help="redact -> placeholders -> RAM map"))
    io_opts(sub.add_parser("restore", help="placeholders -> originals"))

    pm = sub.add_parser("map", help="show the in-RAM mapping")
    pm.add_argument("--reveal", action="store_true", help="show full original values")
    pm.add_argument("--json", action="store_true")
    sub.add_parser("clear", help="wipe the RAM map (panic)")
    sub.add_parser("demo", help="offline end-to-end demo")
    sub.add_parser("repl", help="interactive session (map persists in-process)")

    pw = sub.add_parser("words", help="manage custom dictionary")
    pw.add_argument("action", choices=["list", "add", "rm"])
    pw.add_argument("word", nargs="?")
    pw.add_argument("--group", default="CUSTOM")

    pa = sub.add_parser(
        "allow",
        help="allowlist public values that must never be redacted "
        "(e.g. \"8.8.8.8\", \"10.0.0.0/8\", \"*@docs.public.io\", \"IP:1.1.1.1\")",
    )
    pa.add_argument("action", choices=["list", "add", "rm"])
    pa.add_argument("pattern", nargs="?")

    pc = sub.add_parser("config", help="config file handling")
    pc.add_argument("action", choices=["path", "edit"], nargs="?", default="path")
    return p


HANDLERS = {
    "sanitize": cmd_sanitize,
    "restore": cmd_restore,
    "map": cmd_map,
    "clear": cmd_clear,
    "demo": cmd_demo,
    "repl": cmd_repl,
    "words": cmd_words,
    "allow": cmd_allow,
    "config": cmd_config,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    no_clip = args.cmd in ("demo", "repl", "map", "clear", "words", "allow", "config")
    session = Session(args.config, no_clipboard=no_clip)
    handler = HANDLERS[args.cmd]
    try:
        handler(session, args)
    finally:
        session.secure_map.clear()  # belt & braces on every exit path
    return 0
