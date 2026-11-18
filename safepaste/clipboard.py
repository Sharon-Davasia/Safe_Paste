"""Clipboard access with zero required dependencies.

We shell out to the native OS utilities instead of bundling a GUI toolkit:
the process lives for milliseconds per hotkey press, keeping the "invisible,
ultra-lightweight" promise.

Backend priority:

    Linux   : wl-clipboard (Wayland) → xclip → xsel → pyperclip (optional)
    macOS   : pbpaste / pbcopy → pyperclip (optional)
    Windows : pyperclip (optional) → PowerShell Get-Clipboard / Set-Clipboard

If nothing is available (headless sandbox, SSH session) callers get a clear
error and can fall back to ``--text`` / ``--file`` / stdin or the built-in
demo/REPL modes.
"""

from __future__ import annotations

import base64 as _b64
import os
import shutil
import subprocess
import sys
from typing import List, Optional


class ClipboardUnavailable(RuntimeError):
    pass


def _run(cmd: List[str], data: Optional[str] = None, timeout: float = 10.0) -> str:
    proc = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise OSError(proc.stderr.strip() or f"{cmd[0]} exited {proc.returncode}")
    return proc.stdout


# --------------------------------------------------------------------------
# Windows hardening: Windows PowerShell 5.1 reads stdin in the OEM console
# codepage and writes stdout the same way, so naive `Set-Clipboard`/
# `Get-Clipboard` piping mangles every non-ASCII char (logs with ✓, quotes
# with é, etc). Workaround: shuttle clipboard text as base64 (pure ASCII —
# codepage-proof) and pass the PS script itself via -EncodedCommand
# (UTF-16LE base64). No temp files, no registry, still zero dependencies.
# --------------------------------------------------------------------------


def _ps_b64(text: str) -> str:
    return _b64.b64encode(text.encode("utf-8")).decode("ascii")


def _ps_from_b64(blob: str) -> str:
    return _b64.b64decode("".join(blob.split()).encode("ascii")).decode("utf-8")


def _ps_command(script: str) -> List[str]:
    return [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        _b64.b64encode(script.encode("utf-16-le")).decode("ascii"),
    ]


_PS_GET = (
    "$v = Get-Clipboard -Raw; "
    "if ($null -eq $v) { $v = '' }; "
    "[Console]::Out.Write([Convert]::ToBase64String("
    "[Text.Encoding]::UTF8.GetBytes($v)))"
)

_PS_SET = (
    "$i = [Console]::In.ReadToEnd(); "
    "if ($i.Trim().Length -gt 0) { "
    "$t = [Text.Encoding]::UTF8.GetString("
    "[Convert]::FromBase64String(($i -replace '\\s',''))) } "
    "else { $t = '' }; "
    "Set-Clipboard -Value $t"
)


class _WindowsUnicodeBackend:
    name = "powershell-b64"

    def get_text(self) -> str:
        out = _run(_ps_command(_PS_GET))
        return _ps_from_b64(out) if out.strip() else ""

    def set_text(self, text: str) -> None:
        _run(_ps_command(_PS_SET), data=_ps_b64(text))


class _CliBackend:
    """Generic get/set pair implemented with two external commands."""

    def __init__(self, name: str, get_cmd: List[str], set_cmd: List[str]) -> None:
        self.name = name
        self._get = get_cmd
        self._set = set_cmd

    def get_text(self) -> str:
        return _run(self._get)

    def set_text(self, text: str) -> None:
        _run(self._set, data=text)


class _PyperclipBackend:
    name = "pyperclip"

    def get_text(self) -> str:
        import pyperclip  # noqa: WPS433 (optional dependency)

        return pyperclip.paste()

    def set_text(self, text: str) -> None:
        import pyperclip

        pyperclip.copy(text)


class InMemoryClipboard:
    """Test/headless fallback: one process-wide scratch string."""

    name = "in-memory"
    _store: str = ""

    def get_text(self) -> str:
        return self._store

    def set_text(self, text: str) -> None:
        InMemoryClipboard._store = text


def _which(*names: str) -> Optional[str]:
    for n in names:
        if shutil.which(n):
            return n
    return None


def detect_backend(prefer: Optional[str] = None):
    """Return a clipboard backend instance, or raise ClipboardUnavailable."""
    if prefer == "memory":
        return InMemoryClipboard()

    candidates = []
    if sys.platform.startswith("linux"):
        wayland = bool(os.environ.get("WAYLAND_DISPLAY"))
        if wayland and _which("wl-copy", "wl-paste"):
            candidates.append(
                _CliBackend("wl-clipboard", ["wl-paste", "-n"], ["wl-copy"])
            )
        if _which("xclip"):
            candidates.append(
                _CliBackend(
                    "xclip",
                    ["xclip", "-selection", "clipboard", "-o"],
                    ["xclip", "-selection", "clipboard", "-i"],
                )
            )
        if _which("xsel"):
            candidates.append(
                _CliBackend("xsel", ["xsel", "-b", "-o"], ["xsel", "-b", "-i"])
            )
    elif sys.platform == "darwin":
        if _which("pbpaste", "pbcopy"):
            candidates.append(_CliBackend("pbcopy", ["pbpaste"], ["pbcopy"]))
    elif sys.platform == "win32":
        if _which("powershell"):
            candidates.append(_WindowsUnicodeBackend())

    try:  # pyperclip works everywhere as a last resort if it happens to be installed
        import pyperclip  # noqa: F401

        candidates.append(_PyperclipBackend())
    except ImportError:
        pass

    if candidates:
        # First probe succeeds for the vast majority of setups; the daemon
        # reports a toast (not a crash) if the very first real use fails.
        return candidates[0]

    raise ClipboardUnavailable(
        "No clipboard backend found (no wl-clipboard/xclip/xsel/pbpaste/"
        "pyperclip). Headless environment? Use --text/--file/stdin, "
        "`python -m safepaste repl`, or `python -m safepaste demo`."
    )


def get_text() -> str:
    return detect_backend().get_text()


def set_text(text: str) -> None:
    detect_backend().set_text(text)
