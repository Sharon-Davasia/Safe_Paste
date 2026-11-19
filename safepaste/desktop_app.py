"""Safe-Paste desktop daemon — Phase 2 (hotkeys + tray + toasts).

Zero-dependency core, but the invisible-UI layer needs three small optional
packages (~2 MB total, no Electron, no browser view):

    pip install -r requirements-desktop.txt
    python -m safepaste.desktop_app

Hotkeys:
    Ctrl+Shift+S  sanitize clipboard      -> 🔒 toast
    Ctrl+Shift+R  restore clipboard       -> 🔓 toast
    Ctrl+Shift+X  PANIC: wipe RAM map     -> 🧹 toast

Tray icon: grey when the map is empty, green when it holds secrets.
macOS note: grant Accessibility (Input Monitoring) permission for global
hotkeys, or the key listener will silently do nothing.

Security notes for this file:
  * toast payloads contain counts only — never secret values;
  * "Edit Custom Words" opens the keyword config (no secrets in it);
  * quitting clears the map; there is intentionally no persistence path.
"""

from __future__ import annotations

import sys
import threading
from typing import Optional

try:  # optional desktop deps ------------------------------------------------
    import pystray
    from pystray import Menu, MenuItem
    from pynput import keyboard

    HAS_DEPS = True
except ImportError:  # pragma: no cover - exercised only when deps missing
    HAS_DEPS = False

from . import __version__
from .clipboard import ClipboardUnavailable, detect_backend
from .config import Config
from .engine import SafePasteEngine
from .secure_map import SecureMap

HOTKEYS = {
    "<ctrl>+<shift>+s": "sanitize",
    "<ctrl>+<shift>+r": "restore",
    "<ctrl>+<shift>+x": "panic",
}

ICON_COLORS = {"idle": (128, 128, 128, 255), "active": (0, 170, 90, 255)}


def notify(title: str, message: str) -> None:
    """Native toast with graceful fallbacks (plyer → notify-send → stdout)."""
    try:
        from plyer import notification

        notification.notify(
            title=title, message=message, timeout=2.5, app_name="Safe-Paste"
        )
        return
    except Exception:
        pass
    if sys.platform.startswith("linux"):
        import subprocess

        try:
            subprocess.run(
                ["notify-send", "-t", "2500", title, message],
                capture_output=True,
                timeout=3,
                check=False,
            )
            return
        except Exception:
            pass
    print(f"{title}: {message}")


def make_image(color, size: int = 64):
    try:
        from PIL import Image, ImageDraw

        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([2, 2, size - 2, size - 2], radius=size // 4, fill=color)
        pad = size // 4
        d.ellipse([pad, pad, size - pad, size - pad], fill=(255, 255, 255, 235))
        return img
    except ImportError:
        return None


class SafePasteDaemon:
    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config = Config.load(config_path)
        self.map = SecureMap()
        self.engine = SafePasteEngine.from_config(self.config, self.map)
        try:
            self.clipboard = detect_backend()
        except ClipboardUnavailable:
            print("FATAL: no clipboard backend found — install xclip/wl-clipboard "
                  "or pyperclip.", file=sys.stderr)
            raise SystemExit(1)
        self.icon: Optional["pystray.Icon"] = None
        self._lock = threading.Lock()

    # -- workflow -------------------------------------------------------------
    # A hotkey must NEVER crash the daemon: clipboard backends can fail at
    # runtime (X server died, Wayland lock, powershell blocked by GPO).
    # Every handler is wrapped; failures surface as a toast.

    def _guarded(self, fn):
        def inner():
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - last-resort hotkey guard
                notify("Safe-Paste", f"⚠ {fn.__name__} failed: {exc}")

        inner.__name__ = getattr(fn, "__name__", "handler")
        return inner

    def sanitize(self) -> None:
        with self._lock:
            text = self.clipboard.get_text()
            if not text:
                notify("Safe-Paste", "📋 Clipboard is empty or has no text.")
                return
            result = self.engine.sanitize(text)
            if result.changed:
                self.clipboard.set_text(result.text)
            notify("Safe-Paste", result.notification())
        self.refresh_tray()

    def restore(self) -> None:
        with self._lock:
            text = self.clipboard.get_text()
            if not text:
                notify("Safe-Paste", "📋 Clipboard is empty or has no text.")
                return
            result = self.engine.restore(text)
            if result.changed:
                self.clipboard.set_text(result.text)
            notify("Safe-Paste", result.notification())
        self.refresh_tray()

    def panic(self) -> None:
        with self._lock:
            n = len(self.map)
            self.map.clear()
        notify("Safe-Paste", f"🧹 Wiped {n} mapped secret(s) from RAM. Clipboard untouched.")
        self.refresh_tray()

    # -- tray ------------------------------------------------------------------

    def refresh_tray(self) -> None:
        if self.icon is None:
            return
        active = len(self.map) > 0
        state = "active" if active else "idle"
        img = make_image(ICON_COLORS[state])
        title = (
            f"Safe-Paste — {len(self.map)} secret(s) in RAM"
            if active
            else "Safe-Paste — idle (memory empty)"
        )
        try:
            if img is not None:
                self.icon.icon = img
            self.icon.title = title
            self.icon.update()
        except Exception:
            pass  # tray backends can be flaky; never kill the hotkeys

    def map_count_text(self) -> str:
        return f"View Active Map: {len(self.map)} item(s)"

    def edit_words(self, *_a) -> None:
        import os
        import subprocess

        path = self.config.source_path
        if path is None:
            path = self.config.save()
        if sys.platform == "win32":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])

    def on_menu(self, icon, item) -> None:
        getattr(self, item.action)(icon)

    def quit(self, icon=None) -> None:
        self.map.clear()
        if icon is not None:
            icon.stop()

    # -- run -------------------------------------------------------------------

    def run(self) -> None:
        if not HAS_DEPS:
            raise SystemExit(
                "desktop deps missing — run:  pip install -r requirements-desktop.txt"
            )
        handlers = {
            "sanitize": self._guarded(self.sanitize),
            "restore": self._guarded(self.restore),
            "panic": self._guarded(self.panic),
        }

        def dispatch(name: str):
            def _f():  # hotkey callbacks fire on the pynput listener thread;
                # clipboard + toast work moves to a worker immediately.
                threading.Thread(target=handlers[name], daemon=True).start()

            return _f

        menu = Menu(
            MenuItem(self.map_count_text, None, active=False),
            MenuItem("Edit Custom Words…", self.edit_words),
            MenuItem("Clear Memory (Ctrl+Shift+X)", handlers["panic"]),
            Menu.SEPARATOR,
            MenuItem(f"Quit v{__version__}", self.quit),
        )
        self.icon = pystray.Icon(
            "safepaste", make_image(ICON_COLORS["idle"]), "Safe-Paste — idle", menu
        )
        listener = keyboard.GlobalHotKeys(
            {combo: dispatch(action) for combo, action in HOTKEYS.items()}
        )
        listener.start()
        print("Safe-Paste running. Hotkeys: " + ", ".join(f"{k}={v}" for k, v in HOTKEYS.items()))
        try:
            self.icon.run()  # blocks until Quit
        finally:
            listener.stop()
            self.map.clear()


def main() -> None:
    SafePasteDaemon().run()


if __name__ == "__main__":
    main()
