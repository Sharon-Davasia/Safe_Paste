"""The RAM-only bidirectional map at the heart of Safe-Paste.

SECURITY INVARIANT: nothing in this module may ever touch disk — no files, no
sqlite, no pickle, no logging of raw values, no environment dumps. The map is
allocated on the heap of a single process and is gone when the process dies or
when ``clear()`` is called (Ctrl+Shift+X / tray "Panic").

Both directions are O(1):

    _by_key   :  "IP_1"                          -> Secret   (restore path)
    _by_id    :  ("IP", "192.168.1.50")          -> Secret   (sanitize dedup)

``_by_id`` is what guarantees determinism: the same secret value seen 4 times
always maps to the same placeholder, across the whole session.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class Secret:
    key: str            # canonical token without brackets, e.g. "IP_1", "CLIENT_A"
    category: str
    value: str          # the original, unsanitized string
    occurrences: int = 0
    created_at: float = field(default_factory=time.time)


def letters(n: int) -> str:
    """1 -> A, 2 -> B ... 26 -> Z, 27 -> AA (used for custom word groups)."""
    out = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out = chr(ord("A") + rem) + out
    return out


def _mask(value: str) -> str:
    """Safe-for-screenshot preview of a secret."""
    v = value.replace("\n", "\\n")
    if len(v) <= 10:
        return v[:2] + "…" + f"({len(value)} ch)"
    return v[:4] + "…" + v[-2:] + f" ({len(value)} ch)"


class SecureMap:
    """In-memory, bidirectional placeholder <-> secret store."""

    def __init__(self, letter_categories: Iterable[str] = ()) -> None:
        self._by_key: Dict[str, Secret] = {}
        self._by_id: Dict[Tuple[str, str], Secret] = {}
        self._counters: Dict[str, int] = {}
        self._letter_cats: Set[str] = {c.upper() for c in letter_categories}

    # -- configuration -----------------------------------------------------

    def configure_letter_categories(self, categories: Iterable[str]) -> None:
        """Categories whose placeholders use letters (CLIENT_A) not numbers."""
        self._letter_cats = {c.upper() for c in categories}

    # -- core --------------------------------------------------------------

    def get_or_create(
        self,
        category: str,
        value: str,
        dedup_key: Optional[str] = None,
        forbidden: Optional[Set[str]] = None,
    ) -> Tuple[Secret, bool]:
        """Return ``(secret, created)`` for a secret value.

        ``dedup_key`` lets callers fold case for custom dictionary words so
        ``ACME_CORP`` and ``acme_corp`` share one placeholder. ``forbidden``
        is the set of placeholder tokens that already exist verbatim in the
        source text — allocated keys skip them so we never collide.
        """
        category = category.upper()
        ident = value if dedup_key is None else dedup_key
        existing = self._by_id.get((category, ident))
        if existing is not None:
            return existing, False

        n = self._counters.get(category, 0) + 1
        while True:
            label = letters(n) if category in self._letter_cats else str(n)
            key = f"{category}_{label}"
            if key not in self._by_key and not (forbidden and key in forbidden):
                break
            n += 1
        self._counters[category] = n

        secret = Secret(key=key, category=category, value=value)
        self._by_key[key] = secret
        self._by_id[(category, ident)] = secret
        return secret, True

    def touch(self, secret: Secret) -> None:
        secret.occurrences += 1

    def lookup(self, key: str) -> Optional[Secret]:
        """Restore-path O(1) lookup; keys are case-insensitive by design."""
        return self._by_key.get(key.upper())

    # -- lifecycle / introspection ------------------------------------------

    def clear(self) -> None:
        """Panic button. Drops every reference so RAM can be reclaimed.

        Note: CPython strings are immutable, so we cannot zero the underlying
        bytes; true in-place scrubbing is impossible in Python (see README —
        a Rust core can do it with `zeroize` if that ever matters).
        """
        self._by_key.clear()
        self._by_id.clear()
        self._counters.clear()

    def __len__(self) -> int:
        return len(self._by_key)

    @property
    def total_occurrences(self) -> int:
        return sum(s.occurrences for s in self._by_key.values())

    def entries(self) -> List[Secret]:
        return list(self._by_key.values())

    def snapshot(self, reveal: bool = False) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        for s in self._by_key.values():
            rows.append(
                {
                    "placeholder": f"[{s.key}]",
                    "category": s.category,
                    "occurrences": s.occurrences,
                    "value": s.value if reveal else _mask(s.value),
                }
            )
        return rows

    def __repr__(self) -> str:  # never print secrets by accident
        return f"<SecureMap {len(self._by_key)} entries, {self.total_occurrences} occurrences>"
