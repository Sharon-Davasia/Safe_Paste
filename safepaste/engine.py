"""Safe-Paste core engine: text in -> sanitized text out, and back again.

Pipeline (sanitize):

    text ──► Tier 1: regex detectors        (IPs, keys, tokens, URLs, …)
         ──► Tier 2: custom word dictionary (company terms, grouped)
         ──► overlap resolution             (longest-first, priority tie-break)
         ──► Tier 3: optional NER           (PERSON/ORG in unclaimed regions)
         ──► allowlist filter               (public values never reach the map)
         ──► SecureMap.get_or_create        (deterministic, O(1) dedup)
         ──► right-to-left replacement      (spans never shift out of sync)

Pipeline (restore): find ``[KEY]`` tokens case-insensitively, look them up in
the map (O(1)), substitute the original values. Tokens that look like ours but
aren't in the map (LLM hallucinated an ``[IP_9]``) are reported as misses and
left untouched.

The engine only ever manipulates strings — reading/writing the clipboard is
the caller's job (cli.py, desktop daemon), which keeps it fully unit-testable.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .allowlist import AllowList
from .config import Config
from .detectors import (
    FRIENDLY_NAMES,
    PRIORITY,
    REGEX_DETECTORS,
    Detector,
)
from .secure_map import SecureMap

# [IP_1], [ ip_1 ], [ DB_TABLE_12 ] — deliberately tolerant of LLM reformatting.
PLACEHOLDER_SCAN_RE = re.compile(r"\[\s*([A-Za-z][A-Za-z0-9_]{0,48})\s*\]")
# Shape of a token we mint: CATEGORY_99 or CATEGORY_ZZ (custom groups).
OUR_TOKEN_RE = re.compile(r"[A-Z][A-Z0-9_]*_(?:[0-9]+|[A-Z]+)")

_WORD_PRIORITY = 62  # custom words beat raw IP/IPv6 spans when they overlap


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    category: str
    value: str
    dedup_key: Optional[str] = None

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class SanitizeResult:
    text: str
    unique: int = 0
    replacements: int = 0
    by_category: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return self.replacements > 0

    def notification(self) -> str:
        if not self.changed:
            return "🔒 Nothing sensitive found — clipboard untouched."
        parts = []
        for cat, counts in sorted(
            self.by_category.items(), key=lambda kv: -kv[1]["unique"]
        ):
            n = counts["unique"]
            label = _friendly(cat)
            parts.append(f"{n} {_plural(label, n)}")
        extra = (
            f" ({self.replacements} occurrences)"
            if self.replacements != self.unique
            else ""
        )
        return "🔒 Sanitized: " + ", ".join(parts) + f".{extra}"


@dataclass
class RestoreResult:
    text: str
    replaced: int = 0
    unique_keys: int = 0
    missed: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.replaced > 0

    def notification(self) -> str:
        if not self.changed:
            return "🔓 No Safe-Paste placeholders found — clipboard untouched."
        msg = f"🔓 Restored {self.replaced} original values to clipboard."
        if self.missed:
            msg += f" ⚠ {len(self.missed)} unknown placeholder(s) left as-is."
        return msg


def _friendly(category: str) -> str:
    if category in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[category]
    label = category.replace("_", " ").title()
    return re.sub(r"\bDb\b", "DB", label)


def _plural(label: str, n: int) -> str:
    if n == 1 or label.lower().endswith("s"):
        return label
    return label + "s"


class SafePasteEngine:
    def __init__(
        self,
        secure_map: Optional[SecureMap] = None,
        word_groups: Optional[Dict[str, List[str]]] = None,
        disabled_categories: Optional[List[str]] = None,
        case_sensitive_words: bool = False,
        allowlist: Optional[AllowList] = None,
        ner_tier: Optional[
            Callable[[str, Sequence[Finding]], List[Tuple[int, int, str, str]]]
        ] = None,
    ) -> None:
        # NOTE: never `secure_map or SecureMap()` — a fresh SecureMap has
        # __len__ == 0 and is therefore falsy, silently discarding a caller's
        # map (the daemon passes its own so the tray can observe it).
        self.map = secure_map if secure_map is not None else SecureMap()
        self.case_sensitive_words = case_sensitive_words
        self.allowlist = allowlist if allowlist is not None else AllowList()
        self.ner_tier = ner_tier
        disabled = {c.upper() for c in (disabled_categories or [])}
        self.detectors: List[Detector] = [
            d for d in REGEX_DETECTORS if d.category not in disabled
        ]
        self.word_rules = self._compile_word_rules(word_groups or {})
        self.map.configure_letter_categories(self.word_rules.keys())

    @classmethod
    def from_config(cls, config: Config, secure_map: Optional[SecureMap] = None) -> "SafePasteEngine":
        ner_tier = None
        if config.ner_enabled:
            from .ner import make_tier  # lazy: keeps spacy off the import path

            ner_tier = make_tier(config.ner_model, config.ner_labels)
            if ner_tier is None:
                print(
                    "⚠ ner.enabled but spacy not installed — Tier-3 off "
                    "(pip install spacy && python -m spacy download en_core_web_sm)",
                    file=sys.stderr,
                )
        return cls(
            secure_map=secure_map,
            word_groups=config.groups,
            disabled_categories=config.disabled_categories,
            case_sensitive_words=config.case_sensitive_words,
            allowlist=AllowList(config.allowlist),
            ner_tier=ner_tier,
        )

    # -- Tier 2: custom dictionary ------------------------------------------

    def _compile_word_rules(
        self, groups: Dict[str, List[str]]
    ) -> Dict[str, Tuple[re.Pattern, Dict[str, str]]]:
        r"""One alternation regex per group; longest words first at a position.

        ``(?<!\w)word(?!\w)`` keeps ``users_prod_v2_table`` from matching
        inside longer identifiers, while still matching the bare word.
        """
        rules: Dict[str, Tuple[re.Pattern, Dict[str, str]]] = {}
        flags = 0 if self.case_sensitive_words else re.IGNORECASE
        for raw_cat, words in groups.items():
            clean = [w for w in words if w and w.strip()]
            if not clean:
                continue
            escaped = sorted(
                (re.escape(w) for w in clean), key=len, reverse=True
            )
            pattern = re.compile(
                r"(?<!\w)(?:" + "|".join(escaped) + r")(?!\w)", flags
            )
            # map folded spelling -> canonical config spelling, so restore
            # rewrites every case-variant back to what the user configured
            folded = {w.casefold(): w for w in clean}
            rules[raw_cat.upper()] = (pattern, folded)
        return rules

    # -- scanning --------------------------------------------------------------

    def scan(self, text: str) -> List[Finding]:
        findings: List[Finding] = []

        for det in self.detectors:
            for m in det.pattern.finditer(text):
                span = det.base_span(m)
                if span is None:
                    continue
                if det.refine is not None:
                    span = det.refine(m, text, span)
                    if span is None:
                        continue
                start, end, value = span
                if value:
                    findings.append(
                        Finding(start, end, det.category, value)
                    )

        for category, (pattern, folded) in self.word_rules.items():
            for m in pattern.finditer(text):
                value = m.group(0)
                if self.case_sensitive_words:
                    canonical, dedup = value, value
                else:
                    dedup = value.casefold()
                    canonical = folded.get(dedup, value)
                findings.append(
                    Finding(
                        m.start(), m.end(), category, canonical, dedup_key=dedup
                    )
                )

        return self._resolve_overlaps(findings)

    @staticmethod
    def _resolve_overlaps(findings: List[Finding]) -> List[Finding]:
        """Longest-first, then priority; greedily accept non-overlapping
        findings in text order -> one placeholder per maximal secret span."""
        findings.sort(
            key=lambda f: (
                f.start,
                -f.length,
                -(PRIORITY.get(f.category, _WORD_PRIORITY)),
            )
        )
        accepted: List[Finding] = []
        last_end = -1
        for f in findings:
            if f.start < last_end:
                continue  # overlaps an accepted (longer/higher-priority) span
            accepted.append(f)
            last_end = f.end
        return accepted

    # -- workflows ---------------------------------------------------------------

    def sanitize(self, text: str) -> SanitizeResult:
        findings = self.scan(text)  # Tier 1 + Tier 2, overlaps resolved

        # Tier 3 (optional): NER sees only the regions Tiers 1–2 left over.
        if self.ner_tier is not None and text:
            try:
                extra = [
                    Finding(start, end, cat, value)
                    for (start, end, cat, value) in self.ner_tier(text, findings)
                ]
            except Exception as exc:  # NER must never break the sanitize hotkey
                extra = []
                print(f"⚠ Tier-3 NER skipped: {exc}", file=sys.stderr)
            if extra:
                findings = self._resolve_overlaps(findings + extra)

        # Allowlist: user-declared public values never reach the map at all.
        if self.allowlist:
            findings = [
                f
                for f in findings
                if not self.allowlist.allows(f.value, f.category)
            ]

        if not findings:
            return SanitizeResult(text=text)

        # Placeholders already present verbatim in the source must not be
        # re-used by us, or restore() would clobber unrelated text.
        forbidden = {
            m.group(1).upper()
            for m in PLACEHOLDER_SCAN_RE.finditer(text)
            if OUR_TOKEN_RE.fullmatch(m.group(1).upper())
        }

        by_category: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"unique": 0, "replaced": 0}
        )
        seen_this_call: set = set()
        pieces: List[str] = []
        pos = 0
        for f in findings:
            secret, _created = self.map.get_or_create(
                f.category, f.value, dedup_key=f.dedup_key, forbidden=forbidden
            )
            self.map.touch(secret)
            pieces.append(text[pos : f.start])
            pieces.append(f"[{secret.key}]")
            pos = f.end
            counts = by_category[secret.category]
            counts["replaced"] += 1
            if secret.key not in seen_this_call:
                seen_this_call.add(secret.key)
                counts["unique"] += 1
        pieces.append(text[pos:])

        return SanitizeResult(
            text="".join(pieces),
            unique=len(seen_this_call),
            replacements=len(findings),
            by_category=dict(by_category),
        )

    def restore(self, text: str) -> RestoreResult:
        replaced = 0
        keys: set = set()
        missed: set = set()

        def _sub(m: re.Match) -> str:
            nonlocal replaced
            token = m.group(1).upper()
            secret = self.map.lookup(token)
            if secret is None:
                if OUR_TOKEN_RE.fullmatch(token):
                    missed.add(token)
                return m.group(0)
            replaced += 1
            keys.add(token)
            return secret.value

        new_text = PLACEHOLDER_SCAN_RE.sub(_sub, text)
        return RestoreResult(
            text=new_text,
            replaced=replaced,
            unique_keys=len(keys),
            missed=sorted(missed),
        )
