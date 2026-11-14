"""User configuration: custom word groups and behavior toggles.

The config file contains *keywords*, never secrets — only the RAM map holds
original values, and that map is deliberately not configurable/persistable.

Looked-up path (in order): ``--config PATH``, then ``./safepaste.config.json``.

Schema::

    {
      "groups": {
        "CLIENT":   ["Acme Corp", "acme_corp", "Globex Industries"],
        "DB_TABLE": ["users_prod_v2_table", "billing_events"],
        "HOST":     ["db-prod-01", "jenkins.internal"]
      },
      "word_file": "words.txt",          // optional: one word per line -> CUSTOM group
      "disabled_categories": ["URL"],    // switch off noisy Tier-1 detectors
      "case_sensitive_words": false
    }

Group names become placeholder namespaces: CLIENT -> [CLIENT_A], [CLIENT_B]…
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_FILENAME = "safepaste.config.json"


def normalize_category(name: str) -> str:
    cat = re.sub(r"[^A-Za-z0-9]+", "_", name.strip().upper()).strip("_")
    return cat or "CUSTOM"


@dataclass
class Config:
    groups: Dict[str, List[str]] = field(default_factory=dict)
    disabled_categories: List[str] = field(default_factory=list)
    case_sensitive_words: bool = False
    allowlist: List[str] = field(default_factory=list)
    ner_enabled: bool = False
    ner_model: str = "en_core_web_sm"
    ner_labels: List[str] = field(default_factory=lambda: ["PERSON", "ORG"])
    word_file: Optional[str] = None
    source_path: Optional[Path] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        p = Path(path) if path else Path(DEFAULT_FILENAME)
        if not p.exists():
            if path:  # explicit path missing is an error worth surfacing
                raise FileNotFoundError(f"config not found: {p}")
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        groups: Dict[str, List[str]] = {}
        for raw_name, words in (data.get("groups") or {}).items():
            cat = normalize_category(raw_name)
            cleaned = [str(w).strip() for w in words if str(w).strip()]
            groups.setdefault(cat, []).extend(cleaned)

        word_file = data.get("word_file")
        if word_file:
            wf = Path(word_file)
            if wf.parent == Path(""):
                wf = p.parent / wf
            if wf.exists():
                lines = [
                    ln.strip()
                    for ln in wf.read_text(encoding="utf-8").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
                groups.setdefault("CUSTOM", []).extend(lines)

        ner = data.get("ner") or {}
        return cls(
            groups=groups,
            disabled_categories=[
                str(c).upper() for c in data.get("disabled_categories") or []
            ],
            case_sensitive_words=bool(data.get("case_sensitive_words", False)),
            allowlist=[str(a).strip() for a in data.get("allowlist") or [] if str(a).strip()],
            ner_enabled=bool(ner.get("enabled", False)),
            ner_model=str(ner.get("model", "en_core_web_sm")),
            ner_labels=[str(l).upper() for l in (ner.get("labels") or ["PERSON", "ORG"])],
            word_file=word_file,
            source_path=p if p.exists() else None,
        )

    # -- helpers used by the CLI (`safepaste words add …`) -------------------

    def add_word(self, word: str, group: str = "CUSTOM") -> None:
        cat = normalize_category(group)
        words = self.groups.setdefault(cat, [])
        if word not in words:
            words.append(word)

    def remove_word(self, word: str) -> bool:
        removed = False
        for cat in list(self.groups):
            before = len(self.groups[cat])
            self.groups[cat] = [w for w in self.groups[cat] if w != word]
            if len(self.groups[cat]) != before:
                removed = True
            if not self.groups[cat]:
                del self.groups[cat]
        return removed

    def add_allow(self, pattern: str) -> None:
        if pattern not in self.allowlist:
            self.allowlist.append(pattern)

    def remove_allow(self, pattern: str) -> bool:
        if pattern in self.allowlist:
            self.allowlist.remove(pattern)
            return True
        return False

    def save(self, path: Optional[str] = None) -> Path:
        target = Path(path) if path else (self.source_path or Path(DEFAULT_FILENAME))
        payload = {
            "groups": self.groups,
            "allowlist": self.allowlist,
            "disabled_categories": self.disabled_categories,
            "case_sensitive_words": self.case_sensitive_words,
            "ner": {
                "enabled": self.ner_enabled,
                "model": self.ner_model,
                "labels": self.ner_labels,
            },
        }
        if self.word_file:
            payload["word_file"] = self.word_file
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        self.source_path = target
        return target

    def words(self) -> List[str]:
        return [w for words in self.groups.values() for w in words]
