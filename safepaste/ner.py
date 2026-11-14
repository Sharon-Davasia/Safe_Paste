"""Tier 3 (optional): lightweight NER for names no regex could know.

Catches PERSON / ORG entities (client exec names, internal product/company
names) in the text regions NOT already claimed by Tier-1 (regex) or Tier-2
(dictionary). This is deliberately an *add-on*: the engine works without it,
and the model is lazy-loaded on first sanitize so daemon startup stays
instant and the RAM cost only appears if you enable it.

Enable in config:

    "ner": {"enabled": true, "model": "en_core_web_sm",
            "labels": ["PERSON", "ORG"]}

Install:

    pip install spacy && python -m spacy download en_core_web_sm

Design notes:
  * claimed spans are masked to spaces (length-preserving) so spaCy offsets
    map 1:1 back onto the original string and entities can never swallow a
    placeholder region;
  * entities are re-checked against claimed spans defensively;
  * dedup/placeholder minting goes through the same SecureMap as everything
    else — "Jane Cooper" 6 times ⇒ [PERSON_1] ×6, automatically.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional, Sequence, Tuple

log = logging.getLogger("safepaste.ner")

FindingLike = Tuple[int, int, str, str]  # (start, end, category, value)


def make_tier(
    model: str = "en_core_web_sm",
    labels: Sequence[str] = ("PERSON", "ORG"),
    min_len: int = 3,
):
    """Return a tier callable, or None if spaCy isn't importable."""
    try:
        import spacy  # noqa: F401  (heavy optional dep — import once, cheap)
    except ImportError:
        log.info("spacy not installed — Tier-3 NER disabled")
        return None

    state = {"nlp": None}
    wanted = {l.upper() for l in labels}

    def _load():
        if state["nlp"] is None:
            try:
                state["nlp"] = spacy.load(
                    model,
                    disable=["parser", "lemmatizer", "attribute_ruler", "morphologizer"],
                )
            except OSError:
                log.error(
                    "spaCy model %r missing — run: python -m spacy download %s",
                    model,
                    model,
                )
                raise
        return state["nlp"]

    def tier(text: str, claimed: Sequence) -> List[FindingLike]:
        nlp = _load()
        if len(text) > 200_000:  # NER is the slow tier: cap it, regex stays uncapped
            text_slice = text[:200_000]
        else:
            text_slice = text
        mask = list(text_slice)
        for f in claimed:
            for i in range(f.start, min(f.end, len(mask))):
                if mask[i] != "\n":
                    mask[i] = " "
        doc = nlp("".join(mask))
        out: List[FindingLike] = []
        for ent in doc.ents:
            label = ent.label_.upper()
            if label not in wanted:
                continue
            start, end = ent.start_char, ent.end_char
            if any(start < f.end and f.start < end for f in claimed):
                continue  # defensive: don't touch claimed regions
            value = text[start:end].strip()
            if len(value) < min_len or not any(ch.isalpha() for ch in value):
                continue
            # re-read from ORIGINAL text (whitespace-padded strip is cosmetic)
            real_start = text.index(value, start)
            out.append((real_start, real_start + len(value), label, value))
        return out

    return tier
