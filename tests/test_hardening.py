"""Tests for Phase-1.5 hardening: allowlist, Tier-3 NER plumbing, Win clipboard."""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from safepaste.allowlist import AllowList  # noqa: E402
from safepaste.clipboard import _ps_b64, _ps_command, _ps_from_b64  # noqa: E402
from safepaste.engine import Finding, SafePasteEngine  # noqa: E402
from safepaste.ner import make_tier  # noqa: E402


class TestAllowList(unittest.TestCase):
    def test_exact_ip_allowed_others_redacted(self):
        e = SafePasteEngine(allowlist=AllowList(["8.8.8.8"]))
        r = e.sanitize("dig 8.8.8.8 ; dig 1.1.1.1")
        self.assertIn("8.8.8.8", r.text)  # untouched, public
        self.assertIn("[IP_1]", r.text)
        self.assertEqual(e.map.snapshot(reveal=True)[0]["value"], "1.1.1.1")

    def test_cidr_entry(self):
        e = SafePasteEngine(allowlist=AllowList(["10.0.0.0/8"]))
        r = e.sanitize("10.42.7.19 internal vs 203.0.113.9 external")
        self.assertIn("10.42.7.19", r.text)
        self.assertIn("[IP_1]", r.text)

    def test_glob_entry_case_insensitive(self):
        e = SafePasteEngine(allowlist=AllowList(["*@docs.public.io"]))
        r = e.sanitize("mail bob@docs.public.io and eve@corp.internal")
        self.assertIn("bob@docs.public.io", r.text)
        self.assertIn("[EMAIL_1]", r.text)

    def test_category_scope(self):
        # allow the IP but NOT the same-looking value inside a conn string:
        e = SafePasteEngine(allowlist=AllowList(["IP:10.0.0.5"]))
        r = e.sanitize(
            "standalone 10.0.0.5 ok; postgres://u:p4ssw0rd_long@10.0.0.5/db1 stays hidden"
        )
        self.assertIn("[CONN_STR_1]", r.text)
        self.assertIn("10.0.0.5 ok", r.text)

    def test_url_glob(self):
        # fnmatch semantics: "*" crosses ':' too, so localhost* covers the port
        e = SafePasteEngine(allowlist=AllowList(["https://localhost*"]))
        r = e.sanitize("curl https://localhost:8080/health vs https://api.internal/v1")
        self.assertIn("https://localhost:8080/health", r.text)
        self.assertIn("[URL_1]", r.text)
        self.assertNotIn("api.internal", r.text)

    def test_empty_allowlist_is_falsy_and_fast(self):
        self.assertFalse(bool(AllowList([])))
        self.assertTrue(AllowList(["1.2.3.4"]).allows("1.2.3.4", "IP"))


class TestNERTierPlumbing(unittest.TestCase):
    def test_stub_tier_fills_gaps_and_collapses(self):
        import re

        NAMES = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")

        def fake_tier(text, claimed):
            out = []
            for m in NAMES.finditer(text):
                if any(m.start() < f.end and f.start < m.end() for f in claimed):
                    continue
                out.append((m.start(), m.end(), "PERSON", m.group(0)))
            return out

        e = SafePasteEngine(ner_tier=fake_tier)
        r = e.sanitize("escalated to Jane Cooper about 10.0.0.1, cc Jane Cooper again")
        self.assertEqual(r.text.count("[PERSON_1]"), 2)  # deterministic
        self.assertIn("[IP_1]", r.text)
        self.assertEqual(e.restore(r.text).text.count("Jane Cooper"), 2)

    def test_make_tier_without_spacy_returns_none(self):
        # spacy is not installed in CI/sandbox; contract = degrade, not crash
        try:
            import spacy  # noqa: F401

            self.skipTest("spacy is installed here; cannot test absence")
        except ImportError:
            self.assertIsNone(make_tier())

    def test_ner_failure_does_not_break_sanitize(self):
        def exploding_tier(text, claimed):
            raise RuntimeError("model on fire")

        e = SafePasteEngine(ner_tier=exploding_tier)
        r = e.sanitize("ip 10.0.0.1")
        self.assertIn("[IP_1]", r.text)  # Tier-1/2 unaffected


class TestWindowsClipboardEncoding(unittest.TestCase):
    def test_b64_roundtrip_unicode(self):
        sample = "SELECT * FROM logs WHERE msg = 'héllo ✓ 日本語';\n\ttabbed"
        self.assertEqual(_ps_from_b64(_ps_b64(sample)), sample)

    def test_encoded_command_is_utf16le_b64(self):
        cmd = _ps_command("Get-Clipboard -Raw")
        self.assertEqual(cmd[0], "powershell")
        decoded = base64.b64decode(cmd[-1]).decode("utf-16-le")
        self.assertEqual(decoded, "Get-Clipboard -Raw")

    def test_b64_blob_with_line_wrapping_decodes(self):
        # PowerShell console hosts sometimes hard-wrap stdout; we strip all
        # whitespace before decoding — emulate a wrapped blob here.
        blob = _ps_b64("abc")
        wrapped = blob[:4] + "\r\n" + blob[4:]
        self.assertEqual(_ps_from_b64(wrapped), "abc")


if __name__ == "__main__":
    unittest.main()
