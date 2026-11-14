"""Unit tests for the Safe-Paste core engine — stdlib unittest, no deps.

Run:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from safepaste.engine import SafePasteEngine, OUR_TOKEN_RE  # noqa: E402
from safepaste.secure_map import SecureMap  # noqa: E402


def eng(**kw):
    return SafePasteEngine(**kw)


class TestDeterminism(unittest.TestCase):
    def test_same_ip_four_times_gets_one_placeholder(self):
        e = eng()
        text = "a 192.168.1.50 b 192.168.1.50 c 192.168.1.50 d 192.168.1.50"
        r = e.sanitize(text)
        self.assertEqual(r.text.count("[IP_1]"), 4)
        self.assertEqual(r.unique, 1)
        self.assertEqual(r.replacements, 4)

    def test_different_ips_get_separate_placeholders(self):
        e = eng()
        r = e.sanitize("from 10.0.0.1 to 10.0.0.2 via 10.0.0.1")
        self.assertIn("[IP_1]", r.text)
        self.assertIn("[IP_2]", r.text)
        self.assertEqual(r.text.count("[IP_1]"), 2)

    def test_resanitize_reuses_keys(self):
        e = eng()
        a = e.sanitize("host 10.0.0.1 down")
        b = e.sanitize("host 10.0.0.1 down")
        self.assertEqual(a.text, b.text)


class TestRoundTrip(unittest.TestCase):
    FULL = "\n".join(
        [
            "ERROR 10.42.7.55 auth failed for bob@acmecorp.com",
            "conn: postgres://svc:Tr0ub4dor@10.42.7.55:5432/billing",
            "stripe sk_live_TESTONLYFAKEKEY1234 rotated",
            "refresh token 203.0.113.9 [IPv6 fe80::1]",
        ]
    )

    def test_roundtrip_is_byte_exact(self):
        e = eng()
        s = e.sanitize(self.FULL)
        self.assertTrue(s.changed)
        r = e.restore(s.text)
        self.assertEqual(r.text, self.FULL)
        self.assertEqual(r.missed, [])

    def test_restore_is_case_insensitive(self):
        e = eng()
        s = e.sanitize("ip 10.0.0.1 and email a@b.io")
        mangled = s.text.lower().replace("[email_1]", "[e-mail-1]")  # e-mail-1 unknown
        r = e.restore(s.text.replace("[IP_1]", "[ip_1]"))
        self.assertIn("10.0.0.1", r.text)
        r2 = e.restore(mangled)
        self.assertIn("[e-mail-1]", r2.text)  # unknown token left untouched
        self.assertNotIn("[IP_1]", r2.text)  # lowercased form restored anyway? no: [ip_1]

    def test_whitespace_inside_brackets_is_tolerated(self):
        e = eng()
        s = e.sanitize("host 10.0.0.1")
        key = OUR_TOKEN_RE  # sanity
        r = e.restore(s.text.replace("[IP_1]", "[ IP_1 ]"))
        self.assertEqual(r.text, "host 10.0.0.1")

    def test_unknown_placeholder_reported_as_miss(self):
        e = eng()
        r = e.restore("see [IP_9] and [not-a-token] and [text](url)")
        self.assertEqual(r.missed, ["IP_9"])
        self.assertIn("[text](url)", r.text)
        self.assertEqual(r.replaced, 0)


class TestFalsePositives(unittest.TestCase):
    def test_semver_and_slice_untouched(self):
        code = "def f(x):\n    return x[::2] == v1.2.3.4 and arr[:, ::2] and 1.2.3\n"
        r = eng().sanitize(code)
        self.assertEqual(r.text, code)
        self.assertEqual(r.replacements, 0)

    def test_invalid_octets_not_ip(self):
        r = eng().sanitize("999.1.1.1 and 10.0.0.1.2 and 010.0.0.1")
        self.assertEqual(r.replacements, 0)

    def test_timecode_and_mac_not_ipv6(self):
        r = eng().sanitize("took 12:34:56 on MAC 00:1A:2B:3C:4D:5E end")
        self.assertEqual(r.replacements, 0)

    def test_real_ipv6_redacted(self):
        r = eng().sanitize("ping fe80::1 and 2001:db8::ff00:42:8329 ok")
        self.assertIn("[IPV6_1]", r.text)
        self.assertIn("[IPV6_2]", r.text)

    def test_markdown_link_url_keeps_structure(self):
        e = eng()
        r = e.sanitize("see (https://api.acme.internal/v1) now.")
        self.assertIn("([URL_1])", r.text)  # trailing ')' trimmed (unbalanced)
        self.assertEqual(e.restore(r.text).text, "see (https://api.acme.internal/v1) now.")

    def test_wiki_style_parenthesized_url_not_trimmed(self):
        e = eng()
        url = "https://en.wikipedia.org/wiki/Foo_(bar)"
        r = e.sanitize(url)
        self.assertIn("[URL_1]", r.text)  # balanced parens -> kept whole
        self.assertEqual(e.restore(r.text).text, url)


class TestOverlaps(unittest.TestCase):
    def test_conn_string_claims_inner_ip_and_table(self):
        r = eng().sanitize("pool: postgres://u:passw0rd@10.0.0.5:5432/db1")
        self.assertIn("[CONN_STR_1]", r.text)
        self.assertNotIn("[IP_1]", r.text)

    def test_url_swallows_query_email(self):
        r = eng().sanitize("hit https://x.io/a?email=bob@corp.com done")
        self.assertIn("[URL_1]", r.text)
        self.assertNotIn("[EMAIL_1]", r.text)

    def test_bearer_token_claimed_once(self):
        e = eng()
        r = e.sanitize("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF_123-xyz")
        self.assertEqual(r.unique, 1)  # JWT inside -> one token
        self.assertEqual(e.restore(r.text).text.count("Bearer"), 1)

    def test_api_key_context_key_stays_visible(self):
        r = eng().sanitize('{"api_key": "AKIAIOSFODNN7EXAMPLE"}')
        self.assertIn('{"api_key": "[API_KEY_1]"}', r.text)

    def test_email_before_sentence_period(self):
        e = eng()
        r = e.sanitize("Page ops@acmecorp.com.")
        self.assertEqual(r.text, "Page [EMAIL_1].")
        self.assertEqual(e.restore(r.text).text, "Page ops@acmecorp.com.")

    def test_pem_block_is_single_placeholder(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nabc123\n-----END RSA PRIVATE KEY-----"
        e = eng()
        r = e.sanitize(pem)
        self.assertEqual(r.text, "[PRIVATE_KEY_1]")
        self.assertEqual(e.restore(r.text).text, pem)


class TestCustomDictionary(unittest.TestCase):
    def test_group_letters_and_casefold_dedup(self):
        e = eng(word_groups={"CLIENT": ["Acme Corp"], "DB_TABLE": ["users_prod_v2_table"]})
        r = e.sanitize("ACME CORP hit USERS_PROD_V2_TABLE and acme corp again")
        self.assertIn("[CLIENT_A]", r.text)
        self.assertIn("[DB_TABLE_A]", r.text)
        self.assertEqual(r.text.count("[CLIENT_A]"), 2)  # casefold dedup
        out = e.restore(r.text)
        self.assertIn("Acme Corp", out.text)

    def test_words_do_not_split_identifiers(self):
        e = eng(word_groups={"TABLE": ["users"]})
        r = e.sanitize("SELECT users_prod_v2_table FROM users")
        self.assertEqual(r.replacements, 1)  # only the bare `users` matched

    def test_word_longest_wins(self):
        e = eng(word_groups={"CLIENT": ["Acme", "Acme Cloud Project"]})
        r = e.sanitize("the Acme Cloud Project and plain Acme")
        self.assertEqual(r.replacements, 2)
        self.assertNotIn("Cloud Project", r.text)

    def test_kv_connstring_requires_password(self):
        plain = eng().sanitize("a=1;b=2;c=3 config line")
        self.assertEqual(plain.replacements, 0)
        secret = eng().sanitize(
            "Server=prod-db-01;Database=orders;User Id=sa;Password=C0mpl3x!Pass;"
        )
        self.assertIn("[CONN_STR_1]", secret.text)


class TestMapLifecycle(unittest.TestCase):
    def test_clear_wipes_everything(self):
        e = eng()
        s = e.sanitize("ip 10.0.0.1")
        self.assertEqual(len(e.map), 1)
        e.map.clear()
        self.assertEqual(len(e.map), 0)
        r = e.restore(s.text)  # [IP_1] no longer restorable
        self.assertEqual(r.text, s.text)
        self.assertEqual(r.missed, ["IP_1"])

    def test_snapshot_masks_by_default(self):
        e = eng()
        e.sanitize("secret token = abcdefghijklmnop123")
        rows = e.map.snapshot(reveal=False)
        self.assertTrue(all("abcdefghijklmnop123" != r["value"] for r in rows))
        revealed = e.map.snapshot(reveal=True)
        self.assertTrue(any("abcdefghijklmnop123" in r["value"] for r in revealed))

    def test_injected_empty_map_is_shared(self):
        # regression: `secure_map or SecureMap()` would discard a *fresh*
        # (falsy, len==0) map — the tray daemon depends on sharing this object.
        m = SecureMap()
        e = SafePasteEngine(secure_map=m)
        self.assertIs(e.map, m)
        e.sanitize("ip 10.0.0.1")
        self.assertEqual(len(m), 1)

    def test_placeholder_collision_in_source_skipped(self):
        e = eng()
        r = e.sanitize("use [IP_1] literally and redact 1.2.3.4 too")
        self.assertIn("[IP_2]", r.text)  # IP_1 taken by the user's own text
        self.assertIn("[IP_1] literally", r.text)


class TestNotification(unittest.TestCase):
    def test_summary_counts(self):
        e = eng(word_groups={"CLIENT": ["Globex"]})
        r = e.sanitize(
            "10.0.0.1 10.0.0.2 10.0.0.1 email a@b.io and Globex client"
        )
        msg = r.notification()
        self.assertIn("2 IPs", msg)
        self.assertIn("1 Email", msg)
        self.assertIn("1 Client", msg)


if __name__ == "__main__":
    unittest.main()
