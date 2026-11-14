"""Tier 1 of the Safe-Paste detection engine: structured regex detectors.

Every detector is pure, pre-compiled regex (+ an optional tiny post-validation
function) so the whole scan is a handful of linear passes — no NLP models on
the hot path, millisecond-scale even on multi-MB logs.

Design rules
------------
1. Detectors never mutate text. They emit ``Span = (start, end, value)``
   findings; the engine resolves overlaps between detectors by ``PRIORITY``.
2. Every pattern is wrapped in conservative lookarounds so ordinary code is
   NOT redacted (``v1.2.3.4``, ``a[::2]``, ``x.y`` tuples, semver strings...).
3. A ``refine`` callback can trim a match (trailing punctuation on URLs) or
   reject it entirely (return ``None``).
4. When ``value_group`` is used, only the captured secret is replaced — the
   contextual key (``api_key =``) stays visible so the LLM still understands
   the code structure around the placeholder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern, Tuple

Span = Tuple[int, int, str]  # (start, end, value) — end is exclusive

# --------------------------------------------------------------------------
# Detector container
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    name: str
    category: str  # placeholder namespace: value becomes [CATEGORY_1]
    pattern: Pattern[str]
    value_group: Optional[int] = 0  # 0 = whole match; None = first set group
    refine: Optional[Callable[[re.Match, str, Span], Optional[Span]]] = None

    def base_span(self, m: re.Match) -> Optional[Span]:
        if self.value_group is None:  # first non-empty capture group wins
            for gi in range(1, m.re.groups + 1):
                if m.group(gi) is not None:
                    return (m.start(gi), m.end(gi), m.group(gi))
            return None
        if self.value_group == 0:
            return (m.start(), m.end(), m.group(0))
        if m.group(self.value_group) is None:
            return None
        return (
            m.start(self.value_group),
            m.end(self.value_group),
            m.group(self.value_group),
        )


# Overlap resolution: when two findings conflict, the longer one starting
# first wins; ties break by higher priority. Bigger number = more specific.
PRIORITY: Dict[str, int] = {
    "PRIVATE_KEY": 110,
    "CONN_STR": 100,
    "API_KEY": 92,
    "JWT": 90,
    "TOKEN": 88,
    "SECRET": 86,
    "URL": 70,
    "EMAIL": 65,
    "IPV6": 60,
    "IP": 55,
}

FRIENDLY_NAMES: Dict[str, str] = {
    "IP": "IP",
    "IPV6": "IPv6 address",
    "EMAIL": "Email",
    "URL": "URL",
    "API_KEY": "API Key",
    "TOKEN": "Bearer Token",
    "SECRET": "Secret",
    "CONN_STR": "Connection String",
    "PRIVATE_KEY": "Private Key",
    "JWT": "JWT",
}

# --------------------------------------------------------------------------
# Refine / validate callbacks
# --------------------------------------------------------------------------

_TRAILING_NOISE = ".,;:!?)]}'\"`><*"


def _trim_trailing(m: re.Match, text: str, span: Span) -> Optional[Span]:
    """Drop sentence/markdown punctuation glued to the end of a URL or URI."""
    start, end, value = span
    changed = True
    while value and changed:
        changed = False
        last = value[-1]
        if last in _TRAILING_NOISE:
            if last == ")":
                # keep a trailing ')' when the parens are balanced (wiki links)
                if value.count("(") >= value.count(")"):
                    break
            value = value[:-1]
            end -= 1
            changed = True
    if len(value) < 8:
        return None
    return (start, end, value)


def _validate_ipv6(m: re.Match, text: str, span: Span) -> Optional[Span]:
    """Reject Python/NumPy-style slices such as ``a[::2]`` or ``arr[:, ::2]``.

    A real IPv6 is never bracket-sliced with a trailing ``]`` or ``,``
    immediately after it.
    """
    start, end, value = span
    i = start - 1
    while i >= 0 and text[i] in " ,:":
        i -= 1
    prev = text[i] if i >= 0 else ""
    j = end
    while j < len(text) and text[j] in " ,":
        j += 1
    nxt = text[j] if j < len(text) else ""
    if prev == "[" and nxt in "],":
        # exception: IPv6 in a URL host, e.g. http://[::1]:8080
        if text[max(0, i - 3) : i + 1] != "://[":
            return None
    return span


def _validate_kv_connstring(m: re.Match, text: str, span: Span) -> Optional[Span]:
    """The broad ``k=v;k=v`` pattern is only kept when it embeds a credential."""
    _, _, value = span
    if re.search(r"(?i)\b(?:password|pwd)\s*=", value):
        return span
    return None


# --------------------------------------------------------------------------
# Tier-1 regex patterns
# --------------------------------------------------------------------------

# IPv4: real octets only (0-255, no leading zeros), not glued to words/dots,
# so `v1.2.3.4`, `1.2.3` (semver) and `10.0.0.1.2` are skipped.
_OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_RE = re.compile(
    r"(?<![\w.])" + _OCTET + r"(?:\." + _OCTET + r"){3}(?![\w.])"
)

# IPv6: every legal compressed form, but only when the compressed ``::`` is
# actually present or all 8 groups are written out — this deliberately skips
# timecodes (12:34:56) and MACs (AA:BB:CC:DD:EE:FF).
_H = "[0-9A-Fa-f]{1,4}"
_v6_alts = ["@H@:@H@:@H@:@H@:@H@:@H@:@H@:@H@"]
for _i in range(1, 8):
    _v6_alts.append("(?:@H@:){" + str(_i) + "}:")
for _i in range(1, 7):
    _v6_alts.append(
        "(?:@H@:){" + str(_i) + "}(?::@H@){1," + str(7 - _i) + "}"
    )
_v6_alts.append("@H@:(?::@H@){1,6}")
_v6_alts.append(":(?::@H@){1,7}")
IPV6_RE = re.compile(
    "(?<![\\w.\\-])(?:"
    + "|".join(_v6_alts).replace("@H@", _H)
    + ")(?![\\w.\\-])"
)

# Email: pragmatic charset, guarded so it does not start mid-token. A trailing
# sentence dot must still be allowed to end the match (`Page ops@x.com.`), so
# the lookahead rejects only word chars and hyphens, never '.'.
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])"
)

# URL: everything to the next whitespace (then trimmed of punctuation).
URL_RE = re.compile(r"https?://[^\s<>\"'`\\]+")

# JWT: header always base64url-encodes to an "eyJ..." prefix ({"alg").
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}(?![A-Za-z0-9_\-])")

# PEM private key blocks: the whole block becomes ONE placeholder.
PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

# Connection strings: any credentialed URI scheme (jdbc, postgres, redis...).
# The whole URI is redacted so hosts, ports and passwords inside it can never
# leak through a partial match.
_SCHEMES = (
    "jdbc(?::[A-Za-z0-9]+){1,3}:(?://)?|"
    "(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|rediss|amqps?|"
    "nats|clickhouse|snowflake|cockroachdb|mysql2|oracledb|mssql|sqlserver|"
    "ftp|sftp|ftps)://"
)
CONN_STR_URI_RE = re.compile(
    r"(?i)\b(?:" + _SCHEMES + r")[^\s\"'<>`\\]{6,1024}"
)

# .NET/ODBC-style semicolon connection strings; kept only when a password is
# present (validator) so plain `a=1;b=2` config lines are never touched.
CONN_STR_KV_RE = re.compile(
    r"(?i)\b[a-z][a-z0-9_ ]{1,20}\s*=\s*[^\s;]+"
    r"(?:\s*;\s*[a-z][a-z0-9_ ]{0,20}\s*=\s*[^\s;]+)+"
)

# Provider-specific API keys — distinctive prefixes, near-zero false
# positives. Publishable (pk_live / pk_test) keys are intentionally excluded.
API_KEY_RE = re.compile(
    r"\b(?:"
    r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"          # AWS access key id
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"     # Stripe secret/restricted
    r"|gh[pousr]_[A-Za-z0-9]{36,}"                    # GitHub tokens
    r"|github_pat_[A-Za-z0-9_]{22,}"                  # GitHub fine-grained
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"                 # Slack
    r"|AIza[0-9A-Za-z_\-]{35}"                        # Google API
    r"|sk-(?:proj-|session-)[A-Za-z0-9_\-]{20,}"      # OpenAI project keys
    r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"     # OpenAI legacy
    r"|SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"  # SendGrid
    r"|AC[a-f0-9]{32}"                                # Twilio account SID
    r"|SK[a-f0-9]{32}"                                # Twilio api secret
    r"|npm_[A-Za-z0-9]{36}"                           # npm
    r"|hf_[A-Za-z0-9]{34,}"                           # Hugging Face
    r"|glpat-[A-Za-z0-9_\-]{20,}"                     # GitLab
    r"|dop_v1_[a-f0-9]{64}"                           # DigitalOcean
    r")\b"
)

# Contextual secrets: `password = "..."`, `api_key: xyz`, `aws_secret_access_key
# = ...`. Only the VALUE is replaced (first set capture group); the key name
# stays so the LLM keeps the structural context. The unquoted charset stops at
# whitespace, commas and & — so query strings never swallow their neighbors.
_SECRET_KEYS = (
    "api[\\s_\\-]?key|secret[\\s_\\-]?key|access[\\s_\\-]?token|"
    "access[\\s_\\-]?key[\\s_\\-]?secret|aws[\\s_\\-]?secret[\\s_\\-]?access[\\s_\\-]?key|"
    "refresh[\\s_\\-]?token|id[\\s_\\-]?token|auth[\\s_\\-]?token|"
    "client[\\s_\\-]?secret|api[\\s_\\-]?secret|encryption[\\s_\\-]?key|"
    "signing[\\s_\\-]?key|session[\\s_\\-]?secret|master[\\s_\\-]?key|"
    "passphrase|password|passwd|pwd|secret|token"
)
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?:" + _SECRET_KEYS + r")\b\s*[\"']?\s*[:(=]\s*[\"']?\s*"
    r"(?:[\"']([^\"'\n]{12,256})[\"']|([A-Za-z0-9\-_./+=]{12,256}))"
)

# Bearer tokens (header style): the Authorization prefix makes this safe
# against the word "token" appearing in prose.
BEARER_RE = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_.=+]{16,512})")

# --------------------------------------------------------------------------
# The registry consumed by the engine
# --------------------------------------------------------------------------

REGEX_DETECTORS: List[Detector] = [
    Detector("pem_private_key", "PRIVATE_KEY", PEM_RE),
    Detector("conn_string_uri", "CONN_STR", CONN_STR_URI_RE, refine=_trim_trailing),
    Detector("conn_string_kv", "CONN_STR", CONN_STR_KV_RE, refine=_validate_kv_connstring),
    Detector("jwt", "JWT", JWT_RE),
    Detector("bearer_token", "TOKEN", BEARER_RE, value_group=1),
    Detector("named_api_keys", "API_KEY", API_KEY_RE),
    Detector("secret_assignment", "SECRET", SECRET_ASSIGN_RE, value_group=None),
    Detector("url", "URL", URL_RE, refine=_trim_trailing),
    Detector("email", "EMAIL", EMAIL_RE),
    Detector("ipv6", "IPV6", IPV6_RE, refine=_validate_ipv6),
    Detector("ipv4", "IP", IPV4_RE),
]
