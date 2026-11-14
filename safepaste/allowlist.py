"""Allow-list: values that should NEVER be redacted (public IPs, docs hosts…).

Entries (in `safepaste.config.json` → "allowlist"):

    "8.8.8.8"                     exact value (any category)
    "10.0.0.0/8"  "fe80::/10"     CIDR — matches any finding whose text value
                                  parses as an IP inside the network
    "*@docs.public.io"            glob (fnmatch, case-insensitive)
    "https://localhost/*"         glob agains URLs
    "IP:8.8.8.8"                  category-scoped: only IP findings are
                                  allowed; a same-looking value in another
                                  category (e.g. inside a conn string) is not

The engine consults this AFTER detection but BEFORE mapping, so an allowed
value simply never gets a placeholder and the RAM map never stores it.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import List, Optional, Tuple

_SCOPE_RE = re.compile(r"^([A-Z][A-Z0-9_]*)[:=](.+)$")


class AllowList:
    __slots__ = ("globs", "nets", "empty")

    def __init__(self, entries: Optional[List[str]] = None) -> None:
        self.globs: List[Tuple[Optional[str], str]] = []
        self.nets: List[Tuple[Optional[str], object]] = []
        for raw in entries or []:
            entry = str(raw).strip()
            if not entry:
                continue
            scope: Optional[str] = None
            m = _SCOPE_RE.match(entry)
            if m:  # "IP:8.8.8.8" — scope must be ALL-CAPS token, so
                scope, entry = m.group(1), m.group(2)  # "https://…" stays a glob
            ip = None
            try:
                ip = ipaddress.ip_address(entry)
            except ValueError:
                try:
                    ip = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    ip = None
            if ip is not None:
                net = ip if "/" in str(entry) else ipaddress.ip_network(f"{ip}/32" if ":" not in str(ip) else f"{ip}/128")
                self.nets.append((scope, net))
            self.globs.append((scope, entry.lower()))  # exact form doubles as glob
        self.empty = not (self.globs or self.nets)

    def __bool__(self) -> bool:
        return not self.empty

    def allows(self, value: str, category: str) -> bool:
        if self.empty:
            return False
        fold = value.lower()
        if self.nets:
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                addr = None
            if addr is not None:
                for scope, net in self.nets:
                    if (scope is None or scope == category.upper()) and addr in net:
                        return True
        for scope, pat in self.globs:
            if scope is not None and scope != category.upper():
                continue
            if pat == fold or fnmatch.fnmatchcase(fold, pat):
                return True
        return False

    def entries(self) -> List[str]:
        return [p if s is None else f"{s}:{p}" for s, p in self.globs]
