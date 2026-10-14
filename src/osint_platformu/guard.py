"""Scope policy: what may be investigated, and what is never stored.

The platform looks at organisations through public infrastructure records, so the only valid target is a registered domain name. It refuses
anything that points at a natural person or at a device: e-mail addresses, names with spaces, IP addresses, URLs with paths, private and
special-use names, and public suffixes (querying ``co.uk`` would ask the world's certificate logs for everything).

The public suffix list is not in the standard library, so the check for two-label suffixes is a short built-in list, best effort.
"""
from __future__ import annotations

import re

SPECIAL_USE_TLDS = {"local", "localhost", "internal", "invalid", "test", "example", "lan", "home", "corp", "intranet", "onion", "arpa", "home.arpa"}

# the common second-level public suffixes (best effort; a missing one only means the refusal does not fire)
PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.tr", "org.tr", "net.tr", "gen.tr", "edu.tr", "gov.tr", "k12.tr", "av.tr", "bel.tr", "biz.tr", "info.tr", "web.tr", "tv.tr", "name.tr", "dr.tr", "pol.tr", "mil.tr", "kep.tr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "go.kr", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.mx", "org.mx", "gob.mx", "com.ar", "gob.ar", "com.co", "com.pe", "com.ve",
    "co.za", "org.za", "gov.za", "ac.za", "co.in", "net.in", "org.in", "gov.in", "ac.in", "com.sg", "edu.sg", "gov.sg", "com.hk", "org.hk", "edu.hk",
    "com.tw", "org.tw", "edu.tw", "com.my", "com.ph", "com.vn", "co.id", "co.th", "co.il", "org.il", "ac.il", "com.eg", "com.sa", "com.pk", "com.ng", "co.ke",
    "com.ua", "com.pl", "com.ru", "com.de", "co.at", "or.at", "com.es", "com.pt", "com.gr", "com.cy", "com.ee", "com.ro",
}

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class ScopeError(ValueError):
    """The requested target is outside what the platform investigates."""


def normalize_domain(raw, allow_special_use=False):
    """The ASCII (punycode) lower-case form of a domain target, or ``ScopeError`` saying why it is out of scope."""
    s = (raw or "").strip()
    if not s:
        raise ScopeError("empty target")
    if "@" in s:
        raise ScopeError("e-mail addresses identify people and are out of scope: give the organisation's domain")
    if any(c.isspace() for c in s):
        raise ScopeError("a name with spaces looks like a person or a company name, not a domain: give a domain such as example.org")
    if "://" in s or "/" in s or "?" in s or "#" in s:
        raise ScopeError("give a bare domain (example.org), not a URL")
    if ":" in s or "*" in s:
        raise ScopeError("ports, IPv6 addresses and wildcards are not valid targets")
    s = s.rstrip(".").lower()
    if re.fullmatch(r"[0-9.]+", s):
        raise ScopeError("IP addresses identify devices that may belong to individuals and are out of scope: give a domain")
    try:
        ascii_name = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScopeError("not a valid domain name (an invalid or over-long label)")
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or any(not _LABEL.match(label) for label in labels):
        raise ScopeError("not a valid domain name")
    if len(labels) < 2:
        raise ScopeError("a single label is a top-level domain, not an organisation's domain")
    tld = labels[-1]
    if not allow_special_use and (tld in SPECIAL_USE_TLDS or ".".join(labels[-2:]) in SPECIAL_USE_TLDS):
        raise ScopeError(f".{tld} is a private or special-use name that public sources know nothing about")
    if tld.isdigit():
        raise ScopeError("a numeric top-level domain is not valid")
    if ascii_name in PUBLIC_SUFFIXES:
        raise ScopeError(f"{ascii_name} is a public suffix shared by many organisations: give the organisation's own domain below it")
    return ascii_name


def clean_name(name):
    """A DNS name as found in certificates or records: lower case, no trailing dot, no leading wildcard label."""
    n = name.strip().lower().rstrip(".")
    return n[2:] if n.startswith("*.") else n


def in_scope(name, target):
    """Is ``name`` the target or one of its subdomains? (Certificates often list unrelated names too.)"""
    n = clean_name(name)
    return n == target or n.endswith("." + target)


def scrub_text(text):
    """Replace e-mail addresses in free text from public records by ``<mailbox at domain>``: the platform stores no personal contact data, but the
    mail domain (for example the processor named in a DMARC ``rua``) is infrastructure and stays."""
    return _EMAIL.sub(lambda m: "<mailbox at " + m.group(0).split("@", 1)[1] + ">", text)


def scrub_bytes(body):
    """``scrub_text`` for a response body (the default transform of every fetch)."""
    return scrub_text(body.decode("utf-8", errors="replace")).encode("utf-8")


def is_hostname(name):
    """Does ``name`` look like a DNS host name (letters, digits, hyphens, dots, an optional leading wildcard)? Certificates also list e-mail addresses."""
    n = name.strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    labels = n.split(".")
    return 0 < len(n) <= 253 and all(re.match(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$", label) for label in labels)


def scrub(value):
    """``scrub_text`` applied through nested strings, lists and dicts."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value
