"""The data model: an investigation is a set of observations, each one a (subject, predicate, object) claim with the source, the evidence URL and the
SHA-256 of the raw response it was read from, so that every line of a report can be traced back to bytes that are stored with it."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Obs:
    source: str          # e.g. "ct:crtsh", "dns:doh", "rdap:domain"
    subject: str         # "domain:www.example.org", "ip:192.0.2.1", "asn:64500", "org:example"
    predicate: str       # e.g. "cert_name", "a", "cname", "mx", "registrar"
    object: Any          # JSON-serialisable
    url: str = ""        # the evidence URL
    raw: str = ""        # SHA-256 of the raw response body (stored in the investigation database)


@dataclass
class SourceStatus:
    source: str
    state: str           # "ok" | "partial" | "unavailable" | "error" | "skipped"
    detail: str = ""
    count: int = 0


@dataclass
class SourceResult:
    observations: list = field(default_factory=list)
    status: SourceStatus = None


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    """Parse the timestamp formats the sources use ('2026-09-24T23:13:26', '...Z', '...+00:00', '...128Z' fractions) as UTC."""
    t = text.strip().replace("Z", "+00:00")
    if "." in t:
        head, rest = t.split(".", 1)
        tz = ""
        for sign in ("+", "-"):
            if sign in rest:
                rest, tz = rest.split(sign, 1)
                tz = sign + tz
                break
        t = head + tz
    dt = datetime.fromisoformat(t)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
