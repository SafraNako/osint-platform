"""What a collector needs: the target, the HTTP client, where each source lives, the clock, and a way to turn a response into evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .model import Obs


@dataclass
class Endpoints:
    """Where each public source lives. The tests point every one of them at a local server; ``web`` is a template for the target's own sites."""

    crtsh: str = "https://crt.sh/"
    certspotter: str = "https://api.certspotter.com/v1/issuances"
    doh: str = "https://cloudflare-dns.com/dns-query"
    doh_fallback: str = "https://dns.google/resolve"
    rdap_bootstrap: str = "https://data.iana.org/rdap/dns.json"
    wayback: str = "https://web.archive.org/cdx/search/cdx"
    github: str = "https://api.github.com"
    web: str = "https://{host}"


@dataclass
class Context:
    target: str
    http: object
    store: object
    endpoints: Endpoints = field(default_factory=Endpoints)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    options: dict = field(default_factory=dict)       # github_org, github_token, max_names, max_cert_records, max_archive_rows, workers
    workers: int = 6

    def fetch(self, url, params=None, headers=None, use_cache=True, transform=None):
        """GET through the client and keep the (transformed) body as evidence; returns ``(response, sha256)``."""
        kwargs = {} if transform is None else {"transform": transform}
        response = self.http.get(url, params=params, headers=headers, use_cache=use_cache, **kwargs)
        return response, self.store.put_raw(response.body)

    def obs(self, source, subject, predicate, obj, url="", raw=""):
        return Obs(source, subject, predicate, obj, url, raw)
