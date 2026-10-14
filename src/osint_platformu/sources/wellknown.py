"""The target's own published text files: ``robots.txt`` (which paths its owner asks crawlers to skip, and where its sitemaps are),
``security.txt`` (RFC 9116: how to report a vulnerability to them) and the ``sitemap.xml`` URL count. One plain GET each, on the apex and ``www``;
no page is crawled. The only e-mail addresses the platform keeps are the ones an organisation publishes in ``security.txt`` for exactly this purpose."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..guard import in_scope, is_hostname
from ..http import HttpError
from ..model import SourceResult, SourceStatus, iso, parse_iso

NAME = "web"


def parse_robots(text):
    disallow, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return sorted(set(disallow)), sorted(set(sitemaps))


def parse_security_txt(text):
    """RFC 9116 fields; a PGP clear-signature wrapper is ignored."""
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-----") or line.lower().startswith("hash:") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


def collect(ctx):
    out, errors = [], []
    hosts = [ctx.target, "www." + ctx.target]
    got_security = got_robots = False
    for host in hosts:
        base = ctx.endpoints.web.format(host=host).rstrip("/")
        for path in ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/sitemap.xml"):
            if path == "/security.txt" and got_security:
                continue
            if path == "/robots.txt" and got_robots:
                continue
            try:
                keep_emails = path.endswith("security.txt")             # published for reporting: the one place addresses are kept
                response, sha = ctx.fetch(base + path, use_cache=False, transform=(lambda b: b) if keep_emails else None)
            except HttpError as exc:
                errors.append(f"{host}{path}: {exc.reason}")
                continue
            if response.status != 200 or not response.body:
                continue
            text = response.text()
            if path == "/robots.txt" and "<html" not in text[:200].lower():
                got_robots = True
                disallow, sitemaps = parse_robots(text)
                out.append(ctx.obs("web:robots", "domain:" + host, "robots", {"disallow": disallow[:200], "sitemaps": sitemaps[:20]}, response.url, sha))
            elif path.endswith("security.txt") and "contact:" in text.lower():
                got_security = True
                f = parse_security_txt(text)
                expires = f.get("expires", [None])[0]
                expired = None
                if expires:
                    try:
                        expired = parse_iso(expires) < ctx.now
                        expires = iso(parse_iso(expires))
                    except ValueError:
                        expired = None
                out.append(ctx.obs("web:security.txt", "domain:" + host, "security_txt", {
                    "contacts": f.get("contact", []), "expires": expires, "expired": expired, "policy": f.get("policy", []), "hiring": f.get("hiring", []),
                    "canonical": f.get("canonical", []), "encryption": f.get("encryption", []), "path": path}, response.url, sha))
            elif path == "/sitemap.xml" and "<loc>" in text:
                locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)
                kind = "index" if "<sitemapindex" in text else "urlset"
                loc_hosts = sorted({(urlparse(u).hostname or "").lower() for u in locs})
                loc_hosts = [h for h in loc_hosts if h and is_hostname(h) and in_scope(h, ctx.target)]
                out.append(ctx.obs("web:sitemap", "domain:" + host, "sitemap", {"kind": kind, "locs": len(locs), "hosts": loc_hosts}, response.url, sha))
    detail = f"{len(out)} facts from {', '.join(hosts)}" + (f"; {len(errors)} requests failed" if errors else "")
    state = "error" if errors and not out else ("partial" if errors else "ok")
    return SourceResult(out, SourceStatus(NAME, state, detail, len(out)))
