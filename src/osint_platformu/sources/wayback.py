"""The Internet Archive's CDX index: URLs that were archived for the domain. It reveals hosts that no longer appear in certificates and paths that
once existed. Nothing in the archive (or on the live site) is fetched: only the index is read, and the historic URLs are reported as *candidates*."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..guard import in_scope, is_hostname
from ..http import HttpError
from ..redact import redact_cdx
from ..model import SourceResult, SourceStatus

NAME = "wayback"

# (category, pattern over the URL *path*): what the path of an archived URL suggests, not proof of anything. Query strings are ignored on purpose
# (``?ref=bojana.dev`` is not a development server) and so are generic archives (a public ``tzdata.tar.gz`` is not a backup).
INTERESTING = [
    ("admin-or-login", re.compile(r"(^|/)(admin|administrator|wp-admin|wp-login|login|signin|sign-in|phpmyadmin|cpanel|dashboard|console|manager)(/|\.|$)", re.I)),
    ("vcs-or-env-file", re.compile(r"(^|/)(\.git|\.svn|\.hg|\.env|\.htpasswd|\.ds_store)(/|$)", re.I)),
    ("backup-or-dump", re.compile(r"(backup|backups|dump|\.bak|\.old|\.orig|\.sql)(/|$|\.)|(^|/)(db|database|www|site|full)[^/]*\.(zip|tar|tgz|gz|7z|rar)$", re.I)),
    ("api-surface", re.compile(r"(^|/)(api|graphql|swagger|openapi)(/|\.|$)|swagger|openapi", re.I)),
    ("config-file", re.compile(r"(^|/)(config|configuration|settings|web\.config|phpinfo)(/|\.|$)", re.I)),
    ("pre-production", re.compile(r"(^|/)(staging|stage|dev|uat|test|beta|sandbox|internal)(/|\.|$)", re.I)),
]


def categories(path):
    return [name for name, pattern in INTERESTING if pattern.search(path)]


def collect(ctx):
    limit = int(ctx.options.get("max_archive_rows", 5000))
    url = ctx.endpoints.wayback
    params = {"url": ctx.target, "matchType": "domain", "output": "json", "fl": "timestamp,original,statuscode,mimetype", "collapse": "urlkey", "limit": str(limit)}
    try:
        response, sha = ctx.fetch(url, params=params, transform=lambda b: redact_cdx(b, ctx.target))
        if response.status != 200:
            return SourceResult([], SourceStatus(NAME, "error", f"HTTP {response.status}"))
        rows = response.json()
    except (HttpError, ValueError) as exc:
        return SourceResult([], SourceStatus(NAME, "error", str(exc)))
    if not rows:
        return SourceResult([], SourceStatus(NAME, "ok", "no archived URLs", 0))
    rows = rows[1:]                                                         # the first row is the header
    hosts, interesting = {}, {}
    for stamp, original, status, mime in rows:
        parsed = urlparse(original)
        host = (parsed.hostname or "").lower()
        if not host or not is_hostname(host) or not in_scope(host, ctx.target):
            continue
        h = hosts.setdefault(host, {"urls": 0, "first_seen": stamp[:8], "last_seen": stamp[:8]})
        h["urls"] += 1
        h["first_seen"], h["last_seen"] = min(h["first_seen"], stamp[:8]), max(h["last_seen"], stamp[:8])
        cats = categories(parsed.path)
        if cats and original not in interesting:
            interesting[original] = {"categories": cats, "captured": stamp[:8], "status": status, "mime": mime}
    out = [ctx.obs("wayback:cdx", "domain:" + h, "archive_host", info, url, sha) for h, info in sorted(hosts.items())]
    out += [ctx.obs("wayback:cdx", "url:" + u, "archive_candidate", info, url, sha) for u, info in sorted(interesting.items())]
    out.append(ctx.obs("wayback:cdx", "domain:" + ctx.target, "archive_total", {"urls": len(rows), "truncated": len(rows) >= limit}, url, sha))
    state = "partial" if len(rows) >= limit else "ok"
    detail = f"{len(rows)} archived URLs on {len(hosts)} hosts; {len(interesting)} with paths worth a look" + (f"; truncated at {limit}" if state == "partial" else "")
    return SourceResult(out, SourceStatus(NAME, state, detail, len(hosts)))
