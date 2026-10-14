"""Certificate transparency: every publicly trusted certificate is logged, so the names on the certificates issued for a domain are a passive
inventory of its hosts. crt.sh is the primary source and Cert Spotter the fallback.

Two properties of the real data matter and are handled here: one certificate lists several names (``name_value`` holds them newline-separated,
and often includes names that are not under the target at all, or e-mail addresses), and wildcard names (``*.example.org``) say that a zone exists,
not which hosts are in it.
"""
from __future__ import annotations

import json

from ..context import Context
from ..guard import clean_name, in_scope, is_hostname
from ..http import HttpError
from ..redact import redact_certspotter, redact_crtsh
from ..model import SourceResult, SourceStatus, iso, parse_iso

NAME = "ct"


def parse_dn(dn):
    """The attributes of a distinguished name such as ``C=US, O="GoDaddy.com, Inc.", CN=G2``: commas inside quotes or after a backslash do not split."""
    parts, cur, quoted, escaped = [], "", False, False
    for ch in dn or "":
        if escaped:
            cur, escaped = cur + ch, False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    attrs = {}
    for part in parts:
        key, _, value = part.strip().partition("=")
        attrs.setdefault(key.strip().upper(), value.strip())
    return attrs


def _issuer(issuer_name):
    attrs = parse_dn(issuer_name)
    return attrs.get("O") or attrs.get("CN") or "unknown"


def _crtsh(ctx, limit):
    url = ctx.endpoints.crtsh
    response, sha = ctx.fetch(url, params={"q": "%." + ctx.target, "output": "json"}, transform=lambda b: redact_crtsh(b, ctx.target))
    if response.status != 200:
        raise HttpError(url, f"HTTP {response.status}")
    rows = response.json()
    if not isinstance(rows, list):
        raise ValueError("unexpected crt.sh response shape")
    certs, seen = [], set()
    for r in rows[:limit]:
        key = (r.get("serial_number"), r.get("name_value"))
        if key in seen:                     # a precertificate and its final certificate share a serial number
            continue
        seen.add(key)
        certs.append({"names": r.get("name_value", "").split("\n"), "not_before": r.get("not_before"), "not_after": r.get("not_after"),
                      "issuer": _issuer(r.get("issuer_name"))})
    return certs, len(rows) > limit, response.url, sha, "crt.sh"


def _certspotter(ctx, limit):
    base, certs, after, sha, url = ctx.endpoints.certspotter, [], None, "", ""
    for _ in range(10):
        params = {"domain": ctx.target, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        response, sha = ctx.fetch(base, params=params, transform=lambda b: redact_certspotter(b, ctx.target))
        url = response.url
        if response.status != 200:
            raise HttpError(base, f"HTTP {response.status}")
        page = response.json()
        for r in page:
            certs.append({"names": r.get("dns_names", []), "not_before": r.get("not_before"), "not_after": r.get("not_after"), "issuer": "unknown"})
        if len(page) < 100 or len(certs) >= limit:
            break
        after = page[-1]["id"]
    return certs[:limit], len(certs) > limit, url, sha, "Cert Spotter"


def collect(ctx: Context):
    limit = int(ctx.options.get("max_cert_records", 20000))
    errors, certs = [], None
    for fetcher in (_crtsh, _certspotter):
        try:
            certs, truncated, url, sha, label = fetcher(ctx, limit)
            break
        except (HttpError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{fetcher.__name__.strip('_')}: {exc}")
    if certs is None:
        return SourceResult([], SourceStatus(NAME, "error", "; ".join(errors)))
    names, zones = {}, {}
    for c in certs:
        for raw_name in c["names"]:
            if not is_hostname(raw_name) or not in_scope(raw_name, ctx.target):
                continue
            wildcard = raw_name.strip().startswith("*.")
            n = clean_name(raw_name)
            bucket = zones if wildcard else names
            entry = bucket.setdefault(n, {"first_seen": None, "last_seen": None, "certs": 0, "issuers": set()})
            entry["certs"] += 1
            entry["issuers"].add(c["issuer"])
            for key, field in (("first_seen", "not_before"), ("last_seen", "not_after")):
                if c[field]:
                    stamp = iso(parse_iso(c[field]))
                    if entry[key] is None or (stamp < entry[key] if key == "first_seen" else stamp > entry[key]):
                        entry[key] = stamp
    source = "ct:" + label.lower().replace(" ", "")
    out = []
    for kind, bucket, predicate in (("name", names, "cert_name"), ("zone", zones, "cert_wildcard")):
        for n, e in sorted(bucket.items()):
            obj = {"first_seen": e["first_seen"], "last_seen": e["last_seen"], "certs": e["certs"], "issuers": sorted(e["issuers"])}
            out.append(ctx.obs(source, "domain:" + n, predicate, obj, url, sha))
    detail = f"{len(names)} names and {len(zones)} wildcard zones from {len(certs)} certificates via {label}"
    state = "ok"
    if errors:
        detail += f" (primary failed: {errors[0]}; fell back; this source lists only certificates that are still valid, so hosts known only from expired ones are missing)"
        state = "partial"
    if truncated:
        detail += f"; truncated at {limit} certificate records"
        state = "partial"
    return SourceResult(out, SourceStatus(NAME, state, detail, len(names)))
