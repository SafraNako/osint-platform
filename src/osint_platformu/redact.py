"""Privacy at ingestion: structural allowlists. Each source's response is rebuilt from only the fields the collector actually reads, so a field nobody
thought about (a common name that is a person's name, an owner object, a contact entity) cannot reach the database. E-mail addresses are scrubbed from
whatever is kept. Unparseable bodies fall back to the e-mail scrub alone.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit, urlunsplit

from .guard import in_scope, is_hostname, scrub_bytes, scrub_text


def _load(body):
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _dump(data):
    return scrub_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"))).encode("utf-8")


def _keep_name(name, scope):
    return is_hostname(name) and (scope is None or in_scope(name, scope))


def redact_crtsh(body, scope=None):
    """crt.sh rows reduced to id, serial, issuer, validity and the host names under ``scope`` (names of other organisations on multi-tenant certificates and lines
    that are not host names, such as e-mail addresses, are dropped; ``common_name`` is dropped because on S/MIME certificates it is a person's name)."""
    rows = _load(body)
    if not isinstance(rows, list):
        return scrub_bytes(body)
    keep = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        names = [n for n in str(r.get("name_value", "")).split("\n") if _keep_name(n, scope)]
        keep.append({"id": r.get("id"), "serial_number": r.get("serial_number"), "issuer_name": r.get("issuer_name"), "name_value": "\n".join(names),
                     "not_before": r.get("not_before"), "not_after": r.get("not_after")})
    return _dump(keep)


def redact_certspotter(body, scope=None):
    rows = _load(body)
    if not isinstance(rows, list):
        return scrub_bytes(body)
    return _dump([{"id": r.get("id"), "dns_names": [n for n in r.get("dns_names", []) if _keep_name(n, scope)], "not_before": r.get("not_before"), "not_after": r.get("not_after")}
                  for r in rows if isinstance(r, dict)])


def redact_rdap(body):
    """RDAP reduced to the domain's technical facts and the registrar's name and IANA id. Contact entities (registrant, administrative, technical, abuse),
    notices, remarks and links never survive."""
    data = _load(body)
    if not isinstance(data, dict):
        return scrub_bytes(body)
    registrars = []
    for entity in data.get("entities", []) or []:
        if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
            vcard = (entity.get("vcardArray") or [None, []])[1]
            registrars.append({"roles": ["registrar"], "publicIds": [{"type": p.get("type"), "identifier": p.get("identifier")} for p in entity.get("publicIds", []) if isinstance(p, dict)],
                               "vcardArray": ["vcard", [item for item in vcard if item and item[0] == "fn"]]})
    return _dump({
        "ldhName": data.get("ldhName"), "status": data.get("status", []),
        "events": [{"eventAction": e.get("eventAction"), "eventDate": e.get("eventDate")} for e in data.get("events", []) if isinstance(e, dict)],
        "nameservers": [{"ldhName": n.get("ldhName")} for n in data.get("nameservers", []) if isinstance(n, dict)],
        "secureDNS": {"delegationSigned": (data.get("secureDNS") or {}).get("delegationSigned")} if "secureDNS" in data else None,
        "entities": registrars})


GITHUB_ORG_FIELDS = ("login", "name", "description", "blog", "location", "created_at", "public_repos", "followers", "is_verified", "type")
GITHUB_REPO_FIELDS = ("name", "language", "pushed_at", "created_at", "archived", "fork", "stargazers_count", "description")


def redact_github(body):
    """GitHub organisation and repository JSON reduced to the fields the collector reads: no owner objects, no e-mail, no handles of people."""
    data = _load(body)
    if isinstance(data, dict):
        return _dump({k: data.get(k) for k in GITHUB_ORG_FIELDS if k in data})
    if isinstance(data, list):
        return _dump([{k: r.get(k) for k in GITHUB_REPO_FIELDS if k in r} for r in data if isinstance(r, dict)])
    return scrub_bytes(body)


def redact_cdx(body, scope=None):
    """CDX rows with the query string and fragment removed from every archived URL (query strings can carry tokens and personal data), and, when ``scope``
    is given, only the rows whose host is under it."""
    rows = _load(body)
    if not isinstance(rows, list):
        return scrub_bytes(body)
    out = []
    for i, row in enumerate(rows):
        if i == 0 or not isinstance(row, list) or len(row) < 2:
            out.append(row)
            continue
        parts = urlsplit(row[1])
        if scope is not None and not (parts.hostname and in_scope(parts.hostname, scope)):
            continue
        out.append([row[0], urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))] + row[2:])
    return _dump(out)
