"""RDAP, the structured successor of WHOIS: when the domain was registered, when it expires, which registrar and name servers it uses, whether it
is DNSSEC-signed. Contact entities (registrant, administrative, technical, abuse) are never read: the response is redacted on arrival so that only
the registrar entity, reduced to its name and IANA id, survives, in the stored copy as well as in the parsed one."""
from __future__ import annotations

from ..http import HttpError
from ..redact import redact_rdap
from ..model import SourceResult, SourceStatus

NAME = "rdap"


def _service_for(bootstrap, target):
    tld = target.rsplit(".", 1)[1]
    for tlds, urls in bootstrap.get("services", []):
        if tld in tlds:
            https = [u for u in urls if u.startswith("https://")]
            return (https or urls)[0]
    return None


def collect(ctx):
    try:
        response, _ = ctx.fetch(ctx.endpoints.rdap_bootstrap, transform=lambda b: b)        # public IANA registry, no personal data in it
        if response.status != 200:
            return SourceResult([], SourceStatus(NAME, "error", f"bootstrap HTTP {response.status}"))
        base = _service_for(response.json(), ctx.target)
        if not base:
            tld = ctx.target.rsplit(".", 1)[1]
            return SourceResult([], SourceStatus(NAME, "unavailable", f"IANA publishes no RDAP service for .{tld}"))
        url = base.rstrip("/") + "/domain/" + ctx.target
        response, sha = ctx.fetch(url, headers={"Accept": "application/rdap+json"}, use_cache=False, transform=redact_rdap)
    except (HttpError, ValueError) as exc:
        return SourceResult([], SourceStatus(NAME, "error", str(exc)))
    if response.status == 404:
        return SourceResult([], SourceStatus(NAME, "ok", "the registry has no such domain (404)", 0))
    if response.status != 200:
        return SourceResult([], SourceStatus(NAME, "error", f"HTTP {response.status}"))
    try:
        data = response.json()
    except ValueError as exc:
        return SourceResult([], SourceStatus(NAME, "error", f"not JSON: {exc}"))
    subject, out, src = "domain:" + ctx.target, [], "rdap:domain"
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if e.get("eventAction")}
    for action, predicate in (("registration", "registered"), ("expiration", "expires"), ("last changed", "last_changed"), ("transfer", "transferred")):
        if action in events:
            out.append(ctx.obs(src, subject, predicate, events[action], response.url, sha))
    for entity in data.get("entities", []):
        name = next((i[3] for i in (entity.get("vcardArray") or [None, []])[1] if i[0] == "fn"), None)
        ids = {p.get("type"): p.get("identifier") for p in entity.get("publicIds", [])}
        out.append(ctx.obs(src, subject, "registrar", {"name": name, "iana_id": ids.get("IANA Registrar ID")}, response.url, sha))
    out.append(ctx.obs(src, subject, "rdap_status", sorted(data.get("status", [])), response.url, sha))
    for ns in data.get("nameservers", []):
        out.append(ctx.obs(src, subject, "nameserver", (ns.get("ldhName") or "").lower().rstrip("."), response.url, sha))
    if "secureDNS" in data:
        out.append(ctx.obs(src, subject, "dnssec_signed", bool(data["secureDNS"].get("delegationSigned")), response.url, sha))
    return SourceResult(out, SourceStatus(NAME, "ok", f"{len(out)} facts from {base}", len(out)))
