"""Findings: what a snapshot says about the organisation's exposure, with the evidence for each. Severities are deliberately modest (info, low,
medium) because every rule works on public records alone: a finding is a reason to look, never a verified vulnerability."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime

from . import fingerprints as fp
from .model import parse_iso

SEVERITIES = ["info", "low", "medium"]


@dataclass
class Finding:
    id: str                       # stable across runs: "<rule>:<subject>"
    severity: str
    title: str
    detail: str
    evidence: list = field(default_factory=list)


def spf_analysis(record):
    """The all-qualifier, the number of top-level DNS lookups and whether the record delegates with ``redirect=``."""
    tokens = record.split()[1:]
    final = None
    for t in tokens:
        m = re.fullmatch(r"([+\-~?]?)all", t)
        if m:
            final = m.group(1) or "+"
    lookups = sum(1 for t in tokens if re.match(r"(include:|a(:|/|$)|mx(:|/|$)|ptr|exists:|redirect=)", t.lstrip("+-~?")))
    return {"all": final, "lookups": lookups, "redirect": any(t.startswith("redirect=") for t in tokens),
            "includes": [t.split(":", 1)[1] for t in tokens if t.startswith("include:")]}


def dmarc_analysis(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    rua = re.findall(r"<mailbox at ([^>]+)>", tags.get("rua", ""))
    return {"p": tags.get("p", "").lower(), "sp": tags.get("sp", "").lower(), "pct": int(tags["pct"]) if tags.get("pct", "").isdigit() else 100, "rua_domains": sorted(set(rua)),
            "has_rua": bool(tags.get("rua"))}


def service_inventory(snap):
    """Third-party services the records reveal: {service: [(kind, evidence)]}. Mail, DNS, CDN and SaaS providers named by MX, SPF, NS, TXT tokens and CNAME targets."""
    inv = {}

    def add(service, kind, evidence):
        inv.setdefault(service, [])
        if (kind, evidence) not in inv[service]:
            inv[service].append((kind, evidence))
    for _, host in snap.apex["mx"]:
        label = fp.match(host, dict(fp.MX_SERVICES))
        if label:
            add(label, "mx", host)
    for ns in snap.apex["ns"]:
        label = fp.match(ns, fp.NS_PROVIDERS)
        if label:
            add(label, "ns", ns)
    for text in snap.apex["txt"]:
        for prefix, label in fp.TXT_PREFIXES.items():
            if text.startswith(prefix) or text.lower().startswith(prefix.lower()):
                add(label, "txt", prefix.rstrip("=:"))
    for record in snap.apex["spf"]:
        for host in spf_analysis(record)["includes"]:
            label = fp.match(host, fp.SPF_INCLUDES)
            if label:
                add(label, "spf", host)
    for name in sorted(snap.names):
        for hop in snap.chain(name)[1:]:
            label = fp.match(hop, fp.CNAME_PROVIDERS)
            if label:
                add(label, "cname", f"{name} -> {hop}")
                break
    return inv


def findings(snap, now=None):
    """All findings for a snapshot, most serious first. ``now`` (a datetime) fixes the date used for expiry rules, so that a stored run always gives the same report."""
    now = now or (parse_iso(snap.taken_at) if snap.taken_at else datetime.now().astimezone())
    out = []
    ok = lambda source: any(s["source"] == source and s["state"] in ("ok", "partial") for s in snap.status)  # noqa: E731

    # --- dangling and broken aliases ---------------------------------------------------------------------------------------------------
    for name, e in sorted(snap.names.items()):
        if e["nxdomain"] and e["nxdomain"].get("cname_target"):
            hops = snap.chain(name)
            last = hops[-1]
            provider = fp.match(last, fp.CLAIMABLE_PROVIDERS)
            evidence = [f"DNS: {' -> '.join(hops)} (the last name does not exist: NXDOMAIN)"]
            if provider:
                out.append(Finding(f"dangling-cname:{name}", "medium", f"{name} is an alias of a released {provider} name",
                                   f"The alias chain ends at {last}, which no longer exists. If {provider} lets anyone register that name, whoever does can serve content "
                                   "under this subdomain. Candidate from DNS evidence only: check whether the name can be claimed, on assets you are responsible for.", evidence))
            else:
                out.append(Finding(f"broken-cname:{name}", "low", f"{name} is an alias of a name that does not exist",
                                   f"The alias chain ends at {last} (NXDOMAIN). Either a leftover record to remove, or a name at a provider that may let others claim it.", evidence))
    # --- private addresses in public DNS -----------------------------------------------------------------------------------------------
    private = []
    for name, e in sorted(snap.names.items()):
        bad = [ip for ip in e["a"] + e["aaaa"] if not ipaddress.ip_address(ip).is_global]
        if bad:
            private.append(f"DNS: {name} -> {', '.join(bad)}")
    if private:
        out.append(Finding(f"private-ip:{snap.target}", "low", f"{len(private)} name(s) resolve to non-public addresses",
                           "Internal addressing in public DNS reveals the internal network layout and usually is a leftover.", private))
    # --- registration ------------------------------------------------------------------------------------------------------------------
    reg = snap.registration
    if reg.get("expires"):
        days = (parse_iso(reg["expires"]) - now).days
        if days < 0:
            out.append(Finding(f"domain-expiry:{snap.target}", "medium", "The domain registration has expired", f"The registry reports an expiry date {-days} days ago.", [f"RDAP: expires {reg['expires']}"]))
        elif days < 30:
            out.append(Finding(f"domain-expiry:{snap.target}", "medium", f"The domain expires in {days} days", "A lapsed domain can be re-registered by someone else.", [f"RDAP: expires {reg['expires']}"]))
        elif days < 90:
            out.append(Finding(f"domain-expiry:{snap.target}", "low", f"The domain expires in {days} days", "Check that renewal is arranged.", [f"RDAP: expires {reg['expires']}"]))
    if reg.get("dnssec_signed") is False:
        out.append(Finding(f"dnssec:{snap.target}", "info", "The domain is not DNSSEC-signed", "Resolvers that validate DNSSEC cannot detect forged answers for this domain.", ["RDAP: secureDNS.delegationSigned is false"]))
    # --- mail authentication -----------------------------------------------------------------------------------------------------------
    apex = snap.apex
    if ok("dns") and (apex["mx"] or apex["spf"]):
        if not apex["spf"]:
            out.append(Finding(f"spf-missing:{snap.target}", "low", "No SPF record", "Receivers cannot tell which servers may send mail for the domain.", ["DNS: no TXT record starting with v=spf1"]))
        elif len(apex["spf"]) > 1:
            out.append(Finding(f"spf-multiple:{snap.target}", "low", "More than one SPF record", "RFC 7208 makes this a permanent error: receivers ignore SPF.", [f"DNS TXT: {r}" for r in apex["spf"]]))
        else:
            a = spf_analysis(apex["spf"][0])
            if a["all"] == "+":
                out.append(Finding(f"spf-open:{snap.target}", "medium", "SPF allows any sender (+all)", "The record authorises the whole internet to send as this domain.", [f"DNS TXT: {apex['spf'][0]}"]))
            elif a["all"] == "?":
                out.append(Finding(f"spf-neutral:{snap.target}", "low", "SPF ends in a neutral qualifier (?all)", "Neutral says nothing about unlisted senders.", [f"DNS TXT: {apex['spf'][0]}"]))
            elif a["all"] is None and not a["redirect"]:
                out.append(Finding(f"spf-open-ended:{snap.target}", "low", "SPF has no all-mechanism", "Without a closing all or redirect, unlisted senders get a neutral result.", [f"DNS TXT: {apex['spf'][0]}"]))
            if a["lookups"] > 10:
                out.append(Finding(f"spf-lookups:{snap.target}", "low", f"SPF needs at least {a['lookups']} DNS lookups", "More than 10 makes SPF fail with a permanent error (RFC 7208).", [f"DNS TXT: {apex['spf'][0]}"]))
        if not apex["dmarc"]:
            out.append(Finding(f"dmarc-missing:{snap.target}", "low", "No DMARC record", "Without DMARC, receivers have no policy for mail that fails SPF and DKIM.", [f"DNS: no v=DMARC1 record at _dmarc.{snap.target}"]))
        else:
            d = dmarc_analysis(apex["dmarc"][0])
            if d["p"] == "none":
                out.append(Finding(f"dmarc-monitor:{snap.target}", "low", "DMARC policy is p=none (monitoring only)", "Failing mail is delivered as usual; the policy only asks for reports.", [f"DNS TXT: {apex['dmarc'][0]}"]))
            elif d["pct"] < 100:
                out.append(Finding(f"dmarc-pct:{snap.target}", "info", f"DMARC applies to only {d['pct']}% of mail", "The policy is partially enforced.", [f"DNS TXT: {apex['dmarc'][0]}"]))
        if apex["mx"] and not apex["mta_sts"]:
            out.append(Finding(f"mta-sts:{snap.target}", "info", "No MTA-STS policy", "Senders are not told to require TLS when delivering mail to this domain.", [f"DNS: no v=STSv1 record at _mta-sts.{snap.target}"]))
    if ok("dns") and not apex["caa"]:
        out.append(Finding(f"caa:{snap.target}", "info", "No CAA record", "Any certificate authority may issue certificates for the domain.", ["DNS: no CAA records at the apex"]))
    # --- certificates ------------------------------------------------------------------------------------------------------------------
    if snap.wildcards:
        zones = sorted(snap.wildcards)
        out.append(Finding(f"wildcard-certs:{snap.target}", "info", f"Wildcard certificates exist for {len(zones)} zone(s)", "A wildcard hides which hosts exist in a zone: certificate transparency shows the zone, not its hosts.",
                           [f"CT: *.{z}" for z in zones[:10]]))
    historic = sorted(n for n, e in snap.names.items() if e["nxdomain"] and not e["nxdomain"].get("cname_target") and "ct" in e["sources"])
    if historic:
        out.append(Finding(f"historic-names:{snap.target}", "info", f"{len(historic)} names from certificates no longer resolve",
                           "Names that were certified but do not exist in DNS today: decommissioned hosts, internal names, or typos in certificate requests.", [f"CT+DNS: {n} (NXDOMAIN)" for n in historic[:10]]))
    # --- published files ---------------------------------------------------------------------------------------------------------------
    sec = snap.web.get("security_txt", {})
    if ok("web") and not sec:
        out.append(Finding(f"security-txt-missing:{snap.target}", "info", "No security.txt", "RFC 9116 asks organisations to publish how to report vulnerabilities; none was found on the apex or www.", ["web: /.well-known/security.txt and /security.txt not found"]))
    for host, s in sorted(sec.items()):
        if s.get("expired"):
            out.append(Finding(f"security-txt-expired:{host}", "low", "security.txt has expired", "The Expires field is in the past, so researchers may not trust the contact.", [f"web: {host} Expires {s['expires']}"]))
    for host, r in sorted(snap.web.get("robots", {}).items()):
        hints = [d for d in r["disallow"] if re.search(r"admin|internal|staging|backup|private|secret|test|dev|old|tmp|login|config|api", d, re.I)]
        if hints:
            out.append(Finding(f"robots-hints:{host}", "info", f"robots.txt on {host} names {len(hints)} sensitive-looking path(s)", "robots.txt is a request to crawlers, not access control, and anyone can read it.",
                               [f"web: Disallow {h}" for h in hints[:10]]))
    # --- archive -----------------------------------------------------------------------------------------------------------------------
    cands = snap.archive.get("candidates", {})
    by_cat = {}
    for url, c in cands.items():
        for cat in c["categories"]:
            by_cat.setdefault(cat, []).append(url)
    for cat, urls in sorted(by_cat.items()):
        out.append(Finding(f"archive-{cat}:{snap.target}", "info", f"{len(urls)} archived URL(s) suggest {cat.replace('-', ' ')}",
                           "Historic paths from the web archive, not checked and possibly long gone; verify only on assets you are responsible for.", [f"archive: {u}" for u in sorted(urls)[:10]]))
    # --- attribution -------------------------------------------------------------------------------------------------------------------
    if snap.github and not snap.github["info"].get("linked_to_target"):
        out.append(Finding(f"github-unlinked:{snap.github['org']}", "info", f"GitHub organisation {snap.github['org']} does not link to {snap.target}",
                           "The organisation's profile does not point at the domain, so its attribution to the target is unverified.", [f"GitHub: blog = {snap.github['info'].get('blog')!r}"]))
    out.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.id))
    return out
