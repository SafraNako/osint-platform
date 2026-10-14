"""Reports from a snapshot: Markdown for people, JSON for tools. Every statement comes from the snapshot, and ``evidence`` lists the stored observations
(with the evidence URL and the hash of the stored response) behind any entity."""
from __future__ import annotations

import json
from collections import Counter

from .insights import SEVERITIES, dmarc_analysis, service_inventory, spf_analysis

NOT_COLLECTED = ("People: no registrant, administrative or technical contacts, no names or e-mail addresses of individuals (RDAP contact entities are discarded on arrival, "
                 "e-mail addresses in any response are replaced by the mail domain), no usernames, no social-media profiles, no commit authors. "
                 "Content: no page is crawled or scanned, and no historic URL is fetched. The only published contacts kept are those in security.txt, which exist to be used.")


def _md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return out


def _date(stamp):
    return (stamp or "")[:10]


def render_markdown(snap, found):
    inv = service_inventory(snap)
    resolving = sum(1 for e in snap.names.values() if e["a"] or e["aaaa"])
    sev = Counter(f.severity for f in found)
    L = [f"# OSINT report: {snap.target}", "",
         f"- **Purpose of the investigation:** {snap.purpose}", f"- **Run:** {snap.run_id}, taken {snap.taken_at}",
         "- **Method:** passive collection from public records only (certificate transparency, RDAP, DNS over HTTPS, the Internet Archive index, public GitHub metadata, the "
         "target's own robots.txt, security.txt and sitemap). Nothing was scanned, crawled or probed.", "",
         "## Summary", "",
         f"- {len(snap.names)} host names known, {resolving} resolving today; {len(snap.ips)} addresses in {len({a for i in snap.ips.values() for a in i['asns']})} networks",
         f"- {len(inv)} third-party services recognised",
         f"- findings: {sev.get('medium', 0)} medium, {sev.get('low', 0)} low, {sev.get('info', 0)} informational", ""]
    L += ["## Findings", ""]
    if not found:
        L.append("None of the rules fired.")
    for sev_name in reversed(SEVERITIES):
        for f in [f for f in found if f.severity == sev_name]:
            L += [f"### [{f.severity}] {f.title}", "", f.detail, ""] + [f"- {e}" for e in f.evidence] + [""]
    L += ["Findings are reasons to look, derived from public records; none is a verified vulnerability.", ""]
    r = snap.registration
    L += ["## Registration (RDAP)", ""]
    if r:
        L += [f"- Registrar: {r['registrar']['name']} (IANA id {r['registrar']['iana_id']})" if r.get("registrar") else "- Registrar: not published",
              f"- Registered {_date(r.get('registered'))}, last changed {_date(r.get('last_changed'))}, expires {_date(r.get('expires'))}",
              f"- Status: {', '.join(r.get('rdap_status', [])) or 'n/a'}", f"- DNSSEC signed: {r.get('dnssec_signed', 'n/a')}",
              f"- Name servers: {', '.join(sorted(r.get('nameservers', []))) or 'n/a'}"]
    else:
        L.append("No registration data (see the source status below).")
    L += ["", "## Hosts", ""]
    rows = []
    for name, e in sorted(snap.names.items()):
        chain = snap.chain(name)
        asns = sorted({a for ip in e["a"] + e["aaaa"] for a in snap.ips.get(ip, {}).get("asns", [])})
        where = ", ".join(f"AS{a}" for a in asns) or "-"
        if e["nxdomain"]:
            resolves = "does not exist" if not e["nxdomain"].get("cname_target") else "dangling alias"
        else:
            resolves = ", ".join((e["a"] + e["aaaa"])[:3]) + (" ..." if len(e["a"] + e["aaaa"]) > 3 else "") or "-"
        rows.append((name, resolves, " -> ".join(chain[1:]) if len(chain) > 1 else "", where, "+".join(sorted(e["sources"]))))
    L += _md_table(["Name", "Resolves to", "Alias chain", "Network", "Seen in"], rows) + [""]
    L += ["## Networks", ""]
    asn_rows = []
    for a, info in sorted(snap.asns.items()):
        hosts = sorted({n for ip, d in snap.ips.items() if a in d["asns"] for n in d["names"]})
        asn_rows.append((f"AS{a}", info["name"], info["country"], len(hosts)))
    L += _md_table(["ASN", "Name", "Country", "Hosts"], asn_rows) + [""]
    L += ["## Third-party services (inferred from MX, NS, SPF, TXT tokens and CNAME targets)", ""]
    for svc, ev in sorted(inv.items()):
        L.append(f"- **{svc}**: " + "; ".join(f"{k} {v}" for k, v in ev[:4]))
    if not inv:
        L.append("None recognised.")
    L += ["", "## Mail and DNS posture", ""]
    a = snap.apex
    L += [f"- MX: {', '.join(f'{p} {h}' for p, h in a['mx']) or 'none'}", f"- Name servers: {', '.join(a['ns']) or 'n/a'}", f"- CAA: {'; '.join(' '.join(c) for c in a['caa']) or 'none'}"]
    for rec in a["spf"]:
        s = spf_analysis(rec)
        L.append(f"- SPF: `{rec}` (closing qualifier {s['all'] or 'none'}, {s['lookups']} DNS lookups at the top level)")
    if not a["spf"]:
        L.append("- SPF: none")
    for rec in a["dmarc"]:
        d = dmarc_analysis(rec)
        L.append(f"- DMARC: `{rec}` (policy {d['p'] or 'n/a'}, reports to {', '.join(d['rua_domains']) or 'n/a'})")
    if not a["dmarc"]:
        L.append("- DMARC: none")
    L.append(f"- MTA-STS: {'present' if a['mta_sts'] else 'none'}")
    ct = [e["ct"] for e in snap.names.values() if e["ct"]]
    L += ["", "## Certificates (certificate transparency)", ""]
    if ct:
        issuers = Counter(i for c in ct for i in c["issuers"])
        L += [f"- {len(ct)} host names appear on publicly logged certificates; first issuance {_date(min(c['first_seen'] for c in ct if c['first_seen']))}, "
              f"latest expiry {_date(max(c['last_seen'] for c in ct if c['last_seen']))}",
              "- Issuers: " + ", ".join(f"{i} ({n})" for i, n in issuers.most_common(6))]
        if snap.wildcards:
            L.append("- Wildcard zones: " + ", ".join("*." + z for z in sorted(snap.wildcards)))
    else:
        L.append("No certificate data.")
    L += ["", "## Web archive", ""]
    total = snap.archive.get("total")
    if total:
        L.append(f"- {total['urls']} archived URLs read{' (truncated)' if total.get('truncated') else ''}; hosts: " + (", ".join(sorted(n for n, e in snap.names.items() if e["archive"])) or "none"))
        for url, c in sorted(snap.archive.get("candidates", {}).items())[:15]:
            L.append(f"- candidate ({', '.join(c['categories'])}): {url} (archived {c['captured']}, status {c['status']})")
    else:
        L.append("No archive data.")
    L += ["", "## Public files", ""]
    for host, rob in sorted(snap.web.get("robots", {}).items()):
        L.append(f"- robots.txt on {host}: {len(rob['disallow'])} Disallow rules, {len(rob['sitemaps'])} sitemaps")
    for host, s in sorted(snap.web.get("security_txt", {}).items()):
        L.append(f"- security.txt on {host}: contact {', '.join(s['contacts'])}; expires {_date(s['expires'])}{' (EXPIRED)' if s.get('expired') else ''}")
    for host, sm in sorted(snap.web.get("sitemap", {}).items()):
        L.append(f"- sitemap on {host}: {sm['locs']} URLs ({sm['kind']})")
    if not snap.web:
        L.append("None found.")
    if snap.github:
        g, info = snap.github, snap.github["info"]
        langs = Counter(r["language"] for r in g["repos"] if r["language"])
        L += ["", "## GitHub organisation", "",
              f"- {info['login']} ({info.get('name')}): {info['public_repos']} public repositories, created {_date(info['created_at'])}, profile links to the target: {info['linked_to_target']}",
              "- Languages: " + (", ".join(f"{k} ({v})" for k, v in langs.most_common(6)) or "n/a"),
              f"- Archived: {sum(1 for r in g['repos'] if r['archived'])}, forks: {sum(1 for r in g['repos'] if r['fork'])}"]
    L += ["", "## Sources and gaps", ""] + _md_table(["Source", "State", "Detail"], [(s["source"], s["state"], s["detail"]) for s in snap.status]) + ["", "## What was not collected", "", NOT_COLLECTED, ""]
    return "\n".join(L)


def to_json(snap, found):
    inv = service_inventory(snap)
    return json.dumps({
        "target": snap.target, "run": snap.run_id, "taken_at": snap.taken_at, "purpose": snap.purpose,
        "names": {n: {**e, "sources": sorted(e["sources"]), "chain": snap.chain(n)} for n, e in sorted(snap.names.items())},
        "ips": snap.ips, "asns": {str(k): v for k, v in sorted(snap.asns.items())}, "wildcards": snap.wildcards, "registration": snap.registration, "apex": snap.apex,
        "archive": snap.archive, "github": snap.github, "web": snap.web, "services": {k: [list(x) for x in v] for k, v in inv.items()}, "status": snap.status,
        "findings": [{"id": f.id, "severity": f.severity, "title": f.title, "detail": f.detail, "evidence": f.evidence} for f in found],
        "not_collected": NOT_COLLECTED}, indent=2, ensure_ascii=False, default=list)


def evidence(store, run_id, needle):
    """The stored observations whose subject or object mentions ``needle``: claim, source, evidence URL and the hash of the stored response."""
    rows = []
    for o in store.observations(run_id):
        if needle in o.subject or needle in json.dumps(o.object):
            rows.append({"source": o.source, "subject": o.subject, "predicate": o.predicate, "object": o.object, "url": o.url, "raw_sha256": o.raw})
    return rows
