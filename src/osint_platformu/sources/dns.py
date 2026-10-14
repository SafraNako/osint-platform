"""DNS over HTTPS (JSON): what the names found elsewhere resolve to, who runs the mail and the name servers, which TXT records the zone publishes,
and, through Team Cymru's DNS-based service, which autonomous system each public address belongs to.

One address query per name is enough to see a whole CNAME chain: the answer lists the aliases and then the final addresses, and a status of
NXDOMAIN with aliases in the answer means the chain ends at a name that does not exist (a dangling alias).
"""
from __future__ import annotations

import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor

from ..guard import clean_name
from ..http import HttpError
from ..model import SourceResult, SourceStatus

NAME = "dns"
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
CODE = {v: k for k, v in TYPES.items()}


def query(ctx, name, rtype):
    """One DoH query, trying the primary resolver and then the fallback. Returns a dict with ``status`` (DNS RCODE or None), ``answers``,
    ``url``, ``sha`` and ``error``."""
    last = None
    for base, headers in ((ctx.endpoints.doh, {"Accept": "application/dns-json"}), (ctx.endpoints.doh_fallback, {"Accept": "application/dns-json"})):
        if not base:
            continue
        try:
            response, sha = ctx.fetch(base, params={"name": name, "type": rtype}, headers=headers)
            if response.status != 200:
                last = f"HTTP {response.status} from {base}"
                continue
            data = response.json()
            return {"status": data.get("Status"), "answers": data.get("Answer", []), "url": response.url, "sha": sha, "error": None}
        except (HttpError, ValueError, json.JSONDecodeError) as exc:
            last = str(exc)
    return {"status": None, "answers": [], "url": "", "sha": "", "error": last}


def parse_txt(data):
    """The text of a TXT answer: the quoted segments joined (Cloudflare), or the plain string (Google)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts).replace('\\"', '"') if parts else data


def _reverse_name(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    return ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"


def _fields(txt):
    return [f.strip() for f in parse_txt(txt).split("|")]


def collect(ctx, names):
    target = ctx.target
    workers = max(1, int(ctx.workers))
    max_names = int(ctx.options.get("max_names", 400))
    names = sorted(set(names) | {target})
    truncated = len(names) > max_names
    if truncated:
        names = sorted(names, key=lambda n: (n != target, n.count("."), n))[:max_names]
    jobs = [(n, "A") for n in names] + [(n, "AAAA") for n in names]
    jobs += [(target, t) for t in ("MX", "NS", "TXT", "CAA")] + [("_dmarc." + target, "TXT"), ("_mta-sts." + target, "TXT")]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda job: (job, query(ctx, *job)), jobs))
    out, ips, failures = [], {}, 0
    src = "dns:doh"
    for (name, rtype), res in results:
        if res["error"]:
            failures += 1
            continue
        subject_base = "domain:" + name
        if rtype == "A":
            out.append(ctx.obs(src, subject_base, "dns_status", {"rcode": res["status"]}, res["url"], res["sha"]))
        last_cname = None
        for ans in res["answers"]:
            kind, owner, data = CODE.get(ans.get("type")), clean_name(ans.get("name", "")), ans.get("data", "")
            subject = "domain:" + owner
            if kind == "CNAME":
                last_cname = clean_name(data)
                out.append(ctx.obs(src, subject, "cname", last_cname, res["url"], res["sha"]))
            elif kind in ("A", "AAAA") and rtype in ("A", "AAAA"):
                out.append(ctx.obs(src, subject_base, kind.lower(), data, res["url"], res["sha"]))     # the address belongs to the name that was asked
                ips.setdefault(data, res)
            elif kind == "MX" and rtype == "MX":
                pref, _, host = data.partition(" ")
                out.append(ctx.obs(src, subject, "mx", {"pref": int(pref), "host": clean_name(host)}, res["url"], res["sha"]))
            elif kind == "NS" and rtype == "NS":
                out.append(ctx.obs(src, subject, "ns", clean_name(data), res["url"], res["sha"]))
            elif kind == "TXT" and rtype == "TXT":
                out.append(ctx.obs(src, subject, "txt", parse_txt(data), res["url"], res["sha"]))
            elif kind == "CAA" and rtype == "CAA":
                flags, _, rest = data.partition(" ")
                tag, _, value = rest.partition(" ")
                out.append(ctx.obs(src, subject, "caa", {"flags": flags, "tag": tag, "value": value.strip('"')}, res["url"], res["sha"]))
        if rtype == "A" and res["status"] == 3:
            out.append(ctx.obs(src, subject_base, "nxdomain", {"cname_target": last_cname}, res["url"], res["sha"]))
    # the autonomous system of every public address
    public = sorted(ip for ip in ips if ipaddress.ip_address(ip).is_global)
    asn_jobs = [(ip, _reverse_name(ip)) for ip in public]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        asn_results = list(pool.map(lambda job: (job[0], query(ctx, job[1], "TXT")), asn_jobs))
    asns = {}
    for ip, res in asn_results:
        if res["error"]:
            failures += 1
            continue
        for ans in res["answers"][:1]:
            f = _fields(ans.get("data", ""))
            if len(f) >= 5:
                asn_list = [a for a in f[0].split() if a.isdigit()]
                out.append(ctx.obs("dns:cymru", "ip:" + ip, "ip_asn", {"asns": [int(a) for a in asn_list], "prefix": f[1], "country": f[2], "registry": f[3], "allocated": f[4]},
                                   res["url"], res["sha"]))
                for a in asn_list:
                    asns.setdefault(int(a), res)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        name_results = list(pool.map(lambda a: (a, query(ctx, f"AS{a}.asn.cymru.com", "TXT")), sorted(asns)))
    for a, res in name_results:
        if res["error"]:
            failures += 1
            continue
        for ans in res["answers"][:1]:
            f = _fields(ans.get("data", ""))
            if len(f) >= 5:
                out.append(ctx.obs("dns:cymru", f"asn:{a}", "asn_info", {"name": f[4], "country": f[1], "registry": f[2]}, res["url"], res["sha"]))
    total = len(jobs) + len(asn_jobs) + len(asns)
    state, detail = "ok", f"{len(names)} names, {total} queries"
    if failures:
        state, detail = ("partial" if failures < total else "error"), detail + f"; {failures} failed"
    if truncated:
        state, detail = "partial", detail + f"; only the first {max_names} names were resolved"
    return SourceResult(out, SourceStatus(NAME, state, detail, len(names)))
