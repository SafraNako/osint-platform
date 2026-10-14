"""A snapshot is the picture of one run: the observations of the run folded into names, addresses, networks, the apex records, the registration, the
archive, the organisation on GitHub and the published files. Reports, findings and diffs all work on snapshots, never on raw rows."""
from __future__ import annotations

from dataclasses import dataclass, field

from .guard import in_scope


@dataclass
class Snapshot:
    target: str
    run_id: int
    taken_at: str
    purpose: str
    names: dict = field(default_factory=dict)
    ips: dict = field(default_factory=dict)
    asns: dict = field(default_factory=dict)
    wildcards: dict = field(default_factory=dict)
    cname_of: dict = field(default_factory=dict)
    registration: dict = field(default_factory=dict)
    apex: dict = field(default_factory=dict)
    archive: dict = field(default_factory=dict)
    github: dict = None
    web: dict = field(default_factory=dict)
    status: list = field(default_factory=list)

    def chain(self, name):
        """The CNAME chain from ``name`` to the last alias, as a list of names (``[name]`` when it is not an alias)."""
        hops, seen = [name], {name}
        while hops[-1] in self.cname_of and self.cname_of[hops[-1]] not in seen:
            hops.append(self.cname_of[hops[-1]])
            seen.add(hops[-1])
        return hops


def _name(subject):
    return subject[len("domain:"):] if subject.startswith("domain:") else None


def build_snapshot(store, run_id, target, taken_at="", purpose=""):
    snap = Snapshot(target, run_id, taken_at, purpose)
    obs = store.observations(run_id)

    def entry(name):
        return snap.names.setdefault(name, {"sources": set(), "ct": None, "archive": None, "a": [], "aaaa": [], "cname": None, "nxdomain": None, "rcode": None})

    txt_by_name, caa, mx, ns = {}, [], [], []
    for o in obs:
        name = _name(o.subject)
        p = o.predicate
        if p == "cert_name" and name:
            e = entry(name)
            e["sources"].add("ct")
            e["ct"] = o.object
        elif p == "cert_wildcard" and name:
            snap.wildcards[name] = o.object
        elif p == "archive_host" and name and in_scope(name, target):
            e = entry(name)
            e["sources"].add("archive")
            e["archive"] = o.object
        elif p == "sitemap" and name:
            for h in o.object.get("hosts", []):
                entry(h)["sources"].add("sitemap")
            snap.web.setdefault("sitemap", {})[name] = o.object
        elif p == "cname" and name:
            snap.cname_of[name] = o.object
        elif p in ("a", "aaaa") and name:
            e = entry(name)
            e["sources"].add("dns")
            e[p].append(o.object)
            snap.ips.setdefault(o.object, {"asns": [], "prefix": None, "country": None, "registry": None, "names": []})["names"].append(name)
        elif p == "dns_status" and name:
            entry(name)["rcode"] = o.object["rcode"]
        elif p == "nxdomain" and name:
            entry(name)["nxdomain"] = o.object
        elif p == "txt" and name:
            txt_by_name.setdefault(name, []).append(o.object)
        elif p == "mx" and name == target:
            mx.append(o.object)
        elif p == "ns" and name == target:
            ns.append(o.object)
        elif p == "caa" and name == target:
            caa.append(o.object)
        elif p == "ip_asn":
            ip = o.subject[len("ip:"):]
            snap.ips.setdefault(ip, {"asns": [], "prefix": None, "country": None, "registry": None, "names": []}).update(
                {"asns": o.object["asns"], "prefix": o.object["prefix"], "country": o.object["country"], "registry": o.object["registry"]})
        elif p == "asn_info":
            snap.asns[int(o.subject[len("asn:"):])] = o.object
        elif p in ("registered", "expires", "last_changed", "transferred", "rdap_status", "dnssec_signed", "registrar"):
            snap.registration[p] = o.object
        elif p == "nameserver":
            snap.registration.setdefault("nameservers", []).append(o.object)
        elif p == "archive_candidate":
            snap.archive.setdefault("candidates", {})[o.subject[len("url:"):]] = o.object
        elif p == "archive_total":
            snap.archive["total"] = o.object
        elif p == "gh_org":
            snap.github = {"org": o.subject[len("org:github:"):], "info": o.object, "repos": []}
        elif p == "gh_repo" and snap.github is not None:
            snap.github["repos"].append(o.object)
        elif p == "robots" and name:
            snap.web.setdefault("robots", {})[name] = o.object
        elif p == "security_txt" and name:
            snap.web.setdefault("security_txt", {})[name] = o.object
    for e in snap.names.values():
        e["a"], e["aaaa"] = sorted(set(e["a"])), sorted(set(e["aaaa"]))
    for info in snap.ips.values():
        info["names"] = sorted(set(info["names"]))
    txt = sorted(set(txt_by_name.get(target, [])))
    snap.apex = {
        "mx": sorted({(m["pref"], m["host"]) for m in mx}), "ns": sorted(set(ns)), "txt": txt,
        "caa": sorted({(c["flags"], c["tag"], c["value"]) for c in caa}),
        "spf": [t for t in txt if t.lower().startswith("v=spf1")],
        "dmarc": [t for t in txt_by_name.get("_dmarc." + target, []) if t.lower().startswith("v=dmarc1")],
        "mta_sts": [t for t in txt_by_name.get("_mta-sts." + target, []) if t.lower().startswith("v=stsv1")],
    }
    snap.status = store.statuses(run_id)
    return snap
