"""Self-validation: what the platform reports is compared with a planted truth or with recorded real data, never with its own output.

The planted organisation (``fakeworld``) has a fully known structure, with the traps real data contains; the cassette is a real recorded investigation of iana.org.
Each check returns ``Check(name, passed, detail)``; ``osint dogrulama`` prints them all. Nothing here uses the network (the planted world speaks over the loopback
interface only).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import cassette, engine, fakeworld, insights
from . import snapshot as snapmod
from . import store as storemod
from .context import Context, Endpoints
from .diff import diff_snapshots
from .guard import ScopeError, normalize_domain
from .model import parse_iso
from .sources import ct

CASSETTE = Path(__file__).parent / "data" / "iana.org.cassette.json.gz"
D = fakeworld.PlantedWorld.domain
_cache = {}


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


def _planted(variant="first", **kw):
    key = (variant,) if not kw else None
    if key and key in _cache:
        return _cache[key]
    run = fakeworld.run_planted(variant, **kw)
    if key:
        _cache[key] = run
    return run


def _emails(text):
    return set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))


def _prf(found, truth):
    tp = len(found & truth)
    return (tp / len(found) if found else 1.0), (tp / len(truth) if truth else 1.0)


def check_inventory():
    r = _planted()
    found, truth = set(r.snap.names), r.world.all_names
    precision, recall = _prf(found, truth)
    return Check("host inventory against the planted organisation", found == truth,
                 f"{len(truth)} planted hosts: precision {precision:.2f}, recall {recall:.2f}; {len(r.world.archive_only_hosts)} found only in the web archive, "
                 f"{len(r.world.sitemap_only_hosts)} only in a sitemap, {len(r.world.ct_only)} only in certificates")


def check_scope_isolation():
    r = _planted()
    dump = r.store.dump_text()
    outsiders = ["shared-cdn-customer.com", "unrelated-example.net", f"not{D}", f"{D}.evil.example"]
    leaked = [o for o in outsiders if o in dump]
    return Check("names outside the target never enter the investigation", not leaked,
                 f"{len(outsiders)} planted outsiders (other tenants on shared certificates, a lookalike that ends with the same letters, a domain that contains the name): "
                 f"{len(leaked)} stored, in observations or in the kept raw responses")


def check_dns_and_networks():
    r = _planted()
    w, n, bad = r.world, r.snap.names, []
    for name, spec in w.hosts.items():
        e = n[name]
        if spec.get("nxdomain") and not (e["nxdomain"] and not e["a"]):
            bad.append(name)
        if "a" in spec and e["a"] != sorted(spec["a"]):
            bad.append(name)
    v6 = r.snap.ips.get("2a00:1450:4001:81b::200e", {})
    asn_ok = r.snap.ips["45.60.1.10"]["asns"] == [64496] and r.snap.ips["45.61.2.30"]["asns"] == [64497] and v6.get("asns") == [64496]
    private_sent = [q for q in r.requests if q["route"] == "doh" and q["query"]["name"].startswith(("5.0.0.10.", "6.0.0.10."))]
    return Check("DNS answers, networks and the privacy of internal addresses", not bad and asn_ok and not private_sent,
                 f"{len(w.hosts)} planted names resolved as planted ({len(bad)} wrong); IPv4 and IPv6 addresses mapped to their planted ASNs; "
                 f"{len(private_sent)} private (RFC 1918) addresses sent to the ASN service")


def check_alias_findings():
    r = _planted()
    got = {f.id for f in r.findings}
    dangling = {i.split(":", 1)[1] for i in got if i.startswith("dangling-cname:")}
    broken = {i.split(":", 1)[1] for i in got if i.startswith("broken-cname:")}
    ok = dangling == r.world.dangling_expected and broken == r.world.broken_expected
    return Check("dangling aliases are found and ranked, and nothing else is accused", ok,
                 f"planted: 1 alias to a released GitHub Pages name (medium), 1 to an unknown vendor (low), 3 names that simply do not exist (not aliases): "
                 f"found {len(dangling)} medium and {len(broken)} low, no false accusation" if ok else f"dangling {sorted(dangling)}, broken {sorted(broken)}")


def check_archive_candidates():
    r = _planted()
    found = {u: set(c["categories"]) for u, c in r.snap.archive["candidates"].items()}
    ok = found == r.world.interesting_urls and not any("?" in u for u in found)
    return Check("archived paths of interest: all found, none of the look-alike traps flagged", ok,
                 f"{len(r.world.interesting_urls)} planted paths matched with their categories; a public tarball, a '?ref=partner.dev' URL and a lookalike domain "
                 f"were correctly not flagged; no query string stored")


def check_privacy():
    r = _planted()
    dump = r.store.dump_text()
    leaked = [s for s in fakeworld.PERSONAL_STRINGS if s in dump]
    mails = _emails(dump)
    return Check("planted personal data is never stored", not leaked and mails == {f"security@{D}"},
                 f"{len(fakeworld.PERSONAL_STRINGS)} planted personal strings (registrant, admin and tech contacts, abuse mailbox, GitHub e-mail and a free-text field, a TXT "
                 f"address, an S/MIME address): {len(leaked)} stored; the only address in the whole database is the published security.txt contact")


def check_provenance():
    r = _planted()
    needle = {"cert_name": lambda o, name: name, "a": lambda o, name: o.object, "aaaa": lambda o, name: o.object, "mx": lambda o, name: o.object["host"],
              "nameserver": lambda o, name: o.object, "registrar": lambda o, name: o.object["name"], "ip_asn": lambda o, name: o.object["prefix"],
              "gh_repo": lambda o, name: o.object["name"], "archive_host": lambda o, name: name, "robots": lambda o, name: o.object["disallow"][0]}
    checked = missing = 0
    for o in r.store.observations(r.run_id):
        body = r.store.get_raw(o.raw) if o.raw else None
        if body is None or not o.url:
            missing += 1
            continue
        if o.predicate in needle:
            checked += 1
            if str(needle[o.predicate](o, o.subject.split(":", 1)[1])).lower() not in body.decode("utf-8").lower():
                missing += 1
    return Check("every claim traces to the stored response it came from", missing == 0 and checked >= 3 * len(needle),
                 f"{checked} claims of {len(needle)} kinds looked up in the stored bytes behind their evidence URL: {missing} not found")


def check_diff():
    first, later = _planted("first"), _planted("later", store=_planted("first").store)
    d = diff_snapshots(snapmod.build_snapshot(first.store, first.run_id, D, "", ""), later.snap,
                       first.findings, later.findings)
    want = {"new host": d["names"]["added"] == [f"new-app.{D}"], "moved records": set(d["records_changed"]) == {f"api.{D}", f"shop.{D}"},
            "new mail exchanger": d["mx"]["added"] == ["30 mx.sendgrid.net"], "registrar change": "registrar" in d["registration"],
            "new archived path": len(d["archive_candidates"]["added"]) == 1, "new repository": d["github_repos"]["added"] == ["planted-new"],
            "resolved finding": d["findings"]["resolved"] == [f"security-txt-expired:{D}"], "nothing spurious": not d["names"]["removed"] and not d["findings"]["new"]}
    return Check("a second run shows exactly the planted changes", all(want.values()), "recovered: " + ", ".join(k for k, v in want.items() if v) + (
        "" if all(want.values()) else "; MISSED: " + ", ".join(k for k, v in want.items() if not v)))


def check_resilience():
    plain = _planted()
    spot = fakeworld.run_planted(faults={"crtsh": "always:500"})
    fallback_ok = set(spot.snap.names) == set(plain.snap.names) and any(s.state == "partial" for s in spot.statuses if s.source == "ct")
    dns_down = fakeworld.run_planted(faults={"doh": "always:503", "doh2": "always:503"})
    outage_ok = next(s for s in dns_down.statuses if s.source == "dns").state == "error" and set(dns_down.snap.names) == set(plain.snap.names)
    doh2 = fakeworld.run_planted(faults={"doh": "always:503"})
    dialect_ok = doh2.snap.apex == plain.snap.apex
    return Check("outages degrade into statuses, fallbacks give the same answers", fallback_ok and outage_ok and dialect_ok,
                 f"crt.sh down: Cert Spotter fallback {'finds the same names' if fallback_ok else 'FAILED'} (status partial); both resolvers down: DNS reported as error, "
                 f"other sources intact: {outage_ok}; Google-style resolver dialect parses to identical records: {dialect_ok}")


def check_scope_guard():
    refused, allowed = 0, 0
    bad = ["jane.doe@example.org", "Jane Doe", "192.0.2.1", "10.0.0.1", "https://example.org/x", "localhost", "printer.local", "co.uk", "com.tr", "*.example.org", "example.org:80", ""]
    for b in bad:
        try:
            normalize_domain(b)
        except ScopeError:
            refused += 1
    good = {"example.org": "example.org", "Example.ORG.": "example.org", "ışık.org": "xn--k-ekaa7p.org"}
    allowed = sum(1 for g, e in good.items() if normalize_domain(g) == e)
    with fakeworld.FakeInternet() as net:
        try:
            engine.investigate("someone@example.org", "a long enough purpose", storemod.Store(), None, endpoints=net.endpoints())
        except ScopeError:
            pass
        silent = not net.requests
    return Check("people, devices and shared suffixes are refused before anything is contacted", refused == len(bad) and allowed == len(good) and silent,
                 f"{refused}/{len(bad)} out-of-scope targets refused (e-mail addresses, names, IP addresses, URLs, special-use names, public suffixes); "
                 f"{allowed}/{len(good)} valid domains accepted; no request made for a refused target: {silent}")


def check_rules():
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)

    def snap(**kw):
        s = snapmod.Snapshot("example.org", 1, "2026-10-14T00:00:00Z", "t")
        s.status = [{"source": x, "state": "ok", "detail": "", "count": 1} for x in ("dns", "web", "rdap", "ct")]
        s.apex = {"mx": [(10, "m")], "ns": [], "txt": [], "caa": [("0", "issue", "x")], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"], "mta_sts": ["v=STSv1"]}
        s.web = {"security_txt": {"example.org": {"contacts": ["x"], "expires": "2030-01-01T00:00:00Z", "expired": False}}}
        s.registration = {"expires": "2030-01-01T00:00:00Z", "dnssec_signed": True}
        s.__dict__.update(kw)
        return s

    def ids(s):
        return {f.id.split(":")[0]: f.severity for f in insights.findings(s, now)}
    grid = [("quiet baseline", ids(snap()) == {})]
    for record, expect in (("v=spf1 +all", ("spf-open", "medium")), ("v=spf1 ?all", ("spf-neutral", "low")), ("v=spf1 ~all", None), ("v=spf1 -all", None)):
        s = snap()
        s.apex["spf"] = [record]
        got = ids(s)
        grid.append((f"SPF {record}", (got == {expect[0]: expect[1]}) if expect else got == {}))
    for days, expect in ((-5, "medium"), (20, "medium"), (60, "low"), (400, None)):
        s = snap(registration={"expires": (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"), "dnssec_signed": True})
        got = ids(s)
        grid.append((f"expiry in {days} days", (got.get("domain-expiry") == expect) if expect else "domain-expiry" not in got))
    failed = [name for name, ok in grid if not ok]
    return Check("findings rules at their thresholds", not failed, f"{len(grid) - len(failed)}/{len(grid)} cases (SPF qualifiers, expiry at -5, 20, 60 and 400 days, a quiet baseline)"
                 + (f"; FAILED: {failed}" if failed else ""))


def check_real_data():
    meta, tape = cassette.load(CASSETTE)
    now = parse_iso(meta["recorded_at"])
    store = storemod.Store()
    run_id, statuses = engine.investigate(meta["target"], "replaying a recorded real investigation", store, cassette.ReplayClient(tape, retries=0),
                                          options={"github_org": meta["github_org"]}, now=now)
    snap = snapmod.build_snapshot(store, run_id, meta["target"], meta["recorded_at"], "real")

    def names(endpoints):
        ctx = Context(target=meta["target"], http=cassette.ReplayClient(tape, retries=0), store=storemod.Store(), endpoints=endpoints)
        res = ct.collect(ctx)
        return {o.subject[7:]: o.object for o in res.observations if o.predicate == "cert_name"}
    crt, spot = names(Endpoints()), names(Endpoints(crtsh="http://127.0.0.1:1/unreachable"))
    consistent = set(spot) < set(crt) and all(crt[n]["last_seen"] >= meta["recorded_at"] for n in spot) and all(crt[n]["last_seen"] < meta["recorded_at"] for n in set(crt) - set(spot))
    facts = (snap.names["iana.org"]["a"] == ["192.0.43.8"] and snap.ips["192.0.43.8"]["asns"] == [16876] and snap.registration["registrar"]["iana_id"] == "299"
             and snap.chain("data.iana.org")[-1].endswith("cdn.cloudflare.net"))
    clean = not _emails(store.dump_text())
    return Check("real recorded data (iana.org): independent sources agree, nothing personal kept", consistent and facts and clean and len(snap.names) == 25,
                 f"{len(snap.names)} hosts from {len(tape)} recorded responses; Cert Spotter's {len(spot)} names are a subset of crt.sh's {len(crt)}, and every one has a "
                 f"certificate still valid at recording time while every crt.sh-only name has only expired ones; ASN, registrar and CDN alias match the live facts; "
                 f"no e-mail address in the database: {clean}")


def check_politeness():
    r = _planted()
    ua = all(q["ua"].startswith("osint-platform/") for q in r.requests)
    routes = {q["route"] for q in r.requests} <= {"crtsh", "rdap", "rdap-org", "cdx", "web", "github", "doh"}
    asked = {q["query"]["name"] for q in r.requests if q["route"] == "doh" and not q["query"]["name"].endswith("cymru.com")}
    guessing = asked - (r.world.all_names | {f"_dmarc.{D}", f"_mta-sts.{D}"})
    return Check("requests are identified, limited to the planned sources, and never guess names", ua and routes and not guessing,
                 f"{len(r.requests)} requests, all with the platform's User-Agent; {len(asked)} DNS names queried, all discovered by other sources or the fixed mail-policy "
                 f"names; {len(guessing)} guessed")


ALL = [check_inventory, check_scope_isolation, check_dns_and_networks, check_alias_findings, check_archive_candidates, check_privacy, check_provenance, check_diff,
       check_resilience, check_scope_guard, check_rules, check_real_data, check_politeness]


def run_all():
    results = []
    for f in ALL:
        try:
            results.append(f())
        except Exception as exc:                      # a broken check is a failed check, not a crash
            results.append(Check(f.__name__.replace("check_", "").replace("_", " "), False, f"{type(exc).__name__}: {exc}"))
    return results
