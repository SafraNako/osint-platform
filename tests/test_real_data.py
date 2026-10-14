"""The collectors on genuine responses: a cassette recorded from a live investigation of iana.org (a public non-profit's domain) on 2026-10-14, replayed
without any network. Facts asserted here are frozen in the recording; the independent checks (two certificate sources, ASN data, redaction) hold on whatever the
real services returned."""
import json
from pathlib import Path

import pytest

from conftest import emails_in
from osint_platformu import cassette, engine, insights, report
from osint_platformu import snapshot as snapmod
from osint_platformu import store as storemod
from osint_platformu.context import Context, Endpoints
from osint_platformu.model import parse_iso
from osint_platformu.sources import ct

FIXTURE = Path(__file__).resolve().parents[1] / "src" / "osint_platformu" / "data" / "iana.org.cassette.json.gz"
META, TAPE = cassette.load(FIXTURE)
NOW = parse_iso(META["recorded_at"])


def investigate():
    store = storemod.Store()
    client = cassette.ReplayClient(TAPE, retries=0)
    run_id, statuses = engine.investigate("iana.org", "replaying a recorded real investigation", store, client, options={"github_org": META["github_org"]}, now=NOW)
    snap = snapmod.build_snapshot(store, run_id, "iana.org", META["recorded_at"], "real data")
    return store, snap, statuses


@pytest.fixture(scope="module")
def real():
    return investigate()


def test_the_cassette_is_what_it_claims_to_be():
    assert META["target"] == "iana.org" and META["requests"] == len(TAPE) >= 90
    assert any("crt.sh" in u for u in TAPE) and any("certspotter" in u for u in TAPE) and any("cymru" in u for u in TAPE) and any("rdap" in u for u in TAPE)
    assert not emails_in(json.dumps(TAPE))                                           # scrubbed when recorded


def test_every_source_works_on_the_real_responses(real):
    store, snap, statuses = real
    assert {s.source: s.state for s in statuses} == {"ct": "ok", "rdap": "ok", "wayback": "partial", "web": "ok", "github": "ok", "dns": "ok"}
    assert "truncated" in next(s for s in statuses if s.source == "wayback").detail           # a big site fills the row limit: said so, not hidden


def test_certificate_names_wildcards_and_issuers(real):
    _, snap, _ = real
    assert len(snap.names) == 25 and {"iana.org", "www.iana.org", "data.iana.org", "ftp.iana.org"} <= set(snap.names)
    assert set(snap.wildcards) == {"iana.org", "int.iana.org"}
    issuers = {i for e in snap.names.values() if e["ct"] for i in e["ct"]["issuers"]}
    assert "GoDaddy.com, Inc." in issuers and "Let's Encrypt" in issuers and "DigiCert Inc" in issuers
    assert not [i for i in issuers if i.startswith('"') or i.endswith('"')]               # quoted organisation names containing a comma are parsed whole


def test_the_two_certificate_sources_agree_on_what_they_both_know():
    def names(endpoints):
        ctx = Context(target="iana.org", http=cassette.ReplayClient(TAPE, retries=0), store=storemod.Store(), endpoints=endpoints)
        result = ct.collect(ctx)
        return {o.subject[7:]: o.object for o in result.observations if o.predicate == "cert_name"}, {o.subject[7:] for o in result.observations if o.predicate == "cert_wildcard"}, result.status
    crt, crt_zones, crt_status = names(Endpoints())
    spot, spot_zones, spot_status = names(Endpoints(crtsh="http://127.0.0.1:1/unreachable"))       # not in the cassette: forces the fallback
    assert crt_status.state == "ok" and spot_status.state == "partial" and "fell back" in spot_status.detail
    assert set(spot) < set(crt) and crt_zones == spot_zones                          # an independent source: a subset of crt.sh's names, the same wildcard zones
    recorded = META["recorded_at"]
    assert all(crt[n]["last_seen"] >= recorded for n in spot)                       # everything Cert Spotter lists has a certificate still valid at the time
    assert all(crt[n]["last_seen"] < recorded for n in set(crt) - set(spot))        # everything only crt.sh lists has only expired certificates: the two sources are consistent


def test_dns_on_the_real_resolver_answers(real):
    _, snap, _ = real
    assert snap.names["iana.org"]["a"] == ["192.0.43.8"] and snap.names["iana.org"]["aaaa"] == ["2001:500:88:200::8"]
    assert snap.ips["192.0.43.8"]["asns"] == [16876] and snap.ips["192.0.43.8"]["prefix"] == "192.0.43.0/24" and snap.asns[16876]["name"].startswith("ICANN-DC")
    assert snap.ips["2001:500:88:200::8"]["asns"] == [16876]                          # IPv6 through the real origin6 service
    assert snap.chain("data.iana.org") == ["data.iana.org", "data.iana.org.cdn.cloudflare.net"] and snap.asns[13335]["name"].startswith("CLOUDFLARENET")
    assert len(snap.apex["mx"]) == 4 and len(snap.apex["ns"]) == 4 and snap.apex["spf"] == ["v=spf1 redirect=icann.org"]
    assert ("0", "issue", "digicert.com") in snap.apex["caa"] and snap.apex["dmarc"] and "p=none" in snap.apex["dmarc"][0]


def test_names_that_exist_only_in_old_certificates_are_nxdomain_on_the_real_resolver(real):
    _, snap, _ = real
    gone = {n for n, e in snap.names.items() if e["nxdomain"] and not e["nxdomain"]["cname_target"]}
    assert {"ns.iana.org", "www.rzm.iana.org", "www.itar.iana.org"} <= gone and len(gone) == 8
    assert all(snap.names[n]["sources"] == {"ct"} for n in gone)


def test_private_addresses_in_the_real_public_dns_are_recognised(real):
    _, snap, _ = real
    internal = {n for n, e in snap.names.items() if any(a.startswith("10.") for a in e["a"])}
    assert {"int.iana.org", "intranet.int.iana.org", "dnstest.int.iana.org"} <= internal
    assert all(not snap.ips[a]["asns"] for n in internal for a in snap.names[n]["a"])


def test_real_registration_data_has_no_contacts(real):
    store, snap, _ = real
    r = snap.registration
    assert r["registrar"] == {"name": "CSC Corporate Domains, Inc.", "iana_id": "299"} and r["expires"].startswith("2027-12-08") and r["dnssec_signed"] is True
    assert sorted(r["nameservers"]) == ["a.iana-servers.net", "b.iana-servers.net", "c.iana-servers.net", "ns.icann.org"]
    rdap_raw = [store.get_raw(o.raw).decode() for o in store.observations(1, predicate="registrar")][0]
    assert set(json.loads(rdap_raw)) == {"ldhName", "status", "events", "nameservers", "secureDNS", "entities"}      # only the allowlisted fields were stored


def test_real_github_organisation(real):
    _, snap, _ = real
    g = snap.github
    assert g["org"] == "iana-org" and g["info"]["public_repos"] == len(g["repos"]) == 9
    assert g["info"]["linked_to_target"] is True                                      # the organisation's own profile points at iana.org


def test_real_archive_and_published_files(real):
    _, snap, _ = real
    assert snap.archive["total"] == {"urls": 5000, "truncated": True}
    assert snap.web["robots"]["iana.org"] == {"disallow": [], "sitemaps": []} and "security_txt" not in snap.web


def test_nothing_personal_is_stored_from_real_responses(real):
    store, _, _ = real
    assert emails_in(store.dump_text()) == set()


def test_every_observation_has_stored_evidence(real):
    store, _, _ = real
    for o in store.observations(1):
        assert o.url and store.get_raw(o.raw) is not None


def test_findings_on_the_real_data(real):
    _, snap, _ = real
    found = {f.id: f for f in insights.findings(snap, NOW)}
    assert found["dmarc-monitor:iana.org"].severity == "low" and found["private-ip:iana.org"].severity == "low" and "5 name(s)" in found["private-ip:iana.org"].title
    assert found["historic-names:iana.org"].severity == "info" and "security-txt-missing:iana.org" in found
    assert not [f for f in found.values() if f.severity == "medium"]                  # a well-run domain: nothing medium


def test_the_real_report_renders_and_names_its_gaps(real):
    store, snap, _ = real
    md = report.render_markdown(snap, insights.findings(snap, NOW))
    assert "## Hosts" in md and "AS16876" in md and "CSC Corporate Domains" in md and "partial" in md
    assert json.loads(report.to_json(snap, insights.findings(snap, NOW)))["registration"]["registrar"]["iana_id"] == "299"


def test_replay_is_deterministic():
    a, b = investigate(), investigate()
    assert report.to_json(a[1], insights.findings(a[1], NOW)) == report.to_json(b[1], insights.findings(b[1], NOW))
