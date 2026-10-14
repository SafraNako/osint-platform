"""The pipeline against a world whose truth is known: whatever it reports is compared with what was planted."""
import json

import pytest

from conftest import TARGET, emails_in, make_client, run_world
from osint_platformu import fakeworld as F
from osint_platformu import report
from osint_platformu.insights import service_inventory

D = TARGET


def test_every_planted_host_is_found_and_nothing_else(first):
    assert set(first.snap.names) == first.world.all_names                      # precision and recall of the name inventory are both exactly 1


def test_hosts_are_attributed_to_the_sources_that_revealed_them(first):
    n = first.snap.names
    assert "ct" in n[f"api.{D}"]["sources"] and "dns" in n[f"api.{D}"]["sources"]
    assert n[f"forum.{D}"]["sources"] == {"archive"}                           # visible only through the web archive, and DNS says it no longer exists
    assert n[f"docs.{D}"]["sources"] == {"sitemap", "dns"}                     # visible only through the sitemap, and it resolves
    assert n[f"vpn.{D}"]["sources"] == {"ct"} and n[f"a.b.c.{D}"]["sources"] == {"ct", "dns"}      # 'dns' means "resolves today": NXDOMAIN is evidence of absence


def test_out_of_scope_names_never_enter_the_investigation(first):
    everything = first.store.dump_text()
    for outsider in ("shared-cdn-customer.com", "unrelated-example.net", f"not{D}", f"{D}.evil.example"):
        assert outsider not in everything, outsider
    assert all(o.subject.endswith(D) for o in first.store.observations(first.run_id, predicate="cert_name"))


def test_certificate_facts_are_aggregated_per_name(first):
    api = first.snap.names[f"api.{D}"]["ct"]
    assert api["certs"] == 1 and api["issuers"] == ["Sectigo Limited, Ltd."]    # the precertificate with the same serial is not counted twice, the quoted comma survives
    assert api["first_seen"] == "2026-03-01T00:00:00Z" and api["last_seen"] == "2027-03-01T00:00:00Z"
    assert first.snap.names[D]["ct"]["certs"] == 3                              # three certificates list the apex (S1, S4 and the multi-tenant S8)
    assert f"mail.{D}" in first.snap.names                                      # 'MAIL.Planted-Corp.org' on a certificate is normalised
    assert set(first.snap.wildcards) == first.world.wildcard_zones


def test_dns_answers_match_the_planted_records(first):
    w, n = first.world, first.snap.names
    for name, spec in w.hosts.items():
        e = n[name]
        if spec.get("nxdomain"):
            assert e["nxdomain"] is not None and e["nxdomain"]["cname_target"] is None and not e["a"], name
        elif "a" in spec:
            assert e["a"] == sorted(spec["a"]) and e["nxdomain"] is None, name
    assert n[D]["aaaa"] == ["2a00:1450:4001:81b::200e"] and first.snap.ips["2a00:1450:4001:81b::200e"]["asns"] == [64496]       # the IPv6 route to the ASN service
    assert first.snap.ips["2a00:1450:4001:81b::200e"]["prefix"] == "2a00:1450::/32"
    assert n[f"www.{D}"]["a"] == ["45.60.1.10", "45.60.1.11"] and first.snap.chain(f"www.{D}") == [f"www.{D}", D]
    assert first.snap.chain(f"shop.{D}") == [f"shop.{D}", "planted-shop.myshopify.com"] and n[f"shop.{D}"]["a"] == ["45.61.2.30"]
    assert n[f"old-blog.{D}"]["nxdomain"] == {"cname_target": "gone-blog.github.io"}
    assert n[f"legacy.{D}"]["nxdomain"] == {"cname_target": "retired.internal-vendor.example.net"}


def test_networks_come_from_the_planted_prefixes_and_private_addresses_are_not_looked_up(first):
    ips = first.snap.ips
    assert ips["45.60.1.10"]["asns"] == [64496] and ips["45.60.1.10"]["prefix"] == "45.60.0.0/16" and ips["45.60.1.10"]["country"] == "US"
    assert ips["45.61.2.30"]["asns"] == [64497] and ips["45.61.2.30"]["registry"] == "ripencc"
    assert first.snap.asns == {64496: {"name": "PLANTED-HOSTING-A - Planted Hosting A, US", "country": "US", "registry": "arin"},
                               64497: {"name": "PLANTED-CDN-B - Planted CDN B, DE", "country": "DE", "registry": "ripencc"}}
    assert ips["10.0.0.5"]["asns"] == [] and ips["10.0.0.5"]["names"] == [f"dev.{D}"]
    asked = [r["query"]["name"] for r in first.requests if r["route"] == "doh"]
    assert not any(q.endswith(".origin.asn.cymru.com") and q.startswith("5.0.0.10") for q in asked)     # RFC 1918 addresses are not sent to a third party


def test_apex_records_and_mail_posture(first):
    a = first.snap.apex
    assert a["mx"] == [(10, "aspmx.l.google.com"), (20, "alt1.aspmx.l.google.com")] and a["ns"] == ["ns-1.awsdns-01.org", "ns-2.awsdns-02.co.uk"]
    assert "v=spf1 include:_spf.google.com include:sendgrid.net ~all" in a["spf"] and len(a["spf"]) == 1
    assert a["dmarc"] == ["v=DMARC1; p=none; rua=mailto:<mailbox at dmarc-vendor.example>"] and a["mta_sts"] == [] and a["caa"] == []
    assert "contact=<mailbox at planted-corp.org>" in a["txt"]                  # the planted address in a TXT record was scrubbed down to its domain


def test_third_party_services_are_inferred_from_the_records(first):
    inv = service_inventory(first.snap)
    assert {"Google Workspace (mail)", "SendGrid", "Atlassian", "Microsoft 365", "HackerOne", "Amazon Route 53", "Shopify"} <= set(inv)
    assert ("mx", "aspmx.l.google.com") in inv["Google Workspace (mail)"] and ("spf", "sendgrid.net") in inv["SendGrid"]
    assert any(k == "cname" and "planted-shop.myshopify.com" in v for k, v in inv["Shopify"])


def test_registration_is_read_from_rdap_without_any_contact(first):
    r = first.snap.registration
    assert r["registrar"] == {"name": "Planted Registrar LLC", "iana_id": "9999"}
    assert r["registered"] == "2005-03-01T10:00:00Z" and r["expires"] == "2026-11-03T00:00:00Z" and r["dnssec_signed"] is False
    assert r["nameservers"] == ["ns-1.awsdns-01.org", "ns-2.awsdns-02.co.uk"] and r["rdap_status"] == ["client transfer prohibited"]


def test_archive_candidates_are_exactly_the_interesting_paths(first):
    found = {u: set(c["categories"]) for u, c in first.snap.archive["candidates"].items()}
    assert found == first.world.interesting_urls                                 # the public tarball and the '?ref=partner.dev' URL are not flagged
    assert first.snap.archive["total"]["urls"] == 205 - 2 + 0 or first.snap.archive["total"]["urls"] > 190
    assert not any("?" in u for u in found)


def test_github_organisation_and_repositories(first):
    g = first.snap.github
    assert g["info"]["linked_to_target"] is True and g["info"]["public_repos"] == 5 and g["info"]["blog"] == f"https://{D}"
    assert sorted(r["name"] for r in g["repos"]) == sorted(n for n, *_ in first.world.repos)
    assert sum(r["archived"] for r in g["repos"]) == 1 and sum(r["fork"] for r in g["repos"]) == 1


def test_published_files(first):
    web = first.snap.web
    assert web["robots"][D]["disallow"] == ["/internal-admin/", "/search", "/staging/"] and web["robots"][D]["sitemaps"][0].endswith(f"/web/{D}/sitemap.xml")
    sec = web["security_txt"][D]
    assert sec["contacts"] == [f"mailto:security@{D}", f"https://{D}/security"] and sec["expires"] == "2026-01-01T00:00:00Z" and sec["expired"] is True
    assert web["sitemap"][D]["locs"] == 3 and web["sitemap"][D]["hosts"] == [f"docs.{D}", f"www.{D}"]
    assert f"www.{D}" not in web.get("security_txt", {})


EXPECTED_FINDINGS = {
    f"dangling-cname:old-blog.{D}": "medium", f"domain-expiry:{D}": "medium", f"broken-cname:legacy.{D}": "low", f"dmarc-monitor:{D}": "low", f"private-ip:{D}": "low",
    f"security-txt-expired:{D}": "low", f"archive-admin-or-login:{D}": "info", f"archive-api-surface:{D}": "info", f"archive-backup-or-dump:{D}": "info",
    f"archive-config-file:{D}": "info", f"archive-pre-production:{D}": "info", f"archive-vcs-or-env-file:{D}": "info", f"caa:{D}": "info", f"dnssec:{D}": "info",
    f"historic-names:{D}": "info", f"mta-sts:{D}": "info", f"robots-hints:{D}": "info", f"wildcard-certs:{D}": "info"}


def test_findings_are_exactly_the_planted_weaknesses(first):
    assert {f.id: f.severity for f in first.findings} == EXPECTED_FINDINGS


def test_finding_details_carry_their_evidence(first):
    by = {f.id: f for f in first.findings}
    dangling = by[f"dangling-cname:old-blog.{D}"]
    assert "GitHub Pages" in dangling.title and any("gone-blog.github.io" in e and "NXDOMAIN" in e for e in dangling.evidence)
    assert sorted(by[f"private-ip:{D}"].evidence) == [f"DNS: dev.{D} -> 10.0.0.5", f"DNS: staging.{D} -> 10.0.0.6"]
    assert "19 days" in by[f"domain-expiry:{D}"].title                          # 2026-10-14 12:00 to 2026-11-03 00:00
    assert {e.split(": ")[1].split(" (")[0] for e in by[f"historic-names:{D}"].evidence} == {f"smime.{D}", f"vpn.{D}"}
    assert any("/internal-admin/" in e for e in by[f"robots-hints:{D}"].evidence) and not any("/search" in e for e in by[f"robots-hints:{D}"].evidence)


def test_no_personal_data_is_stored_anywhere(first):
    dump = first.store.dump_text()
    for secret in F.PERSONAL_STRINGS:
        assert secret not in dump, secret
    assert emails_in(dump) == {f"security@{D}"}                                 # the single published contact security.txt exists to share


def test_every_claim_traces_to_the_stored_bytes_it_came_from(first):
    needle = {"cert_name": lambda o, name: name, "a": lambda o, name: o.object, "aaaa": lambda o, name: o.object, "mx": lambda o, name: o.object["host"],
              "ns": lambda o, name: o.object, "nameserver": lambda o, name: o.object, "registrar": lambda o, name: o.object["name"],
              "ip_asn": lambda o, name: o.object["prefix"], "asn_info": lambda o, name: o.object["name"], "gh_repo": lambda o, name: o.object["name"],
              "archive_host": lambda o, name: name, "robots": lambda o, name: o.object["disallow"][0], "security_txt": lambda o, name: o.object["contacts"][0]}
    seen = set()
    for o in first.store.observations(first.run_id):
        assert o.url and o.raw, o
        body = first.store.get_raw(o.raw)
        assert body is not None, o
        if o.predicate in needle:
            name = o.subject.split(":", 1)[1]
            text = body.decode("utf-8")
            assert str(needle[o.predicate](o, name)).lower() in text.lower(), (o.predicate, o.subject, o.object)
            seen.add(o.predicate)
    assert seen == set(needle)                                                  # every claim kind was checked at least once


def test_the_report_and_json_are_consistent_with_the_snapshot(first):
    md = report.render_markdown(first.snap, first.findings)
    data = json.loads(report.to_json(first.snap, first.findings))
    assert set(data["names"]) == first.world.all_names and {f["id"] for f in data["findings"]} == set(EXPECTED_FINDINGS)
    for name in first.world.all_names:
        assert f"| {name} |" in md
    assert "validation against a planted organisation" in md and "## What was not collected" in md
    assert all(secret not in md and secret not in json.dumps(data) for secret in F.PERSONAL_STRINGS)
    assert data["registration"]["registrar"]["name"] == "Planted Registrar LLC" and data["services"]["Shopify"]


def test_the_same_world_gives_the_same_report():
    import re
    a, b = run_world("first"), run_world("first")

    def normal(run):
        return re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", report.render_markdown(run.snap, run.findings))      # the loopback port differs from run to run
    assert normal(a) == normal(b)
    assert [f.id for f in a.findings] == [f.id for f in b.findings]


def test_every_request_is_polite_and_goes_only_where_the_platform_says(first):
    assert first.requests and all(r["ua"].startswith("osint-platform/") for r in first.requests)
    assert {r["route"] for r in first.requests} == {"crtsh", "rdap", "rdap-org", "cdx", "web", "github", "doh"}
    assert all(r["accept"] == "application/dns-json" for r in first.requests if r["route"] == "doh")
    assert all("vnd.github" in r["accept"] for r in first.requests if r["route"] == "github")
    asked_names = {r["query"]["name"] for r in first.requests if r["route"] == "doh"}
    allowed = first.world.all_names | {f"_dmarc.{D}", f"_mta-sts.{D}"}
    assert {n for n in asked_names if not n.endswith("cymru.com")} <= allowed         # no guessing of names: only what other sources revealed
    web_paths = {r["path"] for r in first.requests if r["route"] == "web"}
    assert web_paths <= {f"/web/{h}{p}" for h in (D, f"www.{D}") for p in ("/robots.txt", "/.well-known/security.txt", "/security.txt", "/sitemap.xml")}


def test_a_client_confined_to_loopback_cannot_reach_anything_else():
    from osint_platformu.http import HttpError
    with pytest.raises(HttpError):
        make_client().get("https://example.com/")


def test_the_second_run_shows_exactly_the_planted_changes(first, later_in_same_store):
    from conftest import snapshot_of
    from osint_platformu.diff import diff_snapshots, render_diff
    from osint_platformu.insights import findings
    old, new = snapshot_of(first.store, first.run_id), later_in_same_store.snap
    d = diff_snapshots(old, new, findings(old), later_in_same_store.findings)
    assert d["changed"] and d["names"] == {"added": [f"new-app.{D}"], "removed": []}
    assert set(d["records_changed"]) == {f"api.{D}", f"shop.{D}"}
    assert d["records_changed"][f"api.{D}"]["before"]["a"] == ["45.61.2.20"] and d["records_changed"][f"api.{D}"]["after"]["a"] == ["45.61.2.21"]
    assert d["records_changed"][f"shop.{D}"]["after"] == {"a": [], "aaaa": [], "cname": []}
    assert d["mx"] == {"added": ["30 mx.sendgrid.net"], "removed": []} and d["ns"] == {"added": [], "removed": []} and d["asns"] == {"added": [], "removed": []}
    assert d["registration"] == {"registrar": {"before": {"name": "Planted Registrar LLC", "iana_id": "9999"}, "after": {"name": "Better Registrar Inc", "iana_id": "9999"}}}
    assert d["archive_candidates"]["added"] == [f"https://forum.{D}/phpmyadmin/index.php"] and d["archive_candidates"]["removed"] == []
    assert d["github_repos"] == {"added": ["planted-new"], "removed": []}
    assert d["findings"]["resolved"] == [f"security-txt-expired:{D}"]
    assert d["findings"]["new"] == []
    text = render_diff(d)
    assert f"new-app.{D}" in text and "planted-new" in text and "Better Registrar Inc" in text


def test_identical_runs_show_no_change(first):
    from conftest import snapshot_of
    from osint_platformu.diff import diff_snapshots, render_diff
    from osint_platformu.insights import findings
    again = run_world("first", store=first.store)
    old, new = snapshot_of(first.store, first.run_id), again.snap
    d = diff_snapshots(old, new, findings(old), again.findings)
    assert not d["changed"] and "No changes" in render_diff(d)
