"""The findings rules on hand-built snapshots: each rule, each severity threshold, and the cases where it must stay silent."""
from datetime import datetime, timezone

import pytest

from osint_platformu import insights
from osint_platformu.snapshot import Snapshot

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
T = "example.org"


def snap(**kw):
    """A quiet snapshot: every source ran, and nothing in it triggers a finding until a test changes something."""
    s = Snapshot(T, 1, "2026-10-14T00:00:00Z", "test")
    s.status = [{"source": x, "state": "ok", "detail": "", "count": 1} for x in ("dns", "web", "rdap", "ct")]
    s.apex = {"mx": [(10, "mx.example.org")], "ns": [], "txt": [], "caa": [("0", "issue", "x")], "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"], "mta_sts": ["v=STSv1; id=1"]}
    s.web = {"security_txt": {T: {"contacts": ["mailto:a"], "expires": "2030-01-01T00:00:00Z", "expired": False}}}
    s.registration = {"expires": "2030-01-01T00:00:00Z", "dnssec_signed": True}
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def ids(s):
    return {f.id: f.severity for f in insights.findings(s, NOW)}


@pytest.mark.parametrize("record,expected", [
    ("v=spf1 include:_spf.google.com -all", {"all": "-", "lookups": 1, "redirect": False}),
    ("v=spf1 a mx ~all", {"all": "~", "lookups": 2, "redirect": False}),
    ("v=spf1 +all", {"all": "+", "lookups": 0, "redirect": False}), ("v=spf1 all", {"all": "+", "lookups": 0, "redirect": False}),
    ("v=spf1 ?all", {"all": "?", "lookups": 0, "redirect": False}), ("v=spf1 redirect=_spf.example.net", {"all": None, "lookups": 1, "redirect": True})])
def test_spf_parsing(record, expected):
    a = insights.spf_analysis(record)
    assert {k: a[k] for k in expected} == expected


def test_dmarc_parsing_reads_the_report_processor_domain_from_the_scrubbed_address():
    d = insights.dmarc_analysis("v=DMARC1; p=Quarantine; pct=50; rua=mailto:<mailbox at vendor.example>,mailto:<mailbox at other.example>")
    assert d == {"p": "quarantine", "sp": "", "pct": 50, "rua_domains": ["other.example", "vendor.example"], "has_rua": True}
    assert insights.dmarc_analysis("v=DMARC1; p=reject")["pct"] == 100


@pytest.mark.parametrize("spf,expected_id,sev", [
    (["v=spf1 +all"], f"spf-open:{T}", "medium"), (["v=spf1 ?all"], f"spf-neutral:{T}", "low"), (["v=spf1 include:a.example"], f"spf-open-ended:{T}", "low"),
    (["v=spf1 -all", "v=spf1 ~all"], f"spf-multiple:{T}", "low"), ([], f"spf-missing:{T}", "low"),
    (["v=spf1 " + " ".join(f"include:i{n}.example" for n in range(11)) + " -all"], f"spf-lookups:{T}", "low")])
def test_spf_findings(spf, expected_id, sev):
    s = snap()
    s.apex["spf"], s.apex["dmarc"] = spf, ["v=DMARC1; p=reject"]
    assert ids(s)[expected_id] == sev


def test_good_spf_and_dmarc_raise_nothing():
    s = snap()
    s.apex["spf"], s.apex["dmarc"] = ["v=spf1 include:_spf.google.com -all"], ["v=DMARC1; p=reject; rua=mailto:<mailbox at v.example>"]
    assert ids(s) == {}


def test_spf_redirect_is_not_judged_without_following_it():
    s = snap()
    s.apex["spf"], s.apex["dmarc"] = ["v=spf1 redirect=_spf.example.net"], ["v=DMARC1; p=reject"]
    assert ids(s) == {}


@pytest.mark.parametrize("dmarc,expected_id,sev", [
    (["v=DMARC1; p=none"], f"dmarc-monitor:{T}", "low"), ([], f"dmarc-missing:{T}", "low"), (["v=DMARC1; p=reject; pct=25"], f"dmarc-pct:{T}", "info")])
def test_dmarc_findings(dmarc, expected_id, sev):
    s = snap()
    s.apex["spf"], s.apex["dmarc"] = ["v=spf1 -all"], dmarc
    assert ids(s)[expected_id] == sev


def test_mail_rules_stay_silent_for_a_domain_that_does_not_do_mail():
    s = snap()
    s.apex["mx"], s.apex["spf"], s.apex["mta_sts"] = [], [], []
    assert not [i for i in ids(s) if i.startswith(("spf", "dmarc", "mta-sts"))]


def test_mail_rules_stay_silent_when_dns_was_not_collected():
    s = snap()
    s.status = [x for x in s.status if x["source"] != "dns"]
    s.apex["caa"] = []
    assert not [i for i in ids(s) if i.startswith(("spf", "dmarc", "mta-sts", "caa"))]


@pytest.mark.parametrize("expires,expected", [
    ("2026-10-10T00:00:00Z", ("medium", "expired")), ("2026-11-03T00:00:00Z", ("medium", "20 days")), ("2026-12-01T00:00:00Z", ("low", "48 days")), ("2027-12-01T00:00:00Z", None)])
def test_domain_expiry_thresholds(expires, expected):
    s = snap(registration={"expires": expires, "dnssec_signed": True})
    found = {f.id: f for f in insights.findings(s, NOW)}
    f = found.get(f"domain-expiry:{T}")
    if expected is None:
        assert f is None
    else:
        assert f.severity == expected[0] and expected[1] in f.title.lower()


def entry(**kw):
    return {"sources": {"dns"}, "ct": None, "archive": None, "a": [], "aaaa": [], "cname": None, "nxdomain": None, "rcode": 0, **kw}


@pytest.mark.parametrize("target,rule,sev", [
    ("old.herokuapp.com", "dangling-cname", "medium"), ("x.azurewebsites.net", "dangling-cname", "medium"), ("shop.myshopify.com", "dangling-cname", "medium"),
    ("gone.vendor-unknown.example", "broken-cname", "low"), ("x.nowhere.org", "broken-cname", "low")])
def test_dangling_aliases_are_ranked_by_whether_the_provider_lets_anyone_claim_the_name(target, rule, sev):
    s = snap(names={f"x.{T}": entry(nxdomain={"cname_target": target})}, cname_of={f"x.{T}": target})
    assert ids(s) == {f"{rule}:x.{T}": sev}


def test_the_quiet_baseline_really_is_quiet():
    assert ids(snap()) == {}


def test_a_name_that_does_not_exist_is_not_a_dangling_alias():
    s = snap(names={f"x.{T}": entry(sources={"ct"}, nxdomain={"cname_target": None}, ct={})})
    assert list(ids(s)) == [f"historic-names:{T}"]


@pytest.mark.parametrize("ip,flagged", [("10.1.2.3", True), ("192.168.1.1", True), ("172.16.0.1", True), ("127.0.0.1", True), ("169.254.1.1", True), ("100.64.0.1", True),
                                         ("fd00::1", True), ("8.8.8.8", False), ("45.60.1.10", False), ("2a00:1450:4001:81b::200e", False)])
def test_non_public_addresses_in_public_dns(ip, flagged):
    key = "aaaa" if ":" in ip else "a"
    s = snap(names={f"x.{T}": entry(**{key: [ip]})})
    assert (f"private-ip:{T}" in ids(s)) is flagged


def test_security_txt_rules_only_fire_when_the_web_source_ran():
    s = snap(web={})
    assert ids(s) == {f"security-txt-missing:{T}": "info"}
    s.status = [x for x in s.status if x["source"] != "web"]
    assert ids(s) == {}
    s = snap(web={"security_txt": {T: {"contacts": ["mailto:a"], "expires": "2020-01-01T00:00:00Z", "expired": True}}})
    assert ids(s) == {f"security-txt-expired:{T}": "low"}


def test_robots_hints_only_for_sensitive_looking_paths():
    s = snap(web={"robots": {T: {"disallow": ["/search", "/tmp/", "/private-area/", "/images"], "sitemaps": []}}, "security_txt": {T: {"contacts": ["x"], "expired": False, "expires": None}}})
    f = {f.id: f for f in insights.findings(s, NOW)}[f"robots-hints:{T}"]
    assert sorted(e.split("Disallow ")[1] for e in f.evidence) == ["/private-area/", "/tmp/"]


def test_github_attribution_is_flagged_when_the_profile_does_not_link_back():
    s = snap(github={"org": "someorg", "info": {"linked_to_target": False, "blog": "https://elsewhere.example"}, "repos": []})
    assert ids(s)["github-unlinked:someorg"] == "info"
    s.github["info"]["linked_to_target"] = True
    assert ids(s) == {}


def test_findings_are_sorted_most_serious_first_and_stable():
    s = snap(registration={"expires": "2026-10-20T00:00:00Z", "dnssec_signed": False}, names={f"x.{T}": entry(a=["10.0.0.1"])})
    s.apex["spf"], s.apex["dmarc"] = ["v=spf1 ~all"], []
    out = insights.findings(s, NOW)
    assert [f.severity for f in out] == sorted((f.severity for f in out), key=lambda v: -insights.SEVERITIES.index(v))
    assert [f.id for f in out] == [f.id for f in insights.findings(s, NOW)]


def test_service_inventory_recognises_providers_by_domain_boundary_not_by_substring():
    from osint_platformu import fingerprints as fp
    assert fp.match("a.b.fastly.net", fp.CNAME_PROVIDERS) == "Fastly (CDN)" and fp.match("notfastly.net", fp.CNAME_PROVIDERS) is None
    assert fp.match("ns-12.awsdns-01.org", fp.NS_PROVIDERS) == "Amazon Route 53"
    assert fp.match("x.cdn.cloudflare.net", fp.CNAME_PROVIDERS) == "Cloudflare (CDN)"
    assert fp.match("gone.github.io", fp.CLAIMABLE_PROVIDERS) == "GitHub Pages" and fp.match("github.io.evil.example", fp.CLAIMABLE_PROVIDERS) is None
