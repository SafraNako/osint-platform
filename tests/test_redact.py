import json

from osint_platformu import redact


def loads(b):
    return json.loads(b.decode("utf-8"))


def test_crtsh_keeps_only_host_names_and_drops_personal_fields():
    rows = [{"id": 1, "serial_number": "ab", "issuer_name": "C=US, O=CA", "common_name": "Jane Doe", "name_value": "www.example.org\njane.doe@example.org\n*.example.org\nnot a host",
             "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00", "entry_timestamp": "x", "result_count": 3}]
    out = redact.redact_crtsh(json.dumps(rows).encode())
    assert b"Jane" not in out and b"jane.doe" not in out and b"entry_timestamp" not in out
    assert loads(out)[0]["name_value"] == "www.example.org\n*.example.org"


def test_certspotter_keeps_host_names_and_dates():
    out = redact.redact_certspotter(json.dumps([{"id": "1", "dns_names": ["a.example.org", "x@y.org"], "not_before": "n", "not_after": "a", "pubkey_sha256": "zzz"}]).encode())
    assert loads(out) == [{"id": "1", "dns_names": ["a.example.org"], "not_before": "n", "not_after": "a"}]


def test_rdap_keeps_the_registrar_and_nothing_personal():
    data = {"ldhName": "example.org", "status": ["ok"], "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z", "eventActor": "Jane Doe"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.NET", "remarks": [{"description": ["Jane Doe"]}]}], "secureDNS": {"delegationSigned": True, "dsData": [{"keyTag": 1}]},
            "notices": [{"description": ["mail abuse@example.org"]}], "links": [{"href": "https://x"}],
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Jane Doe"], ["email", {}, "text", "jane@example.org"]]]},
                         {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "1"}],
                          "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"], ["email", {}, "text", "r@reg.example"], ["tel", {}, "uri", "tel:+1"]]],
                          "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Person"]]]}]}]}
    out = redact.redact_rdap(json.dumps(data).encode())
    for secret in (b"Jane", b"jane@", b"r@reg", b"tel:", b"Abuse Person", b"abuse@", b"dsData", b"notices"):
        assert secret not in out
    r = loads(out)
    assert [e["vcardArray"][1] for e in r["entities"]] == [[["fn", {}, "text", "Reg Inc"]]]
    assert r["nameservers"] == [{"ldhName": "NS1.EXAMPLE.NET"}] and r["secureDNS"] == {"delegationSigned": True}


def test_github_allowlist_drops_fields_nobody_thought_about():
    org = {"login": "o", "name": "O", "email": "x@y.org", "twitter_username": "t", "blog": "https://o.org", "public_repos": 3, "private_note": "Alice Maintainer", "followers": 1}
    out = redact.redact_github(json.dumps(org).encode())
    assert b"Alice" not in out and b"x@y" not in out and b"twitter" not in out and loads(out)["login"] == "o"
    repos = [{"name": "r", "language": "Go", "owner": {"login": "o", "email": "e@f.org"}, "stargazers_count": 1, "extra": "Bob"}]
    out = redact.redact_github(json.dumps(repos).encode())
    assert b"Bob" not in out and b"owner" not in out and loads(out) == [{"name": "r", "language": "Go", "stargazers_count": 1}]


def test_cdx_strips_query_strings_and_fragments_but_keeps_the_header():
    rows = [["timestamp", "original", "statuscode"], ["2020", "https://example.org/a/b?token=secret&email=a@b.org#frag", "200"], ["2021", "https://example.org/", "404"]]
    out = loads(redact.redact_cdx(json.dumps(rows).encode()))
    assert out[0] == rows[0] and out[1][1] == "https://example.org/a/b" and out[2][1] == "https://example.org/"


def test_unparseable_bodies_fall_back_to_the_email_scrub():
    for fn in (redact.redact_crtsh, redact.redact_certspotter, redact.redact_rdap, redact.redact_github, redact.redact_cdx):
        assert fn(b"<html>write to someone@example.org</html>") == b"<html>write to <mailbox at example.org></html>"
