import pytest

from osint_platformu import guard


@pytest.mark.parametrize("raw,expected", [
    ("example.org", "example.org"), ("  Example.ORG. ", "example.org"), ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
    ("bücher.example.de", "xn--bcher-kva.example.de"), ("ışık.org", "xn--k-ekaa7p.org"), ("a-b.example.com", "a-b.example.com")])
def test_valid_targets_are_normalised(raw, expected):
    assert guard.normalize_domain(raw) == expected


@pytest.mark.parametrize("raw,why", [
    ("", "empty target"), ("jane.doe@example.org", "identify people"), ("Jane Doe", "spaces"), ("https://example.org/path", "bare domain"), ("example.org/path", "bare domain"),
    ("192.0.2.10", "identify devices"), ("10.0.0.1", "identify devices"), ("[2001:db8::1]", "IPv6"), ("example.org:8080", "ports"), ("*.example.org", "wildcards"),
    ("com", "top-level domain"), ("localhost", "top-level domain"), ("printer.local", "special-use"), ("host.internal", "special-use"), ("example.test", "special-use"),
    ("co.uk", "public suffix"), ("com.tr", "public suffix"), ("-bad.example.org", "not a valid domain"), ("exa mple.org", "spaces"), ("a" * 64 + ".org", "not a valid domain"),
    ("example.123", "numeric top-level")])
def test_out_of_scope_targets_are_refused_with_a_reason(raw, why):
    with pytest.raises(guard.ScopeError) as e:
        guard.normalize_domain(raw)
    assert why in str(e.value)


def test_special_use_names_are_allowed_only_when_asked():
    assert guard.normalize_domain("planted.test", allow_special_use=True) == "planted.test"


def test_scope_boundary_is_on_label_boundaries():
    t = "planted-corp.org"
    assert guard.in_scope("planted-corp.org", t) and guard.in_scope("WWW.Planted-Corp.org.", t) and guard.in_scope("*.eu.planted-corp.org", t)
    assert not guard.in_scope("notplanted-corp.org", t)              # ends with the same letters, is another domain
    assert not guard.in_scope("planted-corp.org.evil.example", t)    # contains the name, is another domain
    assert not guard.in_scope("unrelated-example.net", t)


def test_clean_name_and_hostname_syntax():
    assert guard.clean_name("*.Example.ORG.") == "example.org"
    for ok in ("example.org", "*.example.org", "a_b.example.org", "xn--bcher-kva.example"):
        assert guard.is_hostname(ok)
    for bad in ("jane.doe@example.org", "has space.example.org", "", "a..b", "-x.org", "exa$mple.org"):
        assert not guard.is_hostname(bad)


def test_email_scrub_keeps_only_the_mail_domain():
    text = "rua=mailto:dmarc-reports@dmarc-vendor.example; ruf=mailto:Jane.Doe+x@sub.planted-corp.org;"
    out = guard.scrub_text(text)
    assert "@" not in out and "dmarc-reports" not in out and "Jane" not in out
    assert "<mailbox at dmarc-vendor.example>" in out and "<mailbox at sub.planted-corp.org>" in out
    assert guard.scrub({"a": ["x@y.org", {"b": "q@r.com"}], "n": 3}) == {"a": ["<mailbox at y.org>", {"b": "<mailbox at r.com>"}], "n": 3}
    assert guard.scrub_bytes(b"mail a@b.org") == b"mail <mailbox at b.org>"
