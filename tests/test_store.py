import pytest

from osint_platformu.model import Obs, SourceStatus, iso, parse_iso
from osint_platformu.store import Store
from datetime import datetime, timezone


def test_raw_responses_are_deduplicated_and_round_trip():
    s = Store()
    a, b = s.put_raw(b"hello"), s.put_raw(b"hello")
    assert a == b and s.get_raw(a) == b"hello" and s.get_raw("0" * 64) is None
    assert s.db.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 1


def test_cache_respects_the_ttl():
    s = Store()
    s.cache_put("k", 200, b"body", now=1000.0)
    assert s.cache_get("k", ttl=60, now=1030.0) == (200, b"body")
    assert s.cache_get("k", ttl=60, now=1061.0) is None
    assert s.cache_get("missing", ttl=60, now=1000.0) is None


def test_investigations_runs_and_observations_round_trip():
    s = Store()
    inv = s.investigation("example.org", "test", "2026-01-01T00:00:00Z")
    assert s.investigation("example.org", "other purpose", "2027-01-01T00:00:00Z") == inv      # one investigation per target
    run = s.start_run(inv, ["dns", "ct"], "test", "2026-01-01T00:00:00Z")
    sha = s.put_raw(b"x")
    s.add_observations(run, [Obs("dns:doh", "domain:a.example.org", "a", "192.0.2.1", "http://u", sha), Obs("dns:doh", "domain:a.example.org", "mx", {"pref": 10, "host": "m"}, "http://u", sha)])
    s.add_status(run, SourceStatus("dns", "ok", "fine", 2))
    s.finish_run(run, "2026-01-01T00:01:00Z")
    obs = s.observations(run)
    assert [o.predicate for o in obs] == ["a", "mx"] and obs[1].object == {"pref": 10, "host": "m"} and obs[0].raw == sha
    assert [o.predicate for o in s.observations(run, predicate="mx")] == ["mx"] and len(s.observations(run, subject="domain:a.example.org")) == 2
    assert s.statuses(run) == [{"source": "dns", "state": "ok", "detail": "fine", "count": 2}]
    assert s.runs("example.org")[0]["sources"] == '["ct", "dns"]' and s.investigations()[0]["runs"] == 1


def test_database_persists_in_a_file(tmp_path):
    path = str(tmp_path / "o.db")
    s = Store(path)
    s.investigation("example.org", "p", "2026-01-01T00:00:00Z")
    s.close()
    assert Store(path).investigations()[0]["target"] == "example.org"


def test_timestamp_parsing_covers_the_formats_the_sources_use():
    expected = datetime(2026, 9, 24, 23, 13, 26, tzinfo=timezone.utc)
    for text in ("2026-09-24T23:13:26", "2026-09-24T23:13:26Z", "2026-09-24T23:13:26+00:00", "2026-09-24T23:13:26.191Z", "2026-09-24T23:13:26.776+00:00"):
        assert parse_iso(text) == expected
    assert parse_iso("2026-09-25T01:13:26+02:00") == expected
    assert iso(expected) == "2026-09-24T23:13:26Z"
    with pytest.raises(ValueError):
        parse_iso("not a date")
