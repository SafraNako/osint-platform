"""Sources fail in practice. A failure must show up as a status, never as a crash and never as silently missing data."""
import pytest

from conftest import TARGET, make_client, run_world
from osint_platformu import engine, fakeworld, guard
from osint_platformu import store as storemod

D = TARGET


def states(run):
    return {s.source: s.state for s in run.statuses}


def test_a_flaky_certificate_source_is_retried_and_the_run_is_complete():
    r = run_world(faults={"crtsh": [502, 503]}, client=make_client(retries=2))
    assert set(r.snap.names) == r.world.all_names and states(r)["ct"] == "ok"
    assert [q["route"] for q in r.requests].count("crtsh") == 3


def test_when_crtsh_is_down_certspotter_gives_the_same_names_and_the_status_says_so():
    r = run_world(faults={"crtsh": "always:500"})
    assert set(r.snap.names) == r.world.all_names
    ct = next(s for s in r.statuses if s.source == "ct")
    assert ct.state == "partial" and "fell back" in ct.detail and "Cert Spotter" in ct.detail
    assert {o.source for o in r.store.observations(r.run_id, predicate="cert_name")} == {"ct:certspotter"}
    assert set(r.snap.wildcards) == r.world.wildcard_zones


def test_when_every_certificate_source_is_down_the_run_still_finishes_with_the_other_sources():
    r = run_world(faults={"crtsh": "always:500", "certspotter": "always:500"})
    assert states(r)["ct"] == "error" and states(r)["dns"] == "ok" and states(r)["rdap"] == "ok"
    assert set(r.snap.names) == {D, f"www.{D}", f"forum.{D}", f"docs.{D}"} - {f"www.{D}"} | {f"www.{D}"} & set(r.snap.names)      # only names other sources reveal
    assert f"api.{D}" not in r.snap.names and r.snap.registration["registrar"]["name"] == "Planted Registrar LLC"
    assert "ct" in str(r.statuses[0].detail) or r.statuses[0].state == "error"


def test_the_fallback_resolver_is_used_when_the_primary_is_down_and_parses_its_different_dialect():
    r = run_world(faults={"doh": "always:503"})
    assert states(r)["dns"] == "ok"
    assert {q["route"] for q in r.requests if q["path"].startswith("/doh")} == {"doh", "doh2"}
    ref = run_world()
    assert r.snap.apex == ref.snap.apex                                          # Google-style unquoted TXT parses to the same records
    assert {n: (e["a"], e["nxdomain"]) for n, e in r.snap.names.items()} == {n: (e["a"], e["nxdomain"]) for n, e in ref.snap.names.items()}
    assert r.snap.ips == ref.snap.ips


def test_when_both_resolvers_are_down_dns_is_an_error_and_everything_else_survives():
    r = run_world(faults={"doh": "always:500", "doh2": "always:500"})
    assert states(r)["dns"] == "error" and not any(e["a"] for e in r.snap.names.values())
    assert set(r.snap.names) == r.world.all_names and states(r)["ct"] == "ok"
    assert not [f for f in r.findings if f.id.startswith(("spf", "dmarc", "caa", "mta-sts"))]       # no DNS data, so no claims about mail or CAA records


def test_a_slow_site_times_out_without_stopping_anything_else():
    r = run_world(faults={"web": "slow"}, client=make_client(retries=0, timeout=0.2), delay=0.6)
    assert states(r)["web"] == "error" and states(r)["dns"] == "ok" and set(r.snap.names) >= r.world.ct_names
    assert not any(f.id.startswith("security-txt") for f in r.findings)          # no claim of a missing security.txt when the fetch failed


def test_github_rate_limiting_is_reported_as_unavailable():
    r = run_world(faults={"github": "always:403"})
    gh = next(s for s in r.statuses if s.source == "github")
    assert gh.state == "unavailable" and "rate limited" in gh.detail and r.snap.github is None


def test_an_unknown_github_organisation_is_not_an_error():
    r = run_world(options={"github_org": "no-such-org"})
    gh = next(s for s in r.statuses if s.source == "github")
    assert gh.state == "ok" and "no public organisation" in gh.detail and r.snap.github is None


def test_github_is_skipped_unless_an_organisation_is_named():
    r = run_world(options={"github_org": None})
    gh = next(s for s in r.statuses if s.source == "github")
    assert gh.state == "skipped" and "never guessed" in gh.detail
    assert not [q for q in r.requests if q["route"] == "github"]


def test_a_registry_without_rdap_is_unavailable_not_broken():
    w = fakeworld.PlantedWorld()
    with fakeworld.FakeInternet(w) as net:
        ep = net.endpoints()
        store = storemod.Store()
        run_id, statuses = engine.investigate("planted-corp.com", "a .com name whose registry the planted bootstrap points at a dead port", store, make_client(retries=0),
                                              endpoints=ep, sources=["rdap"], now=w.now)
    s = statuses[0]
    assert s.source == "rdap" and s.state == "error"                             # the bootstrap names a server that refuses connections: an error, with the reason
    with fakeworld.FakeInternet(w) as net:
        run_id, statuses = engine.investigate("planted-corp.xyz", "a TLD that the bootstrap does not list at all", storemod.Store(), make_client(), endpoints=net.endpoints(),
                                              sources=["rdap"], now=w.now)
    assert statuses[0].state == "unavailable" and "no RDAP service for .xyz" in statuses[0].detail


def test_choosing_sources_contacts_only_those_sources():
    r = run_world(sources=["ct"])
    assert {q["route"] for q in r.requests} == {"crtsh"} and [s.source for s in r.statuses] == ["ct"]
    r = run_world(sources=["wayback", "web"])
    assert {q["route"] for q in r.requests} == {"cdx", "web"}


def test_dns_alone_resolves_only_the_target():
    r = run_world(sources=["dns"])
    assert set(r.snap.names) == {D}
    assert {q["query"]["name"] for q in r.requests if q["route"] == "doh" and not q["query"]["name"].endswith("cymru.com")} == {D, f"_dmarc.{D}", f"_mta-sts.{D}"}


def test_the_scope_is_checked_before_anything_is_contacted():
    w = fakeworld.PlantedWorld()
    with fakeworld.FakeInternet(w) as net:
        store = storemod.Store()
        for bad in ("jane.doe@planted-corp.org", "Jane Doe", "192.0.2.1", "https://planted-corp.org/x", "co.uk", "planted-corp.local"):
            with pytest.raises(guard.ScopeError):
                engine.investigate(bad, "a long enough purpose", store, make_client(), endpoints=net.endpoints(), now=w.now)
        assert net.requests == [] and store.investigations() == []


@pytest.mark.parametrize("purpose", ["", "   ", "short"])
def test_an_investigation_needs_a_stated_purpose(purpose):
    w = fakeworld.PlantedWorld()
    with fakeworld.FakeInternet(w) as net:
        store = storemod.Store()
        with pytest.raises(guard.ScopeError) as e:
            engine.investigate(D, purpose, store, make_client(), endpoints=net.endpoints(), now=w.now)
        assert "purpose" in str(e.value) and net.requests == [] and store.investigations() == []


def test_unknown_sources_are_refused():
    with pytest.raises(guard.ScopeError) as e:
        engine.investigate(D, "a long enough purpose", storemod.Store(), make_client(), sources=["ct", "shodan"], now=fakeworld.PlantedWorld.now)
    assert "shodan" in str(e.value)


def test_the_http_cache_serves_repeat_runs_and_keeps_personal_data_out_of_the_database():
    from conftest import snapshot_of
    w = fakeworld.PlantedWorld()
    store = storemod.Store()
    cached = make_client(cache=store, cache_ttl=3600)
    with fakeworld.FakeInternet(w) as net:                                      # one server for both runs: the cache is keyed by URL
        kw = dict(endpoints=net.endpoints(), options={"github_org": "plantedcorp"}, now=w.now)
        engine.investigate(D, "the first run fills the cache", store, cached, **kw)
        first_count = len(net.requests)
        engine.investigate(D, "the second run reads it", store, cached, **kw)
        second = net.requests[first_count:]
    routes = [q["route"] for q in second]
    assert 0 < len(second) < first_count and routes.count("crtsh") == 0 and routes.count("doh") == 0 and routes.count("cdx") == 0
    assert "rdap-org" in routes and "github" in routes                           # responses that may carry personal data are never cached
    dump = store.dump_text()
    assert all(secret not in dump for secret in fakeworld.PERSONAL_STRINGS)
    a, b = snapshot_of(store, 1), snapshot_of(store, 2)
    assert set(a.names) == set(b.names) and a.registration == b.registration and a.apex == b.apex


def test_collector_exceptions_become_statuses():
    from osint_platformu.model import SourceResult

    def boom(ctx):
        raise RuntimeError("parser exploded")
    result = engine._guarded("ct", boom, None)
    assert isinstance(result, SourceResult) and result.status.state == "error" and "parser exploded" in result.status.detail
