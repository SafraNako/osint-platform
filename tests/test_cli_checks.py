import json

import pytest

from conftest import TARGET
from osint_platformu import checks, cli, fakeworld
from osint_platformu import http as httpmod

D = TARGET


def test_every_validation_check_passes():
    results = checks.run_all()
    assert len(results) == len(checks.ALL) == 13
    failed = [(c.name, c.detail) for c in results if not c.passed]
    assert not failed, failed


@pytest.fixture
def env(tmp_path):
    """The CLI pointed at a planted world on loopback: the endpoints are injected and the client can only reach loopback."""
    net = fakeworld.FakeInternet(fakeworld.PlantedWorld())
    net.__enter__()
    yield str(tmp_path / "o.db"), net
    net.__exit__(None, None, None)


def run_cli(db, *args, net=None):
    return cli.main(["--db", db, *args], endpoints=net.endpoints() if net else None,
                    client=httpmod.HttpClient(allow_hosts={"127.0.0.1"}, sleep=lambda s: None, retries=1, cache=None))


def test_scan_report_evidence_list_and_graph_end_to_end(env, tmp_path, capsys):
    db, net = env
    assert run_cli(db, "tara", D, "--amac", "validating the command line against a planted organisation", "--github-org", "plantedcorp", net=net) == 0
    out = capsys.readouterr().out
    assert "Calisma 1 tamamlandi" in out and "14 ad" in out and "2 orta" in out and f"osint rapor --hedef {D}" in out
    assert run_cli(db, "rapor", "--hedef", D) == 0
    md = capsys.readouterr().out
    assert md.startswith(f"# OSINT report: {D}") and "dangling" in md.lower() and "Planted Registrar LLC" in md
    path = tmp_path / "r.json"
    assert run_cli(db, "rapor", "--hedef", D, "--bicim", "json", "--cikti", str(path)) == 0
    data = json.loads(path.read_text())
    assert set(data["names"]) >= {f"old-blog.{D}", f"docs.{D}"} and any(f["id"].startswith("dangling-cname") for f in data["findings"])
    assert run_cli(db, "kanit", "--hedef", D, "--varlik", "gone-blog.github.io") == 0
    ev = capsys.readouterr().out
    assert "kanit URL:" in ev and "saklanan yanit SHA-256:" in ev and "old-blog" in ev
    assert run_cli(db, "liste") == 0
    assert f"{D}  (1 calisma" in capsys.readouterr().out
    pytest.importorskip("matplotlib")
    assert run_cli(db, "graf", "--hedef", D, "--png", str(tmp_path / "g.png")) == 0
    png = (tmp_path / "g.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and len(png) > 10000


def test_the_second_scan_can_be_compared_with_the_first(env, capsys):
    db, net = env
    for _ in range(2):
        assert run_cli(db, "tara", D, "--amac", "two identical runs of the planted organisation", net=net) == 0
    capsys.readouterr()
    assert run_cli(db, "fark", "--hedef", D) == 0
    assert "No changes between the two runs." in capsys.readouterr().out
    assert run_cli(db, "fark", "--hedef", D, "--bicim", "json") == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False


def test_a_purpose_is_mandatory_and_out_of_scope_targets_are_refused(env, capsys):
    db, net = env
    with pytest.raises(SystemExit) as e:
        run_cli(db, "tara", D, net=net)                                                   # --amac is required by the parser
    assert e.value.code == 2
    for bad in ("jane.doe@example.org", "192.0.2.1", "Jane Doe"):
        assert run_cli(db, "tara", bad, "--amac", "this must be refused before anything is contacted", net=net) == 2
        assert "Kapsam disi" in capsys.readouterr().err
    assert run_cli(db, "tara", D, "--amac", "short", net=net) == 2
    assert net.requests == []


def test_reading_commands_explain_what_is_missing(env, capsys):
    db, net = env
    assert run_cli(db, "rapor", "--hedef", D) == 2 and "once 'osint tara" in capsys.readouterr().err
    assert run_cli(db, "liste") == 0 and "Kayitli arastirma yok" in capsys.readouterr().out
    assert run_cli(db, "tara", D, "--amac", "one run so that the numbered lookups can fail", "--kaynak", "web", net=net) == 0
    capsys.readouterr()
    assert run_cli(db, "rapor", "--hedef", D, "--calisma", "9") == 2 and "9 numarali calisma yok" in capsys.readouterr().err
    assert run_cli(db, "fark", "--hedef", D) == 2 and "en az iki calisma" in capsys.readouterr().err
    assert run_cli(db, "kanit", "--hedef", D, "--varlik", "no-such-thing-anywhere") == 1


def test_sources_command_lists_every_source_and_its_limits(capsys):
    assert cli.main(["kaynaklar"]) == 0
    out = capsys.readouterr().out
    for name in ("ct", "rdap", "dns", "wayback", "web", "github"):
        assert f"  {name}" in out
    assert "ASLA okunmaz" in out and "e-posta" in out and "belirtilmeden baslamaz" in out


def test_validation_command_reports_all_passed(capsys):
    assert cli.main(["dogrulama"]) == 0
    assert "13/13 dogrulama gecti" in capsys.readouterr().out


def test_argument_errors_and_version(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
    with pytest.raises(SystemExit):
        cli.main(["tara"])
    with pytest.raises(SystemExit) as e:
        cli.main(["--surum"])
    assert e.value.code == 0 and capsys.readouterr().out.startswith("osint 0.")


def test_source_choice_is_validated(env, capsys):
    db, net = env
    assert run_cli(db, "tara", D, "--amac", "a run with a source that does not exist", "--kaynak", "ct,shodan", net=net) == 2
    assert "shodan" in capsys.readouterr().err and net.requests == []
