"""Regenerate the example report, JSON and graph from the recorded real investigation of iana.org (no network):  python tools/make_examples.py"""
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from osint_platformu import cassette, engine, insights, plots, report  # noqa: E402
from osint_platformu import snapshot as snapmod  # noqa: E402
from osint_platformu.model import parse_iso  # noqa: E402
from osint_platformu.store import Store  # noqa: E402

meta, tape = cassette.load(root / "src" / "osint_platformu" / "data" / "iana.org.cassette.json.gz")
store = Store()
now = parse_iso(meta["recorded_at"])
run_id, _ = engine.investigate(meta["target"], "example report from a recorded investigation of a public non-profit's domain", store, cassette.ReplayClient(tape, retries=0),
                               options={"github_org": meta["github_org"]}, now=now)
snap = snapmod.build_snapshot(store, run_id, meta["target"], meta["recorded_at"], "example report from a recorded investigation of a public non-profit's domain")
found = insights.findings(snap, now)
out = root / "examples"
(out / "report-iana.org.md").write_text(report.render_markdown(snap, found), encoding="utf-8")
(out / "report-iana.org.json").write_text(report.to_json(snap, found), encoding="utf-8")
plots.plot_graph(snap, out / "graph-iana.org.png")
print("written:", ", ".join(p.name for p in sorted(out.iterdir())))
