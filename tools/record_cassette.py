"""Record a live investigation as a cassette for the real-data tests:  python tools/record_cassette.py iana.org iana-org src/osint_platformu/data/iana.org.cassette.json.gz

Uses the network (about 100 requests, under a minute). The result is public infrastructure data of the target; e-mail addresses are scrubbed."""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osint_platformu import cassette, engine  # noqa: E402
from osint_platformu.context import Context  # noqa: E402
from osint_platformu.model import iso  # noqa: E402
from osint_platformu.sources import ct  # noqa: E402
from osint_platformu.store import Store  # noqa: E402


def main(target, github_org, out):
    client = cassette.RecordingClient(cache=None)
    now = datetime.now(timezone.utc)
    run_id, statuses = engine.investigate(target, "recording a cassette for the real-data tests", Store(":memory:"), client,
                                          options={"github_org": github_org}, now=now, progress=print)
    ct._certspotter(Context(target=target, http=client, store=Store(":memory:")), 20000)      # also record the second certificate source, for the cross-check test
    cassette.save(out, client.tape, {"target": target, "github_org": github_org, "recorded_at": iso(now), "requests": len(client.tape)})
    print(f"{len(client.tape)} responses recorded to {out}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
