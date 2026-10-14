"""A picture of the infrastructure: target, hosts, the services their aliases point at, and the networks they sit in (matplotlib is imported lazily)."""
from __future__ import annotations

import ipaddress

from . import fingerprints as fp


def _provider(snap, name):
    """The service an alias chain ends at: a recognised provider, or the registrable-looking tail of the last external name."""
    for hop in snap.chain(name)[1:]:
        label = fp.match(hop, fp.CNAME_PROVIDERS)
        if label:
            return label
    hops = snap.chain(name)
    if len(hops) > 1 and not (hops[-1] == snap.target or hops[-1].endswith("." + snap.target)):
        return ".".join(hops[-1].split(".")[-2:])
    return None


def plot_graph(snap, path, max_hosts=40):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    hosts = [n for n, e in sorted(snap.names.items()) if n != snap.target and (e["a"] or e["aaaa"] or e["nxdomain"] or e["cname"] is not None or snap.chain(n)[1:])][:max_hosts]
    providers = sorted({_provider(snap, n) for n in hosts} - {None})
    asns = sorted({a for n in hosts for ip in snap.names[n]["a"] + snap.names[n]["aaaa"] for a in snap.ips.get(ip, {}).get("asns", [])})
    columns = {"target": [snap.target], "hosts": hosts, "providers": providers, "asns": [f"AS{a}" for a in asns]}
    xs = {"target": 0.0, "hosts": 1.0, "providers": 2.0, "asns": 3.0}
    pos = {}
    for key, items in columns.items():
        n = len(items)
        for i, item in enumerate(items):
            pos[(key, item)] = (xs[key], 1.0 - (i + 0.5) / max(n, 1))
    fig, ax = plt.subplots(figsize=(13, max(5.0, 0.28 * max(len(hosts), len(providers), len(asns), 6))))
    for h in hosts:
        e = snap.names[h]
        ax.plot(*zip(pos[("target", snap.target)], pos[("hosts", h)]), color="0.8", lw=0.8, zorder=1)
        prov = _provider(snap, h)
        if prov:
            ax.plot(*zip(pos[("hosts", h)], pos[("providers", prov)]), color="C4", lw=0.9, alpha=0.7, zorder=1)
        for a in sorted({a for ip in e["a"] + e["aaaa"] for a in snap.ips.get(ip, {}).get("asns", [])}):
            ax.plot(*zip(pos[("hosts", h)], pos[("asns", f"AS{a}")]), color="C2", lw=0.9, alpha=0.7, zorder=1)

    def colour(name):
        e = snap.names[name]
        if e["nxdomain"] and e["nxdomain"].get("cname_target"):
            return "C3"
        if e["nxdomain"]:
            return "0.6"
        if any(not ipaddress.ip_address(ip).is_global for ip in e["a"] + e["aaaa"]):
            return "C1"
        return "C0"
    for (key, item), (x, y) in pos.items():
        c = {"target": "k", "providers": "C4", "asns": "C2"}.get(key) or colour(item)
        ax.scatter([x], [y], s=60, color=c, zorder=3)
        ha, dx = ("right", -0.03) if key in ("target",) else ("left", 0.03)
        ax.text(x + dx, y, item if key != "asns" else f"{item} {snap.asns.get(int(item[2:]), {}).get('name', '')}"[:44], ha=ha, va="center", fontsize=8, zorder=4,
                bbox=dict(facecolor="white", edgecolor="none", pad=0.6, alpha=0.85))
    ax.set_xlim(-0.9, 3.9)
    ax.set_ylim(0, 1)
    ax.axis("off")
    for x, label in ((0.0, "target"), (1.0, "hosts"), (2.0, "services behind aliases"), (3.0, "networks")):
        ax.text(x, 1.03, label, ha="center", fontsize=10, weight="bold")
    ax.text(0.0, -0.02, "host colours: blue resolves, grey does not exist, red dangling alias, orange non-public address", fontsize=8, color="0.3")
    ax.set_title(f"Infrastructure of {snap.target} (run {snap.run_id}, public records only)", pad=22)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
