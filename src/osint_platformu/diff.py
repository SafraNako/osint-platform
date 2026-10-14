"""What changed between two runs of the same target: hosts that appeared or went away, records that moved, registration changes, new archived paths,
new repositories, and findings that arrived or were resolved."""
from __future__ import annotations


def _set_diff(old, new):
    return {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new))}


def _existing(snap):
    """Names the run saw evidence of (a certificate, an address, a record or an archive entry), not names that merely appear as alias owners."""
    return {n for n, e in snap.names.items() if e["sources"]}


def diff_snapshots(old, new, old_findings, new_findings):
    d = {"target": new.target, "old_run": old.run_id, "new_run": new.run_id, "old_time": old.taken_at, "new_time": new.taken_at}
    d["names"] = _set_diff(_existing(old), _existing(new))
    moved = {}
    for name in sorted(_existing(old) & _existing(new)):
        a, b = old.names[name], new.names[name]
        before = {"a": a["a"], "aaaa": a["aaaa"], "cname": old.chain(name)[1:]}
        after = {"a": b["a"], "aaaa": b["aaaa"], "cname": new.chain(name)[1:]}
        if before != after:
            moved[name] = {"before": before, "after": after}
    d["records_changed"] = moved
    d["asns"] = _set_diff({a for i in old.ips.values() for a in i["asns"]}, {a for i in new.ips.values() for a in i["asns"]})
    d["mx"] = _set_diff([f"{p} {h}" for p, h in old.apex["mx"]], [f"{p} {h}" for p, h in new.apex["mx"]])
    d["ns"] = _set_diff(old.apex["ns"], new.apex["ns"])
    d["txt"] = _set_diff(old.apex["txt"], new.apex["txt"])
    d["caa"] = _set_diff([" ".join(c) for c in old.apex["caa"]], [" ".join(c) for c in new.apex["caa"]])
    reg = {}
    for key in sorted(set(old.registration) | set(new.registration)):
        if old.registration.get(key) != new.registration.get(key):
            reg[key] = {"before": old.registration.get(key), "after": new.registration.get(key)}
    d["registration"] = reg
    d["archive_candidates"] = _set_diff(old.archive.get("candidates", {}), new.archive.get("candidates", {}))
    old_repos = [r["name"] for r in (old.github or {"repos": []})["repos"]]
    new_repos = [r["name"] for r in (new.github or {"repos": []})["repos"]]
    d["github_repos"] = _set_diff(old_repos, new_repos)
    of, nf = {f.id: f for f in old_findings}, {f.id: f for f in new_findings}
    d["findings"] = {"new": sorted(set(nf) - set(of)), "resolved": sorted(set(of) - set(nf)),
                     "severity_changed": sorted(i for i in set(of) & set(nf) if of[i].severity != nf[i].severity)}
    d["changed"] = any([d["names"]["added"], d["names"]["removed"], moved, d["asns"]["added"], d["asns"]["removed"], d["mx"]["added"], d["mx"]["removed"], d["ns"]["added"], d["ns"]["removed"],
                        d["txt"]["added"], d["txt"]["removed"], d["caa"]["added"], d["caa"]["removed"], reg, d["archive_candidates"]["added"], d["archive_candidates"]["removed"],
                        d["github_repos"]["added"], d["github_repos"]["removed"], d["findings"]["new"], d["findings"]["resolved"]])
    return d


def render_diff(d):
    lines = [f"# Changes for {d['target']}: run {d['old_run']} ({d['old_time']}) to run {d['new_run']} ({d['new_time']})", ""]
    if not d["changed"]:
        return "\n".join(lines + ["No changes between the two runs."])

    def block(title, items, prefix="+"):
        if items:
            lines.append(f"## {title}")
            lines.extend(f"- {prefix} {i}" for i in items)
            lines.append("")
    block("New hosts", d["names"]["added"])
    block("Hosts no longer seen", d["names"]["removed"], "-")
    if d["records_changed"]:
        lines.append("## Records that moved")
        for n, c in d["records_changed"].items():
            lines.append(f"- {n}: {c['before']} -> {c['after']}")
        lines.append("")
    for key, title in (("asns", "Networks (ASN)"), ("mx", "Mail exchangers"), ("ns", "Name servers"), ("txt", "TXT records"), ("caa", "CAA records"),
                       ("archive_candidates", "Archived URLs of interest"), ("github_repos", "GitHub repositories")):
        block(title + " added", d[key]["added"])
        block(title + " removed", d[key]["removed"], "-")
    if d["registration"]:
        lines.append("## Registration")
        lines += [f"- {k}: {c['before']} -> {c['after']}" for k, c in d["registration"].items()]
        lines.append("")
    block("New findings", d["findings"]["new"])
    block("Resolved findings", d["findings"]["resolved"], "-")
    block("Findings whose severity changed", d["findings"]["severity_changed"], "~")
    return "\n".join(lines).rstrip() + "\n"
