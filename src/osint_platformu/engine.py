"""Run an investigation: validate the scope, run the independent collectors side by side, resolve every name they found, and store everything."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .context import Context, Endpoints
from .guard import ScopeError, normalize_domain
from .model import SourceResult, SourceStatus, iso
from .sources import ct, dns, github, rdap, wayback, wellknown

STAGE_ONE = {"ct": ct.collect, "rdap": rdap.collect, "wayback": wayback.collect, "web": wellknown.collect, "github": github.collect}
ALL_SOURCES = ["ct", "rdap", "wayback", "web", "github", "dns"]
MIN_PURPOSE = 8


def _guarded(name, function, *args):
    try:
        return function(*args)
    except Exception as exc:          # a collector must never take the investigation down; its failure is a status, not a crash
        return SourceResult([], SourceStatus(name, "error", f"{type(exc).__name__}: {exc}"))


def discovered_names(observations, target):
    """The hosts the first-stage sources revealed: certificate names, archived hosts and sitemap hosts (all inside the target's scope)."""
    names = {target}
    for o in observations:
        if o.predicate in ("cert_name", "archive_host") and o.subject.startswith("domain:"):
            names.add(o.subject[len("domain:"):])
        elif o.predicate == "sitemap":
            names.update(o.object.get("hosts", []))
        elif o.predicate == "robots" and o.subject.startswith("domain:"):
            names.add(o.subject[len("domain:"):])
    return sorted(names)


def unique(observations):
    """Drop repeated claims (the A and the AAAA answer for a name both carry its CNAME chain): the first evidence for each claim is kept."""
    seen, out = set(), []
    for o in observations:
        key = (o.subject, o.predicate, json.dumps(o.object, sort_keys=True))
        if key not in seen:
            seen.add(key)
            out.append(o)
    return out


def investigate(target, purpose, store, http, endpoints=None, sources=None, options=None, now=None, allow_special_use=False, progress=None):
    """Collect everything the chosen sources know about ``target`` and store it as a new run. Returns ``(run_id, statuses)``."""
    target = normalize_domain(target, allow_special_use=allow_special_use)
    purpose = (purpose or "").strip()
    if len(purpose) < MIN_PURPOSE:
        raise ScopeError("state the purpose of the investigation (at least a short sentence): it is recorded with every run")
    sources = list(sources or ALL_SOURCES)
    unknown = sorted(set(sources) - set(ALL_SOURCES))
    if unknown:
        raise ScopeError(f"unknown sources: {', '.join(unknown)} (choose from {', '.join(ALL_SOURCES)})")
    now = now or datetime.now(timezone.utc)
    emit = progress or (lambda message: None)
    ctx = Context(target=target, http=http, store=store, endpoints=endpoints or Endpoints(), now=now, options=dict(options or {}))
    ctx.workers = int(ctx.options.get("workers", 6))
    investigation = store.investigation(target, purpose, iso(now))
    run_id = store.start_run(investigation, sources, purpose, iso(now))
    results = {}
    first = [s for s in sources if s in STAGE_ONE]
    with ThreadPoolExecutor(max_workers=max(1, len(first))) as pool:
        futures = {name: pool.submit(_guarded, name, STAGE_ONE[name], ctx) for name in first}
        for name, future in futures.items():
            results[name] = future.result()
            emit(f"{name}: {results[name].status.state} - {results[name].status.detail}")
    if "dns" in sources:
        names = discovered_names([o for r in results.values() for o in r.observations], target)
        emit(f"dns: resolving {len(names)} names")
        results["dns"] = _guarded("dns", dns.collect, ctx, names)
        emit(f"dns: {results['dns'].status.state} - {results['dns'].status.detail}")
    statuses = []
    for name in sources:
        result = results[name]
        result.observations = unique(result.observations)
        store.add_observations(run_id, result.observations)
        store.add_status(run_id, result.status)
        statuses.append(result.status)
    store.finish_run(run_id, iso(datetime.now(timezone.utc) if now is None else now))
    return run_id, statuses
