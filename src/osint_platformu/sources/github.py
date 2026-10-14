"""Public GitHub organisation metadata: how many public repositories, in which languages, how recently active. It needs an explicit organisation
name (guessing it from the domain would attribute someone else's organisation to the target), and records whether the organisation's own
profile links back to the domain. No contributors, no commit authors, no e-mail addresses are read: only the organisation and its repositories."""
from __future__ import annotations

from urllib.parse import urlparse

from ..guard import in_scope
from ..http import HttpError
from ..redact import redact_github
from ..model import SourceResult, SourceStatus

NAME = "github"


def collect(ctx):
    org = ctx.options.get("github_org")
    if not org:
        return SourceResult([], SourceStatus(NAME, "skipped", "no organisation given (--github-org); it is never guessed from the domain"))
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if ctx.options.get("github_token"):
        headers["Authorization"] = "Bearer " + ctx.options["github_token"]
    base = ctx.endpoints.github.rstrip("/")
    try:
        response, sha = ctx.fetch(f"{base}/orgs/{org}", headers=headers, use_cache=False, transform=redact_github)
        if response.status == 404:
            return SourceResult([], SourceStatus(NAME, "ok", f"no public organisation named {org}", 0))
        if response.status in (403, 429):
            return SourceResult([], SourceStatus(NAME, "unavailable", f"rate limited (HTTP {response.status}); set GITHUB_TOKEN for a higher limit"))
        if response.status != 200:
            return SourceResult([], SourceStatus(NAME, "error", f"HTTP {response.status}"))
        info = response.json()
        out, subject = [], "org:github:" + org
        blog = info.get("blog") or ""
        host = (urlparse(blog if "://" in blog else "//" + blog).hostname or "").lower()
        out.append(ctx.obs("github:api", subject, "gh_org", {
            "login": info.get("login"), "name": info.get("name"), "description": info.get("description"), "blog": blog or None, "location": info.get("location"),
            "created_at": info.get("created_at"), "public_repos": info.get("public_repos"), "followers": info.get("followers"), "verified": info.get("is_verified"),
            "type": info.get("type"), "linked_to_target": bool(host) and in_scope(host, ctx.target)}, response.url, sha))
        repos, page = [], 1
        while page <= 5:
            r, rsha = ctx.fetch(f"{base}/orgs/{org}/repos", params={"type": "public", "per_page": "100", "page": str(page), "sort": "pushed"}, headers=headers,
                                use_cache=False, transform=redact_github)
            if r.status != 200:
                break
            batch = r.json()
            for repo in batch:
                out.append(ctx.obs("github:api", subject, "gh_repo", {
                    "name": repo.get("name"), "language": repo.get("language"), "pushed_at": repo.get("pushed_at"), "created_at": repo.get("created_at"),
                    "archived": bool(repo.get("archived")), "fork": bool(repo.get("fork")), "stars": repo.get("stargazers_count"),
                    "description": repo.get("description")}, r.url, rsha))
            repos.extend(batch)
            if len(batch) < 100:
                break
            page += 1
    except (HttpError, ValueError) as exc:
        return SourceResult([], SourceStatus(NAME, "error", str(exc)))
    state = "ok" if len(repos) >= (info.get("public_repos") or 0) else "partial"
    return SourceResult(out, SourceStatus(NAME, state, f"{org}: {len(repos)} of {info.get('public_repos')} public repositories", len(repos)))
