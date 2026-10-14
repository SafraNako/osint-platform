"""A small, polite HTTP client: identifying User-Agent, timeouts, bounded retries with back-off, a per-host minimum interval, a response size cap
and an optional on-disk cache. TLS verification is always on."""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .guard import scrub_bytes

USER_AGENT = "osint-platform/0.1 (passive public-record research; https://github.com/SafraNako/osint-platform)"
RETRY_STATUSES = {429, 500, 502, 503, 504}


class HttpError(Exception):
    """A request that could not be completed at all (no response): DNS failure, refused, timed out, too large, host not allowed."""

    def __init__(self, url, reason):
        super().__init__(f"{url}: {reason}")
        self.url, self.reason = url, reason


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes
    from_cache: bool = False
    attempts: int = 1
    sha256: str = field(init=False)

    def __post_init__(self):
        self.sha256 = hashlib.sha256(self.body).hexdigest()

    def text(self):
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class HttpClient:
    def __init__(self, user_agent=USER_AGENT, timeout=25.0, retries=2, backoff=1.0, min_interval=0.0, max_bytes=30_000_000,
                 allow_hosts=None, cache=None, cache_ttl=6 * 3600, sleep=time.sleep, clock=time.time):
        self.user_agent, self.timeout, self.retries, self.backoff = user_agent, timeout, retries, backoff
        self.min_interval, self.max_bytes, self.allow_hosts = min_interval, max_bytes, allow_hosts
        self.cache, self.cache_ttl, self._sleep, self._clock = cache, cache_ttl, sleep, clock
        self._last = {}
        self._lock = threading.Lock()
        self.requests_made = 0

    def _wait_turn(self, host):
        if self.min_interval <= 0:
            return
        with self._lock:
            due = self._last.get(host, 0.0) + self.min_interval
            now = self._clock()
            delay = max(0.0, due - now)
            self._last[host] = now + delay
        if delay:
            self._sleep(delay)

    @staticmethod
    def build_url(url, params):
        return url if not params else url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

    def get(self, url, params=None, headers=None, use_cache=True, transform=scrub_bytes):
        """GET ``url``. Returns a ``Response`` for any HTTP status (after retrying the transient ones); raises ``HttpError`` when there is none.

        ``transform`` is applied to the body once, on arrival, before anything is cached, hashed, stored or parsed (default: e-mail addresses are
        scrubbed), so that no later stage can see what it removed; ``Response.sha256`` is the hash of the transformed body, the bytes that are stored."""
        full = self.build_url(url, params)
        host = urllib.parse.urlparse(full).hostname or ""
        if self.allow_hosts is not None and host not in self.allow_hosts:
            raise HttpError(full, f"host {host!r} is not allowed in this client")
        key = hashlib.sha256((full + json.dumps(headers or {}, sort_keys=True)).encode()).hexdigest()
        if use_cache and self.cache is not None:
            hit = self.cache.cache_get(key, self.cache_ttl, self._clock())
            if hit:
                return Response(full, hit[0], {}, hit[1], from_cache=True)
        request_headers = {"User-Agent": self.user_agent, "Accept": "*/*", "Accept-Encoding": "identity"}
        request_headers.update(headers or {})
        last_error, response = None, None
        for attempt in range(1, self.retries + 2):
            self._wait_turn(host)
            self.requests_made += 1
            try:
                response = self._once(full, request_headers, attempt)
                last_error = None
            except HttpError as exc:
                last_error, response = exc, None
            if response is not None and response.status not in RETRY_STATUSES:
                break
            if attempt <= self.retries:
                delay = self.backoff * (2 ** (attempt - 1))
                if response is not None and "retry-after" in response.headers:
                    try:
                        delay = min(float(response.headers["retry-after"]), 10.0)
                    except ValueError:
                        pass
                self._sleep(delay)
        if response is None:
            raise last_error
        if transform is not None and response.body:
            response = Response(response.url, response.status, response.headers, transform(response.body), attempts=response.attempts)
        if response.status == 200 and use_cache and self.cache is not None:
            self.cache.cache_put(key, response.status, response.body, self._clock())
        return response

    def _once(self, url, headers, attempt):
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(self.max_bytes + 1)
                status, hdrs = r.status, {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            body = e.read(self.max_bytes + 1) if e.fp else b""
            status, hdrs = e.code, {k.lower(): v for k, v in (e.headers or {}).items()}
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
            raise HttpError(url, f"{type(e).__name__}: {getattr(e, 'reason', e)}")
        if len(body) > self.max_bytes:
            raise HttpError(url, f"response larger than {self.max_bytes} bytes")
        return Response(url, status, hdrs, body, attempts=attempt)
