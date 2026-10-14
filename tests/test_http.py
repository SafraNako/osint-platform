import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from osint_platformu.http import HttpClient, HttpError
from osint_platformu.store import Store


class Server:
    """A scripted local server: ``script[path]`` is a list of (status, body, headers) answered in order; the last entry repeats."""

    def __init__(self, script):
        self.script, self.requests = {k: list(v) for k, v in script.items()}, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": dict(self.headers)})
                path = self.path.split("?")[0]
                queue = outer.script.get(path, [(404, b"", {})])
                status, body, headers = queue.pop(0) if len(queue) > 1 else queue[0]
                if status == "slow":
                    time.sleep(1.0)
                    status, body, headers = 200, b"late", {}
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    servers = []

    def make(script):
        s = Server(script)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


def test_user_agent_and_accept_headers_are_sent(serve):
    s = serve({"/x": [(200, b"ok", {})]})
    HttpClient().get(s.base + "/x", headers={"Accept": "application/dns-json"})
    h = s.requests[0]["headers"]
    assert h["User-Agent"].startswith("osint-platform/") and h["Accept"] == "application/dns-json"


def test_transient_errors_are_retried_with_exponential_backoff_then_succeed(serve):
    s = serve({"/x": [(502, b"", {}), (503, b"", {}), (200, b"fine", {})]})
    sleeps = []
    r = HttpClient(retries=2, backoff=1.0, sleep=sleeps.append).get(s.base + "/x")
    assert r.status == 200 and r.text() == "fine" and r.attempts == 3 and len(s.requests) == 3
    assert sleeps == [1.0, 2.0]


def test_retry_after_is_honoured_up_to_a_cap(serve):
    s = serve({"/x": [(429, b"", {"Retry-After": "3"}), (429, b"", {"Retry-After": "999"}), (200, b"ok", {})]})
    sleeps = []
    HttpClient(retries=2, backoff=1.0, sleep=sleeps.append).get(s.base + "/x")
    assert sleeps == [3.0, 10.0]


def test_client_errors_are_returned_not_retried(serve):
    s = serve({"/x": [(404, b"nope", {})]})
    r = HttpClient(retries=3).get(s.base + "/x")
    assert r.status == 404 and len(s.requests) == 1


def test_persistent_server_errors_return_the_last_response(serve):
    s = serve({"/x": [(500, b"", {})]})
    r = HttpClient(retries=2, sleep=lambda x: None).get(s.base + "/x")
    assert r.status == 500 and len(s.requests) == 3


def test_timeouts_raise_after_the_retries(serve):
    s = serve({"/x": [("slow", b"", {})]})
    with pytest.raises(HttpError) as e:
        HttpClient(timeout=0.2, retries=1, sleep=lambda x: None).get(s.base + "/x")
    assert "timed out" in str(e.value).lower() or "timeout" in str(e.value).lower()
    assert len(s.requests) == 2


def test_connection_refused_raises_http_error():
    with pytest.raises(HttpError):
        HttpClient(retries=0).get("http://127.0.0.1:1/x")


def test_response_size_is_capped(serve):
    s = serve({"/big": [(200, b"x" * 5000, {})]})
    with pytest.raises(HttpError) as e:
        HttpClient(max_bytes=1000).get(s.base + "/big")
    assert "larger" in str(e.value)


def test_hosts_outside_the_allow_list_are_refused_before_any_request(serve):
    s = serve({"/x": [(200, b"ok", {})]})
    with pytest.raises(HttpError):
        HttpClient(allow_hosts={"example.org"}).get(s.base + "/x")
    assert s.requests == []
    assert HttpClient(allow_hosts={"127.0.0.1"}).get(s.base + "/x").status == 200


def test_per_host_minimum_interval_is_enforced(serve):
    s = serve({"/x": [(200, b"ok", {})]})
    now = [100.0]
    sleeps = []
    client = HttpClient(min_interval=2.0, sleep=lambda d: (sleeps.append(d), now.__setitem__(0, now[0] + d)), clock=lambda: now[0])
    client.get(s.base + "/x")
    client.get(s.base + "/x")
    assert sleeps == [2.0]                                  # the second request waited out the interval; the first did not wait


def test_cache_serves_repeats_without_a_request_and_expires(serve):
    s = serve({"/x": [(200, b"first", {}), (200, b"second", {})]})
    store = Store()
    t = [1000.0]
    client = HttpClient(cache=store, cache_ttl=60, clock=lambda: t[0])
    assert client.get(s.base + "/x").text() == "first"
    again = client.get(s.base + "/x")
    assert again.text() == "first" and again.from_cache and len(s.requests) == 1
    assert client.get(s.base + "/x", use_cache=False).text() == "second"
    assert len(s.requests) == 2
    assert client.get(s.base + "/x", params={"q": "other"}).status == 200 and len(s.requests) == 3        # another URL is another entry


def test_transform_runs_before_caching_so_the_cache_holds_only_the_transformed_body(serve):
    s = serve({"/x": [(200, b"mail jane.doe@example.org here", {})]})
    store = Store()
    client = HttpClient(cache=store)
    r = client.get(s.base + "/x")
    assert r.text() == "mail <mailbox at example.org> here"
    assert "jane.doe" not in store.dump_text() and r.sha256 == store.put_raw(r.body)
    assert client.get(s.base + "/x").text() == "mail <mailbox at example.org> here"
    assert client.get(s.base + "/x", transform=None, use_cache=False).text() == "mail jane.doe@example.org here"        # the transform is the caller's choice


def test_query_parameters_are_encoded(serve):
    s = serve({"/x": [(200, b"ok", {})]})
    HttpClient().get(s.base + "/x", params={"q": "%.example.org", "output": "json"})
    assert s.requests[0]["path"] == "/x?q=%25.example.org&output=json"
