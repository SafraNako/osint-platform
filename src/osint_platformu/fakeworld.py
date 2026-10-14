"""A planted-truth synthetic internet for tests and validation: a real local HTTP server that speaks each source's response format (crt.sh, Cert Spotter,
DNS-over-HTTPS JSON with Cloudflare and Google conventions, RDAP, the Wayback CDX index, the GitHub API and the target's own web server) and serves a made-up
organisation whose whole structure is known, so that whatever the platform reports can be compared with the truth.

The organisation, ``planted-corp.org``, is built with the traps the real data contains: certificates that list names outside the domain and an e-mail address,
a lookalike domain that merely ends with the same letters, a CNAME to a released GitHub Pages name, internal addresses in public DNS, wildcard certificates,
hosts that are visible only in the web archive or a sitemap, and personal data planted in the RDAP, GitHub and TXT responses that must never be stored.

Nothing here touches the network beyond the loopback interface.
"""
from __future__ import annotations

import ipaddress
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .context import Endpoints

PERSONAL_STRINGS = ["Jane Doe", "jane.doe@planted-corp.org", "+90 555 000 00 00", "Gizli Sokak 12", "John Admin", "john.admin@planted-corp.org", "Tech Person",
                    "tech.person@planted-corp.org", "abuse@planted-registrar.example", "contact@planted-corp.org", "dmarc-reports@dmarc-vendor.example", "Alice Maintainer"]

A, AAAA, CNAME, MX, NS, TXT, CAA = 1, 28, 5, 15, 16, 16, 257
TYPE_CODE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


class PlantedWorld:
    """The ground truth. ``variant="later"`` is the same organisation some time afterwards, with a known set of changes."""

    domain = "planted-corp.org"
    now = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)

    def __init__(self, variant="first"):
        self.variant = variant
        later = variant == "later"
        d = self.domain
        # --- DNS truth: name -> spec ------------------------------------------------------------------------------------------------------
        self.hosts = {
            d: {"a": ["45.60.1.10", "45.60.1.11"], "aaaa": ["2a00:1450:4001:81b::200e"]},
            f"www.{d}": {"cname": d},
            f"api.{d}": {"a": ["45.61.2.21" if later else "45.61.2.20"]},
            f"shop.{d}": {"cname": "planted-shop.myshopify.com"},
            f"mail.{d}": {"a": ["45.60.1.50"]},
            f"dev.{d}": {"a": ["10.0.0.5"]},
            f"staging.{d}": {"a": ["10.0.0.6"]},
            f"old-blog.{d}": {"cname": "gone-blog.github.io"},                       # released GitHub Pages name: a dangling alias on a claimable provider
            f"legacy.{d}": {"cname": "retired.internal-vendor.example.net"},         # dangling, but not on a provider known to be claimable
            f"vpn.{d}": {"nxdomain": True},                                          # certified once, gone from DNS
            f"smime.{d}": {"nxdomain": True},                                        # on the same certificate as an e-mail address
            f"a.b.c.{d}": {"a": ["45.60.1.77"]},
            f"docs.{d}": {"a": ["45.60.1.90"]},                                      # only visible through the sitemap
            f"forum.{d}": {"nxdomain": True},                                        # only visible through the web archive
        }
        if later:
            del self.hosts[f"shop.{d}"]                                              # the shop alias was removed
            self.hosts[f"new-app.{d}"] = {"a": ["45.61.2.99"]}                       # a new host
        self.external = {"planted-shop.myshopify.com": ["45.61.2.30"], "gone-blog.github.io": None, "retired.internal-vendor.example.net": None}
        self.ct_only = {f"vpn.{d}", f"smime.{d}", f"a.b.c.{d}"} | ({f"new-app.{d}"} if later else set())
        self.ct_names = {d, f"www.{d}", f"api.{d}", f"shop.{d}", f"mail.{d}", f"dev.{d}", f"staging.{d}", f"old-blog.{d}", f"legacy.{d}", f"vpn.{d}", f"smime.{d}", f"a.b.c.{d}"}
        if later:
            self.ct_names.add(f"new-app.{d}")
        self.wildcard_zones = {d, f"eu.{d}"}
        self.archive_only_hosts = {f"forum.{d}"}
        self.sitemap_only_hosts = {f"docs.{d}"}
        self.all_names = self.ct_names | self.archive_only_hosts | self.sitemap_only_hosts
        self.asn_of_prefix = {"45.60.": (64496, "45.60.0.0/16", "US", "arin"), "45.61.": (64497, "45.61.0.0/16", "DE", "ripencc"),
                              "2a00:1450:": (64496, "2a00:1450::/32", "US", "arin")}
        self.asn_info = {64496: ("US", "arin", "PLANTED-HOSTING-A - Planted Hosting A, US"), 64497: ("DE", "ripencc", "PLANTED-CDN-B - Planted CDN B, DE")}
        # --- apex records ------------------------------------------------------------------------------------------------------------------
        self.mx = [(10, "aspmx.l.google.com."), (20, "alt1.aspmx.l.google.com.")] + ([(30, "mx.sendgrid.net.")] if later else [])
        self.ns = ["ns-1.awsdns-01.org.", "ns-2.awsdns-02.co.uk."]
        self.txt = ["v=spf1 include:_spf.google.com include:sendgrid.net ~all", "google-site-verification=abc123", "atlassian-domain-verification=xyz789", "MS=ms12345678",
                    "h1-domain-verification=h1h1h1", "contact=jane.doe@planted-corp.org"]
        self.caa = []
        self.dmarc = "v=DMARC1; p=none; rua=mailto:dmarc-reports@dmarc-vendor.example"
        # --- registration --------------------------------------------------------------------------------------------------------------------
        self.expires = "2026-11-03T00:00:00Z"                                          # 20 days after ``now``
        # --- expected truth for the tests ---------------------------------------------------------------------------------------------------
        self.interesting_urls = {
            f"https://www.{d}/admin/login": {"admin-or-login"}, f"https://www.{d}/wp-login.php": {"admin-or-login"}, f"https://www.{d}/.git/config": {"vcs-or-env-file", "config-file"},
            f"https://www.{d}/backup/db_dump.sql": {"backup-or-dump"}, f"https://www.{d}/api/v1/users": {"api-surface"}, f"https://www.{d}/config/settings.yml": {"config-file"},
            f"https://www.{d}/staging/index.html": {"pre-production"}}
        if later:
            self.interesting_urls[f"https://forum.{d}/phpmyadmin/index.php"] = {"admin-or-login"}
        self.repos = [("planted-core", "Python", False, False), ("planted-web", "JavaScript", False, False), ("planted-tools", "Go", False, False),
                      ("planted-legacy", "Python", True, False), ("planted-fork", "Python", False, True)] + ([("planted-new", "Rust", False, False)] if later else [])
        self.dangling_expected = {f"old-blog.{d}"}
        self.broken_expected = {f"legacy.{d}"}
        self.private_expected = {f"dev.{d}", f"staging.{d}"}
        self.security_expired = not later                                              # the later variant renewed security.txt

    # --- response builders -------------------------------------------------------------------------------------------------------------------
    def ct_certs(self):
        d = self.domain
        rows = [
            ("S1", f"{d}\nwww.{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-08-01T00:00:00", "2026-10-30T00:00:00"),
            ("S2", f"api.{d}", 'C=GB, O="Sectigo Limited, Ltd.", CN=Sectigo RSA', "2026-03-01T00:00:00", "2027-03-01T00:00:00"),
            ("S2", f"api.{d}", 'C=GB, O="Sectigo Limited, Ltd.", CN=Sectigo RSA', "2026-03-01T00:00:00", "2027-03-01T00:00:00"),    # the precertificate: same serial
            ("S3", f"shop.{d}\nMAIL.Planted-Corp.org", "C=US, O=DigiCert Inc, CN=DigiCert TLS", "2026-02-01T00:00:00", "2027-02-01T00:00:00"),
            ("S4", f"*.{d}\n{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-07-01T00:00:00", "2026-09-29T00:00:00"),
            ("S5", f"dev.{d}\nstaging.{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-09-01T00:00:00", "2026-11-30T00:00:00"),
            ("S6", f"old-blog.{d}", "C=US, O=Let's Encrypt, CN=R3", "2025-05-01T00:00:00", "2025-07-30T00:00:00"),
            ("S7", f"legacy.{d}", "C=US, O=Let's Encrypt, CN=R3", "2025-06-01T00:00:00", "2025-08-30T00:00:00"),
            ("S8", f"shared-cdn-customer.com\n{d}\nunrelated-example.net\nnot{d}", "C=US, O=Cloudflare Inc, CN=CF CA", "2026-04-01T00:00:00", "2027-04-01T00:00:00"),
            ("S9", f"jane.doe@{d}\nsmime.{d}", "C=US, O=Planted S/MIME CA, CN=S/MIME", "2026-05-01T00:00:00", "2027-05-01T00:00:00"),
            ("S10", f"vpn.{d}", "C=US, O=Let's Encrypt, CN=R3", "2023-01-01T00:00:00", "2024-04-01T00:00:00"),
            ("S11", f"*.eu.{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-06-01T00:00:00", "2026-09-01T00:00:00"),
            ("S12", f"a.b.c.{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-09-10T00:00:00", "2026-12-09T00:00:00"),
        ]
        if self.variant == "later":
            rows.append(("S13", f"new-app.{d}", "C=US, O=Let's Encrypt, CN=R3", "2026-10-01T00:00:00", "2026-12-30T00:00:00"))
        return rows

    def crtsh_json(self):
        out = []
        for i, (serial, names, issuer, nb, na) in enumerate(self.ct_certs()):
            out.append({"issuer_ca_id": 1, "issuer_name": issuer, "common_name": names.split("\n")[0], "name_value": names, "id": 1000 + i, "entry_timestamp": nb,
                        "not_before": nb, "not_after": na, "serial_number": serial, "result_count": len(names.split("\n"))})
        return out

    def certspotter_json(self, after=None):
        rows = [{"id": str(2000 + i), "tbs_sha256": "t", "cert_sha256": "c", "dns_names": names.split("\n"), "pubkey_sha256": "p", "not_before": nb + "Z", "not_after": na + "Z",
                 "revoked": False} for i, (serial, names, issuer, nb, na) in enumerate(self.ct_certs())]
        if after:
            rows = [r for r in rows if int(r["id"]) > int(after)]
        return rows[:100]

    def resolve(self, name, rtype):
        """``(rcode, answers)`` for a DNS question; answers are ``(owner, type_code, data)`` in the order a recursive resolver returns them."""
        name = name.lower().rstrip(".")
        d = self.domain
        if name.endswith(".origin6.asn.cymru.com"):
            nibbles = name[: -len(".origin6.asn.cymru.com")].split(".")
            hexstr = "".join(reversed(nibbles))
            ip = str(ipaddress.ip_address(":".join(hexstr[i:i + 4] for i in range(0, 32, 4))))
            for prefix, (asn, cidr, cc, reg) in self.asn_of_prefix.items():
                if ":" in prefix and ip.startswith(prefix):
                    return 0, [(name, TXT, f'"{asn} | {cidr} | {cc} | {reg} | 2015-01-01"')]
            return 3, []
        if name.endswith(".origin.asn.cymru.com"):
            octets = name[: -len(".origin.asn.cymru.com")].split(".")
            ip = ".".join(reversed(octets))
            for prefix, (asn, cidr, cc, reg) in self.asn_of_prefix.items():
                if ip.startswith(prefix):
                    return 0, [(name, TXT, f'"{asn} | {cidr} | {cc} | {reg} | 2015-01-01"')]
            return 3, []
        if name.startswith("as") and name.endswith(".asn.cymru.com"):
            asn = int(name[2:-len(".asn.cymru.com")])
            if asn in self.asn_info:
                cc, reg, label = self.asn_info[asn]
                return 0, [(name, TXT, f'"{asn} | {cc} | {reg} | 2010-01-01 | {label}"')]
            return 3, []
        if name == d:
            if rtype == "MX":
                return 0, [(name, MX, f"{p} {h}") for p, h in self.mx]
            if rtype == "NS":
                return 0, [(name, 2, h) for h in self.ns]
            if rtype == "TXT":
                return 0, [(name, TXT, '"' + t + '"') for t in self.txt]
            if rtype == "CAA":
                return 0, [(name, CAA, f'0 issue "{c}"') for c in self.caa]
        if name == f"_dmarc.{d}" and rtype == "TXT":
            return 0, [(name, TXT, '"' + self.dmarc + '"')]
        if name == f"_mta-sts.{d}" and rtype == "TXT":
            return 0, []
        if rtype not in ("A", "AAAA"):
            return (0, []) if name in self.hosts or name == d else (3, [])
        spec = self.hosts.get(name)
        if spec is None and name not in self.external:
            return 3, []
        answers, current, seen = [], name, set()
        while current not in seen:
            seen.add(current)
            spec = self.hosts.get(current)
            if spec and spec.get("nxdomain"):
                return 3, answers
            if spec and spec.get("cname"):
                answers.append((current, CNAME, spec["cname"] + "."))
                current = spec["cname"]
                continue
            if current in self.external:
                ips = self.external[current]
                if ips is None:
                    return 3, answers
            else:
                ips = (spec or {}).get("a", [])
            if rtype == "A":
                answers += [(current, A, ip) for ip in ips]
            elif rtype == "AAAA":
                answers += [(current, AAAA, ip) for ip in (spec or {}).get("aaaa", [])]
            return 0, answers
        return 0, answers

    def rdap_bootstrap(self, base):
        return {"description": "planted", "publication": "2026-10-01T00:00:00Z", "version": "1.0", "services": [[["org"], [base + "/rdap-org/"]], [["com"], ["http://127.0.0.1:1/never/"]]]}

    def rdap_domain(self):
        d = self.domain

        def entity(roles, fn, email, tel=None, adr=None, nested=None):
            items = [["version", {}, "text", "4.0"], ["fn", {}, "text", fn], ["email", {}, "text", email]]
            if tel:
                items.append(["tel", {"type": "voice"}, "uri", "tel:" + tel])
            if adr:
                items.append(["adr", {}, "text", ["", "", adr, "Ankara", "", "06000", "TR"]])
            e = {"objectClassName": "entity", "roles": roles, "vcardArray": ["vcard", items]}
            if nested:
                e["entities"] = nested
            return e
        registrar = entity(["registrar"], "Planted Registrar LLC", "support@planted-registrar.example", nested=[entity(["abuse"], "Abuse Desk", "abuse@planted-registrar.example", "+1.5555550100")])
        registrar["publicIds"] = [{"type": "IANA Registrar ID", "identifier": "9999"}]
        if self.variant == "later":
            registrar["vcardArray"][1][1] = ["fn", {}, "text", "Better Registrar Inc"]
        return {"rdapConformance": ["rdap_level_0"], "notices": [{"title": "TOS", "description": ["Contact abuse@planted-registrar.example"]}], "ldhName": d, "objectClassName": "domain",
                "status": ["client transfer prohibited"],
                "events": [{"eventAction": "registration", "eventDate": "2005-03-01T10:00:00Z"}, {"eventAction": "expiration", "eventDate": self.expires},
                           {"eventAction": "last changed", "eventDate": "2026-09-01T10:00:00Z"}, {"eventAction": "last update of RDAP database", "eventDate": "2026-10-14T10:00:00Z"}],
                "nameservers": [{"objectClassName": "nameserver", "ldhName": h.upper().rstrip(".")} for h in self.ns],
                "secureDNS": {"delegationSigned": False},
                "entities": [registrar, entity(["registrant"], "Jane Doe", "jane.doe@planted-corp.org", "+90 555 000 00 00", "Gizli Sokak 12"),
                             entity(["administrative"], "John Admin", "john.admin@planted-corp.org", "+90 555 000 00 01"), entity(["technical"], "Tech Person", "tech.person@planted-corp.org")],
                "links": [{"rel": "self", "href": "https://rdap.example/domain/" + d}]}

    def cdx_rows(self):
        d = self.domain
        rows = [["timestamp", "original", "statuscode", "mimetype"]]
        for i in range(190):
            rows.append([f"2024{(i % 12) + 1:02d}15120000", f"https://www.{d}/blog/post-{i}", "200", "text/html"])
        for url in self.interesting_urls:
            rows.append(["20230101120000", url, "200", "text/html"])
        rows += [["20220101120000", f"https://www.{d}/downloads/tool.tar.gz", "200", "application/gzip"],            # a public archive: not a backup
                 ["20220201120000", f"https://www.{d}/?ref=partner.dev&email=jane.doe@{d}", "200", "text/html"],   # 'dev' in a query string, and an address: neither may count or be stored
                 ["20210101120000", f"https://forum.{d}/", "200", "text/html"], ["20210101120000", f"https://forum.{d}/thread/1", "200", "text/html"],
                 ["20200101120000", f"http://not{d}/admin/login", "200", "text/html"],                                  # a lookalike domain: out of scope
                 ["20200101120000", f"http://{d}.evil.example/admin/login", "200", "text/html"]]                        # a different domain that contains the name
        return rows

    def github_org(self):
        return {"login": "plantedcorp", "name": "Planted Corp", "description": "planted", "email": "contact@planted-corp.org", "twitter_username": "plantedcorp", "blog": f"https://{self.domain}",
                "location": "Ankara", "public_repos": len(self.repos), "followers": 12, "is_verified": True, "type": "Organization", "created_at": "2018-01-01T00:00:00Z"}

    def github_repos(self):
        return [{"name": n, "language": lang, "archived": arch, "fork": fork, "pushed_at": "2026-09-01T00:00:00Z", "created_at": "2019-01-01T00:00:00Z", "stargazers_count": 3 + i,
                 "description": "planted repo", "owner": {"login": "plantedcorp", "email": "alice@planted-corp.org"}, "private_note": "Alice Maintainer"} for i, (n, lang, arch, fork) in enumerate(self.repos)]

    def web_file(self, host, path, base):
        d = self.domain
        if host != d:
            return None
        if path == "/robots.txt":
            return f"User-agent: *\nDisallow: /internal-admin/\nDisallow: /staging/\nDisallow: /search\nSitemap: {base}/web/{d}/sitemap.xml\n# contact: webmaster@{d}\n"
        if path == "/.well-known/security.txt":
            expires = "2026-01-01T00:00:00Z" if self.security_expired else "2027-06-01T00:00:00Z"
            return f"Contact: mailto:security@{d}\nContact: https://{d}/security\nExpires: {expires}\nPolicy: https://{d}/security-policy\nPreferred-Languages: en, tr\n"
        if path == "/sitemap.xml":
            return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    f"<url><loc>https://www.{d}/</loc></url><url><loc>https://docs.{d}/start</loc></url><url><loc>https://docs.{d}/api</loc></url></urlset>")
        return None


class Faults:
    """Scripted failures per route: ``{"crtsh": [502, 502]}`` answers the first two requests with 502, ``{"crtsh": "always:500"}`` always fails,
    ``{"web": "slow"}`` answers after a delay longer than the client's timeout."""

    def __init__(self, spec=None):
        self.spec = {k: (list(v) if isinstance(v, list) else v) for k, v in (spec or {}).items()}
        self._lock = threading.Lock()

    def take(self, route):
        with self._lock:
            s = self.spec.get(route)
            if isinstance(s, list) and s:
                return s.pop(0)
            if isinstance(s, str):
                return s
        return None


class FakeInternet:
    def __init__(self, world=None, faults=None, delay=1.0):
        self.world = world or PlantedWorld()
        self.faults = Faults(faults)
        self.delay = delay
        self.requests = []
        self._lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def endpoints(self):
        return Endpoints(crtsh=self.base + "/crtsh/", certspotter=self.base + "/certspotter/v1/issuances", doh=self.base + "/doh", doh_fallback=self.base + "/doh2",
                         rdap_bootstrap=self.base + "/rdap/dns.json", wayback=self.base + "/cdx", github=self.base + "/github", web=self.base + "/web/{host}")

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body, ctype="application/json"):
                data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                route = url.path.strip("/").split("/")[0]
                with outer._lock:
                    outer.requests.append({"path": url.path, "query": q, "route": route, "ua": self.headers.get("User-Agent", ""), "accept": self.headers.get("Accept", "")})
                fault = outer.faults.take(route)
                if fault == "slow":
                    time.sleep(outer.delay)
                elif isinstance(fault, int):
                    return self._send(fault, {"error": "planted failure"})
                elif isinstance(fault, str) and fault.startswith("always:"):
                    return self._send(int(fault.split(":")[1]), {"error": "planted outage"})
                w = outer.world
                try:
                    return self._route(w, route, url, q)
                except KeyError:
                    return self._send(404, {"error": "not found"})

            def _route(self, w, route, url, q):
                base = outer.base
                if route == "crtsh":
                    if q.get("q") != f"%.{w.domain}":
                        return self._send(200, [])
                    return self._send(200, w.crtsh_json())
                if route == "certspotter":
                    return self._send(200, w.certspotter_json(q.get("after")))
                if route in ("doh", "doh2"):
                    rcode, answers = w.resolve(q["name"], q["type"])
                    google = route == "doh2"
                    fix = (lambda n: n + ".") if google else (lambda n: n)
                    out = {"Status": rcode, "TC": False, "RD": True, "RA": True, "Question": [{"name": fix(q["name"]), "type": TYPE_CODE[q["type"]]}]}
                    if answers:
                        out["Answer"] = [{"name": fix(o), "type": t, "TTL": 300, "data": (data.strip('"') if google and t == TXT else data)} for o, t, data in answers]
                    return self._send(200, out, "application/dns-json")
                if route == "rdap":
                    if url.path.endswith("/dns.json"):
                        return self._send(200, w.rdap_bootstrap(base))
                if route == "rdap-org" and url.path.endswith("/domain/" + w.domain):
                    return self._send(200, w.rdap_domain(), "application/rdap+json")
                if route == "cdx":
                    rows = w.cdx_rows()
                    limit = int(q.get("limit", len(rows)))
                    return self._send(200, [rows[0]] + rows[1:1 + limit])
                if route == "github":
                    parts = url.path.strip("/").split("/")
                    if parts[1:3] == ["orgs", "plantedcorp"] and len(parts) == 3:
                        return self._send(200, w.github_org())
                    if parts[1:3] == ["orgs", "plantedcorp"] and parts[3:] == ["repos"]:
                        return self._send(200, w.github_repos())
                    return self._send(404, {"message": "Not Found"})
                if route == "web":
                    parts = url.path.strip("/").split("/", 2)
                    body = w.web_file(parts[1], "/" + parts[2], base)
                    if body is None:
                        return self._send(404, "not found", "text/plain")
                    return self._send(200, body, "text/plain")
                return self._send(404, {"error": "no such route"})
        return Handler


class PlantedRun:
    """One investigation of the planted organisation: everything a test or a check wants to look at afterwards."""

    def __init__(self, store, run_id, world, snap, findings, statuses, requests):
        self.store, self.run_id, self.world, self.snap, self.findings, self.statuses, self.requests = store, run_id, world, snap, findings, statuses, requests


def run_planted(variant="first", faults=None, sources=None, options=None, store=None, client=None, delay=0.3, purpose="validation against a planted organisation", client_kwargs=None):
    """Investigate the planted organisation through a loopback-only client and return a ``PlantedRun``."""
    from . import engine, insights
    from . import http as httpmod
    from . import snapshot as snapmod
    from . import store as storemod
    world = PlantedWorld(variant)
    with FakeInternet(world, faults=faults, delay=delay) as net:
        store = store or storemod.Store(":memory:")
        kwargs = {"allow_hosts": {"127.0.0.1"}, "sleep": lambda s: None, "retries": 1, "timeout": 5.0}
        kwargs.update(client_kwargs or {})
        opts = {"github_org": "plantedcorp"}
        opts.update(options or {})
        run_id, statuses = engine.investigate(world.domain, purpose, store, client or httpmod.HttpClient(**kwargs), endpoints=net.endpoints(), sources=sources, options=opts, now=world.now)
        meta = next(r for r in store.runs(world.domain) if r["id"] == run_id)
        snap = snapmod.build_snapshot(store, run_id, world.domain, meta["finished_at"] or meta["started_at"], meta["purpose"])
        return PlantedRun(store, run_id, world, snap, insights.findings(snap), statuses, list(net.requests))
