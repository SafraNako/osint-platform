# OSINT report: iana.org

- **Purpose of the investigation:** example report from a recorded investigation of a public non-profit's domain
- **Run:** 1, taken 2026-10-14T16:07:42Z
- **Method:** passive collection from public records only (certificate transparency, RDAP, DNS over HTTPS, the Internet Archive index, public GitHub metadata, the target's own robots.txt, security.txt and sitemap). Nothing was scanned, crawled or probed.

## Summary

- 25 host names known, 15 resolving today; 26 addresses in 4 networks
- 6 third-party services recognised
- findings: 0 medium, 2 low, 4 informational

## Findings

### [low] DMARC policy is p=none (monitoring only)

Failing mail is delivered as usual; the policy only asks for reports.

- DNS TXT: v=DMARC1; p=none;fo=1; rua=mailto:<mailbox at ag.us.dmarcian.com>; ruf=mailto:<mailbox at iana.org>;

### [low] 5 name(s) resolve to non-public addresses

Internal addressing in public DNS reveals the internal network layout and usually is a leftover.

- DNS: dnstest.int.iana.org -> 10.32.10.92
- DNS: int.iana.org -> 10.32.10.95
- DNS: intranet.int.iana.org -> 10.32.10.29
- DNS: opal.int.iana.org -> 10.32.10.93
- DNS: rdns.int.iana.org -> 10.47.10.94

### [info] 8 names from certificates no longer resolve

Names that were certified but do not exist in DNS today: decommissioned hosts, internal names, or typos in certificate requests.

- CT+DNS: ns.iana.org (NXDOMAIN)
- CT+DNS: rzm-iana-ote.iana.org (NXDOMAIN)
- CT+DNS: rzm-ote-epp.iana.org (NXDOMAIN)
- CT+DNS: www-cdn.iana.org (NXDOMAIN)
- CT+DNS: www.itar.iana.org (NXDOMAIN)
- CT+DNS: www.ns.iana.org (NXDOMAIN)
- CT+DNS: www.rzm-epp.iana.org (NXDOMAIN)
- CT+DNS: www.rzm.iana.org (NXDOMAIN)

### [info] No MTA-STS policy

Senders are not told to require TLS when delivering mail to this domain.

- DNS: no v=STSv1 record at _mta-sts.iana.org

### [info] No security.txt

RFC 9116 asks organisations to publish how to report vulnerabilities; none was found on the apex or www.

- web: /.well-known/security.txt and /security.txt not found

### [info] Wildcard certificates exist for 2 zone(s)

A wildcard hides which hosts exist in a zone: certificate transparency shows the zone, not its hosts.

- CT: *.iana.org
- CT: *.int.iana.org

Findings are reasons to look, derived from public records; none is a verified vulnerability.

## Registration (RDAP)

- Registrar: CSC Corporate Domains, Inc. (IANA id 299)
- Registered 1995-06-05, last changed 2026-08-12, expires 2027-12-08
- Status: server delete prohibited, server transfer prohibited, server update prohibited
- DNSSEC signed: True
- Name servers: a.iana-servers.net, b.iana-servers.net, c.iana-servers.net, ns.icann.org

## Hosts

| Name | Resolves to | Alias chain | Network | Seen in |
|---|---|---|---|---|
| data.iana.org | 104.18.24.232, 104.18.25.232, 2606:4700::6812:18e8 ... | data.iana.org.cdn.cloudflare.net | AS13335 | ct+dns |
| data2.iana.org | - | data2.iana.org.cdn.cloudflare.net | - | ct |
| dnstest.int.iana.org | 10.32.10.92 | ianadnstest.int.vip.icann.org | - | ct+dns |
| ftp.iana.org | 192.0.32.8, 2620:0:2d0:200::8 | ianaftp.vip.icann.org | AS40528 | ct+dns |
| handbook.int.iana.org | 185.199.108.153, 185.199.109.153, 185.199.110.153 ... |  | AS54113 | ct+dns |
| iana.org | 192.0.43.8, 2001:500:88:200::8 |  | AS16876 | archive+ct+dns |
| int.iana.org | 10.32.10.95 | ianaintranet.int.vip.icann.org | - | ct+dns |
| intranet.int.iana.org | 10.32.10.29 | ianavhost-int.int.vip.icann.org | - | ct+dns |
| itar.iana.org | 192.0.43.12, 2001:500:88:200::12 |  | AS16876 | ct+dns |
| ns.iana.org | does not exist |  | - | ct |
| opal.int.iana.org | 10.32.10.93 | ianaopal.int.vip.icann.org | - | ct+dns |
| pen.iana.org | 104.18.24.232, 104.18.25.232, 2606:4700::6812:18e8 ... | pen.iana.org.cdn.cloudflare.net | AS13335 | ct+dns |
| rdns-public.int.iana.org | 192.0.33.91, 2620:0:2d0:201::91 | rdns.vip.icann.org | AS40528 | ct+dns |
| rdns.int.iana.org | 10.47.10.94 | ianardns.int.vip.icann.org | - | ct+dns |
| rzm-epp.iana.org | - |  | - | ct |
| rzm-iana-ote.iana.org | does not exist |  | - | ct |
| rzm-ote-epp.iana.org | does not exist |  | - | ct |
| rzm.iana.org | 192.0.33.87 | ianarzm.vip.icann.org | AS40528 | ct+dns |
| sle-dashboard.iana.org | 104.18.24.232, 104.18.25.232, 2606:4700::6812:18e8 ... | sle-dashboard.iana.org.cdn.cloudflare.net | AS13335 | ct+dns |
| www-cdn.iana.org | does not exist |  | - | ct |
| www.iana.org | 104.18.24.232, 104.18.25.232, 2606:4700::6812:18e8 ... | www.iana.org.cdn.cloudflare.net | AS13335 | archive+ct+dns |
| www.itar.iana.org | does not exist |  | - | ct |
| www.ns.iana.org | does not exist |  | - | ct |
| www.rzm-epp.iana.org | does not exist |  | - | ct |
| www.rzm.iana.org | does not exist |  | - | ct |

## Networks

| ASN | Name | Country | Hosts |
|---|---|---|---|
| AS13335 | CLOUDFLARENET - Cloudflare, Inc., US | US | 4 |
| AS16876 | ICANN-DC - ICANN, US | US | 2 |
| AS40528 | ICANN-LAX - ICANN, US | US | 3 |
| AS54113 | FASTLY - Fastly, Inc., US | US | 1 |

## Third-party services (inferred from MX, NS, SPF, TXT tokens and CNAME targets)

- **Cloudflare (CDN)**: cname data.iana.org -> data.iana.org.cdn.cloudflare.net; cname data2.iana.org -> data2.iana.org.cdn.cloudflare.net; cname pen.iana.org -> pen.iana.org.cdn.cloudflare.net; cname sle-dashboard.iana.org -> sle-dashboard.iana.org.cdn.cloudflare.net
- **DocuSign**: txt docusign
- **Google (Search Console / Workspace)**: txt google-site-verification
- **Have I Been Pwned**: txt hibp-verify
- **Microsoft 365**: txt MS
- **Zoom**: txt ZOOM_verify_

## Mail and DNS posture

- MX: 10 pechora1.icann.org, 10 pechora6.icann.org, 10 pechora7.icann.org, 10 pechora8.icann.org
- Name servers: a.iana-servers.net, b.iana-servers.net, c.iana-servers.net, ns.icann.org
- CAA: 0 iodef mailto:<mailbox at icann.org>; 0 issue digicert.com; 0 issue letsencrypt.org; 0 issue pki.goog; 0 issue sectigo.com; 0 issuemail sectigo.com; 0 issuewild sectigo.com
- SPF: `v=spf1 redirect=icann.org` (closing qualifier none, 1 DNS lookups at the top level)
- DMARC: `v=DMARC1; p=none;fo=1; rua=mailto:<mailbox at ag.us.dmarcian.com>; ruf=mailto:<mailbox at iana.org>;` (policy none, reports to ag.us.dmarcian.com)
- MTA-STS: none

## Certificates (certificate transparency)

- 25 host names appear on publicly logged certificates; first issuance 2007-09-26, latest expiry 2027-01-05
- Issuers: DigiCert Inc (11), GoDaddy.com, Inc. (7), Sectigo Limited (7), Google Trust Services (6), Let's Encrypt (6)
- Wildcard zones: *.iana.org, *.int.iana.org

## Web archive

- 5000 archived URLs read (truncated); hosts: iana.org, www.iana.org

## Public files

- robots.txt on iana.org: 0 Disallow rules, 0 sitemaps

## GitHub organisation

- iana-org (IANA): 9 public repositories, created 2016-03-02, profile links to the target: True
- Languages: Python (5), C (2), Shell (1), Handlebars (1)
- Archived: 3, forks: 0

## Sources and gaps

| Source | State | Detail |
|---|---|---|
| ct | ok | 25 names and 2 wildcard zones from 205 certificates via crt.sh |
| rdap | ok | 11 facts from https://rdap.publicinterestregistry.org/rdap/ |
| wayback | partial | 5000 archived URLs on 2 hosts; 0 with paths worth a look; truncated at 5000 |
| web | ok | 1 facts from iana.org, www.iana.org |
| github | ok | iana-org: 9 of 9 public repositories |
| dns | ok | 25 names, 81 queries |

## What was not collected

People: no registrant, administrative or technical contacts, no names or e-mail addresses of individuals (RDAP contact entities are discarded on arrival, e-mail addresses in any response are replaced by the mail domain), no usernames, no social-media profiles, no commit authors. Content: no page is crawled or scanned, and no historic URL is fetched. The only published contacts kept are those in security.txt, which exist to be used.
