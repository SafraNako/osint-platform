"""Public knowledge used to read the records: which service a host name, TXT token or mail exchanger points at, and which providers let anyone claim
a name that has been released. Short curated lists, not exhaustive: they name what they recognise and say nothing about the rest."""

# a CNAME target under one of these that no longer exists can often be claimed by whoever registers that name at the provider
# (from public takeover research); it prioritises a finding, it does not prove the name is claimable
CLAIMABLE_PROVIDERS = {
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Services", "cloudapp.azure.com": "Azure VM public IP", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage", "azureedge.net": "Azure CDN", "azure-api.net": "Azure API Management", "azurefd.net": "Azure Front Door",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk", "cloudfront.net": "Amazon CloudFront", "s3.amazonaws.com": "Amazon S3", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "github.io": "GitHub Pages", "bitbucket.io": "Bitbucket Pages", "readthedocs.io": "Read the Docs", "ghost.io": "Ghost", "pantheonsite.io": "Pantheon", "surge.sh": "Surge",
    "netlify.app": "Netlify", "wordpress.com": "WordPress.com", "zendesk.com": "Zendesk", "statuspage.io": "Statuspage", "helpscoutdocs.com": "Help Scout Docs",
    "unbouncepages.com": "Unbounce", "myshopify.com": "Shopify", "wpengine.com": "WP Engine", "readme.io": "ReadMe", "vercel.app": "Vercel", "fly.dev": "Fly.io",
}

MX_SERVICES = [
    ("aspmx.l.google.com", "Google Workspace (mail)"), ("googlemail.com", "Google Workspace (mail)"), ("mail.protection.outlook.com", "Microsoft 365 (mail)"),
    ("pphosted.com", "Proofpoint (mail security)"), ("mimecast", "Mimecast (mail security)"), ("protonmail.ch", "Proton Mail"), ("zoho.", "Zoho Mail"),
    ("yandex.net", "Yandex Mail"), ("mailgun.org", "Mailgun"), ("secureserver.net", "GoDaddy (mail)"), ("icloud.com", "Apple iCloud Mail"), ("messagelabs.com", "Broadcom/Symantec (mail security)"),
    ("fastmail.com", "Fastmail"), ("improvmx.com", "ImprovMX"), ("forwardemail.net", "Forward Email"),
]

TXT_PREFIXES = {
    "google-site-verification=": "Google (Search Console / Workspace)", "MS=": "Microsoft 365", "atlassian-domain-verification=": "Atlassian", "facebook-domain-verification=": "Meta",
    "docusign=": "DocuSign", "apple-domain-verification=": "Apple", "stripe-verification=": "Stripe", "adobe-idp-site-verification=": "Adobe", "zoom-domain-verification=": "Zoom",
    "ZOOM_verify_": "Zoom", "slack-domain-verification=": "Slack", "onetrust-domain-verification=": "OneTrust", "globalsign-domain-verification=": "GlobalSign",
    "hibp-verify=": "Have I Been Pwned", "h1-domain-verification=": "HackerOne", "cisco-ci-domain-verification=": "Cisco", "docker-verification=": "Docker",
    "dropbox-domain-verification=": "Dropbox", "miro-verification=": "Miro", "notion-domain-verification=": "Notion", "airtable-verification=": "Airtable",
    "figma-domain-verification=": "Figma", "postman-domain-verification=": "Postman", "mongodb-site-verification=": "MongoDB", "canva-site-verification=": "Canva",
    "pinterest-site-verification=": "Pinterest", "yandex-verification:": "Yandex", "_github-pages-challenge": "GitHub Pages", "webexdomainverification.": "Webex",
    "ca3-": "DigiCert", "sophos-domain-verification=": "Sophos", "knowbe4-site-verification=": "KnowBe4", "teamviewer-sso-verification=": "TeamViewer",
}

SPF_INCLUDES = {
    "_spf.google.com": "Google Workspace (mail)", "spf.protection.outlook.com": "Microsoft 365 (mail)", "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun",
    "amazonses.com": "Amazon SES", "mandrillapp.com": "Mandrill", "servers.mcsv.net": "Mailchimp", "_spf.salesforce.com": "Salesforce", "spf.mtasv.net": "Postmark",
    "zendesk.com": "Zendesk", "helpscoutemail.com": "Help Scout", "freshdesk.com": "Freshdesk", "spf.sendinblue.com": "Brevo (Sendinblue)", "_spf.mlsend.com": "MailerLite",
    "mailjet.com": "Mailjet", "spf.mandrillapp.com": "Mandrill", "_spf.createsend.com": "Campaign Monitor", "hubspotemail.net": "HubSpot", "pphosted.com": "Proofpoint",
}

NS_PROVIDERS = {
    "awsdns": "Amazon Route 53", "cloudflare.com": "Cloudflare DNS", "domaincontrol.com": "GoDaddy DNS", "azure-dns": "Azure DNS", "nsone.net": "NS1", "dnsimple.com": "DNSimple",
    "ultradns": "UltraDNS", "googledomains.com": "Google Domains DNS", "dynect.net": "Dyn", "akam.net": "Akamai DNS", "registrar-servers.com": "Namecheap DNS", "gandi.net": "Gandi",
    "dns.google": "Google Cloud DNS", "ns.cloudflare.com": "Cloudflare DNS", "digitalocean.com": "DigitalOcean DNS", "hetzner.com": "Hetzner DNS", "he.net": "Hurricane Electric",
}

CNAME_PROVIDERS = {
    "cloudfront.net": "Amazon CloudFront (CDN)", "cdn.cloudflare.net": "Cloudflare (CDN)", "fastly.net": "Fastly (CDN)", "akamaiedge.net": "Akamai (CDN)", "edgekey.net": "Akamai (CDN)",
    "edgesuite.net": "Akamai (CDN)", "azureedge.net": "Azure CDN", "azurefd.net": "Azure Front Door", "herokuapp.com": "Heroku", "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure App Service", "trafficmanager.net": "Azure Traffic Manager", "netlify.app": "Netlify", "vercel-dns.com": "Vercel", "vercel.app": "Vercel", "pages.dev": "Cloudflare Pages",
    "readthedocs.io": "Read the Docs", "zendesk.com": "Zendesk", "myshopify.com": "Shopify", "statuspage.io": "Statuspage", "wpengine.com": "WP Engine", "squarespace.com": "Squarespace",
    "unbouncepages.com": "Unbounce", "helpscoutdocs.com": "Help Scout Docs", "ghost.io": "Ghost", "elasticbeanstalk.com": "AWS Elastic Beanstalk", "amazonaws.com": "Amazon Web Services",
    "googlehosted.com": "Google Sites", "ghs.googlehosted.com": "Google Sites", "wixdns.net": "Wix", "pantheonsite.io": "Pantheon", "readme.io": "ReadMe",
}


def match(host, table):
    """The label of the table entry that ``host`` belongs to; the longest matching key wins.

    A key that is a whole domain (``fastly.net``) matches the host or any subdomain of it, on label boundaries; a bare fragment (``awsdns``,
    ``zoho.``) matches anywhere in the host name.
    """
    best = None
    for key, label in table.items():
        is_domain = "." in key and not key.endswith(".")
        hit = (host == key or host.endswith("." + key)) if is_domain else key in host
        if hit and (best is None or len(key) > len(best[0])):
            best = (key, label)
    return best[1] if best else None
