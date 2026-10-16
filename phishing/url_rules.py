import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .common import Finding, noisy_or

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", re.I)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "kim", "loan", "work", "party", "gdn", "rest", "fit", "cam", "icu", "buzz", "monster",
}

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "co.jp",
    "com.br", "com.pk", "co.za", "com.cn", "com.mx", "com.tr", "com.sg",
}

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "office365": {"office.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
}

PATH_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "banking", "webscr", "unlock", "billing",
)

LOOKALIKE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


@dataclass
class UrlReport:
    url: str
    host: str
    domain: str
    findings: list = field(default_factory=list)

    @property
    def score(self):
        return noisy_or(f.weight for f in self.findings)

    def to_dict(self):
        return {
            "url": self.url,
            "host": self.host,
            "domain": self.domain,
            "score": round(self.score, 3),
            "findings": [f.to_dict() for f in self.findings],
        }


def extract_urls(text):
    if not text:
        return []
    found = [m.rstrip(".,;:!?") for m in URL_PATTERN.findall(text)]
    return list(dict.fromkeys(found))


def registrable_domain(host):
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_match(token, brand):
    return token == brand or (len(brand) >= 6 and brand in token)


def brand_impersonation(host):
    host = (host or "").lower()
    domain = registrable_domain(host)
    for token in re.split(r"[.\-_]", host):
        if not token:
            continue
        decoded = token.translate(LOOKALIKE_MAP).replace("rn", "m").replace("vv", "w")
        for brand, official in BRAND_DOMAINS.items():
            if domain in official:
                continue
            if _brand_match(token, brand):
                return brand, "name"
            if decoded != token and _brand_match(decoded, brand):
                return brand, "lookalike"
    return None


def analyze_url(raw):
    url = raw.strip()
    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.I))
    parsed = urlparse(url if has_scheme else "http://" + url)
    host = (parsed.hostname or "").lower()
    report = UrlReport(url=url, host=host, domain=registrable_domain(host) if host else "")
    add = report.findings.append

    if not host:
        add(Finding("Malformed link", "URL", 0.3, f"'{url}' could not be parsed into a valid host."))
        return report

    tld = host.rsplit(".", 1)[-1]
    path_and_query = (parsed.path + "?" + parsed.query).lower()

    if is_ip(host):
        add(Finding("IP address used as host", "URL", 0.45, f"{url} points to a raw IP address instead of a domain."))
    if "@" in parsed.netloc:
        add(Finding("@ symbol in link", "URL", 0.4, f"{url} hides the real destination behind an @ symbol."))
    if "xn--" in host:
        add(Finding("Punycode domain", "URL", 0.35, f"{host} uses punycode, often used for look-alike characters."))
    if report.domain in SHORTENERS:
        add(Finding("Shortened link", "URL", 0.3, f"{report.domain} is a link shortener that hides the final destination."))
    if tld in SUSPICIOUS_TLDS:
        add(Finding("High-risk top-level domain", "URL", 0.25, f".{tld} domains are frequently abused in phishing campaigns."))
    if host.count(".") >= 4:
        add(Finding("Too many subdomains", "URL", 0.2, f"{host} has an unusually deep subdomain chain."))
    if has_scheme and parsed.scheme.lower() == "http":
        add(Finding("No HTTPS", "URL", 0.15, f"{url} does not use an encrypted connection."))
    if len(url) > 75:
        add(Finding("Very long link", "URL", 0.1, f"The link is {len(url)} characters long."))
    if report.domain.split(".")[0].count("-") >= 2:
        add(Finding("Hyphen-heavy domain", "URL", 0.15, f"{report.domain} contains several hyphens."))

    impersonation = brand_impersonation(host)
    if impersonation:
        brand, kind = impersonation
        if kind == "lookalike":
            add(Finding("Look-alike brand domain", "URL", 0.55, f"{host} imitates '{brand}' using swapped characters."))
        else:
            add(Finding("Brand name on unofficial domain", "URL", 0.5, f"{host} uses '{brand}' but is not an official {brand} domain."))

    keywords = [k for k in PATH_KEYWORDS if k in path_and_query]
    if keywords:
        add(Finding("Credential-related keywords in link", "URL", 0.15, f"Link path contains: {', '.join(keywords[:5])}."))

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        add(Finding("Non-standard port", "URL", 0.2, f"{url} uses port {port}."))

    if "//" in parsed.path or re.search(r"=(https?%3a|https?:)", parsed.query, re.I):
        add(Finding("Embedded redirect", "URL", 0.15, f"{url} appears to redirect to another address."))
    if url.count("%") >= 5:
        add(Finding("Heavily encoded link", "URL", 0.15, f"{url} contains many percent-encoded characters."))

    return report
