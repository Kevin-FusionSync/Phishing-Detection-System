import re
from email.utils import parseaddr

from .common import Finding
from .url_rules import BRAND_DOMAINS, analyze_url, brand_impersonation, extract_urls, registrable_domain


def _compile(terms):
    return [(t, re.compile(r"\b" + re.escape(t) + r"\b", re.I)) for t in terms]


URGENCY_TERMS = _compile([
    "urgent", "immediately", "act now", "right away", "within 24 hours", "within 48 hours",
    "suspended", "will be suspended", "will be closed", "final notice", "final warning",
    "limited time", "expires today", "action required", "unusual activity", "unauthorized",
    "locked", "deactivated", "as soon as possible", "failure to", "last chance",
])

SENSITIVE_TERMS = _compile([
    "password", "passcode", "social security", "ssn", "credit card", "card number", "cvv",
    "bank account", "routing number", "login credentials", "verify your account",
    "confirm your identity", "verify your identity", "pin", "username", "update your payment",
    "billing information", "account details", "one-time code", "otp", "security question",
])

LURE_TERMS = _compile([
    "you have won", "winner", "claim your prize", "lottery", "inheritance", "refund",
    "gift card", "bitcoin", "wire transfer", "cash prize", "congratulations", "free iphone",
    "beneficiary", "compensation",
])

GENERIC_GREETINGS = _compile([
    "dear customer", "dear user", "dear account holder", "dear valued customer",
    "dear member", "dear client", "dear sir/madam", "dear sir or madam",
])

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
    "protonmail.com", "icloud.com", "mail.ru", "gmx.com", "yandex.com", "live.com",
}

OFFICIAL_WORDS = {"support", "security", "service", "billing", "admin", "helpdesk", "team", "account", "bank", "it"}

HEADER_RE = re.compile(r"^(from|reply-to|return-path|subject)\s*:\s*(.+)$", re.I | re.M)
ANCHOR_RE = re.compile(r"<a\s[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
ATTACHMENT_RE = re.compile(r"\b[\w\-]+\.(exe|scr|js|vbs|bat|cmd|jar|iso|img|zip|rar|7z|docm|xlsm|hta|lnk)\b", re.I)
MACRO_RE = re.compile(r"enable (editing|content|macros)", re.I)


def parse_headers(text):
    headers = {}
    for key, value in HEADER_RE.findall(text or ""):
        headers.setdefault(key.lower(), value.strip())
    return headers


def split_sender(sender):
    name, address = parseaddr(sender or "")
    domain = address.split("@", 1)[1].lower() if "@" in address else ""
    return name.strip(), address.lower(), domain


def _term_finding(text, terms, name, category, base, step, cap, label):
    matched = [t for t, pattern in terms if pattern.search(text)]
    if not matched:
        return []
    weight = min(base + step * len(matched), cap)
    return [Finding(name, category, round(weight, 3), f"{label}: {', '.join(matched[:6])}.")]


def language_findings(text):
    findings = []
    findings += _term_finding(text, URGENCY_TERMS, "Urgent or threatening language", "Language", 0.12, 0.08, 0.35, "Pressure phrases")
    findings += _term_finding(text, SENSITIVE_TERMS, "Request for sensitive information", "Content", 0.2, 0.1, 0.45, "Sensitive terms")
    findings += _term_finding(text, LURE_TERMS, "Reward or money lure", "Content", 0.1, 0.07, 0.3, "Lure phrases")
    findings += _term_finding(text, GENERIC_GREETINGS, "Generic greeting", "Language", 0.1, 0.0, 0.1, "Greeting used")
    return findings


def _mentions_brand(display_name):
    words = re.findall(r"[a-z0-9]+", display_name.lower())
    compact = "".join(words)
    for brand in BRAND_DOMAINS:
        if brand in words or (len(brand) >= 6 and brand in compact):
            return brand
    return None


def sender_findings(sender, reply_to, url_reports):
    findings = []
    name, address, domain = split_sender(sender)
    if not domain:
        return findings

    sender_root = registrable_domain(domain)
    brand = _mentions_brand(name)
    if brand and sender_root not in BRAND_DOMAINS[brand]:
        findings.append(Finding(
            "Display name impersonates a brand", "Sender", 0.45,
            f"Sender claims to be '{name}' but writes from {domain}.",
        ))

    spoof = brand_impersonation(domain)
    if spoof:
        findings.append(Finding(
            "Look-alike sender domain", "Sender", 0.5,
            f"{domain} imitates '{spoof[0]}'.",
        ))

    if sender_root in FREE_MAIL:
        name_words = set(re.findall(r"[a-z]+", name.lower())) | set(re.findall(r"[a-z]+", address.split("@")[0]))
        if brand or name_words & OFFICIAL_WORDS:
            findings.append(Finding(
                "Official-looking sender on free email", "Sender", 0.3,
                f"'{name or address}' presents as an organisation but uses {sender_root}.",
            ))

    _, _, reply_domain = split_sender(reply_to)
    if reply_domain and registrable_domain(reply_domain) != sender_root:
        findings.append(Finding(
            "Reply-To differs from sender", "Sender", 0.3,
            f"Replies go to {reply_domain} instead of {domain}.",
        ))

    link_roots = {r.domain for r in url_reports if r.domain}
    if link_roots and sender_root not in link_roots and sender_root not in FREE_MAIL:
        findings.append(Finding(
            "Sender/link domain mismatch", "Sender", 0.15,
            f"Sender domain {sender_root} does not match link domains: {', '.join(sorted(link_roots)[:4])}.",
        ))
    return findings


def anchor_findings(text):
    findings = []
    for href, label in ANCHOR_RE.findall(text or ""):
        shown = extract_urls(TAG_RE.sub(" ", label))
        if not shown:
            continue
        real = analyze_url(href).domain
        claimed = analyze_url(shown[0]).domain
        if real and claimed and real != claimed:
            findings.append(Finding(
                "Link text does not match destination", "URL", 0.45,
                f"Link displays {claimed} but actually opens {real}.",
            ))
    return findings


def attachment_findings(text):
    findings = []
    stripped = re.sub(r"(?:https?://|www\.)\S+", " ", text or "")
    files = sorted({m.group(0) for m in ATTACHMENT_RE.finditer(stripped)})
    if files:
        findings.append(Finding(
            "Risky attachment type", "Content", 0.3,
            f"Mentions potentially dangerous files: {', '.join(files[:4])}.",
        ))
    if MACRO_RE.search(text or ""):
        findings.append(Finding(
            "Asks to enable macros", "Content", 0.4,
            "The message asks the reader to enable editing, content or macros.",
        ))
    return findings


def extract_indicators(text="", sender="", url=""):
    text = text or ""
    headers = parse_headers(text)
    sender = sender or headers.get("from", "")
    reply_to = headers.get("reply-to", "")

    urls = extract_urls(text)
    if url and url.strip():
        urls.insert(0, url.strip())
    urls = list(dict.fromkeys(urls))[:25]
    url_reports = [analyze_url(u) for u in urls]

    findings = []
    findings += language_findings(text)
    findings += sender_findings(sender, reply_to, url_reports)
    findings += anchor_findings(text)
    findings += attachment_findings(text)
    for report in url_reports:
        findings += report.findings
    return findings, url_reports
