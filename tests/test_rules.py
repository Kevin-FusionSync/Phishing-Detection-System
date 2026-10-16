import unittest

from phishing.common import noisy_or
from phishing.indicators import extract_indicators, parse_headers
from phishing.preprocess import clean_text, to_label
from phishing.scorer import PhishingDetector, risk_level
from phishing.url_rules import analyze_url, brand_impersonation, extract_urls, registrable_domain


def names(findings):
    return {f.name for f in findings}


class PreprocessTests(unittest.TestCase):
    def test_clean_text_replaces_tokens(self):
        cleaned = clean_text("Visit http://bad.com NOW! Email me at a@b.com, code 1234")
        self.assertIn("urltoken", cleaned)
        self.assertIn("emailtoken", cleaned)
        self.assertIn("numtoken", cleaned)
        self.assertNotIn("http", cleaned)

    def test_labels(self):
        self.assertEqual(to_label("Phishing Email"), 1)
        self.assertEqual(to_label("Safe Email"), 0)
        self.assertEqual(to_label("1.0"), 1)
        self.assertIsNone(to_label("unknown"))


class UrlRuleTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("login.secure.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("mail.google.com"), "google.com")

    def test_ip_host(self):
        self.assertIn("IP address used as host", names(analyze_url("http://192.168.10.5/login").findings))

    def test_lookalike(self):
        self.assertEqual(brand_impersonation("paypa1.com"), ("paypal", "lookalike"))
        self.assertIsNone(brand_impersonation("www.paypal.com"))

    def test_brand_on_unofficial_domain(self):
        report = analyze_url("https://paypal.account-check.xyz/verify")
        self.assertIn("Brand name on unofficial domain", names(report.findings))
        self.assertIn("High-risk top-level domain", names(report.findings))

    def test_clean_url(self):
        self.assertEqual(analyze_url("https://www.wikipedia.org/").findings, [])

    def test_extract_urls(self):
        urls = extract_urls("Go to https://a.com/x. Or www.b.org, thanks")
        self.assertEqual(urls, ["https://a.com/x", "www.b.org"])


class IndicatorTests(unittest.TestCase):
    def test_language(self):
        findings, _ = extract_indicators("Dear customer, act now or your account will be suspended. Enter your password.")
        found = names(findings)
        self.assertIn("Urgent or threatening language", found)
        self.assertIn("Request for sensitive information", found)
        self.assertIn("Generic greeting", found)

    def test_headers_and_reply_to(self):
        text = "From: Bank Support <alerts@mybank.com>\nReply-To: help@collect-info.ru\nSubject: Alert\n\nHello"
        self.assertEqual(parse_headers(text)["reply-to"], "help@collect-info.ru")
        findings, _ = extract_indicators(text)
        self.assertIn("Reply-To differs from sender", names(findings))

    def test_anchor_mismatch(self):
        html = '<a href="http://evil.example.net/x">https://www.chase.com</a>'
        findings, _ = extract_indicators(html)
        self.assertIn("Link text does not match destination", names(findings))

    def test_free_mail_official(self):
        findings, _ = extract_indicators("Please reset", sender="IT Helpdesk <helpdesk.team@gmail.com>")
        self.assertIn("Official-looking sender on free email", names(findings))


class ScoringTests(unittest.TestCase):
    def test_noisy_or(self):
        self.assertAlmostEqual(noisy_or([0.5, 0.5]), 0.75)
        self.assertEqual(noisy_or([]), 0.0)

    def test_levels(self):
        self.assertEqual(risk_level(0.1), "Low")
        self.assertEqual(risk_level(0.5), "Medium")
        self.assertEqual(risk_level(0.9), "High")

    def test_rule_only_url(self):
        detector = PhishingDetector(model_path="does-not-exist.joblib")
        result = detector.analyze(url="http://secure-update.chase.account-verify.click/signin/confirm")
        self.assertEqual(result.risk_level, "High")
        self.assertIsNone(result.ml_probability)

    def test_benign_message(self):
        detector = PhishingDetector(model_path="does-not-exist.joblib")
        result = detector.analyze(text="Hi, are we still on for lunch tomorrow at noon?", sender="Sam <sam@acme.com>")
        self.assertEqual(result.risk_level, "Low")


if __name__ == "__main__":
    unittest.main()
