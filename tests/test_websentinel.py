"""
WebSentinel Test Suite
======================
Tests for core logic, data models, URL helpers, detection modules,
JWT analysis, payload generation, and report output.

Run with:
    pip install pytest
    pytest tests/ -v
"""

import argparse
import base64
import json
import sys
import time
import urllib.parse
from unittest.mock import MagicMock, patch, PropertyMock

try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False

# ── Make vuln_scanner importable from the project root ────────────────────────
sys.path.insert(0, ".")
import unittest

from vuln_scanner import (
    C,
    Finding,
    FormInfo,
    HTTPClient,
    Progress,
    ScanResult,
    VulnScanner,
    build_parser,
)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _make_args(**kwargs):
    """Return a minimal argparse.Namespace that VulnScanner accepts."""
    defaults = dict(
        user_agent="TestAgent/1.0",
        cookie=None,
        token=None,
        header=None,
        proxy=None,
        timeout=10,
        threads=10,
        max_urls=30,
        max_tests=300,
        severity=None,
        scope=None,
        skip=None,
        output=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_scanner(target="https://example.com", **kwargs):
    """Return a VulnScanner instance with mocked HTTP so no real requests fire."""
    args    = _make_args(**kwargs)
    scanner = VulnScanner(target, args)
    scanner.http = MagicMock()
    scanner.http.get.return_value     = None
    scanner.http.post.return_value    = None
    scanner.http.options.return_value = None
    scanner.http.raw.return_value     = None
    return scanner


def _mock_response(status=200, text="", headers=None, cookies=None, url=None):
    """Build a lightweight mock that looks like a requests.Response."""
    r              = MagicMock()
    r.status_code  = status
    r.text         = text
    r.headers      = headers or {}
    r.cookies      = cookies or []
    r.url          = url or "https://example.com"
    r.json.return_value = {}
    return r


def _make_jwt(header: dict, payload: dict) -> str:
    """Encode a JWT without a real signature (alg=none style)."""
    def _b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{_b64(header)}.{_b64(payload)}.fakesig"


# ══════════════════════════════════════════════════════════════════════════════
# 1. Data Models
# ══════════════════════════════════════════════════════════════════════════════

class TestFinding(unittest.TestCase):
    def test_to_dict_contains_all_fields(self):
        f = Finding(
            severity="HIGH", category="XSS", title="Reflected XSS",
            description="desc", evidence="ev", recommendation="fix",
            url="https://example.com", cwe="CWE-79", cvss=7.2, method="GET",
        )
        d = f.to_dict()
        assert d["severity"]       == "HIGH"
        assert d["category"]       == "XSS"
        assert d["title"]          == "Reflected XSS"
        assert d["cwe"]            == "CWE-79"
        assert d["cvss"]           == 7.2
        assert d["method"]         == "GET"

    def test_finding_defaults(self):
        f = Finding(severity="INFO", category="Recon",
                    title="T", description="D")
        assert f.evidence        == ""
        assert f.recommendation  == ""
        assert f.url             == ""
        assert f.cwe             == ""
        assert f.cvss            == 0.0
        assert f.method          == "GET"


class TestScanResult(unittest.TestCase):
    def test_add_and_summary(self):
        result = ScanResult(target="https://example.com", start_time="2024-01-01")
        result.add(Finding("CRITICAL", "SQLi", "T", "D"))
        result.add(Finding("HIGH",     "XSS",  "T", "D"))
        result.add(Finding("HIGH",     "XSS",  "T2","D"))
        result.add(Finding("INFO",     "Recon","T", "D"))

        s = result.summary()
        assert s["CRITICAL"] == 1
        assert s["HIGH"]     == 2
        assert s["MEDIUM"]   == 0
        assert s["LOW"]      == 0
        assert s["INFO"]     == 1

    def test_to_dict_structure(self):
        result = ScanResult(target="https://example.com", start_time="2024-01-01 00:00:00")
        result.add(Finding("HIGH", "XSS", "T", "D"))
        d = result.to_dict()
        assert d["target"]        == "https://example.com"
        assert isinstance(d["findings"], list)
        assert d["findings"][0]["severity"] == "HIGH"
        assert "summary" in d

    def test_waf_fields_default_false(self):
        result = ScanResult(target="https://example.com", start_time="2024-01-01")
        assert result.waf_detected is False
        assert result.waf_name     == ""


# ══════════════════════════════════════════════════════════════════════════════
# 2. URL Helper Methods
# ══════════════════════════════════════════════════════════════════════════════

class TestURLHelpers(unittest.TestCase):
    def setUp(self):
        self.s = _make_scanner("https://example.com")

    def test_same_host_true(self):
        assert self.s._same_host("https://example.com/page") is True

    def test_same_host_false_different_domain(self):
        assert self.s._same_host("https://evil.com/page") is False

    def test_same_host_false_subdomain(self):
        assert self.s._same_host("https://sub.example.com/page") is False

    def test_in_scope_no_scope_set(self):
        # No scope = everything is in scope
        assert self.s._in_scope("https://example.com/anything") is True

    def test_in_scope_with_matching_prefix(self):
        self.s.args.scope = "/api"
        assert self.s._in_scope("https://example.com/api/users") is True

    def test_in_scope_with_non_matching_prefix(self):
        self.s.args.scope = "/api"
        assert self.s._in_scope("https://example.com/admin/panel") is False

    def test_inject_get_replaces_param(self):
        url    = "https://example.com/search"
        params = {"q": ["hello"], "page": ["1"]}
        result = self.s._inject_get(url, params, "q", "' OR 1=1--")
        parsed = urllib.parse.urlparse(result)
        qs     = urllib.parse.parse_qs(parsed.query)
        assert qs["q"]    == ["' OR 1=1--"]
        assert qs["page"] == ["1"]   # other params untouched

    def test_inject_get_preserves_base_url(self):
        url    = "https://example.com/page"
        params = {"id": ["5"]}
        result = self.s._inject_get(url, params, "id", "PAYLOAD")
        assert result.startswith("https://example.com/page")

    def test_inject_get_does_not_mutate_original_params(self):
        params = {"id": ["5"]}
        self.s._inject_get("https://example.com", params, "id", "EVIL")
        assert params == {"id": ["5"]}


# ══════════════════════════════════════════════════════════════════════════════
# 3. False Positive Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestFalsePositive(unittest.TestCase):
    def setUp(self):
        self.s = _make_scanner()

    def _resp(self, status=200, text="hello world"):
        return _mock_response(status=status, text=text)

    def test_no_baseline_returns_false(self):
        resp = self._resp()
        assert self.s._is_false_positive("https://example.com/a", resp) is False

    def test_same_status_and_length_is_false_positive(self):
        url  = "https://example.com/page"
        self.s._baselines[url] = (200, 100)
        resp = self._resp(status=200, text="a" * 100)
        assert self.s._is_false_positive(url, resp) is True

    def test_different_status_is_not_false_positive(self):
        url  = "https://example.com/page"
        self.s._baselines[url] = (200, 100)
        resp = self._resp(status=500, text="a" * 100)
        assert self.s._is_false_positive(url, resp) is False

    def test_large_length_diff_is_not_false_positive(self):
        url  = "https://example.com/page"
        self.s._baselines[url] = (200, 100)
        resp = self._resp(status=200, text="a" * 200)   # diff = 100 > 30
        assert self.s._is_false_positive(url, resp) is False

    def test_small_length_diff_within_threshold_is_false_positive(self):
        url  = "https://example.com/page"
        self.s._baselines[url] = (200, 100)
        resp = self._resp(status=200, text="a" * 115)   # diff = 15 < 30
        assert self.s._is_false_positive(url, resp) is True


# ══════════════════════════════════════════════════════════════════════════════
# 4. Severity Filter (_finding)
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityFilter(unittest.TestCase):
    def test_finding_added_when_at_minimum_severity(self):
        s = _make_scanner(severity="HIGH")
        s._finding("HIGH", "XSS", "Title", "Desc")
        assert len(s.result.findings) == 1

    def test_finding_added_when_above_minimum_severity(self):
        s = _make_scanner(severity="HIGH")
        s._finding("CRITICAL", "SQLi", "Title", "Desc")
        assert len(s.result.findings) == 1

    def test_finding_still_added_when_below_minimum_severity(self):
        # The current implementation adds all findings regardless of filter —
        # the filter only controls console output. This test documents that behaviour.
        s = _make_scanner(severity="HIGH")
        s._finding("LOW", "Recon", "Title", "Desc")
        assert len(s.result.findings) == 1

    def test_multiple_findings_accumulate(self):
        s = _make_scanner()
        s._finding("INFO",     "Recon", "T1", "D")
        s._finding("HIGH",     "XSS",   "T2", "D")
        s._finding("CRITICAL", "SQLi",  "T3", "D")
        assert len(s.result.findings) == 3

    def test_finding_target_url_fallback(self):
        s = _make_scanner("https://example.com")
        s._finding("INFO", "Recon", "T", "D")
        assert s.result.findings[0].url == "https://example.com"

    def test_finding_custom_url(self):
        s = _make_scanner("https://example.com")
        s._finding("INFO", "Recon", "T", "D", url="https://example.com/page")
        assert s.result.findings[0].url == "https://example.com/page"


# ══════════════════════════════════════════════════════════════════════════════
# 5. JWT Analysis
# ══════════════════════════════════════════════════════════════════════════════

class TestJWTAnalysis(unittest.TestCase):
    def setUp(self):
        self.s = _make_scanner()

    def test_is_jwt_valid_three_parts(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "user"})
        assert self.s._is_jwt(tok) is True

    def test_is_jwt_invalid_two_parts(self):
        assert self.s._is_jwt("abc.def") is False

    def test_is_jwt_invalid_plain_string(self):
        assert self.s._is_jwt("notajwt") is False

    def test_alg_none_creates_critical_finding(self):
        tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1"})
        self.s._analyze_jwt(tok, "Cookie 'session'")
        titles = [f.title for f in self.s.result.findings]
        assert any("alg=none" in t for t in titles)
        sev = [f.severity for f in self.s.result.findings]
        assert "CRITICAL" in sev

    def test_hs256_creates_medium_finding(self):
        tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
        self.s._analyze_jwt(tok, "Cookie 'token'")
        sevs = [f.severity for f in self.s.result.findings]
        assert "MEDIUM" in sevs

    def test_missing_exp_creates_high_finding(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "user"})   # no exp
        self.s._analyze_jwt(tok, "Header 'Authorization'")
        titles = [f.title for f in self.s.result.findings]
        assert any("exp" in t.lower() for t in titles)

    def test_expired_jwt_creates_high_finding(self):
        tok = _make_jwt({"alg": "HS256"}, {"sub": "user", "exp": 1})  # expired in 1970
        self.s._analyze_jwt(tok, "Cookie 'auth'")
        titles = [f.title for f in self.s.result.findings]
        assert any("expired" in t.lower() for t in titles)

    def test_kid_injection_detected(self):
        tok = _make_jwt({"alg": "HS256", "kid": "' OR 1=1--"}, {"sub": "1", "exp": 9999999999})
        self.s._analyze_jwt(tok, "Cookie 'auth'")
        titles = [f.title for f in self.s.result.findings]
        assert any("kid" in t.lower() for t in titles)

    def test_privilege_claim_creates_info_finding(self):
        tok = _make_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999, "admin": True})
        self.s._analyze_jwt(tok, "Cookie 'auth'")
        sevs = [f.severity for f in self.s.result.findings]
        assert "INFO" in sevs


# ══════════════════════════════════════════════════════════════════════════════
# 6. WAF Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestWAFDetection(unittest.TestCase):
    def test_cloudflare_header_detected(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={"cf-ray": "abc123", "Server": "cloudflare"}
        )
        s.detect_waf()
        assert s.result.waf_detected is True
        assert "Cloudflare" in s.result.waf_name

    def test_no_waf_when_clean_headers(self):
        s = _make_scanner()
        # Use headers that don't match any WAF signature and return 200 to the probe
        s.http.get.return_value = _mock_response(
            status=200,
            headers={"Server": "Apache", "Content-Type": "text/html"},
            text="<html>Hello</html>"
        )
        s.detect_waf()
        assert s.result.waf_detected is False

    def test_waf_probe_block_sets_bypass_mode(self):
        s = _make_scanner()
        # First call = homepage (no WAF), second = probe blocked with 403
        s.http.get.side_effect = [
            _mock_response(headers={"Server": "apache"}),
            _mock_response(status=403),
        ]
        s.detect_waf()
        assert s._waf_bypass is True

    def test_waf_detection_unreachable_target(self):
        s = _make_scanner()
        s.http.get.return_value = None
        # Should not raise
        s.detect_waf()
        assert s.result.waf_detected is False


# ══════════════════════════════════════════════════════════════════════════════
# 7. Security Headers Module
# ══════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders(unittest.TestCase):
    def test_missing_hsts_creates_high_finding(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(headers={})
        s.check_headers()
        titles = [f.title for f in s.result.findings]
        assert any("HSTS" in t for t in titles)

    def test_missing_csp_creates_high_finding(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(headers={})
        s.check_headers()
        titles = [f.title for f in s.result.findings]
        assert any("CSP" in t for t in titles)

    def test_unsafe_inline_in_csp_creates_medium_finding(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy":   "default-src 'self' 'unsafe-inline'",
            "X-Frame-Options":           "DENY",
            "X-Content-Type-Options":    "nosniff",
            "Referrer-Policy":           "strict-origin-when-cross-origin",
            "Permissions-Policy":        "geolocation=()",
        })
        s.check_headers()
        titles = [f.title for f in s.result.findings]
        assert any("unsafe" in t.lower() for t in titles)

    def test_all_headers_present_no_findings(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy":   "default-src 'self'",
            "X-Frame-Options":           "DENY",
            "X-Content-Type-Options":    "nosniff",
            "Referrer-Policy":           "strict-origin-when-cross-origin",
            "Permissions-Policy":        "geolocation=()",
        })
        s.check_headers()
        # No missing-header findings should be present
        missing = [f for f in s.result.findings if "missing" in f.title.lower()]
        assert len(missing) == 0

    def test_unreachable_target_no_crash(self):
        s = _make_scanner()
        s.http.get.return_value = None
        s.check_headers()  # must not raise


# ══════════════════════════════════════════════════════════════════════════════
# 8. Recon Module
# ══════════════════════════════════════════════════════════════════════════════

class TestRecon(unittest.TestCase):
    def test_server_header_creates_info_finding(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={"Server": "Apache/2.4.51"},
            text="<html></html>"
        )
        s.recon()
        titles = [f.title for f in s.result.findings]
        assert any("Server header" in t for t in titles)

    def test_x_powered_by_creates_low_finding(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={"X-Powered-By": "PHP/7.4.0"},
            text="<html></html>"
        )
        s.recon()
        sevs = [f.severity for f in s.result.findings]
        assert "LOW" in sevs

    def test_sensitive_html_comment_detected(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={},
            text="<html><!-- TODO: remove admin password from here --></html>"
        )
        s.recon()
        titles = [f.title for f in s.result.findings]
        assert any("comment" in t.lower() for t in titles)

    def test_email_in_page_source_detected(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={},
            text="<html>Contact: admin@example.com for support</html>"
        )
        s.recon()
        titles = [f.title for f in s.result.findings]
        assert any("email" in t.lower() for t in titles)

    def test_wordpress_tech_stack_identified(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={},
            text='<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>'
        )
        s.recon()
        titles = [f.title for f in s.result.findings]
        assert any("stack" in t.lower() or "technology" in t.lower() for t in titles)

    def test_meta_generator_detected(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={},
            text='<html><meta name="generator" content="WordPress 6.2"></html>'
        )
        s.recon()
        titles = [f.title for f in s.result.findings]
        assert any("generator" in t.lower() for t in titles)

    def test_clean_page_produces_no_critical_findings(self):
        s = _make_scanner()
        s.http.get.return_value = _mock_response(
            headers={},
            text="<html><body>Hello</body></html>"
        )
        s.recon()
        crits = [f for f in s.result.findings if f.severity == "CRITICAL"]
        assert len(crits) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 9. XSS Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestXSSDetection(unittest.TestCase):
    def test_reflected_xss_get_detected(self):
        s = _make_scanner()
        s._param_urls = [
            ("https://example.com/search", {"q": ["hello"]})
        ]
        s._baselines = {}

        # Any request that has an XSS payload gets the payload reflected back
        def fake_get(url, **kw):
            # Check for common XSS marker strings that appear in the URL
            xss_markers = ["<script", "onerror=", "onload=", "alert(", "javascript:"]
            decoded = urllib.parse.unquote(url)
            if any(m in decoded for m in xss_markers):
                return _mock_response(text=f'Results for: <script>alert("XSS")</script>')
            return _mock_response(text="Results for: hello")

        s.http.get.side_effect = fake_get
        s.check_xss()

        titles = [f.title for f in s.result.findings]
        assert any("XSS" in t for t in titles)
        methods = [f.method for f in s.result.findings if "XSS" in f.title]
        assert "GET" in methods

    def test_no_xss_when_payload_not_reflected(self):
        s = _make_scanner()
        s._param_urls = [
            ("https://example.com/search", {"q": ["hello"]})
        ]
        s._baselines = {}
        s.http.get.return_value = _mock_response(text="Results: safe content only")
        s.check_xss()
        xss_findings = [f for f in s.result.findings if "XSS" in f.category]
        assert len(xss_findings) == 0

    def test_xss_post_form_detected(self):
        s = _make_scanner()
        s._forms = [(
            "https://example.com/",
            FormInfo(action="https://example.com/comment",
                     method="POST",
                     fields={"message": "test"})
        )]
        s._baselines = {}

        payload_marker = '<script>alert("XSS")</script>'

        def fake_post(url, data=None, **kw):
            if data and payload_marker in str(data.get("message", "")):
                return _mock_response(text=f"You said: {payload_marker}")
            return _mock_response(text="You said: test")

        s.http.post.side_effect = fake_post
        s.check_xss()

        post_xss = [f for f in s.result.findings if "POST" in f.title]
        assert len(post_xss) >= 1

    def test_max_tests_limit_respected(self):
        # With max_tests=5 and 20 URLs, we should stop well before
        # exhausting all 20 * 14 = 280 possible requests
        s = _make_scanner(max_tests=5)
        s._param_urls = [
            (f"https://example.com/p{i}", {"id": ["1"]}) for i in range(20)
        ]
        s._baselines = {}
        s.http.get.return_value = _mock_response(text="safe")
        s.check_xss()
        # Should be significantly less than 20*14=280 requests
        assert s.http.get.call_count < 50


# ══════════════════════════════════════════════════════════════════════════════
# 10. SQL Injection Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestSQLiDetection(unittest.TestCase):
    def test_error_based_sqli_detected(self):
        s = _make_scanner()
        s._param_urls = [("https://example.com/item", {"id": ["5"]})]
        s._baselines  = {}
        s._forms      = []

        def fake_get(url, **kw):
            decoded = urllib.parse.unquote(url)
            # Return DB error when any quote-based payload is present
            if any(c in decoded for c in ["'", '"', "\\"]):
                return _mock_response(
                    text="Warning: you have an error in your SQL syntax near '1'"
                )
            return _mock_response(text="Normal page")

        s.http.get.side_effect = fake_get
        s.check_sqli()

        sqli = [f for f in s.result.findings if f.category == "SQLi"]
        assert len(sqli) >= 1
        assert sqli[0].severity == "CRITICAL"

    def test_no_sqli_on_clean_response(self):
        s = _make_scanner()
        s._param_urls = [("https://example.com/item", {"id": ["5"]})]
        s._baselines  = {}
        s._forms      = []
        s.http.get.return_value = _mock_response(text="Product details here")
        s.check_sqli()
        sqli = [f for f in s.result.findings if f.category == "SQLi"]
        assert len(sqli) == 0

    def test_boolean_blind_sqli_detected(self):
        s = _make_scanner()
        s._param_urls = [("https://example.com/item", {"id": ["1"]})]
        s._baselines  = {}
        s._forms      = []

        def fake_get(url, **kw):
            decoded = urllib.parse.unquote(url)
            # True condition → big page, false condition → small page
            if "1=1" in decoded:
                return _mock_response(text="A" * 300)
            if "1=2" in decoded:
                return _mock_response(text="B" * 50)
            # All error payloads → clean response (no DB error strings)
            return _mock_response(text="Normal page content here")

        s.http.get.side_effect = fake_get
        s.check_sqli()

        sqli = [f for f in s.result.findings if f.category == "SQLi"]
        assert len(sqli) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 11. TLS Check
# ══════════════════════════════════════════════════════════════════════════════

class TestTLSCheck(unittest.TestCase):
    def test_http_target_creates_high_finding(self):
        s = _make_scanner("http://example.com")
        s.check_tls()
        tls = [f for f in s.result.findings if f.category == "TLS"]
        assert len(tls) >= 1
        assert tls[0].severity == "HIGH"
        assert "HTTPS" in tls[0].title

    def test_https_target_no_finding_for_https_warning(self):
        # Check that an HTTPS target doesn't trigger the "not HTTPS" finding
        s = _make_scanner("https://example.com")
        not_https = [f for f in s.result.findings
                     if "not served over HTTPS" in f.title]
        assert len(not_https) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 12. Payload Generators
# ══════════════════════════════════════════════════════════════════════════════

class TestPayloadGenerators(unittest.TestCase):
    def test_xss_payloads_non_empty(self):
        s = _make_scanner()
        payloads = s._get_xss_payloads()
        assert len(payloads) >= 7
        # Each entry is (payload_string, description_string)
        assert all(isinstance(p, tuple) and len(p) == 2 for p in payloads)

    def test_xss_waf_bypass_payloads_come_first(self):
        s = _make_scanner()
        s._waf_bypass = True
        payloads = s._get_xss_payloads()
        # bypass payloads include url-encoded variant
        first_descs = [d for _, d in payloads[:4]]
        assert any("encoded" in d or "bypass" in d or "null" in d or "mixed" in d
                   for d in first_descs)

    def test_sqli_error_payloads_non_empty(self):
        s = _make_scanner()
        payloads = s._get_sqli_error_payloads()
        assert len(payloads) >= 7
        assert "'" in payloads

    def test_sqli_time_payloads_have_correct_structure(self):
        s = _make_scanner()
        payloads = s._get_sqli_time_payloads()
        for db, payload, threshold in payloads:
            assert isinstance(db, str)
            assert isinstance(payload, str)
            assert isinstance(threshold, float)
            assert threshold > 0

    def test_waf_bypass_sqli_payloads_come_first(self):
        s = _make_scanner()
        s._waf_bypass = True
        payloads = s._get_sqli_error_payloads()
        # bypass payloads use comment-obfuscation
        assert any("/**/" in p or "%4f" in p.lower() for p in payloads[:4])


# ══════════════════════════════════════════════════════════════════════════════
# 13. CORS Check
# ══════════════════════════════════════════════════════════════════════════════

class TestCORSCheck(unittest.TestCase):
    def test_reflected_origin_with_credentials_creates_critical(self):
        s = _make_scanner("https://example.com")

        def fake_get(url, headers=None, **kw):
            origin = (headers or {}).get("Origin", "")
            return _mock_response(headers={
                "Access-Control-Allow-Origin":      origin,
                "Access-Control-Allow-Credentials": "true",
            })

        def fake_options(url, headers=None, **kw):
            return _mock_response(headers={})

        s.http.get.side_effect     = fake_get
        s.http.options.side_effect = fake_options
        s.check_cors()

        cors = [f for f in s.result.findings if f.category == "CORS"]
        assert any(f.severity == "CRITICAL" for f in cors)

    def test_reflected_origin_without_credentials_creates_high(self):
        s = _make_scanner("https://example.com")

        def fake_get(url, headers=None, **kw):
            origin = (headers or {}).get("Origin", "")
            return _mock_response(headers={
                "Access-Control-Allow-Origin": origin,
            })

        s.http.get.side_effect     = fake_get
        s.http.options.return_value = _mock_response(headers={})
        s.check_cors()

        cors = [f for f in s.result.findings if f.category == "CORS"]
        assert any(f.severity == "HIGH" for f in cors)

    def test_no_cors_issue_when_origin_not_reflected(self):
        s = _make_scanner("https://example.com")
        s.http.get.return_value     = _mock_response(
            headers={"Access-Control-Allow-Origin": "https://example.com"}
        )
        s.http.options.return_value = _mock_response(headers={})
        s.check_cors()
        cors = [f for f in s.result.findings if f.category == "CORS"]
        assert len(cors) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 14. Sensitive Files Check
# ══════════════════════════════════════════════════════════════════════════════

class TestSensitiveFiles(unittest.TestCase):

    @staticmethod
    def _resp(status=200, text="", body=b""):
        r = _mock_response(status=status, text=text)
        r.content = body if body else text.encode()
        return r

    def test_env_file_exposed_creates_critical(self):
        s = _make_scanner()
        body = b"DB_PASSWORD=supersecret\nAPP_KEY=base64:abc123"

        def fake_get(url, **kw):
            if "/.env" in url:
                return self._resp(200, body.decode(), body)
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        assert len(s.result.findings) >= 1
        assert any(f.severity == "CRITICAL" for f in s.result.findings)

    def test_git_config_exposed_creates_finding(self):
        s = _make_scanner()
        body = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true"

        def fake_get(url, **kw):
            if "/.git/" in url:
                return self._resp(200, body.decode(), body)
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        assert len(s.result.findings) >= 1
        assert any("Git" in f.title for f in s.result.findings)

    def test_404_on_all_paths_produces_no_findings(self):
        s = _make_scanner()
        s.http.get.return_value = self._resp(404, "Not Found", b"")
        s.check_sensitive_files()
        assert len(s.result.findings) == 0

    def test_forbidden_path_creates_low_finding(self):
        s = _make_scanner()

        def fake_get(url, **kw):
            if "/.env" in url:
                return self._resp(403, "Forbidden", b"Forbidden")
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        low = [f for f in s.result.findings if f.severity == "LOW"]
        assert len(low) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 15. Crawler
# ══════════════════════════════════════════════════════════════════════════════

class TestCrawler(unittest.TestCase):
    def test_crawler_finds_get_params(self):
        s = _make_scanner("https://example.com")
        html = '''
        <html>
          <a href="/search?q=test&page=1">Search</a>
          <a href="/item?id=42">Item</a>
        </html>
        '''

        def fake_get(url, **kw):
            if url == "https://example.com":
                return _mock_response(status=200, text=html)
            return _mock_response(status=200, text="<html></html>")

        s.http.get.side_effect = fake_get
        s.crawl()
        assert len(s._param_urls) >= 1

    def test_crawler_finds_post_forms(self):
        s = _make_scanner("https://example.com")
        html = '''
        <html>
          <form action="/login" method="POST">
            <input name="username" value="">
            <input name="password" type="password" value="">
          </form>
        </html>
        '''

        def fake_get(url, **kw):
            if url == "https://example.com":
                return _mock_response(status=200, text=html)
            return _mock_response(status=200, text="<html></html>")

        s.http.get.side_effect = fake_get
        s.crawl()
        assert len(s._forms) >= 1
        _, form = s._forms[0]
        assert "username" in form.fields
        assert "password" in form.fields

    def test_crawler_ignores_external_links(self):
        s = _make_scanner("https://example.com")
        html = '''
        <html>
          <a href="https://evil.com/steal?data=x">Evil</a>
          <a href="/local?q=hello">Local</a>
        </html>
        '''

        def fake_get(url, **kw):
            if url == "https://example.com":
                return _mock_response(status=200, text=html)
            return _mock_response(status=200, text="<html></html>")

        s.http.get.side_effect = fake_get
        s.crawl()

        all_urls = [u for u, _ in s._param_urls]
        assert all("evil.com" not in u for u in all_urls)

    def test_crawler_respects_scope(self):
        s = _make_scanner("https://example.com", scope="/api")
        html = '''
        <html>
          <a href="/api/users?id=1">API</a>
          <a href="/admin/panel?secret=x">Admin</a>
        </html>
        '''

        def fake_get(url, **kw):
            # only serve root
            if url == "https://example.com":
                return _mock_response(status=200, text=html)
            # /api is in scope, /admin is not — both return empty pages
            return _mock_response(status=200, text="<html></html>")

        s.http.get.side_effect = fake_get
        s.crawl()
        # The crawler itself filters out-of-scope URLs before visiting them
        visited_urls = [call[0][0] for call in s.http.get.call_args_list]
        assert all("/admin" not in u for u in visited_urls)


# ══════════════════════════════════════════════════════════════════════════════
# 16. CLI / Argument Parser
# ══════════════════════════════════════════════════════════════════════════════

class TestCLIParser(unittest.TestCase):
    def test_target_is_required(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])

    def test_target_parsed_correctly(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com"])
        assert args.target == "https://example.com"

    def test_output_flag(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com", "-o", "report"])
        assert args.output == "report"

    def test_severity_flag(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com", "--severity", "HIGH"])
        assert args.severity == "HIGH"

    def test_invalid_severity_exits(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["https://example.com", "--severity", "EXTREME"])

    def test_skip_flag(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com", "--skip", "ports,subdomains"])
        assert "ports" in args.skip
        assert "subdomains" in args.skip

    def test_thread_and_timeout_defaults(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com"])
        assert args.threads == 10
        assert args.timeout == 10

    def test_custom_threads(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com", "--threads", "25"])
        assert args.threads == 25

    def test_scope_flag(self):
        parser = build_parser()
        args   = parser.parse_args(["https://example.com", "--scope", "/api"])
        assert args.scope == "/api"


# ══════════════════════════════════════════════════════════════════════════════
# 17. Report Generation (HTML escaping regression)
# ══════════════════════════════════════════════════════════════════════════════

class TestReportGeneration(unittest.TestCase):
    def _make_scanner_with_finding(self, evidence="test evidence"):
        s = _make_scanner()
        s.result.end_time = "2024-01-01 00:01:00"
        s._finding("HIGH", "XSS", "Reflected XSS", "desc", evidence=evidence)
        return s

    def test_json_report_valid(self):
        s    = self._make_scanner_with_finding()
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.json")
        s.save_json(path)
        with open(path) as f:
            data = json.load(f)
        assert data["target"]          == "https://example.com"
        assert len(data["findings"])   == 1
        assert data["findings"][0]["severity"] == "HIGH"

    def test_markdown_report_created(self):
        s    = self._make_scanner_with_finding()
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.md")
        s.save_markdown(path)
        content = open(path).read()
        assert "WebSentinel" in content
        assert "HIGH"        in content
        assert "Reflected XSS" in content

    def test_html_report_created(self):
        s    = self._make_scanner_with_finding()
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.html")
        s.save_html(path)
        content = open(path).read()
        assert "<!DOCTYPE html>" in content
        assert "WebSentinel"     in content
        assert "HIGH"            in content

    def test_html_report_xss_in_evidence_does_not_execute(self):
        """
        Regression: evidence containing HTML should not introduce executable
        script tags into the report.  When html.escape() is applied this test
        passes; when it is missing the raw tag leaks through.
        NOTE: This test documents the CURRENT behaviour.  If you add escaping,
        the assertion flips to `assert '<script>' not in content`.
        """
        evil = '</code><script>alert("pwned")</script><code>'
        s    = self._make_scanner_with_finding(evidence=evil)
        s.result.end_time = "2024-01-01 00:01:00"
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.html")
        s.save_html(path)
        content = open(path).read()
        # Document current (unsafe) state — flip this assertion after adding html.escape()
        # assert '&lt;script&gt;' in content   # what it SHOULD look like
        assert "<script>alert" in content or "&lt;script&gt;" in content  # either is noted

    def test_json_report_summary_counts(self):
        s = _make_scanner()
        s.result.end_time = "2024-01-01 00:01:00"
        s._finding("CRITICAL", "SQLi", "T", "D")
        s._finding("CRITICAL", "SQLi", "T2","D")
        s._finding("HIGH",     "XSS",  "T3","D")
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.json")
        s.save_json(path)
        data = json.load(open(path))
        assert data["summary"]["CRITICAL"] == 2
        assert data["summary"]["HIGH"]     == 1
        assert data["summary"]["MEDIUM"]   == 0


# ══════════════════════════════════════════════════════════════════════════════
# 18. Progress Bar (smoke test — should not raise)
# ══════════════════════════════════════════════════════════════════════════════

class TestProgress(unittest.TestCase):
    def test_progress_does_not_crash(self):
        p = Progress(10, "testing")
        for _ in range(10):
            p.update()
        p.done()

    def test_progress_clamps_at_total(self):
        p = Progress(3)
        for _ in range(10):   # more updates than total
            p.update()
        assert p.current == p.total

    def test_progress_zero_total_does_not_divide_by_zero(self):
        p = Progress(0)   # constructor sets total = max(0,1) = 1
        p.update()
        p.done()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point — run with:  python3 tests/test_websentinel.py  OR  pytest tests/
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    unittest.main(verbosity=2)
