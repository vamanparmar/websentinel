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

    def test_finding_dropped_when_below_minimum_severity(self):
        # v3.1.0 fix: findings below the minimum severity are now correctly
        # dropped from results, not silently added.
        s = _make_scanner(severity="HIGH")
        s._finding("LOW", "Recon", "Title", "Desc")
        assert len(s.result.findings) == 0

    def test_finding_dropped_info_when_minimum_is_medium(self):
        s = _make_scanner(severity="MEDIUM")
        s._finding("INFO", "Recon", "Title", "Desc")
        assert len(s.result.findings) == 0

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

    def test_deduplication_prevents_identical_findings(self):
        # v3.1.0 addition: thread-safe dedup means calling _finding() twice
        # with the same severity/category/title/url only stores one result.
        s = _make_scanner("https://example.com")
        s._finding("HIGH", "XSS", "Reflected XSS", "Desc", url="https://example.com/search")
        s._finding("HIGH", "XSS", "Reflected XSS", "Desc", url="https://example.com/search")
        assert len(s.result.findings) == 1

    def test_deduplication_allows_different_urls(self):
        # Same title/category/severity but different URL = distinct finding.
        s = _make_scanner("https://example.com")
        s._finding("HIGH", "XSS", "Reflected XSS", "Desc", url="https://example.com/a")
        s._finding("HIGH", "XSS", "Reflected XSS", "Desc", url="https://example.com/b")
        assert len(s.result.findings) == 2

    def test_deduplication_allows_different_titles(self):
        s = _make_scanner("https://example.com")
        s._finding("HIGH", "XSS", "Title One", "Desc")
        s._finding("HIGH", "XSS", "Title Two", "Desc")
        assert len(s.result.findings) == 2


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

    def test_is_jwt_rejects_version_numbers(self):
        # v3.1.0 fix: dotted version strings like "3.1.0" were previously
        # matched as JWTs. They must now be rejected — no valid base64url
        # header with an 'alg' field can be decoded from a short string like "3".
        assert self.s._is_jwt("3.1.0") is False
        assert self.s._is_jwt("1.2.3") is False
        assert self.s._is_jwt("10.0.0-beta") is False

    def test_is_jwt_requires_alg_field_in_header(self):
        # A token whose header decodes to JSON without 'alg' is not a JWT.
        def _b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        no_alg_token = f"{_b64({'typ': 'JWT'})}.{_b64({'sub': '1'})}.fakesig"
        assert self.s._is_jwt(no_alg_token) is False

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

    def test_cookie_with_none_value_does_not_raise(self):
        # v3.1.1 fix: check_cookies called _is_jwt(cookie.value) without first
        # guarding against None, causing AttributeError on .split(".") for cookies
        # that have no value set. Verify that None-value cookies are silently skipped.
        s = _make_scanner()
        none_cookie  = MagicMock(); none_cookie.name = "session"; none_cookie.value = None
        valid_cookie = MagicMock(); valid_cookie.name = "other";   valid_cookie.value = "plain"
        resp = _mock_response(status=200, headers={})
        resp.cookies = [none_cookie, valid_cookie]
        s.http.get.return_value = resp
        # Must not raise AttributeError
        try:
            s.check_cookies()
        except AttributeError:
            self.fail("check_cookies() raised AttributeError on a cookie with value=None")

    def test_cookie_with_empty_string_value_does_not_raise(self):
        # Empty string is also falsy — should be skipped like None.
        s = _make_scanner()
        empty_cookie = MagicMock(); empty_cookie.name = "tok"; empty_cookie.value = ""
        resp = _mock_response(status=200, headers={})
        resp.cookies = [empty_cookie]
        s.http.get.return_value = resp
        try:
            s.check_cookies()
        except (AttributeError, ValueError):
            self.fail("check_cookies() raised on a cookie with an empty value")


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

    def test_sensitive_files_respects_severity_filter(self):
        # v3.1.0 fix: check_sensitive_files now routes through _finding() so
        # the severity filter is honoured — LOW findings are dropped when
        # minimum severity is set to MEDIUM or above.
        s = _make_scanner(severity="MEDIUM")
        body = b"Forbidden"

        def fake_get(url, **kw):
            # Return 403 for .env (would produce a LOW finding) and 404 for all else
            if "/.env" in url:
                return self._resp(403, "Forbidden", body)
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        # The 403 finding is LOW — it must be dropped when min severity is MEDIUM
        assert len(s.result.findings) == 0

    def test_external_redirect_is_not_treated_as_exposure(self):
        # v3.1.1 fix: allow_redirects=False means a 301 to an external host
        # (e.g. a CDN) is no longer mistakenly flagged as a sensitive-file exposure.
        s = _make_scanner("https://example.com")

        def fake_get(url, **kw):
            if "/.env" in url:
                # Simulate a redirect to an external host
                r = self._resp(301, "", b"")
                r.headers = {"Location": "https://cdn.external.com/.env"}
                return r
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        # External redirect should produce no finding
        assert len(s.result.findings) == 0

    def test_on_host_redirect_does_not_create_finding(self):
        # A redirect that stays on the same host (e.g. /env → /env/) should
        # also be ignored — only real 200 exposures or 403s matter.
        s = _make_scanner("https://example.com")

        def fake_get(url, **kw):
            if url.endswith("/.env"):
                r = self._resp(301, "", b"")
                r.headers = {"Location": "https://example.com/.env/"}
                return r
            return self._resp(404, "Not Found", b"")

        s.http.get.side_effect = fake_get
        s.check_sensitive_files()
        assert len(s.result.findings) == 0

    def test_sensitive_files_uses_allow_redirects_false(self):
        # v3.1.1 fix: verify that http.get is always called with
        # allow_redirects=False so raw redirects can be inspected.
        s = _make_scanner()
        s.http.get.return_value = self._resp(404, "Not Found", b"")
        s.check_sensitive_files()

        for call in s.http.get.call_args_list:
            kwargs = call[1]
            assert kwargs.get("allow_redirects") is False, (
                "check_sensitive_files must pass allow_redirects=False to http.get"
            )


# ══════════════════════════════════════════════════════════════════════════════
# 15. GraphQL Introspection
# ══════════════════════════════════════════════════════════════════════════════

class TestGraphQLIntrospection(unittest.TestCase):
    def test_introspection_post_sends_json_not_form_data(self):
        # v3.1.0 fix: introspection query must be sent as a JSON body, not
        # form-encoded data. Verify that http.post is called with json_data=
        # (i.e. the 'json' kwarg reaches requests) and not data= only.
        s = _make_scanner()

        # First POST (/graphql probe) → looks like a GraphQL endpoint
        probe_resp = _mock_response(
            status=200,
            text='{"data": {"__typename": "Query"}}',
        )
        # Second POST (introspection) → returns a schema
        intro_resp = _mock_response(
            status=200,
            text='{"data": {"__schema": {"types": [{"name": "Query", "kind": "OBJECT", "fields": []}]}}}',
        )
        intro_resp.json.return_value = {
            "data": {
                "__schema": {
                    "types": [{"name": "Query", "kind": "OBJECT", "fields": []}]
                }
            }
        }

        # The scanner probes 6 GraphQL endpoints; only /graphql hits — pad the
        # remaining 5 endpoint probes (each needs a probe call) with None so
        # the mock iterator doesn't run out before check_graphql() returns.
        s.http.post.side_effect = [probe_resp, intro_resp] + [None] * 10
        s.check_graphql()

        # Collect all calls to http.post
        calls = s.http.post.call_args_list
        assert len(calls) >= 2, "Expected at least two POST calls (probe + introspection)"

        # The introspection call (second call) must pass json_data, not raw data
        introspection_call = calls[1]
        kwargs = introspection_call[1]  # keyword arguments
        # json_data kwarg must be present and be a dict (not a raw string)
        assert "json_data" in kwargs, (
            "Introspection POST must use json_data= (sends Content-Type: application/json), "
            "not data= (sends form-encoded body)"
        )
        assert isinstance(kwargs["json_data"], dict), (
            "json_data must be a dict, not a raw JSON string"
        )

    def test_graphql_endpoint_not_found_produces_no_finding(self):
        s = _make_scanner()
        # All probes return 404
        s.http.post.return_value = _mock_response(status=404, text="Not Found")
        s.check_graphql()
        graphql = [f for f in s.result.findings if f.category == "GraphQL"]
        assert len(graphql) == 0

    def test_graphql_introspection_disabled_creates_info_finding(self):
        s = _make_scanner()
        # Probe succeeds but introspection is blocked
        probe_resp = _mock_response(status=200, text='{"data": {"__typename": "Query"}}')
        blocked    = _mock_response(status=200, text='{"errors": [{"message": "introspection disabled"}]}')
        # The scanner probes 6 GraphQL endpoints; /graphql hits (probe_resp),
        # then the introspection call is blocked. Pad remaining endpoint probes
        # with None so the mock iterator doesn't exhaust prematurely.
        s.http.post.side_effect = [probe_resp, blocked] + [None] * 10
        s.check_graphql()
        graphql = [f for f in s.result.findings if f.category == "GraphQL"]
        assert any(f.severity == "INFO" for f in graphql)


# ══════════════════════════════════════════════════════════════════════════════
# 16. Prototype Pollution
# ══════════════════════════════════════════════════════════════════════════════

class TestPrototypePollution(unittest.TestCase):
    def test_dot_notation_payload_reflected_creates_finding(self):
        # v3.1.1 fix: the POST builder previously silently dropped dot-notation
        # payloads like __proto__.test=polluted. Verify they now produce a finding
        # when the server reflects "polluted" in the response.
        s = _make_scanner()
        s._param_urls = []
        s._forms = [(
            "https://example.com/",
            FormInfo(action="https://example.com/api/data",
                     method="POST",
                     fields={"input": "test"})
        )]

        def fake_post(url, json_data=None, **kw):
            # Simulate server reflecting a polluted property
            if json_data and _is_nested_proto(json_data):
                return _mock_response(text='{"polluted": true, "result": "polluted"}')
            return _mock_response(text='{"result": "ok"}')

        def _is_nested_proto(obj, depth=0):
            """Recursively check if dict contains __proto__ key at any level."""
            if depth > 5:
                return False
            for k, v in obj.items():
                if "__proto__" in k or "constructor" in k:
                    return True
                if isinstance(v, dict) and _is_nested_proto(v, depth + 1):
                    return True
            return False

        s.http.post.side_effect = fake_post
        s.check_prototype_pollution()

        pp = [f for f in s.result.findings if f.category == "ProtoPollution"]
        assert len(pp) >= 1

    def test_build_pp_json_bracket_notation(self):
        # Bracket notation __proto__[test]=polluted must produce a nested dict.
        s = _make_scanner()
        result = s._build_pp_json("__proto__[test]=polluted")
        assert result is not None
        assert isinstance(result, dict)
        # Should contain __proto__ key with nested value
        assert "__proto__" in result

    def test_build_pp_json_dot_notation(self):
        # v3.1.1 fix: dot notation __proto__.test=polluted was silently dropped.
        # _build_pp_json must now return a valid dict for this form.
        s = _make_scanner()
        result = s._build_pp_json("__proto__.test=polluted")
        assert result is not None, (
            "_build_pp_json returned None for dot-notation payload — "
            "this was the v3.1.1 bug"
        )
        assert isinstance(result, dict)

    def test_build_pp_json_returns_none_for_invalid_payload(self):
        # Payloads without '=' cannot be parsed and should return None.
        s = _make_scanner()
        assert s._build_pp_json("__proto__") is None
        assert s._build_pp_json("noequalssign") is None


# ══════════════════════════════════════════════════════════════════════════════
# 17. WebSocket Detection
# ══════════════════════════════════════════════════════════════════════════════

class TestWebSocketDetection(unittest.TestCase):
    def test_absolute_wss_url_used_as_is(self):
        # Absolute wss:// URLs must not be modified.
        s = _make_scanner("https://example.com")
        s.http.get.return_value = _mock_response(
            text='var ws = new WebSocket("wss://example.com/socket");'
        )
        s.check_websocket()
        ws = [f for f in s.result.findings if f.category == "WebSocket"]
        assert len(ws) >= 1
        assert "wss://example.com/socket" in ws[0].title
        assert "wss:///socket" not in ws[0].title  # no triple-slash

    def test_relative_path_produces_correct_wss_url(self):
        # v3.1.1 fix: relative paths like "/socket" were joined as wss:///socket.
        # Now they must be joined with the host to produce wss://example.com/socket.
        s = _make_scanner("https://example.com")
        s.http.get.return_value = _mock_response(
            text='var sock = new WebSocket("/socket");'
        )
        s.check_websocket()
        ws = [f for f in s.result.findings if f.category == "WebSocket"]
        assert len(ws) >= 1
        # Must NOT contain triple-slash
        for f in ws:
            assert "wss:///" not in f.title, (
                f"Triple-slash URL detected in finding title: {f.title}"
            )
        # Must contain the correctly formed URL
        assert any("wss://example.com/socket" in f.title for f in ws)

    def test_no_ws_endpoints_produces_no_finding(self):
        s = _make_scanner("https://example.com")
        s.http.get.return_value = _mock_response(
            text="<html><body>No websockets here</body></html>"
        )
        s.check_websocket()
        ws = [f for f in s.result.findings if f.category == "WebSocket"]
        assert len(ws) == 0

    def test_http_target_uses_ws_scheme(self):
        # For plain http:// targets the WS scheme should be ws://, not wss://.
        s = _make_scanner("http://example.com")
        s.http.get.return_value = _mock_response(
            text='var ws = new WebSocket("/live");'
        )
        s.check_websocket()
        ws = [f for f in s.result.findings if f.category == "WebSocket"]
        assert len(ws) >= 1
        assert any("ws://example.com/live" in f.title for f in ws)

    def test_protocol_relative_url_gets_correct_scheme(self):
        # Protocol-relative URLs (//example.com/socket) must pick up the
        # target's scheme (wss for https targets).
        s = _make_scanner("https://example.com")
        s.http.get.return_value = _mock_response(
            text='var ws = new WebSocket("//example.com/socket");'
        )
        s.check_websocket()
        ws = [f for f in s.result.findings if f.category == "WebSocket"]
        assert len(ws) >= 1
        assert any("wss://example.com/socket" in f.title for f in ws)

    def test_unreachable_target_no_crash(self):
        s = _make_scanner()
        s.http.get.return_value = None
        s.check_websocket()  # must not raise


# ══════════════════════════════════════════════════════════════════════════════
# 18. Crawler
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
# 19. CLI / Argument Parser
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
# 20. Report Generation
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

    def test_html_report_xss_in_evidence_is_escaped(self):
        # v3.1.0 fix: all finding fields are now HTML-escaped before being
        # written into the report, so attacker payloads cannot execute.
        evil = '</code><script>alert("pwned")</script><code>'
        s    = self._make_scanner_with_finding(evidence=evil)
        s.result.end_time = "2024-01-01 00:01:00"
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.html")
        s.save_html(path)
        content = open(path).read()
        # The raw <script> tag must NOT appear — only the escaped form is acceptable
        assert "<script>alert" not in content
        assert "&lt;script&gt;" in content

    def test_html_report_title_field_is_escaped(self):
        # Titles can also carry injection — verify they are escaped too.
        s = _make_scanner()
        s.result.end_time = "2024-01-01 00:01:00"
        s._finding("HIGH", "XSS", '<img src=x onerror=alert(1)>', "desc")
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.html")
        s.save_html(path)
        content = open(path).read()
        assert "<img src=x onerror=alert(1)>" not in content
        assert "&lt;img" in content

    def test_html_report_target_url_is_escaped(self):
        # v3.1.1 fix: self.target was not HTML-escaped in save_html, allowing
        # a crafted target URL to inject script tags into the report file.
        evil_target = 'https://example.com/<script>alert("xss")</script>'
        s = _make_scanner(evil_target)
        s.result.end_time = "2024-01-01 00:01:00"
        s._finding("INFO", "Recon", "Test", "desc")
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.html")
        s.save_html(path)
        content = open(path).read()
        assert '<script>alert("xss")</script>' not in content
        assert "&lt;script&gt;" in content

    def test_json_report_summary_counts(self):
        s = _make_scanner()
        s.result.end_time = "2024-01-01 00:01:00"
        s._finding("CRITICAL", "SQLi", "T",  "D")
        s._finding("CRITICAL", "SQLi", "T2", "D")
        s._finding("HIGH",     "XSS",  "T3", "D")
        import tempfile, os; tmp_path = tempfile.mkdtemp(); path = os.path.join(tmp_path, "report.json")
        s.save_json(path)
        data = json.load(open(path))
        assert data["summary"]["CRITICAL"] == 2
        assert data["summary"]["HIGH"]     == 1
        assert data["summary"]["MEDIUM"]   == 0


# ══════════════════════════════════════════════════════════════════════════════
# 21. Progress Bar (smoke test — should not raise)
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
