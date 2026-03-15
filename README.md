# 🛡 WebSentinel — Advanced Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-3.0.0-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Bug Bounty](https://img.shields.io/badge/Use%20Case-Bug%20Bounty%20%7C%20Pentest-red)]()

> **For authorized security testing only. Unauthorized use is illegal.**

A professional-grade Python web vulnerability scanner for bug bounty hunters and penetration testers.  
Single file. One dependency (`requests`). 23 scanning modules. 4 report formats.

---

## What's New in v3.0

| Feature | Description |
|---------|-------------|
| **POST Form Injection** | XSS, SQLi, CMDi, Traversal now tested in POST forms too |
| **WAF Detection & Bypass** | Auto-detects 10 WAFs and switches to bypass payloads |
| **Subdomain Takeover** | Checks CNAME targets (GitHub Pages, Heroku, S3, Azure, Netlify, etc.) |
| **GraphQL Introspection** | Finds GraphQL endpoints and dumps full schema |
| **HTTP Request Smuggling** | CL.TE and TE.CL timing-based detection |
| **Prototype Pollution** | Tests GET params and JSON POST bodies |
| **2FA/OTP Bypass** | Empty OTP test + brute-force rate limit check |
| **WebSocket Detection** | Finds WS endpoints in page source and scripts |
| **Progress Bars** | Visual progress for slow modules |
| **Baseline Fingerprinting** | Reduces false positives by comparing against normal responses |
| **Proxy Support** | Route through Burp Suite (`--proxy`) |
| **Severity Filter** | Show only HIGH+ findings (`--severity HIGH`) |
| **Scope Filter** | Limit crawling to a path (`--scope /api`) |

---

## 23 Scanning Modules

| # | Module | What It Does |
|---|--------|-------------|
| 00 | WAF Detection | Identifies Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva + 5 more |
| 01 | Crawler | Finds all GET params + POST forms (2 levels deep) |
| 02 | Reconnaissance | Server headers, tech stack, HTML comments, emails, robots.txt |
| 03 | Subdomain Enum + Takeover | 60+ subdomains, wildcard DNS, CNAME takeover detection |
| 04 | Port Scanning | 28 ports — databases, Docker, Jupyter, Elasticsearch |
| 05 | TLS / SSL | Protocol, cipher strength, cert expiry, SAN validation |
| 06 | Security Headers | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| 07 | Cookies + JWT | Flags, entropy, alg=none, kid injection, missing exp |
| 08 | CORS | 5 origin bypass patterns, credentials reflection |
| 09 | XSS (GET + POST) | 14 payloads + WAF bypass variants across all params and forms |
| 10 | SQL Injection (GET + POST) | Error-based, boolean-blind, time-based (MySQL/MSSQL/PG/SQLite) |
| 11 | Command Injection (GET + POST) | Output-based + time-based, Linux and Windows |
| 12 | Path Traversal (GET + POST) | 9 encoded variants, cross-platform |
| 13 | SSRF | AWS/GCP/Azure/DO metadata, localhost, file:// |
| 14 | Open Redirect | 8 bypass variants |
| 15 | GraphQL | Endpoint discovery, introspection, schema dump |
| 16 | HTTP Request Smuggling | CL.TE and TE.CL timing detection |
| 17 | Prototype Pollution | Query string and JSON body injection |
| 18 | 2FA/OTP Bypass | Empty OTP + rate limit check |
| 19 | WebSocket Detection | Finds WS endpoints, flags for manual testing |
| 20 | Sensitive Files | 55+ paths: .env, .git, SSH keys, logs, admin panels |
| 21 | API Fuzzing | 30+ endpoints, unauthenticated access |
| 22 | Rate Limiting | 30-request burst test |

---

## Installation

```bash
git clone https://github.com/yourusername/websentinel.git
cd websentinel
pip install requests
```

Python 3.8+ required. No other dependencies.

---

## Usage

### Basic scan
```bash
python vuln_scanner.py https://target.com
```

### Authenticated scan
```bash
python vuln_scanner.py https://target.com --cookie "session=abc123; csrf=xyz"
```

### With Bearer token
```bash
python vuln_scanner.py https://target.com --token "eyJhbGciOiJIUzI1NiJ9..."
```

### Route through Burp Suite
```bash
python vuln_scanner.py https://target.com --proxy http://127.0.0.1:8080
```

### Save all report formats
```bash
python vuln_scanner.py https://target.com -o report
# Creates: report.json  report.html  report.md
```

### Only show HIGH and CRITICAL findings
```bash
python vuln_scanner.py https://target.com --severity HIGH
```

### Restrict to API scope only
```bash
python vuln_scanner.py https://target.com --scope /api
```

### Skip slow modules
```bash
python vuln_scanner.py https://target.com --skip ports,subdomains,smuggling
```

### Full example
```bash
python vuln_scanner.py https://target.com \
  --cookie "session=abc123" \
  --proxy http://127.0.0.1:8080 \
  --severity MEDIUM \
  --scope /api \
  --timeout 15 \
  --threads 20 \
  --output report
```

---

## All Options

| Flag | Default | Description |
|------|---------|-------------|
| `target` | *required* | Target URL (`https://example.com`) |
| `-o, --output` | — | Save `BASENAME.json/.html/.md` |
| `--cookie` | — | Cookie header |
| `--token` | — | Bearer token |
| `--header` | — | Custom header `Key:Value` (repeatable) |
| `--proxy` | — | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--user-agent` | WebSentinel UA | Custom User-Agent |
| `--timeout` | 10 | Request timeout (seconds) |
| `--threads` | 10 | Thread pool size |
| `--max-urls` | 30 | Max crawled URLs to inject into |
| `--max-tests` | 300 | Max injection requests per module |
| `--severity` | INFO | Minimum severity: INFO/LOW/MEDIUM/HIGH/CRITICAL |
| `--scope` | — | Restrict crawl to path prefix |
| `--skip` | — | Comma-separated modules to skip |

### Skip module names
```
waf, crawl, recon, subdomains, ports, tls, headers, cookies,
cors, xss, sqli, cmdi, traversal, ssrf, redirect, graphql,
smuggling, prototype, 2fa, websocket, files, api, ratelimit
```

---

## Severity Guide

| Severity | CVSS | Examples |
|----------|------|---------|
| 🔴 CRITICAL | 9.0–10.0 | RCE, SQLi, SSRF to metadata, SSH key, subdomain takeover |
| 🟠 HIGH | 7.0–8.9 | XSS, Path traversal, JWT bypass, open Redis/MongoDB |
| 🟡 MEDIUM | 4.0–6.9 | Missing CSP, no rate limiting, 2FA bypass |
| 🔵 LOW | 1.0–3.9 | Info leakage, missing headers |
| ⚪ INFO | 0.0 | Tech stack, WebSocket endpoints, GraphQL found |

---

## Report Outputs

| Format | Best For |
|--------|---------|
| **Console** | Real-time colored output |
| **JSON** | Tool integration, automation pipelines |
| **HTML** | Dark-theme visual report for clients/teams |
| **Markdown** | Bug bounty write-ups, GitHub submissions |

Every finding includes: CWE ID, CVSS score, evidence snippet, and fix recommendation.

---

## Legal

This tool is for:
- ✅ Your own systems
- ✅ Bug bounty programs (in-scope targets only)
- ✅ Authorized penetration testing
- ✅ CTF challenges
- ❌ Any system without explicit written permission

---

## License

MIT — see [LICENSE](LICENSE)
