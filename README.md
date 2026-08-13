# GuardScan

**A professional website security scanner in a single file.** Checks 8 security headers, your TLS certificate, HTTPS redirection, and cookie flags — then returns a graded report with severity, impact, and exact remediation for every finding.

```
════════════════════════════════════════════════════════
  GuardScan — Security Assessment Report
════════════════════════════════════════════════════════
  Target:    example.com
  Scanned:   2026-08-13T09:57:47 (UTC)
  Score:     84/100  (Grade B)

  Critical: 0   High: 0   Medium: 1   Low: 2
  ...
```

---

## Quick start

```bash
# 1. Install one dependency
pip install requests

# 2. Scan a site
python guardscan.py yoursite.com

# 3. Scan several at once
python guardscan.py yoursite.com other.com third.com

# 4. Machine-readable output
python guardscan.py yoursite.com --json
```

That's it. No API key, no account, no telemetry.

---

## What GuardScan checks

| Check | Severity | What it prevents |
|---|---|---|
| Content-Security-Policy | Critical | Cross-site scripting (XSS) |
| Strict-Transport-Security | High | Cleartext / MITM interception |
| Cross-Origin-Opener-Policy | Medium | Cross-site interaction (Spectre) |
| X-Content-Type-Options | Medium | MIME sniffing / stored XSS |
| X-Frame-Options | Medium | Clickjacking |
| Cross-Origin-Resource-Policy | Low | Cross-origin resource leakage |
| Referrer-Policy | Low | Token / path leakage in referrer |
| Permissions-Policy | Low | Camera / mic / geolocation abuse |
| TLS certificate | Critical | Invalid or expiring cert |
| HTTPS redirect | High | Plain-HTTP traffic exposure |
| Cookies (Secure/HttpOnly/SameSite) | Medium | Session theft & CSRF |
| Server header | Low | Version disclosure |

## Every finding includes

- **Severity** (critical / high / medium / low) + the relevant **CWE**
- **Impact** — the attack it enables, in plain terms
- **Fix** — what to do
- **Nginx** — copy-paste `add_header` directive
- **Generic** — the raw header value (works on any CDN/host)
- **Reference** — OWASP / CWE / MDN

## Scoring

- **90–100 — A** · 80–89 B · 70–79 C · 60–69 D · below 60 F

## Why this exists

We scanned hundreds of AI company websites and found most fail basic security checks — **the full data is in our [AI Security Report](https://arkprivate.com/ai-security-report.html)**. GuardScan is the free tool from that research, so anyone can assess their own site in seconds.

## About the product

GuardScan is the free scanner from [Ark Private](https://arkprivate.com). If you run an AI chatbot or AI agents, ArkGuard sandboxes them and PromptGuard tests them against prompt-injection. Free scan first; continuous protection if you need it.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
