# GuardScan

**A free, one-file website security scanner.** Checks 7 critical security headers and your SSL certificate, returns a 0–100 score and a list of exactly what to fix. Runs anywhere Python runs.

```
$ python guardscan.py example.com

========================================================
  GuardScan — example.com
========================================================
  Score: 60/100
  Verdict: Needs work — several gaps

  Issues:
    - Missing Content-Security-Policy
    - Missing X-Frame-Options
    - 2 cookie(s) without Secure flag

  SSL: valid (issuer Let's Encrypt, expires in 83 days)
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

| Check | Why it matters |
|---|---|
| Strict-Transport-Security | Forces HTTPS, prevents downgrade attacks |
| Content-Security-Policy | Stops cross-site scripting (XSS) |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Stops MIME sniffing |
| Referrer-Policy | Controls referrer leakage |
| Permissions-Policy | Limits camera/mic/geolocation access |
| X-XSS-Protection | Legacy XSS filter |
| SSL certificate | Validity and expiry (30/7-day warnings) |
| Cookies | Secure + HttpOnly flags |
| Server header | Version disclosure |

## How it works

GuardScan sends a single HTTPS request to the target domain, inspects the response headers and cookies, and validates the SSL certificate. It never touches the target's server beyond a normal GET request — the same as a browser visit. Each missing header is weighted by severity (high/medium/low) and subtracted from a 100-point baseline.

## Scoring

- **80–100** — good, minor gaps only
- **50–79** — needs work, several gaps
- **0–49** — critical, significant gaps

## Why this exists

We scanned hundreds of AI company websites and found most fail basic security checks — **the full data is in our [AI Security Report](https://arkprivate.com/ai-security-report.html)**. GuardScan is the free tool from that research, so anyone can check their own site in seconds.

## About the product

GuardScan is the free scanner from [Ark Private](https://arkprivate.com) — an AI safety suite. If you run an AI bot or AI agents, ArkGuard sandboxes them and PromptGuard tests them against prompt-injection. Free scan first; continuous protection if you need it.

## License

[MIT](LICENSE)
