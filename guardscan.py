#!/usr/bin/env python3
"""
GuardScan — professional website security header & TLS scanner.

Performs a remote security assessment of a target website:
  - 7 security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy, Permissions-Policy, X-XSS-Protection)
  - TLS certificate (issuer, validity, expiry)
  - HTTPS redirection
  - Cookie attributes (Secure, HttpOnly, SameSite)
  - Server version disclosure

Each finding includes severity, impact, remediation (Nginx + generic), and a
reference (OWASP / CWE / MDN). Output is a graded report; use --json for
machine-readable output.

Usage:
    python guardscan.py example.com
    python guardscan.py example.com other.com
    python guardscan.py example.com --json

Dependency:
    pip install requests
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("Error: 'requests' is required. Install with:  pip install requests")
    sys.exit(1)

REQUEST_TIMEOUT = 10


# ─────────────────────────────────────────────────────────────────────
# SECURITY HEADER DEFINITIONS
# Each entry: the check, its severity, what it prevents, the fix (Nginx +
# generic), and a reference. This is the "computer engineer" knowledge base.
# ─────────────────────────────────────────────────────────────────────

HEADERS = [
    {
        "name": "Content-Security-Policy",
        "severity": "critical",
        "cwe": "CWE-79 (Cross-Site Scripting)",
        "impact": (
            "Without CSP, a single injected script can execute in your users' "
            "browsers with your site's privileges — stealing sessions, logging "
            "keystrokes, or defacing the page. This is the most important "
            "defence-in-depth control a website can deploy."
        ),
        "fix": (
            "Define a policy that only allows resources from your own origin. "
            "Start restrictive and loosen only where a feature breaks."
        ),
        "nginx": (
            'add_header Content-Security-Policy "default-src \'self\'; '
            "script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; object-src 'none'; frame-ancestors 'self'; "
            "base-uri 'self'; form-action 'self'\" always;"
        ),
        "generic": (
            'Content-Security-Policy: default-src \'self\'; object-src \'none\'; '
            "frame-ancestors 'self'"
        ),
        "reference": "OWASP CSP Cheat Sheet · MDN Content-Security-Policy",
    },
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "cwe": "CWE-319 (Cleartext Transmission)",
        "impact": (
            "Without HSTS, a user can still reach your site over plain HTTP "
            "(e.g. typing the domain without https://), exposing traffic to "
            "man-in-the-middle interception and credential theft."
        ),
        "fix": (
            "Send the header with a long max-age and includeSubDomains. Add "
            "'preload' only after confirming every subdomain is HTTPS."
        ),
        "nginx": (
            'add_header Strict-Transport-Security "max-age=31536000; '
            'includeSubDomains; preload" always;'
        ),
        "generic": (
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "reference": "OWASP HSTS Cheat Sheet · CWE-319",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "cwe": "CWE-646 (MIME Sniffing)",
        "impact": (
            "Without 'nosniff', browsers may guess (sniff) a file's type and "
            "execute a text file as a script, enabling stored-XSS via uploaded "
            "content."
        ),
        "fix": "Set the header to exactly 'nosniff'. No configuration needed beyond that.",
        "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
        "generic": "X-Content-Type-Options: nosniff",
        "reference": "OWASP Secure Headers · CWE-646",
    },
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "cwe": "CWE-1021 (Clickjacking)",
        "impact": (
            "Without frame protection, an attacker can embed your site in an "
            "invisible iframe and trick users into clicking actions they never "
            "intended (e.g. approving a transfer, changing settings)."
        ),
        "fix": (
            "Send DENY (strongest) or SAMEORIGIN (if you frame your own pages). "
            "Note: CSP 'frame-ancestors' is the modern equivalent and supersedes this."
        ),
        "nginx": 'add_header X-Frame-Options "DENY" always;',
        "generic": "X-Frame-Options: DENY",
        "reference": "OWASP Clickjacking Defense · CWE-1021",
    },
    {
        "name": "Referrer-Policy",
        "severity": "low",
        "cwe": "CWE-200 (Information Exposure)",
        "impact": (
            "The Referer header can leak full URLs — including tokens and "
            "sensitive paths — to third-party analytics, CDNs, or ad networks."
        ),
        "fix": (
            "Use 'strict-origin-when-cross-origin': send only the origin "
            "cross-site, and nothing on HTTPS-to-HTTP downgrades."
        ),
        "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "generic": "Referrer-Policy: strict-origin-when-cross-origin",
        "reference": "MDN Referrer-Policy · OWASP",
    },
    {
        "name": "Permissions-Policy",
        "severity": "low",
        "cwe": "CWE-200 (Information Exposure)",
        "impact": (
            "Without a policy, embedded content can request powerful browser "
            "features — camera, microphone, geolocation — without your consent."
        ),
        "fix": (
            "Deny features your site never needs; allow only those you "
            "explicitly use (e.g. 'geolocation=(self)')."
        ),
        "nginx": (
            'add_header Permissions-Policy "camera=(), microphone=(), '
            'geolocation=(), payment=(), usb=()" always;'
        ),
        "generic": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "reference": "MDN Permissions-Policy · OWASP",
    },
    {
        "name": "X-XSS-Protection",
        "severity": "low",
        "cwe": "CWE-79 (Cross-Site Scripting)",
        "impact": (
            "Without X-XSS-Protection, older browsers do not filter "
            "reflected cross-site scripting attempts, allowing injected "
            "scripts to execute in the page."
        ),
        "fix": (
            "Set '1; mode=block' to enable the browser's built-in XSS "
            "filter and block the page outright when an attack is detected."
        ),
        "nginx": 'add_header X-XSS-Protection "1; mode=block" always;',
        "generic": "X-XSS-Protection: 1; mode=block",
        "reference": "MDN X-XSS-Protection",
    },
]


# ─────────────────────────────────────────────────────────────────────
# SCAN FUNCTIONS
# ─────────────────────────────────────────────────────────────────────

def normalize_domain(domain):
    domain = domain.strip().lower()
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    hostname = urlparse(domain).hostname or urlparse(domain).path
    return hostname.replace("www.", "")


def check_tls(domain):
    """Inspect the TLS certificate and negotiated protocol."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                not_after = cert.get("notAfter", "")
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                return {
                    "valid": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "subject_cn": subject.get("commonName", domain),
                    "tls_version": tls_version,
                    "days_left": days_left,
                    "expiry": not_after,
                    "status": ("good" if days_left > 30 else
                               ("warning" if days_left > 7 else "critical")),
                }
    except Exception as e:
        return {"valid": False, "error": str(e)[:120]}


def check_https_redirect(domain):
    """Verify http:// redirects to https://."""
    try:
        r = requests.get(f"http://{domain}", timeout=REQUEST_TIMEOUT,
                         allow_redirects=False,
                         headers={"User-Agent": "GuardScan/2.0"})
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc.startswith("https://"):
                return {"redirects": True, "status": r.status_code, "target": loc}
            return {"redirects": False, "status": r.status_code,
                    "target": loc, "note": "redirects to non-HTTPS location"}
        if r.status_code == 200:
            return {"redirects": False, "status": 200,
                    "note": "serves content over plain HTTP"}
        return {"redirects": False, "status": r.status_code}
    except Exception as e:
        return {"redirects": False, "error": str(e)[:120]}


def check_headers(domain):
    """Fetch the site and inspect headers + cookies."""
    try:
        resp = requests.get(
            f"https://{domain}", timeout=REQUEST_TIMEOUT, allow_redirects=True,
            headers={"User-Agent": "GuardScan/2.0 (Security Scanner)"},
        )
        raw = {k.lower(): v for k, v in resp.headers.items()}

        headers = {}
        for h in HEADERS:
            hl = h["name"].lower()
            headers[h["name"]] = {
                "present": hl in raw,
                "value": raw.get(hl, None),
            }

        # Cookies — Secure, HttpOnly, SameSite
        cookies = []
        set_cookie = raw.get("set-cookie", "")
        for cookie in resp.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly")
                                 or cookie.has_nonstandard_attr("httponly")),
                # SameSite detected from the raw header string
                "samesite": ("Lax" if "samesite=lax" in set_cookie.lower()
                             else "Strict" if "samesite=strict" in set_cookie.lower()
                             else "None" if "samesite=none" in set_cookie.lower()
                             else "missing"),
            })

        return {
            "reachable": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": headers,
            "cookies": cookies,
            "server_header": raw.get("server", ""),
            "response_time_ms": round(resp.elapsed.total_seconds() * 1000),
        }
    except requests.exceptions.SSLError:
        return {"reachable": False, "error": "SSL certificate invalid or expired"}
    except requests.exceptions.ConnectionError:
        return {"reachable": False, "error": "Could not connect to server"}
    except requests.exceptions.Timeout:
        return {"reachable": False, "error": "Connection timed out"}
    except Exception as e:
        return {"reachable": False, "error": str(e)[:200]}


# ─────────────────────────────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────────────────────────────

SEVERITY_PENALTY = {"critical": 30, "high": 20, "medium": 8, "low": 4}


def analyze(domain):
    clean = normalize_domain(domain)
    tls = check_tls(clean)
    headers = check_headers(clean)
    redirect = check_https_redirect(clean)

    # Unreachable → short-circuit
    if not headers.get("reachable") and not tls.get("valid"):
        return {"domain": clean, "score": 0, "unreachable": True,
                "findings": [], "passing": [], "tls": tls, "redirect": redirect,
                "scanned_at": datetime.now(timezone.utc).isoformat()}

    findings = []
    passing = []

    # 1. Security header findings
    for h in HEADERS:
        state = headers.get("headers", {}).get(h["name"], {})
        if not state.get("present"):
            findings.append({
                "check": h["name"], "status": "missing",
                "severity": h["severity"], "cwe": h["cwe"],
                "impact": h["impact"], "fix": h["fix"],
                "nginx": h["nginx"], "generic": h["generic"],
                "reference": h["reference"],
            })
        else:
            passing.append({"check": h["name"], "status": "present",
                            "value": state.get("value")})

    # 2. TLS findings
    if not tls.get("valid"):
        findings.append({
            "check": "TLS certificate", "status": "invalid", "severity": "critical",
            "cwe": "CWE-295 (Improper Certificate Validation)",
            "impact": "The TLS certificate is invalid or could not be verified. "
                      "Traffic cannot be trusted to be encrypted or authenticated.",
            "fix": "Install a valid certificate from a trusted CA and ensure the "
                   "hostname matches.",
            "nginx": "ssl_certificate /etc/ssl/fullchain.pem;  ssl_certificate_key /etc/ssl/privkey.pem;",
            "generic": "Provision a valid certificate (e.g. Let's Encrypt via certbot).",
            "reference": "CWE-295",
        })
    else:
        if tls.get("status") == "critical":
            findings.append({
                "check": "TLS certificate expiry", "status": "expiring",
                "severity": "critical", "cwe": "CWE-295",
                "impact": f"Certificate expires in {tls['days_left']} days. "
                          "On expiry your site will show a browser warning and lose all traffic.",
                "fix": "Renew the certificate immediately and automate renewal.",
                "nginx": "certbot renew --dry-run   # then ensure a cron job runs 'certbot renew'",
                "generic": "Enable auto-renewal (Let's Encrypt renews every 60-90 days).",
                "reference": "Let's Encrypt docs",
            })
        elif tls.get("status") == "warning":
            findings.append({
                "check": "TLS certificate expiry", "status": "expiring soon",
                "severity": "medium", "cwe": "CWE-295",
                "impact": f"Certificate expires in {tls['days_left']} days.",
                "fix": "Schedule renewal well before expiry.",
                "nginx": "certbot renew",
                "generic": "Ensure auto-renewal is active.",
                "reference": "Let's Encrypt docs",
            })
        else:
            passing.append({"check": "TLS certificate",
                            "status": "valid",
                            "value": f"{tls['issuer']} · {tls['days_left']} days · {tls.get('tls_version','')}"})

    # 3. HTTPS redirect finding
    if not redirect.get("redirects"):
        findings.append({
            "check": "HTTPS redirect", "status": "not enforced",
            "severity": "high", "cwe": "CWE-319",
            "impact": "Visitors can reach the site over plain HTTP, where traffic "
                      "is unencrypted and vulnerable to interception.",
            "fix": "Permanently redirect all HTTP traffic to HTTPS.",
            "nginx": "server { listen 80; server_name example.com; return 301 https://$host$request_uri; }",
            "generic": "Enable 'force HTTPS redirect' in your CDN/host (Vercel, Cloudflare, Netlify).",
            "reference": "OWASP Transport Layer Protection",
        })
    else:
        passing.append({"check": "HTTPS redirect", "status": "enforced",
                        "value": f"HTTP {redirect.get('status')} → {redirect.get('target','https')}"})

    # 4. Cookie findings
    for c in headers.get("cookies", []):
        problems = []
        if not c["secure"]:
            problems.append("Secure flag missing")
        if not c["httponly"]:
            problems.append("HttpOnly flag missing")
        if c["samesite"] == "missing":
            problems.append("SameSite attribute missing")
        if problems:
            findings.append({
                "check": f"Cookie '{c['name']}'", "status": ", ".join(problems),
                "severity": "medium", "cwe": "CWE-614 (Insecure Cookie)",
                "impact": f"The cookie '{c['name']}' lacks: {', '.join(problems)}. "
                          "Without Secure it can leak over HTTP; without HttpOnly "
                          "it can be stolen by XSS; without SameSite it is exposed to CSRF.",
                "fix": "Set the flags when issuing the cookie.",
                "nginx": f"add_header Set-Cookie \"{c['name']}=...; Secure; HttpOnly; SameSite=Lax; Path=/\";",
                "generic": f"Set-Cookie: {c['name']}=...; Secure; HttpOnly; SameSite=Lax",
                "reference": "OWASP Session Management · CWE-614",
            })

    # 5. Server header finding
    server = headers.get("server_header", "")
    if server:
        findings.append({
            "check": "Server header disclosure", "status": f"exposes '{server}'",
            "severity": "low", "cwe": "CWE-200",
            "impact": "Revealing the server name/version helps an attacker target "
                      "known exploits for that specific software.",
            "fix": "Remove or neutralise the Server header.",
            "nginx": "server_tokens off;   # then: add_header Server \"\" always;  (or proxy_hide_header Server;)",
            "generic": "Most CDNs/hosts let you remove the Server header in settings.",
            "reference": "CWE-200",
        })

    # Score
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f["severity"], 5)
    score = max(0, min(100, score))

    return {"domain": clean, "score": score, "unreachable": False,
            "findings": findings, "passing": passing, "tls": tls,
            "redirect": redirect,
            "scanned_at": datetime.now(timezone.utc).isoformat()}


def grade(score):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ─────────────────────────────────────────────────────────────────────
# REPORT RENDERING
# ─────────────────────────────────────────────────────────────────────

def render(result):
    if result.get("unreachable"):
        return (f"========================================\n"
                f"  GuardScan — {result['domain']}\n"
                f"========================================\n"
                f"  Site unreachable — could not connect.\n")

    L = []
    bar = "═" * 56
    L.append(bar)
    L.append(f"  GuardScan — Security Assessment Report")
    L.append(bar)
    L.append(f"  Target:    {result['domain']}")
    L.append(f"  Scanned:   {result['scanned_at'][:19]} (UTC)")
    L.append(f"  Score:     {result['score']}/100  (Grade {grade(result['score'])})")
    L.append("")

    sev_order = ["critical", "high", "medium", "low"]
    counts = {s: sum(1 for f in result["findings"] if f["severity"] == s) for s in sev_order}
    L.append(f"  Critical: {counts['critical']}   High: {counts['high']}   "
             f"Medium: {counts['medium']}   Low: {counts['low']}")
    L.append("")

    if result["findings"]:
        L.append("─" * 56)
        L.append("  FINDINGS")
        L.append("─" * 56)
        for sev in sev_order:
            for f in result["findings"]:
                if f["severity"] != sev:
                    continue
                L.append("")
                L.append(f"[{f['severity'].upper()}] {f['check']}")
                L.append(f"  Status:      {f['status']}")
                L.append(f"  Severity:    {f['severity']}  ·  {f.get('cwe','')}")
                L.append(f"  Impact:      {f['impact']}")
                L.append(f"  Fix:         {f['fix']}")
                if f.get("nginx"):
                    L.append(f"  Nginx:       {f['nginx']}")
                L.append(f"  Generic:     {f.get('generic','')}")
                L.append(f"  Reference:   {f.get('reference','')}")
    else:
        L.append("  No findings — all checks passed.")

    if result["passing"]:
        L.append("")
        L.append("─" * 56)
        L.append("  PASSING CHECKS")
        L.append("─" * 56)
        for p in result["passing"]:
            val = f"  ({p['value']})" if p.get("value") else ""
            L.append(f"  ✓ {p['check']}{val}")

    L.append("")
    L.append(bar)
    return "\n".join(L)


def main():
    parser = argparse.ArgumentParser(
        description="GuardScan — professional website security header & TLS scanner")
    parser.add_argument("domains", nargs="+", help="Domain(s) to scan, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    results = [analyze(d) for d in args.domains]

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for i, r in enumerate(results):
            if i:
                print("\n\n")
            print(render(r))


if __name__ == "__main__":
    main()
