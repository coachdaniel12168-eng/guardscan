#!/usr/bin/env python3
"""GuardScan — free website security header scanner.

Checks 7 critical security headers + SSL certificate, returns a 0-100 score
and a list of issues. Free forever. Runs anywhere Python 3.7+ runs.

Usage:
    python guardscan.py example.com
    python guardscan.py example.com other.com
    python guardscan.py example.com --json

Install dependency:
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

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"weight": "high"},
    "Content-Security-Policy": {"weight": "high"},
    "X-Frame-Options": {"weight": "medium"},
    "X-Content-Type-Options": {"weight": "medium"},
    "Referrer-Policy": {"weight": "low"},
    "Permissions-Policy": {"weight": "low"},
    "X-XSS-Protection": {"weight": "low"},
}

WEIGHT_PENALTY = {"high": 10, "medium": 5, "low": 2}


def normalize_domain(domain):
    """Strip protocol, path, and www prefix."""
    domain = domain.strip().lower()
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain
    hostname = urlparse(domain).hostname or urlparse(domain).path
    return hostname.replace("www.", "")


def check_ssl_cert(domain):
    """Check SSL certificate validity and expiry."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                issuer = dict(x[0] for x in cert.get("issuer", []))
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                return {
                    "valid": True,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "days_left": days_left,
                    "expiry": not_after,
                    "status": "good" if days_left > 30 else ("warning" if days_left > 7 else "critical"),
                }
    except Exception as e:
        return {"valid": False, "error": str(e)[:100]}


def check_headers(domain):
    """Check security headers, cookies, and server header."""
    results = {}
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "GuardScan/1.0 (Security Scanner)"},
        )
        response_headers = {k.lower(): v for k, v in resp.headers.items()}
        for header in SECURITY_HEADERS:
            hl = header.lower()
            results[header] = {
                "present": hl in response_headers,
                "value": response_headers.get(hl, None),
            }
        cookies = []
        for cookie in resp.cookies:
            cookies.append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")),
            })
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": results,
            "cookies": cookies,
            "server_header": response_headers.get("server", ""),
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


def run_scan(domain):
    """Run a full scan: SSL + headers + score."""
    clean = normalize_domain(domain)
    ssl_result = check_ssl_cert(clean)
    header_result = check_headers(clean)

    # Unreachable site — no meaningful scan possible
    if not header_result.get("reachable") and not ssl_result.get("valid"):
        return {
            "domain": clean,
            "score": 0,
            "ssl": ssl_result,
            "headers": header_result,
            "issues": ["Site unreachable — could not connect"],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "unreachable": True,
        }

    score = 100
    issues = []

    if not ssl_result.get("valid"):
        score -= 30
        issues.append("HTTPS not available or SSL invalid")
    elif ssl_result.get("status") == "critical":
        score -= 25
        issues.append(f"SSL certificate expires in {ssl_result['days_left']} days")
    elif ssl_result.get("status") == "warning":
        score -= 10
        issues.append(f"SSL certificate expires in {ssl_result['days_left']} days")

    if header_result.get("reachable"):
        for header, result in header_result["headers"].items():
            if not result["present"]:
                penalty = WEIGHT_PENALTY.get(SECURITY_HEADERS[header]["weight"], 5)
                score -= penalty
                issues.append(f"Missing {header}")
        insecure_cookies = [c for c in header_result.get("cookies", []) if not c["secure"]]
        if insecure_cookies:
            score -= 5
            issues.append(f"{len(insecure_cookies)} cookie(s) without Secure flag")
        if header_result.get("server_header"):
            score -= 5
            issues.append(f"Server header exposes version: {header_result['server_header']}")

    score = max(0, min(100, score))
    return {
        "domain": clean,
        "score": score,
        "ssl": ssl_result,
        "headers": header_result,
        "issues": issues,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def render_text(result):
    """Render a human-readable report."""
    lines = []
    lines.append("=" * 56)
    lines.append(f"  GuardScan — {result['domain']}")
    lines.append("=" * 56)
    lines.append(f"  Score: {result['score']}/100")

    if result["score"] >= 80:
        lines.append("  Verdict: Good — minor gaps only")
    elif result["score"] >= 50:
        lines.append("  Verdict: Needs work — several gaps")
    else:
        lines.append("  Verdict: Critical — significant gaps")

    lines.append("")
    lines.append("  Issues:")
    if result["issues"]:
        for issue in result["issues"]:
            lines.append(f"    - {issue}")
    else:
        lines.append("    None — all checks passed.")

    if result["ssl"].get("valid"):
        lines.append("")
        lines.append(f"  SSL: valid (issuer {result['ssl']['issuer']}, expires in {result['ssl']['days_left']} days)")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="GuardScan — free website security header scanner")
    parser.add_argument("domains", nargs="+", help="Domain(s) to scan, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    args = parser.parse_args()

    results = [run_scan(d) for d in args.domains]

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for r in results:
            print(render_text(r))


if __name__ == "__main__":
    main()
