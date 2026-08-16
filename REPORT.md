# State of AI Company Security — 2026

**We scanned 893 AI company websites. 77% failed a basic security check.**

This is a running, open-data report. It updates automatically as the scan list grows (target: 1,000 companies). Every number below comes straight from the scan data in this repository's pipeline — not from a marketing deck.

---

## The headline

| Stat | Count |
|---|---|
| Websites scanned | **893** |
| Failed the basic check | **688 (77%)** |
| Had **zero** security headers | **233 (26%)** |
| Had 6+ headers (reasonably secured) | **79 (9%)** |
| Had all 8 headers | **4** |

## What "failed" means

Each site was checked for **8 basic security headers** — the standard locks every website should have [settings that tell the browser what to block and what to allow]. A site "fails" if it has **fewer than 4 of the 8**.

The 8 headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy.

> One in four AI companies (26%) has **none** of these. That's the equivalent of leaving the front door unlocked while installing an expensive alarm system.

## The full breakdown

| Headers present | Sites | Share |
|---|---|---|
| 0 | 233 | 26% |
| 1 | 235 | 26% |
| 2 | 129 | 14% |
| 3 | 91 | 10% |
| 4 | 46 | 5% |
| 5 | 80 | 9% |
| 6 | 69 | 8% |
| 7 | 6 | 1% |
| 8 | 4 | 0% |

## Why this matters

Security headers are the **first** layer of defense — not a nice-to-have. They block common attacks (clickjacking, cross-site scripting, data leaks) before an attacker even gets to your application code.

The pattern we keep seeing: AI companies ship fast, add a chatbot or an AI agent on day one, and skip the boring baseline security. That's a problem, because AI adds **new** attack surface on top of a base that isn't locked down yet.

## The free scanner (this repo)

This repo is the scanner we used: **GuardScan**, a single-file Python tool that checks all 8 headers, your TLS certificate, HTTPS redirect, and cookie flags — then prints a graded report with plain-English fixes for everything it finds.

```bash
pip install requests
python guardscan.py yoursite.com
```

No API key. No account. No telemetry.

## Run it on your site — 2 seconds, no signup

→ [arkprivate.com](https://arkprivate.com?utm_source=github&utm_medium=report&utm_campaign=guardscan) — instant scan, copy-paste fixes.

If you've added a chatbot or AI agents, that's where the risk doubles — but start with the free scan.

## Methodology

- **What:** the homepage of each company's primary domain.
- **How:** the open-source scanner in this repo (8 headers, over HTTPS).
- **When:** data as of August 16, 2026; updated automatically.
- **Fail threshold:** fewer than 4 of 8 security headers present.
- **Source list:** AI/ML companies from public startup and model directories.

---

*Open data. Open scanner. Questions or corrections: open an issue in this repo.*
