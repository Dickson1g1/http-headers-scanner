```
 ██╗  ██╗████████╗████████╗██████╗
 ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗
 ███████║   ██║      ██║   ██████╔╝
 ██╔══██║   ██║      ██║   ██╔═══╝
 ██║  ██║   ██║      ██║   ██║
 ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝

 ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
 ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
 ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
 ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
 ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

   audit response headers · score · grade · recommend
```

# http-headers-scanner

> Audit any URL's HTTP response headers for missing or weak security controls.
> Get a scored report, a letter grade, and actionable recommendations — in one command.

---

## What it does

`http-headers-scanner` performs a single polite HTTPS request to the URL you
provide and inspects the response headers against a weighted security rubric.
It reports each of six critical headers as `ok`, `weak`, or `missing`, computes
a 0–100 score, maps it to an A–F letter grade, and prints a full recommendation
for every non-`ok` finding.

```
$ python scan.py https://example.com

Scanning https://example.com …

╭──────────────────────────────────┬─────────────┬──────────────────────────────────────────────────╮
│ Header                           │ Status      │ Finding                                          │
├──────────────────────────────────┼─────────────┼──────────────────────────────────────────────────┤
│ Strict-Transport-Security        │ ✔ ok        │ HSTS enabled with max-age >= 1 year              │
│ Content-Security-Policy          │ ✘ missing   │ No CSP — XSS protections rely solely on browser  │
│ X-Frame-Options                  │ ✔ ok        │ Clickjacking protection enabled (DENY)           │
│ X-Content-Type-Options           │ ✔ ok        │ MIME-sniffing disabled (nosniff)                 │
│ Referrer-Policy                  │ ⚠ weak      │ Referrer-Policy absent — URL may leak            │
│ Permissions-Policy               │ ✘ missing   │ Permissions-Policy absent — APIs unrestricted    │
╰──────────────────────────────────┴─────────────┴──────────────────────────────────────────────────╯

  Score: 65/100   Grade: D

Recommendations
  ✘  Content-Security-Policy
     Add a restrictive CSP; start with: default-src 'self'
  ⚠  Referrer-Policy
     Add: Referrer-Policy: strict-origin-when-cross-origin
  ✘  Permissions-Policy
     Add: Permissions-Policy: geolocation=(), camera=(), microphone=()
```

---

## Features

- **Six security-critical headers audited** — Strict-Transport-Security (HSTS),
  Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, and Permissions-Policy
- **Weighted rubric** — high-impact headers (HSTS, CSP) worth 30 pts each;
  medium (XFO, XCTO, Referrer-Policy) 15 pts; low (Permissions-Policy) 5 pts
- **Three-state findings** — `ok`, `weak`, or `missing` with a one-line reason
  for every header
- **Subtle breakage detection** — catches `Strict-Transport-Security: max-age=0`
  (header present, protection actively disabled) and flags it `weak`, not `ok`
- **Redirect-aware** — follows redirects and grades the final URL, the one a
  browser actually lands on; shows the redirect path if it differs
- **HEAD-then-GET fallback** — tries HEAD first to avoid downloading the body;
  retries with GET if the server rejects HEAD
- **0–100 score + A–F letter grade** — 90+ = A, 80+ = B, 70+ = C, 60+ = D,
  below 60 = F
- **Actionable recommendations** — one concrete fix per non-`ok` finding
- **Rich colored terminal output** — results table, grade panel, and
  recommendations list rendered with `rich`
- **JSON mode** — `--json` flag outputs structured results for piping to `jq`
  or ingesting into dashboards
- **CI-friendly exit codes** — `0` for A/B, `1` for C/D, `2` for F or
  network error; drop it straight into a pipeline gate
- **Pure-function core** — `audit()` and `score()` are fully decoupled from
  I/O and trivially unit-testable

---

## Requirements

- Python 3.10+
- [`httpx`](https://www.python-httpx.org/) — modern HTTP client with redirect support
- [`rich`](https://github.com/Textualize/rich) — terminal rendering

```bash
pip install httpx rich
```

---

## Installation

```bash
git clone https://github.com/Dickson1g1/password-manager.git
cd http-headers-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install httpx rich
chmod +x scan.py
```

---

## Usage

```bash
# Basic scan
python scan.py https://example.com

# Scheme is optional — https:// is prepended automatically
python scan.py github.com

# Custom timeout (default 10s)
python scan.py https://slow-site.com --timeout 20

# JSON output — pipe to jq
python scan.py https://example.com --json | jq '.grade'

# Use in a CI pipeline
python scan.py https://your-app.com || exit 1
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Grade A or B — headers in good shape |
| `1`  | Grade C or D — improvements needed |
| `2`  | Grade F, or network / connection error |

---

## Scoring rubric

| Header | Weight | Why |
|--------|--------|-----|
| Strict-Transport-Security | 30 pts | Prevents protocol downgrade and cookie hijacking |
| Content-Security-Policy   | 30 pts | Primary defence against XSS |
| X-Frame-Options           | 15 pts | Prevents clickjacking via iframe embedding |
| X-Content-Type-Options    | 15 pts | Stops MIME-type sniffing attacks |
| Referrer-Policy           | 15 pts | Controls URL leakage to third parties |
| Permissions-Policy        | 5 pts  | Restricts browser API access (camera, mic, etc.) |

`ok` = full points · `weak` = half points · `missing` = 0 points

---

## Project structure

```
http-headers-scanner/
├── scanner/
│   ├── __init__.py
│   ├── rules.py        # header rubric — weights, validators, recommendations
│   ├── grader.py       # audit() + score() — pure functions, no I/O
│   └── display.py      # rich table, grade panel, recommendations list
├── scan.py             # CLI entrypoint
└── tests/
    └── test_grader.py
```

---

## Running tests

```bash
python tests/test_grader.py
```

All tests exercise `audit()` and `score()` directly with plain dicts — no
network required.

---

## Use cases

- **Security audits** — quickly check any site before or after a deployment
- **CI/CD pipeline gate** — fail a build if security headers drop below grade B
- **Developer workflow** — run against `localhost` during development to catch
  missing headers before they reach production
- **Penetration testing recon** — enumerate header posture as part of an
  initial assessment

---

## License

MIT — do whatever you want, attribution appreciated.
