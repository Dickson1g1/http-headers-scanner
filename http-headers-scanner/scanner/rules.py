import re
from dataclasses import dataclass, field
from typing import Callable, Optional

@dataclass
class Rule:
    name: str           # exact header name (case-insensitive match done in grader)
    weight: int         # 30 = high, 15 = medium, 5 = low
    ok: Callable[[str], bool]
    weak: Callable[[str], bool]
    ok_reason: str
    weak_reason: str
    missing_reason: str
    recommendation: str


def _hsts_ok(v: str) -> bool:
    m = re.search(r'max-age\s*=\s*(\d+)', v, re.I)
    return bool(m) and int(m.group(1)) >= 31536000

def _hsts_weak(v: str) -> bool:
    m = re.search(r'max-age\s*=\s*(\d+)', v, re.I)
    return bool(m) and int(m.group(1)) == 0

def _csp_ok(v: str) -> bool:
    v = v.lower()
    return "default-src" in v and "unsafe-inline" not in v and "unsafe-eval" not in v

def _csp_weak(v: str) -> bool:
    return "default-src" in v.lower()  # present but allows unsafe

def _xfo_ok(v: str) -> bool:
    return v.strip().upper() in ("DENY", "SAMEORIGIN")

def _xfo_weak(v: str) -> bool:
    return "ALLOW-FROM" in v.upper()   # deprecated directive

def _xcto_ok(v: str) -> bool:
    return v.strip().lower() == "nosniff"

def _rp_ok(v: str) -> bool:
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "no-referrer-when-downgrade"}
    return v.strip().lower() in safe

def _pp_ok(v: str) -> bool:
    return len(v.strip()) > 0  # any value is fine; absence is the problem


RULES: list[Rule] = [
    Rule(
        name="Strict-Transport-Security",
        weight=30,
        ok=_hsts_ok,
        weak=_hsts_weak,
        ok_reason="HSTS enabled with max-age >= 1 year",
        weak_reason="max-age=0 actively disables HSTS",
        missing_reason="HSTS header absent — browser may allow downgrade attacks",
        recommendation="Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    Rule(
        name="Content-Security-Policy",
        weight=30,
        ok=_csp_ok,
        weak=_csp_weak,
        ok_reason="CSP present with no unsafe directives",
        weak_reason="CSP present but allows unsafe-inline or unsafe-eval",
        missing_reason="No CSP — XSS protections rely solely on the browser",
        recommendation="Add a restrictive CSP; start with: default-src 'self'",
    ),
    Rule(
        name="X-Frame-Options",
        weight=15,
        ok=_xfo_ok,
        weak=_xfo_weak,
        ok_reason="Clickjacking protection enabled (DENY or SAMEORIGIN)",
        weak_reason="ALLOW-FROM is deprecated and unsupported in modern browsers",
        missing_reason="X-Frame-Options absent — page may be embeddable in iframes",
        recommendation="Add: X-Frame-Options: DENY  (or use CSP frame-ancestors instead)",
    ),
    Rule(
        name="X-Content-Type-Options",
        weight=15,
        ok=_xcto_ok,
        weak=lambda v: False,
        ok_reason="MIME-sniffing disabled (nosniff)",
        weak_reason="",
        missing_reason="X-Content-Type-Options absent — browser may sniff MIME types",
        recommendation="Add: X-Content-Type-Options: nosniff",
    ),
    Rule(
        name="Referrer-Policy",
        weight=15,
        ok=_rp_ok,
        weak=lambda v: False,
        ok_reason="Referrer policy is privacy-safe",
        weak_reason="",
        missing_reason="Referrer-Policy absent — full URL may leak to third parties",
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    Rule(
        name="Permissions-Policy",
        weight=5,
        ok=_pp_ok,
        weak=lambda v: False,
        ok_reason="Permissions-Policy header present",
        weak_reason="",
        missing_reason="Permissions-Policy absent — browser APIs unrestricted",
        recommendation="Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    ),
]
