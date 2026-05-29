#!/usr/bin/env python3
"""scan.py — audit HTTP security headers for a URL."""

import argparse
import sys
import httpx

from scanner.grader import audit, score
from scanner.display import render, console


EXIT_AB = 0   # grade A or B
EXIT_CD = 1   # grade C or D
EXIT_F  = 2   # grade F or network error


def fetch_headers(url: str, timeout: float = 10.0) -> tuple[str, dict]:
    """
    Perform one HEAD request (falls back to GET if HEAD fails).
    Follows redirects. Returns (final_url, headers_dict).
    """
    with httpx.Client(follow_redirects=True, timeout=timeout,
                      headers={"User-Agent": "http-headers-scanner/1.0"}) as client:
        try:
            resp = client.head(url)
        except httpx.HTTPStatusError:
            resp = client.get(url)
        return str(resp.url), dict(resp.headers)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="scan",
        description="Audit HTTP security headers for a URL.",
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of the rich table")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print(f"\n[dim]Scanning[/dim] [bold]{url}[/bold] …")

    try:
        final_url, headers = fetch_headers(url, timeout=args.timeout)
    except Exception as exc:
        console.print(f"[bold red]Network error:[/bold red] {exc}")
        sys.exit(EXIT_F)

    findings        = audit(headers)
    numeric, grade  = score(findings)

    if args.json:
        import json
        out = {
            "url": url,
            "final_url": final_url,
            "score": numeric,
            "grade": grade,
            "findings": [
                {"header": f.rule.name, "status": f.status,
                 "reason": f.reason, "value": f.value}
                for f in findings
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        render(url, final_url, findings, numeric, grade)

    if grade in ("A", "B"):
        sys.exit(EXIT_AB)
    elif grade in ("C", "D"):
        sys.exit(EXIT_CD)
    else:
        sys.exit(EXIT_F)


if __name__ == "__main__":
    main()
