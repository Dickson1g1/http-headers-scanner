from .rules import RULES, Rule
from dataclasses import dataclass

STATUS_OK      = "ok"
STATUS_WEAK    = "weak"
STATUS_MISSING = "missing"

GRADE_MAP = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "F"),
]

@dataclass
class Finding:
    rule: Rule
    status: str      # "ok" | "weak" | "missing"
    value: str       # actual header value, or "" if missing
    reason: str      # one-line explanation


def audit(headers: dict[str, str]) -> list[Finding]:
    """
    Pure function. Takes a {header-name: value} dict (any case).
    Returns one Finding per rule.
    """
    # Normalize header names to lowercase for lookup
    normalized = {k.lower(): v for k, v in headers.items()}
    findings = []

    for rule in RULES:
        key = rule.name.lower()
        if key not in normalized:
            findings.append(Finding(rule, STATUS_MISSING, "", rule.missing_reason))
            continue

        val = normalized[key]
        if rule.ok(val):
            findings.append(Finding(rule, STATUS_OK, val, rule.ok_reason))
        elif rule.weak(val):
            findings.append(Finding(rule, STATUS_WEAK, val, rule.weak_reason))
        else:
            findings.append(Finding(rule, STATUS_MISSING, val, rule.missing_reason))

    return findings


def score(findings: list[Finding]) -> tuple[int, str]:
    """
    Returns (numeric_score 0-100, letter_grade A-F).
    Each ok finding earns full weight; weak earns half; missing earns 0.
    """
    max_pts  = sum(f.rule.weight for f in findings)
    earned   = sum(
        f.rule.weight if f.status == STATUS_OK
        else f.rule.weight // 2 if f.status == STATUS_WEAK
        else 0
        for f in findings
    )
    numeric = round((earned / max_pts) * 100) if max_pts else 0
    grade   = next(g for threshold, g in GRADE_MAP if numeric >= threshold)
    return numeric, grade
