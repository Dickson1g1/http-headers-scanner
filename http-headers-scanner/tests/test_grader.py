import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.grader import audit, score, STATUS_OK, STATUS_WEAK, STATUS_MISSING


def get(findings, name):
    return next(f for f in findings if f.rule.name == name)


def test_hsts_ok():
    h = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains"}
    f = get(audit(h), "Strict-Transport-Security")
    assert f.status == STATUS_OK

def test_hsts_weak_zero():
    h = {"Strict-Transport-Security": "max-age=0"}
    f = get(audit(h), "Strict-Transport-Security")
    assert f.status == STATUS_WEAK

def test_hsts_missing():
    f = get(audit({}), "Strict-Transport-Security")
    assert f.status == STATUS_MISSING

def test_csp_ok():
    h = {"Content-Security-Policy": "default-src 'self'"}
    f = get(audit(h), "Content-Security-Policy")
    assert f.status == STATUS_OK

def test_csp_weak_unsafe():
    h = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
    f = get(audit(h), "Content-Security-Policy")
    assert f.status == STATUS_WEAK

def test_xfo_deny():
    h = {"X-Frame-Options": "DENY"}
    f = get(audit(h), "X-Frame-Options")
    assert f.status == STATUS_OK

def test_xfo_allow_from_weak():
    h = {"X-Frame-Options": "ALLOW-FROM https://example.com"}
    f = get(audit(h), "X-Frame-Options")
    assert f.status == STATUS_WEAK

def test_xcto_ok():
    h = {"X-Content-Type-Options": "nosniff"}
    f = get(audit(h), "X-Content-Type-Options")
    assert f.status == STATUS_OK

def test_score_perfect():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy":   "default-src 'self'",
        "X-Frame-Options":           "DENY",
        "X-Content-Type-Options":    "nosniff",
        "Referrer-Policy":           "strict-origin-when-cross-origin",
        "Permissions-Policy":        "geolocation=()",
    }
    findings = audit(headers)
    n, g = score(findings)
    assert n == 100
    assert g == "A"

def test_score_all_missing():
    findings = audit({})
    n, g = score(findings)
    assert n == 0
    assert g == "F"

def test_case_insensitive():
    h = {"strict-transport-security": "max-age=63072000"}
    f = get(audit(h), "Strict-Transport-Security")
    assert f.status == STATUS_OK


if __name__ == "__main__":
    tests = [(k, v) for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✔ {name}")
            passed += 1
        except AssertionError as e:
            print(f"  ✘ {name}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
