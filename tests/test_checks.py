from header_auditor import checks
from header_auditor.fetcher import PROBE_ORIGIN
from header_auditor.models import Severity, Target

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def make_target(headers=None, url="https://example.com", cookies=None):
    return Target(url=url, headers=headers or {}, cookies=cookies or [], probe_origin=PROBE_ORIGIN)


def severities(findings):
    return [f.severity for f in findings]


def titles(findings):
    return " | ".join(f.title for f in findings)


# --- Conjunto completo ---------------------------------------------------- #


def test_secure_site_has_only_passes():
    findings = checks.run_checks(make_target(SECURE_HEADERS))
    assert findings
    assert all(f.severity is Severity.PASS for f in findings), titles(findings)


def test_empty_headers_produce_high_findings():
    findings = checks.run_checks(make_target({}))
    assert findings[0].severity is Severity.HIGH  # ordenados de más a menos grave
    headers = {f.header for f in findings if f.severity is Severity.HIGH}
    assert headers == {"Strict-Transport-Security", "Content-Security-Policy"}


def test_header_names_are_case_insensitive():
    lowered = {k.lower(): v for k, v in SECURE_HEADERS.items()}
    findings = checks.run_checks(make_target(lowered))
    assert all(f.severity is Severity.PASS for f in findings)


# --- HTTPS y HSTS --------------------------------------------------------- #


def test_http_site_is_high_and_skips_hsts():
    t = make_target({}, url="http://example.com")
    assert severities(checks.check_https(t)) == [Severity.HIGH]
    assert checks.check_hsts(t) == []


def test_hsts_short_max_age():
    t = make_target({"Strict-Transport-Security": "max-age=3600; includeSubDomains"})
    assert severities(checks.check_hsts(t)) == [Severity.MEDIUM]


def test_hsts_max_age_zero_disables():
    t = make_target({"Strict-Transport-Security": "max-age=0"})
    assert severities(checks.check_hsts(t)) == [Severity.HIGH]


def test_hsts_invalid_max_age():
    t = make_target({"Strict-Transport-Security": "max-age=abc"})
    assert severities(checks.check_hsts(t)) == [Severity.MEDIUM]


def test_hsts_without_include_subdomains():
    t = make_target({"Strict-Transport-Security": "max-age=31536000"})
    assert severities(checks.check_hsts(t)) == [Severity.LOW]


def test_hsts_quoted_max_age():
    t = make_target({"Strict-Transport-Security": 'max-age="31536000"; includeSubDomains'})
    assert severities(checks.check_hsts(t)) == [Severity.PASS]


# --- CSP ------------------------------------------------------------------ #


def test_parse_csp():
    csp = checks.parse_csp("default-src 'self'; script-src 'self' cdn.example.com;; ")
    assert csp == {"default-src": ["'self'"], "script-src": ["'self'", "cdn.example.com"]}


def test_parse_csp_keeps_first_duplicate():
    assert checks.parse_csp("script-src 'self'; script-src *") == {"script-src": ["'self'"]}


def test_csp_report_only():
    t = make_target({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    assert severities(checks.check_csp(t)) == [Severity.MEDIUM]


def test_csp_unsafe_inline_and_eval():
    policy = "script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'"
    t = make_target({"Content-Security-Policy": policy})
    findings = checks.check_csp(t)
    assert severities(findings) == [Severity.MEDIUM, Severity.MEDIUM]
    assert "unsafe-inline" in titles(findings)
    assert "unsafe-eval" in titles(findings)


def test_csp_unsafe_inline_ignored_with_nonce():
    t = make_target(
        {"Content-Security-Policy": "script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'"}
    )
    assert severities(checks.check_csp(t)) == [Severity.PASS]


def test_csp_wildcard_sources():
    t = make_target({"Content-Security-Policy": "default-src 'self'; script-src https: *"})
    findings = checks.check_csp(t)
    assert severities(findings) == [Severity.MEDIUM]
    assert "* https:" in findings[0].detail


def test_csp_without_script_restriction():
    t = make_target({"Content-Security-Policy": "img-src 'self'"})
    assert severities(checks.check_csp(t)) == [Severity.MEDIUM, Severity.LOW]


# --- Clickjacking --------------------------------------------------------- #


def test_clickjacking_missing():
    assert severities(checks.check_clickjacking(make_target({}))) == [Severity.MEDIUM]


def test_clickjacking_frame_ancestors_is_enough():
    t = make_target({"Content-Security-Policy": "frame-ancestors 'none'"})
    assert severities(checks.check_clickjacking(t)) == [Severity.PASS]


def test_clickjacking_xfo_values():
    assert severities(checks.check_clickjacking(make_target({"X-Frame-Options": "deny"}))) == [
        Severity.PASS
    ]
    allow_from = make_target({"X-Frame-Options": "ALLOW-FROM https://a.com"})
    assert severities(checks.check_clickjacking(allow_from)) == [Severity.LOW]
    invalid = make_target({"X-Frame-Options": "yes"})
    assert severities(checks.check_clickjacking(invalid)) == [Severity.LOW]


# --- Otras cabeceras del navegador ---------------------------------------- #


def test_content_type_options():
    assert severities(checks.check_content_type_options(make_target({}))) == [Severity.MEDIUM]
    bad = make_target({"X-Content-Type-Options": "sniff"})
    assert severities(checks.check_content_type_options(bad)) == [Severity.LOW]


def test_referrer_policy_weak():
    t = make_target({"Referrer-Policy": "unsafe-url"})
    assert severities(checks.check_referrer_policy(t)) == [Severity.LOW]


def test_referrer_policy_uses_last_known_value():
    t = make_target({"Referrer-Policy": "unsafe-url, foo, strict-origin"})
    findings = checks.check_referrer_policy(t)
    assert severities(findings) == [Severity.PASS]
    assert "strict-origin" in findings[0].title


def test_referrer_policy_unknown():
    t = make_target({"Referrer-Policy": "whatever"})
    assert severities(checks.check_referrer_policy(t)) == [Severity.LOW]


def test_cross_origin_isolation_is_informational():
    assert severities(checks.check_cross_origin_isolation(make_target({}))) == [
        Severity.INFO,
        Severity.INFO,
    ]


# --- CORS ----------------------------------------------------------------- #


def test_cors_absent_produces_nothing():
    assert checks.check_cors(make_target({})) == []


def test_cors_reflected_origin_with_credentials():
    t = make_target(
        {"Access-Control-Allow-Origin": PROBE_ORIGIN, "Access-Control-Allow-Credentials": "true"}
    )
    assert severities(checks.check_cors(t)) == [Severity.HIGH]


def test_cors_reflected_origin_without_credentials():
    t = make_target({"Access-Control-Allow-Origin": PROBE_ORIGIN})
    assert severities(checks.check_cors(t)) == [Severity.MEDIUM]


def test_cors_wildcard_and_null():
    assert severities(checks.check_cors(make_target({"Access-Control-Allow-Origin": "*"}))) == [
        Severity.INFO
    ]
    null = make_target({"Access-Control-Allow-Origin": "null"})
    assert severities(checks.check_cors(null)) == [Severity.MEDIUM]


def test_cors_specific_origin_passes():
    t = make_target({"Access-Control-Allow-Origin": "https://app.example.com"})
    assert severities(checks.check_cors(t)) == [Severity.PASS]


# --- Cookies -------------------------------------------------------------- #


def test_secure_cookies_pass():
    t = make_target(cookies=["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"])
    assert severities(checks.check_cookies(t)) == [Severity.PASS]


def test_cookie_without_flags():
    t = make_target(cookies=["sid=abc"])
    findings = checks.check_cookies(t)
    assert severities(findings) == [Severity.MEDIUM]
    assert "'sid'" in findings[0].title
    for flag in ("Secure", "HttpOnly", "SameSite"):
        assert flag in findings[0].detail


def test_cookie_with_expires_comma_is_parsed():
    raw = "sid=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Strict"
    assert severities(checks.check_cookies(make_target(cookies=[raw]))) == [Severity.PASS]


def test_cookie_samesite_none_without_secure():
    t = make_target(cookies=["a=1; HttpOnly; SameSite=None"], url="http://example.com")
    findings = checks.check_cookies(t)
    assert severities(findings) == [Severity.MEDIUM]
    assert "SameSite=None" in findings[0].detail


def test_one_finding_per_bad_cookie():
    t = make_target(cookies=["a=1", "b=2; Secure; HttpOnly; SameSite=Lax", "c=3; Secure"])
    findings = checks.check_cookies(t)
    assert len(findings) == 2
    assert {f.title.split("'")[1] for f in findings} == {"a", "c"}


# --- Fugas de información y obsoletas ------------------------------------- #


def test_server_version_is_disclosed():
    t = make_target({"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"})
    findings = checks.check_information_disclosure(t)
    assert [f.header for f in findings] == ["Server", "X-Powered-By"]
    assert severities(findings) == [Severity.LOW, Severity.LOW]


def test_server_without_version_is_fine():
    assert checks.check_information_disclosure(make_target({"Server": "cloudflare"})) == []


def test_deprecated_headers():
    t = make_target({"X-XSS-Protection": "1; mode=block", "Public-Key-Pins": "pin-sha256=x"})
    assert severities(checks.check_deprecated(t)) == [Severity.INFO, Severity.LOW]
    assert checks.check_deprecated(make_target({"X-XSS-Protection": "0"})) == []
