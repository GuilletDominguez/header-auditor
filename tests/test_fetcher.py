from unittest.mock import MagicMock, patch

import pytest
import requests

from header_auditor.fetcher import PROBE_ORIGIN, FetchError, fetch, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        ("  example.com/path ", "https://example.com/path"),
        ("http://example.com", "http://example.com"),
        ("HTTPS://Example.com", "HTTPS://Example.com"),
    ],
)
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize("raw", ["ftp://example.com", "https://", "file:///etc/passwd"])
def test_normalize_url_rejects_invalid(raw):
    with pytest.raises(ValueError):
        normalize_url(raw)


def fake_response(headers, cookies=(), url="https://example.com/", status=200):
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.url = url
    resp.status_code = status
    resp.headers = requests.structures.CaseInsensitiveDict(headers)
    resp.raw.headers.getlist.return_value = list(cookies)
    return resp


@patch("header_auditor.fetcher.requests.get")
def test_fetch_builds_target(mock_get):
    mock_get.return_value = fake_response(
        {"X-Frame-Options": "DENY"},
        cookies=["a=1; Secure", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"],
        url="https://www.example.com/",
    )
    target = fetch("https://example.com")

    assert target.final_url == "https://www.example.com/"
    assert target.get("x-frame-options") == "DENY"
    assert len(target.cookies) == 2
    assert target.probe_origin == PROBE_ORIGIN

    kwargs = mock_get.call_args.kwargs
    assert kwargs["headers"]["Origin"] == PROBE_ORIGIN
    assert kwargs["allow_redirects"] is True
    assert kwargs["timeout"] == 10.0


@pytest.mark.parametrize(
    ("exc", "message"),
    [
        (requests.exceptions.SSLError("bad cert"), "TLS"),
        (requests.exceptions.ConnectTimeout(), "sin respuesta"),
        (requests.exceptions.ConnectionError("refused"), "no se pudo conectar"),
    ],
)
@patch("header_auditor.fetcher.requests.get")
def test_fetch_wraps_errors(mock_get, exc, message):
    mock_get.side_effect = exc
    with pytest.raises(FetchError, match=message):
        fetch("https://example.com")
