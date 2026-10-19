import json
from unittest.mock import patch

import pytest

from header_auditor import cli
from header_auditor.fetcher import FetchError
from header_auditor.models import Target

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def fake_fetch(headers):
    def _fetch(url, timeout, verify):
        return Target(url=url, status_code=200, headers=headers)

    return _fetch


@patch("header_auditor.cli.fetch", side_effect=fake_fetch(GOOD_HEADERS))
def test_text_output_for_good_site(_mock, capsys):
    assert cli.main(["example.com", "--no-color"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "https://example.com" in out
    assert "Nota: A+ (100/100)" in out
    assert "\033[" not in out


@patch("header_auditor.cli.fetch", side_effect=fake_fetch({}))
def test_json_output(_mock, capsys):
    assert cli.main(["example.com", "--json"]) == cli.EXIT_OK
    data = json.loads(capsys.readouterr().out)
    result = data["results"][0]
    assert result["url"] == "https://example.com"
    assert result["grade"] == "F"
    assert result["findings"][0]["severity"] == "high"


@patch("header_auditor.cli.fetch", side_effect=fake_fetch({}))
def test_fail_on_threshold(_mock, capsys):
    assert cli.main(["example.com", "--fail-on", "high"]) == cli.EXIT_FINDINGS


@patch("header_auditor.cli.fetch", side_effect=fake_fetch(GOOD_HEADERS))
def test_fail_on_not_reached(_mock, capsys):
    assert cli.main(["example.com", "--fail-on", "low"]) == cli.EXIT_OK


@patch("header_auditor.cli.fetch", side_effect=FetchError("no se pudo conectar"))
def test_scan_error_exit_code(_mock, capsys):
    assert cli.main(["example.invalid", "--no-color"]) == cli.EXIT_SCAN_ERROR
    assert "Error: no se pudo conectar" in capsys.readouterr().out


@patch("header_auditor.cli.fetch", side_effect=fake_fetch(GOOD_HEADERS))
def test_urls_from_file_are_deduplicated(mock_fetch, tmp_path, capsys):
    url_file = tmp_path / "urls.txt"
    url_file.write_text("# comentario\nexample.com\n\nhttps://example.com\nexample.org\n")
    assert cli.main(["-f", str(url_file), "--json"]) == cli.EXIT_OK
    urls = [r["url"] for r in json.loads(capsys.readouterr().out)["results"]]
    assert urls == ["https://example.com", "https://example.org"]


def test_no_urls_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == cli.EXIT_USAGE


def test_invalid_url_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["ftp://example.com"])
    assert exc.value.code == cli.EXIT_USAGE
