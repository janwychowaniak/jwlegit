from __future__ import annotations

import pytest

from jwlegit.cli import _validate_url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com",
        "https://example.com/path?q=1",
        "https://sub.example.co.uk:8443/x",
    ],
)
def test_valid_urls_pass_through(url):
    assert _validate_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "example.com",  # no scheme
    ],
)
def test_invalid_scheme_exits(url):
    with pytest.raises(SystemExit):
        _validate_url(url)


def test_missing_hostname_exits():
    with pytest.raises(SystemExit):
        _validate_url("https://")
