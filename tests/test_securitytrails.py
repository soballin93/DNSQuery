from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from dnsquery.securitytrails import get_subdomains, ping


@patch("dnsquery.securitytrails.urllib.request.urlopen")
def test_get_subdomains_success(mock_urlopen):
    response_data = {"subdomains": ["www", "mail", "blog", "api"], "endpoint": "/v1/domain/example.com/subdomains"}
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_resp

    subs, err = get_subdomains("example.com", "test-key")

    assert err is None
    assert subs == [
        "www.example.com",
        "mail.example.com",
        "blog.example.com",
        "api.example.com",
    ]


@patch("dnsquery.securitytrails.urllib.request.urlopen")
def test_get_subdomains_invalid_key(mock_urlopen):
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="", code=401, msg="Unauthorized", hdrs=None, fp=None
    )

    subs, err = get_subdomains("example.com", "bad-key")

    assert subs == []
    assert err == "Invalid API key."


@patch("dnsquery.securitytrails.urllib.request.urlopen")
def test_get_subdomains_rate_limited(mock_urlopen):
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="", code=429, msg="Too Many Requests", hdrs=None, fp=None
    )

    subs, err = get_subdomains("example.com", "test-key")

    assert subs == []
    assert "rate limit" in err.lower()


@patch("dnsquery.securitytrails.urllib.request.urlopen")
def test_ping_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"success": true}'
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_resp

    ok, err = ping("test-key")

    assert ok is True
    assert err is None


@patch("dnsquery.securitytrails.urllib.request.urlopen")
def test_ping_invalid_key(mock_urlopen):
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="", code=401, msg="Unauthorized", hdrs=None, fp=None
    )

    ok, err = ping("bad-key")

    assert ok is False
    assert err == "Invalid API key."
