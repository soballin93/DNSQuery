from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from dnsquery.whois_lookup import lookup_whois


def _make_whois_dict(**overrides) -> dict:
    """Return a realistic whois result dict with optional overrides."""
    base: dict = {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Example Registrar, Inc.",
        "registrar_url": "https://www.example-registrar.com",
        "creation_date": datetime(1995, 8, 14, 4, 0, 0),
        "expiration_date": datetime(2025, 8, 13, 4, 0, 0),
        "updated_date": datetime(2024, 1, 15, 10, 22, 33),
        "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
        "status": [
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
        ],
        "dnssec": "unsigned",
        "name": "REDACTED FOR PRIVACY",
        "org": "Example Organisation Ltd.",
        "emails": "registrant@example.com",
        "admin_name": "Domain Admin",
        "admin_email": "admin@example.com",
        "tech_name": "Tech Support",
        "tech_email": "tech@example.com",
    }
    base.update(overrides)
    return base


@patch("dnsquery.whois_lookup.whois.whois")
def test_lookup_whois_success(mock_whois):
    mock_whois.return_value = _make_whois_dict()

    info, error = lookup_whois("example.com")

    assert error is None
    assert info is not None
    assert info.domain_name == "EXAMPLE.COM"
    assert info.registrar == "Example Registrar, Inc."
    assert info.creation_date == "1995-08-14T04:00:00"
    assert info.name_servers == ["ns1.example.com", "ns2.example.com"]
    assert "clientTransferProhibited" in info.status
    assert info.registrant_email == "registrant@example.com"


@patch("dnsquery.whois_lookup.whois.whois")
def test_lookup_whois_date_list(mock_whois):
    mock_whois.return_value = _make_whois_dict(
        creation_date=[
            datetime(1995, 8, 14, 4, 0, 0),
            datetime(2000, 1, 1, 0, 0, 0),
        ],
    )

    info, error = lookup_whois("example.com")

    assert error is None
    assert info is not None
    assert info.creation_date == "1995-08-14T04:00:00"


@patch("dnsquery.whois_lookup.whois.whois")
def test_lookup_whois_failure(mock_whois):
    mock_whois.side_effect = Exception("Connection refused")

    info, error = lookup_whois("example.com")

    assert info is None
    assert error is not None
    assert "Connection refused" in error


@patch("dnsquery.whois_lookup.whois.whois")
def test_lookup_whois_epp_status_strips_urls(mock_whois):
    mock_whois.return_value = _make_whois_dict(
        status=[
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
        ],
    )

    info, error = lookup_whois("example.com")

    assert error is None
    assert info is not None
    assert info.status == ["clientTransferProhibited", "serverDeleteProhibited"]


@patch("dnsquery.whois_lookup.whois.whois")
def test_lookup_whois_none_fields(mock_whois):
    mock_whois.return_value = _make_whois_dict(
        registrar=None,
        registrar_url=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=None,
        status=None,
        dnssec=None,
        name=None,
        org=None,
        emails=None,
        admin_name=None,
        admin_email=None,
        tech_name=None,
        tech_email=None,
    )

    info, error = lookup_whois("example.com")

    assert error is None
    assert info is not None
    assert info.registrar is None
    assert info.creation_date is None
    assert info.name_servers == []
    assert info.status == []
    assert info.dnssec is None
