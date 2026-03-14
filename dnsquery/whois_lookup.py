from __future__ import annotations

from datetime import datetime

import whois

from dnsquery.models import WhoisInfo


def _normalize_date(value: datetime | list | None) -> str | None:
    """Convert a date value from python-whois to an ISO 8601 string.

    python-whois may return a single datetime, a list of datetimes, or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _normalize_domain_name(value: str | list | None) -> str | None:
    """Extract a single domain name string.

    python-whois sometimes returns a list of domain names.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _normalize_name_servers(value: list | None) -> list[str]:
    """Normalize name servers to a lowercase list of strings."""
    if value is None:
        return []
    return [ns.lower() for ns in value if ns]


def _normalize_status(value: list | str | None) -> list[str]:
    """Parse EPP status codes, stripping appended URLs.

    python-whois may return entries like
    ``"clientTransferProhibited https://icann.org/epp#clientTransferProhibited"``
    We keep only the status code before any whitespace.
    """
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return [s.split()[0] for s in value if s]


def _first_email(value: str | list | None) -> str | None:
    """Return the first email if a list is provided, otherwise the string."""
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def lookup_whois(domain: str) -> tuple[WhoisInfo | None, str | None]:
    """Perform a WHOIS lookup for *domain*.

    Returns
    -------
    tuple[WhoisInfo | None, str | None]
        ``(WhoisInfo, None)`` on success, ``(None, error_message)`` on failure.
    """
    try:
        raw = whois.whois(domain)

        info = WhoisInfo(
            domain_name=_normalize_domain_name(raw.get("domain_name")),
            registrar=raw.get("registrar"),
            registrar_url=raw.get("registrar_url"),
            creation_date=_normalize_date(raw.get("creation_date")),
            expiration_date=_normalize_date(raw.get("expiration_date")),
            updated_date=_normalize_date(raw.get("updated_date")),
            name_servers=_normalize_name_servers(raw.get("name_servers")),
            status=_normalize_status(raw.get("status")),
            dnssec=str(raw.get("dnssec")) if raw.get("dnssec") is not None else None,
            registrant_name=raw.get("name"),
            registrant_org=raw.get("org"),
            registrant_email=_first_email(raw.get("emails")),
            admin_name=raw.get("admin_name"),
            admin_email=raw.get("admin_email"),
            tech_name=raw.get("tech_name"),
            tech_email=raw.get("tech_email"),
        )

        return info, None

    except Exception as exc:
        return None, str(exc)
