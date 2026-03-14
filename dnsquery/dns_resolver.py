from __future__ import annotations

import ipaddress
from datetime import datetime

import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename

from dnsquery.models import DnsRecord, QueryResult, SoaRecord

# Default resolver timing constants
QUERY_TIMEOUT = 5.0  # seconds per query
QUERY_LIFETIME = 10.0  # seconds total lifetime

# Record types queried for a domain lookup
_RECORD_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "SRV",
    "PTR",
    "CAA",
    "DNSKEY",
    "DS",
    "NAPTR",
    "NS",
    "SOA",
    "LOC",
    "HINFO",
    "SPF",
    "TLSA",
]


def is_ip_address(input_str: str) -> bool:
    """Return True if *input_str* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False


def _query_record_type(
    domain: str,
    rdtype: str,
    errors: list[str],
) -> list[DnsRecord]:
    """Query a single DNS record type and return a list of DnsRecord objects."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = QUERY_TIMEOUT
    resolver.lifetime = QUERY_LIFETIME

    try:
        answer = resolver.resolve(domain, rdtype)
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        errors.append(f"NXDOMAIN: The domain '{domain}' does not exist.")
        return []
    except dns.resolver.NoNameservers:
        errors.append(
            f"NoNameservers: No nameservers available for '{domain}' "
            f"(record type {rdtype})."
        )
        return []
    except dns.resolver.Timeout:
        errors.append(
            f"Timeout: Query for '{domain}' record type {rdtype} timed out."
        )
        return []
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Error querying {rdtype} for '{domain}': {exc}")
        return []

    records: list[DnsRecord] = []
    for rdata in answer:
        priority: int | None = None
        if rdtype == "MX":
            priority = rdata.preference
        elif rdtype == "SRV":
            priority = rdata.priority

        records.append(
            DnsRecord(
                record_type=rdtype,
                name=str(answer.qname),
                ttl=answer.rrset.ttl,
                value=str(rdata),
                priority=priority,
            )
        )

    return records


def _query_soa(domain: str, errors: list[str]) -> SoaRecord | None:
    """Query the SOA record for *domain* and return a SoaRecord or None."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = QUERY_TIMEOUT
    resolver.lifetime = QUERY_LIFETIME

    try:
        answer = resolver.resolve(domain, "SOA")
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        errors.append(f"NXDOMAIN: The domain '{domain}' does not exist.")
        return None
    except dns.resolver.NoNameservers:
        errors.append(
            f"NoNameservers: No nameservers available for '{domain}' "
            f"(record type SOA)."
        )
        return None
    except dns.resolver.Timeout:
        errors.append(
            f"Timeout: Query for '{domain}' record type SOA timed out."
        )
        return None
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Error querying SOA for '{domain}': {exc}")
        return None

    for rdata in answer:
        return SoaRecord(
            mname=str(rdata.mname),
            rname=str(rdata.rname),
            serial=rdata.serial,
            refresh=rdata.refresh,
            retry=rdata.retry,
            expire=rdata.expire,
            minimum=rdata.minimum,
        )

    return None


def resolve_domain(
    domain: str,
    subdomains: list[str] | None = None,
) -> QueryResult:
    """Perform a comprehensive DNS lookup for *domain*.

    Queries all standard record types on the apex domain. If *subdomains* is
    provided (e.g. from SecurityTrails), each subdomain is also queried for
    CNAME records.
    """
    errors: list[str] = []
    dns_records: list[DnsRecord] = []
    nameservers: list[DnsRecord] = []
    soa: SoaRecord | None = None

    for rdtype in _RECORD_TYPES:
        if rdtype == "SOA":
            soa = _query_soa(domain, errors)
            soa_records = _query_record_type(domain, "SOA", errors)
            dns_records.extend(soa_records)
        elif rdtype == "NS":
            ns_records = _query_record_type(domain, "NS", errors)
            nameservers.extend(ns_records)
            dns_records.extend(ns_records)
        else:
            dns_records.extend(_query_record_type(domain, rdtype, errors))

    # Query each known subdomain for CNAME records
    if subdomains:
        for fqdn in subdomains:
            dns_records.extend(_query_record_type(fqdn, "CNAME", errors))

    return QueryResult(
        query_input=domain,
        query_type="domain",
        timestamp=datetime.now().isoformat(),
        nameservers=nameservers,
        soa=soa,
        dns_records=dns_records,
        errors=errors,
    )


def resolve_ip(ip_address: str) -> QueryResult:
    """Perform a reverse DNS lookup for *ip_address*."""
    errors: list[str] = []
    reverse_records: list[DnsRecord] = []
    dns_records: list[DnsRecord] = []

    try:
        rev_name = dns.reversename.from_address(ip_address)
        ptr_records = _query_record_type(str(rev_name), "PTR", errors)
        reverse_records.extend(ptr_records)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Error performing reverse lookup for '{ip_address}': {exc}")

    for ptr in reverse_records:
        hostname = ptr.value.rstrip(".")
        if hostname:
            for rdtype in ("A", "AAAA"):
                dns_records.extend(
                    _query_record_type(hostname, rdtype, errors)
                )

    return QueryResult(
        query_input=ip_address,
        query_type="ip",
        timestamp=datetime.now().isoformat(),
        reverse_dns=reverse_records if reverse_records else None,
        dns_records=dns_records,
        errors=errors,
    )
