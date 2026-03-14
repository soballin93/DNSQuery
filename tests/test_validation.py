from __future__ import annotations

from dnsquery.models import DnsRecord, QueryResult, SoaRecord
from dnsquery.validation import validate_dns


def _make_result(
    dns_records: list[DnsRecord] | None = None,
    nameservers: list[DnsRecord] | None = None,
    soa: SoaRecord | None = None,
) -> QueryResult:
    return QueryResult(
        query_input="example.com",
        query_type="domain",
        timestamp="2026-03-14T00:00:00",
        dns_records=dns_records or [],
        nameservers=nameservers or [],
        soa=soa,
    )


def test_validate_a_records_match():
    result = _make_result(dns_records=[
        DnsRecord("A", "example.com.", 300, "93.184.216.34"),
    ])
    st_dns = {"a": {"values": [{"ip": "93.184.216.34"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1
    assert v.summary.mismatches == 0
    assert v.comparisons[0].status == "match"


def test_validate_a_records_mismatch():
    result = _make_result(dns_records=[
        DnsRecord("A", "example.com.", 300, "1.2.3.4"),
    ])
    st_dns = {"a": {"values": [{"ip": "5.6.7.8"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.dns_only == 1
    assert v.summary.st_only == 1
    statuses = {c.status for c in v.comparisons}
    assert "dns_only" in statuses
    assert "st_only" in statuses


def test_validate_mx_records_match():
    result = _make_result(dns_records=[
        DnsRecord("MX", "example.com.", 300, "10 mail.example.com.", priority=10),
    ])
    st_dns = {"mx": {"values": [{"priority": 10, "host": "mail.example.com"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1


def test_validate_ns_records_partial_overlap():
    result = _make_result(nameservers=[
        DnsRecord("NS", "example.com.", 300, "ns1.example.com."),
        DnsRecord("NS", "example.com.", 300, "ns2.example.com."),
    ])
    st_dns = {"ns": {"values": [
        {"nameserver": "ns1.example.com"},
        {"nameserver": "ns3.example.com"},
    ]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1
    assert v.summary.dns_only == 1
    assert v.summary.st_only == 1


def test_validate_txt_records_match_with_quotes():
    result = _make_result(dns_records=[
        DnsRecord("TXT", "example.com.", 300, '"v=spf1 include:_spf.google.com ~all"'),
    ])
    st_dns = {"txt": {"values": [{"value": "v=spf1 include:_spf.google.com ~all"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1


def test_validate_soa_match():
    soa = SoaRecord("ns1.example.com.", "admin.example.com.", 2024010101, 3600, 900, 604800, 86400)
    result = _make_result(soa=soa)
    st_dns = {"soa": {"values": [{"email": "admin.example.com"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1


def test_validate_soa_mismatch():
    soa = SoaRecord("ns1.example.com.", "admin.example.com.", 2024010101, 3600, 900, 604800, 86400)
    result = _make_result(soa=soa)
    st_dns = {"soa": {"values": [{"email": "hostmaster.example.com"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.mismatches == 1


def test_validate_empty_st_dns():
    result = _make_result(dns_records=[
        DnsRecord("A", "example.com.", 300, "93.184.216.34"),
    ])
    st_dns = {}

    v = validate_dns(result, st_dns)

    # A record exists in DNS but not in SecurityTrails
    assert v.summary.dns_only == 1


def test_validate_missing_record_type_in_dns():
    result = _make_result()
    st_dns = {"a": {"values": [{"ip": "93.184.216.34"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.st_only == 1


def test_validate_trailing_dot_normalization():
    result = _make_result(nameservers=[
        DnsRecord("NS", "example.com.", 300, "ns1.example.com."),
    ])
    st_dns = {"ns": {"values": [{"nameserver": "ns1.example.com"}]}}

    v = validate_dns(result, st_dns)

    assert v.summary.matches == 1


def test_validate_summary_totals():
    result = _make_result(
        dns_records=[
            DnsRecord("A", "example.com.", 300, "1.2.3.4"),
            DnsRecord("A", "example.com.", 300, "5.6.7.8"),
        ],
        nameservers=[
            DnsRecord("NS", "example.com.", 300, "ns1.example.com."),
        ],
    )
    st_dns = {
        "a": {"values": [{"ip": "1.2.3.4"}]},
        "ns": {"values": [{"nameserver": "ns1.example.com"}]},
    }

    v = validate_dns(result, st_dns)

    assert v.summary.total == v.summary.matches + v.summary.mismatches + v.summary.dns_only + v.summary.st_only
