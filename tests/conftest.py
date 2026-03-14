from __future__ import annotations

import pytest

from dnsquery.models import DnsRecord, QueryResult, SoaRecord, WhoisInfo


@pytest.fixture()
def sample_dns_record() -> DnsRecord:
    return DnsRecord(
        record_type="A",
        name="example.com.",
        ttl=300,
        value="93.184.216.34",
    )


@pytest.fixture()
def sample_soa_record() -> SoaRecord:
    return SoaRecord(
        mname="ns1.example.com.",
        rname="admin.example.com.",
        serial=2024031401,
        refresh=3600,
        retry=900,
        expire=1209600,
        minimum=86400,
    )


@pytest.fixture()
def sample_whois_info() -> WhoisInfo:
    return WhoisInfo(
        domain_name="example.com",
        registrar="Example Registrar, Inc.",
        registrar_url="https://www.example-registrar.com",
        creation_date="1995-08-14T04:00:00",
        expiration_date="2025-08-13T04:00:00",
        updated_date="2024-01-15T10:22:33",
        name_servers=["ns1.example.com", "ns2.example.com"],
        status=[
            "clientTransferProhibited",
            "clientDeleteProhibited",
            "clientUpdateProhibited",
        ],
        dnssec="unsigned",
        registrant_name="REDACTED FOR PRIVACY",
        registrant_org="Example Organisation Ltd.",
        registrant_email="registrant@example.com",
        admin_name="Domain Admin",
        admin_email="admin@example.com",
        tech_name="Tech Support",
        tech_email="tech@example.com",
    )


@pytest.fixture()
def sample_query_result(
    sample_dns_record: DnsRecord,
    sample_soa_record: SoaRecord,
    sample_whois_info: WhoisInfo,
) -> QueryResult:
    mx_record = DnsRecord(
        record_type="MX",
        name="example.com.",
        ttl=600,
        value="10 mail.example.com.",
        priority=10,
    )
    return QueryResult(
        query_input="example.com",
        query_type="domain",
        timestamp="2026-03-14T12:00:00",
        nameservers=[
            DnsRecord(
                record_type="NS",
                name="example.com.",
                ttl=86400,
                value="ns1.example.com.",
            ),
        ],
        soa=sample_soa_record,
        dns_records=[sample_dns_record, mx_record],
        whois=sample_whois_info,
        reverse_dns=None,
        errors=[
            "Timeout: Query for 'example.com' record type DNSKEY timed out.",
            "Timeout: Query for 'example.com' record type TLSA timed out.",
        ],
    )
