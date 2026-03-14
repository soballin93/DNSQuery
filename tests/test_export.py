from __future__ import annotations

import csv
from pathlib import Path

from dnsquery.export import export_to_csv
from dnsquery.models import DnsRecord, QueryResult


def test_export_to_csv_creates_file(tmp_path: Path, sample_query_result: QueryResult):
    filepath = tmp_path / "result.csv"
    export_to_csv(sample_query_result, str(filepath))

    assert filepath.exists()

    content = filepath.read_text(encoding="utf-8")
    assert "QUERY INFO" in content
    assert "WHOIS" in content
    assert "SOA" in content
    assert "DNS RECORDS" in content
    assert "ERRORS" in content


def test_export_to_csv_handles_none_whois(
    tmp_path: Path, sample_query_result: QueryResult,
):
    sample_query_result.whois = None
    filepath = tmp_path / "result_no_whois.csv"

    export_to_csv(sample_query_result, str(filepath))

    assert filepath.exists()
    content = filepath.read_text(encoding="utf-8")
    assert "QUERY INFO" in content
    assert "WHOIS" not in content


def test_export_to_csv_dns_records(
    tmp_path: Path, sample_query_result: QueryResult,
):
    filepath = tmp_path / "result.csv"
    export_to_csv(sample_query_result, str(filepath))

    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        dns_rows = [row for row in reader if row and row[0] == "DNS RECORDS"]

    assert len(dns_rows) == len(sample_query_result.dns_records)
    for row in dns_rows:
        # Section, Type, Name, TTL, Value, Priority
        assert len(row) == 6


def test_export_to_csv_special_characters(tmp_path: Path):
    tricky_record = DnsRecord(
        record_type="TXT",
        name="example.com.",
        ttl=300,
        value='"v=spf1 include:_spf.google.com ~all", "another part"',
    )
    result = QueryResult(
        query_input="example.com",
        query_type="domain",
        timestamp="2026-03-14T12:00:00",
        dns_records=[tricky_record],
    )

    filepath = tmp_path / "result_special.csv"
    export_to_csv(result, str(filepath))

    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        dns_rows = [row for row in reader if row and row[0] == "DNS RECORDS"]

    assert len(dns_rows) == 1
    assert dns_rows[0][4] == tricky_record.value
