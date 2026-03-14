from __future__ import annotations

import csv
from dataclasses import fields

from dnsquery.models import QueryResult


def export_to_csv(result: QueryResult, filepath: str) -> None:
    """Export a QueryResult to a CSV file with sectioned layout."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)

        # --- QUERY INFO section ---
        writer.writerow(["QUERY INFO", "Field", "Value"])
        writer.writerow(["QUERY INFO", "Input", result.query_input])
        writer.writerow(["QUERY INFO", "Type", result.query_type])
        writer.writerow(["QUERY INFO", "Timestamp", result.timestamp])

        # --- WHOIS section ---
        if result.whois is not None:
            writer.writerow([])
            writer.writerow(["WHOIS", "Field", "Value"])
            for fld in fields(result.whois):
                value = getattr(result.whois, fld.name)
                if value is None:
                    continue
                if isinstance(value, list):
                    for item in value:
                        writer.writerow(["WHOIS", fld.name, item])
                else:
                    writer.writerow(["WHOIS", fld.name, value])

        # --- SOA section ---
        if result.soa is not None:
            writer.writerow([])
            writer.writerow(["SOA", "Field", "Value"])
            for fld in fields(result.soa):
                writer.writerow(["SOA", fld.name, getattr(result.soa, fld.name)])

        # --- DNS RECORDS section ---
        writer.writerow([])
        writer.writerow(["Section", "Type", "Name", "TTL", "Value", "Priority"])
        for rec in result.dns_records:
            writer.writerow([
                "DNS RECORDS",
                rec.record_type,
                rec.name,
                rec.ttl,
                rec.value,
                rec.priority if rec.priority is not None else "",
            ])

        # --- REVERSE DNS section ---
        if result.reverse_dns is not None and len(result.reverse_dns) > 0:
            writer.writerow([])
            writer.writerow(["Section", "Type", "Name", "TTL", "Value", "Priority"])
            for rec in result.reverse_dns:
                writer.writerow([
                    "REVERSE DNS",
                    rec.record_type,
                    rec.name,
                    rec.ttl,
                    rec.value,
                    rec.priority if rec.priority is not None else "",
                ])

        # --- ERRORS section ---
        if result.errors:
            writer.writerow([])
            writer.writerow(["ERRORS", "Message"])
            for error in result.errors:
                writer.writerow(["ERRORS", error])
