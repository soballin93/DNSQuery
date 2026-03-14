from __future__ import annotations

from dataclasses import dataclass, field

from dnsquery.models import DnsRecord, QueryResult, SoaRecord


@dataclass
class RecordComparison:
    record_type: str
    status: str  # "match", "mismatch", "dns_only", "st_only"
    dns_value: str
    st_value: str
    detail: str


@dataclass
class ValidationSummary:
    total: int = 0
    matches: int = 0
    mismatches: int = 0
    dns_only: int = 0
    st_only: int = 0


@dataclass
class ValidationResult:
    domain: str
    comparisons: list[RecordComparison] = field(default_factory=list)
    summary: ValidationSummary = field(default_factory=ValidationSummary)
    errors: list[str] = field(default_factory=list)


def _normalize_hostname(h: str) -> str:
    return h.rstrip(".").lower()


def _strip_txt_quotes(v: str) -> str:
    s = v.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


def _dns_records_by_type(result: QueryResult, rtype: str) -> list[DnsRecord]:
    return [r for r in result.dns_records if r.record_type == rtype]


def _compare_a_aaaa(
    rtype: str,
    dns_records: list[DnsRecord],
    st_values: list[dict],
) -> list[RecordComparison]:
    dns_set = {r.value.strip() for r in dns_records}
    st_set = {v.get("ip", "").strip() for v in st_values if v.get("ip")}

    comparisons: list[RecordComparison] = []
    for val in dns_set & st_set:
        comparisons.append(RecordComparison(rtype, "match", val, val, "Confirmed by both sources"))
    for val in dns_set - st_set:
        comparisons.append(RecordComparison(rtype, "dns_only", val, "", "Found in DNS but not in SecurityTrails"))
    for val in st_set - dns_set:
        comparisons.append(RecordComparison(rtype, "st_only", "", val, "Found in SecurityTrails but not in DNS"))
    return comparisons


def _compare_mx(
    dns_records: list[DnsRecord],
    st_values: list[dict],
) -> list[RecordComparison]:
    # Build canonical (priority, hostname) tuples
    dns_set: set[tuple[int, str]] = set()
    for r in dns_records:
        pri = r.priority if r.priority is not None else 0
        # MX value from dnspython may include priority prefix; extract hostname
        parts = r.value.strip().split()
        host = _normalize_hostname(parts[-1])
        dns_set.add((pri, host))

    st_set: set[tuple[int, str]] = set()
    for v in st_values:
        pri = v.get("priority", 0) or 0
        host = _normalize_hostname(v.get("host", ""))
        if host:
            st_set.add((pri, host))

    comparisons: list[RecordComparison] = []
    for pri, host in dns_set & st_set:
        val = f"{pri} {host}"
        comparisons.append(RecordComparison("MX", "match", val, val, "Confirmed by both sources"))
    for pri, host in dns_set - st_set:
        comparisons.append(RecordComparison("MX", "dns_only", f"{pri} {host}", "", "Found in DNS but not in SecurityTrails"))
    for pri, host in st_set - dns_set:
        comparisons.append(RecordComparison("MX", "st_only", "", f"{pri} {host}", "Found in SecurityTrails but not in DNS"))
    return comparisons


def _compare_ns(
    dns_records: list[DnsRecord],
    st_values: list[dict],
) -> list[RecordComparison]:
    dns_set = {_normalize_hostname(r.value) for r in dns_records}
    st_set = {_normalize_hostname(v.get("nameserver", "")) for v in st_values if v.get("nameserver")}

    comparisons: list[RecordComparison] = []
    for val in dns_set & st_set:
        comparisons.append(RecordComparison("NS", "match", val, val, "Confirmed by both sources"))
    for val in dns_set - st_set:
        comparisons.append(RecordComparison("NS", "dns_only", val, "", "Found in DNS but not in SecurityTrails"))
    for val in st_set - dns_set:
        comparisons.append(RecordComparison("NS", "st_only", "", val, "Found in SecurityTrails but not in DNS"))
    return comparisons


def _compare_txt(
    dns_records: list[DnsRecord],
    st_values: list[dict],
) -> list[RecordComparison]:
    dns_set = {_strip_txt_quotes(r.value) for r in dns_records}
    st_set = {_strip_txt_quotes(v.get("value", "")) for v in st_values if v.get("value")}

    comparisons: list[RecordComparison] = []
    for val in dns_set & st_set:
        display = val[:80] + "..." if len(val) > 80 else val
        comparisons.append(RecordComparison("TXT", "match", display, display, "Confirmed by both sources"))
    for val in dns_set - st_set:
        display = val[:80] + "..." if len(val) > 80 else val
        comparisons.append(RecordComparison("TXT", "dns_only", display, "", "Found in DNS but not in SecurityTrails"))
    for val in st_set - dns_set:
        display = val[:80] + "..." if len(val) > 80 else val
        comparisons.append(RecordComparison("TXT", "st_only", "", display, "Found in SecurityTrails but not in DNS"))
    return comparisons


def _compare_soa(
    soa: SoaRecord | None,
    st_values: list[dict],
) -> list[RecordComparison]:
    comparisons: list[RecordComparison] = []
    if not soa or not st_values:
        if soa and not st_values:
            comparisons.append(RecordComparison("SOA", "dns_only", soa.rname, "", "SOA not available from SecurityTrails"))
        elif not soa and st_values:
            email = st_values[0].get("email", "N/A")
            comparisons.append(RecordComparison("SOA", "st_only", "", email, "SOA not found in DNS"))
        return comparisons

    st_email = _normalize_hostname(st_values[0].get("email", ""))
    dns_rname = _normalize_hostname(soa.rname)

    if dns_rname == st_email:
        comparisons.append(RecordComparison("SOA", "match", dns_rname, st_email, "Responsible party confirmed"))
    else:
        comparisons.append(RecordComparison("SOA", "mismatch", dns_rname, st_email, "Responsible party email differs"))

    return comparisons


def validate_dns(query_result: QueryResult, st_dns: dict) -> ValidationResult:
    """Compare direct DNS results against SecurityTrails current_dns data."""
    validation = ValidationResult(domain=query_result.query_input)

    record_types = [
        ("a", "A"),
        ("aaaa", "AAAA"),
    ]
    for st_key, rtype in record_types:
        st_data = st_dns.get(st_key, {})
        st_values = st_data.get("values", []) if isinstance(st_data, dict) else []
        dns_records = _dns_records_by_type(query_result, rtype)
        if dns_records or st_values:
            validation.comparisons.extend(_compare_a_aaaa(rtype, dns_records, st_values))

    # MX
    st_mx = st_dns.get("mx", {})
    st_mx_values = st_mx.get("values", []) if isinstance(st_mx, dict) else []
    dns_mx = _dns_records_by_type(query_result, "MX")
    if dns_mx or st_mx_values:
        validation.comparisons.extend(_compare_mx(dns_mx, st_mx_values))

    # NS
    st_ns = st_dns.get("ns", {})
    st_ns_values = st_ns.get("values", []) if isinstance(st_ns, dict) else []
    dns_ns = [r for r in query_result.nameservers]
    if dns_ns or st_ns_values:
        validation.comparisons.extend(_compare_ns(dns_ns, st_ns_values))

    # TXT
    st_txt = st_dns.get("txt", {})
    st_txt_values = st_txt.get("values", []) if isinstance(st_txt, dict) else []
    dns_txt = _dns_records_by_type(query_result, "TXT")
    if dns_txt or st_txt_values:
        validation.comparisons.extend(_compare_txt(dns_txt, st_txt_values))

    # SOA
    st_soa = st_dns.get("soa", {})
    st_soa_values = st_soa.get("values", []) if isinstance(st_soa, dict) else []
    if query_result.soa or st_soa_values:
        validation.comparisons.extend(_compare_soa(query_result.soa, st_soa_values))

    # Build summary
    summary = ValidationSummary(total=len(validation.comparisons))
    for c in validation.comparisons:
        if c.status == "match":
            summary.matches += 1
        elif c.status == "mismatch":
            summary.mismatches += 1
        elif c.status == "dns_only":
            summary.dns_only += 1
        elif c.status == "st_only":
            summary.st_only += 1
    validation.summary = summary

    return validation
