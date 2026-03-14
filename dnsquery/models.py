from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DnsRecord:
    record_type: str
    name: str
    ttl: int
    value: str
    priority: int | None = None


@dataclass
class SoaRecord:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass
class WhoisInfo:
    domain_name: str | None = None
    registrar: str | None = None
    registrar_url: str | None = None
    creation_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    dnssec: str | None = None
    registrant_name: str | None = None
    registrant_org: str | None = None
    registrant_email: str | None = None
    admin_name: str | None = None
    admin_email: str | None = None
    tech_name: str | None = None
    tech_email: str | None = None


@dataclass
class QueryResult:
    query_input: str
    query_type: str  # "domain" or "ip"
    timestamp: str
    nameservers: list[DnsRecord] = field(default_factory=list)
    soa: SoaRecord | None = None
    dns_records: list[DnsRecord] = field(default_factory=list)
    whois: WhoisInfo | None = None
    reverse_dns: list[DnsRecord] | None = None
    errors: list[str] = field(default_factory=list)
