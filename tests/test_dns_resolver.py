from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver

from dnsquery.dns_resolver import is_ip_address, resolve_domain, resolve_ip


# ---------------------------------------------------------------------------
# is_ip_address
# ---------------------------------------------------------------------------


def test_is_ip_address_ipv4():
    assert is_ip_address("8.8.8.8") is True


def test_is_ip_address_ipv6():
    assert is_ip_address("2001:db8::1") is True


def test_is_ip_address_domain():
    assert is_ip_address("example.com") is False


def test_is_ip_address_empty():
    assert is_ip_address("") is False


# ---------------------------------------------------------------------------
# Helpers for building mock dns.resolver answers
# ---------------------------------------------------------------------------


def _make_mock_answer(rdata_list, qname="example.com.", ttl=300):
    """Return a mock Answer object that iterates over *rdata_list*."""
    mock_qname = MagicMock()
    mock_qname.__str__ = MagicMock(return_value=qname)

    mock_rrset = MagicMock()
    mock_rrset.ttl = ttl

    answer = MagicMock()
    answer.qname = mock_qname
    answer.rrset = mock_rrset
    answer.__iter__ = MagicMock(return_value=iter(rdata_list))
    return answer


# ---------------------------------------------------------------------------
# resolve_domain
# ---------------------------------------------------------------------------


@patch("dns.resolver.Resolver.resolve")
def test_resolve_domain_a_record(mock_resolve):
    rdata = MagicMock()
    rdata.to_text.return_value = "93.184.216.34"
    rdata.__str__ = MagicMock(return_value="93.184.216.34")

    answer = _make_mock_answer([rdata], qname="example.com.", ttl=300)

    def _side_effect(domain, rdtype):
        if rdtype == "A":
            return answer
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = _side_effect

    result = resolve_domain("example.com")

    a_records = [r for r in result.dns_records if r.record_type == "A"]
    assert len(a_records) == 1
    assert a_records[0].value == "93.184.216.34"
    assert a_records[0].name == "example.com."
    assert a_records[0].ttl == 300
    assert a_records[0].priority is None


@patch("dns.resolver.Resolver.resolve")
def test_resolve_domain_mx_record(mock_resolve):
    rdata = MagicMock()
    rdata.preference = 10
    rdata.to_text.return_value = "10 mail.example.com."
    rdata.__str__ = MagicMock(return_value="10 mail.example.com.")

    answer = _make_mock_answer([rdata], qname="example.com.", ttl=600)

    def _side_effect(domain, rdtype):
        if rdtype == "MX":
            return answer
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = _side_effect

    result = resolve_domain("example.com")

    mx_records = [r for r in result.dns_records if r.record_type == "MX"]
    assert len(mx_records) == 1
    assert mx_records[0].priority == 10
    assert mx_records[0].value == "10 mail.example.com."


@patch("dns.resolver.Resolver.resolve")
def test_resolve_domain_nxdomain(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()

    result = resolve_domain("nonexistent.example.invalid")

    assert len(result.dns_records) == 0
    assert any("NXDOMAIN" in e for e in result.errors)


@patch("dns.resolver.Resolver.resolve")
def test_resolve_domain_timeout(mock_resolve):
    rdata = MagicMock()
    rdata.__str__ = MagicMock(return_value="93.184.216.34")

    a_answer = _make_mock_answer([rdata], qname="example.com.", ttl=300)

    def _side_effect(domain, rdtype):
        if rdtype == "A":
            return a_answer
        if rdtype == "AAAA":
            raise dns.resolver.Timeout()
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = _side_effect

    result = resolve_domain("example.com")

    a_records = [r for r in result.dns_records if r.record_type == "A"]
    assert len(a_records) == 1
    assert any("Timeout" in e for e in result.errors)


# ---------------------------------------------------------------------------
# resolve_ip (PTR)
# ---------------------------------------------------------------------------


@patch("dns.resolver.Resolver.resolve")
@patch("dns.reversename.from_address")
def test_resolve_ip_ptr(mock_from_address, mock_resolve):
    mock_from_address.return_value = "34.216.184.93.in-addr.arpa."

    ptr_rdata = MagicMock()
    ptr_rdata.__str__ = MagicMock(return_value="dns.google.")

    ptr_answer = _make_mock_answer(
        [ptr_rdata], qname="34.216.184.93.in-addr.arpa.", ttl=3600,
    )

    fwd_rdata = MagicMock()
    fwd_rdata.__str__ = MagicMock(return_value="8.8.8.8")

    fwd_answer = _make_mock_answer([fwd_rdata], qname="dns.google.", ttl=300)

    def _side_effect(domain, rdtype):
        if rdtype == "PTR":
            return ptr_answer
        if rdtype == "A":
            return fwd_answer
        raise dns.resolver.NoAnswer()

    mock_resolve.side_effect = _side_effect

    result = resolve_ip("93.184.216.34")

    assert result.reverse_dns is not None
    assert len(result.reverse_dns) >= 1
    assert result.reverse_dns[0].value == "dns.google."
