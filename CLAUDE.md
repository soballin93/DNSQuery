# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DNSQuery is a Python application for comprehensive DNS lookups and WHOIS queries, designed for domain ownership transfers. It resolves all DNS record types, fetches WHOIS contact/registrar data, checks transfer lock status (EPP codes), and exports results to CSV. Available as both a Tkinter desktop app and a Flask web app (Dockerized).

## Build & Run

```bash
# Create venv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the desktop application
python main.py

# Run the web server (development)
flask --app dnsquery.web.app run --port 8080

# Run the web server (production via Docker)
docker compose up --build

# Run tests
pytest

# Run a single test
pytest tests/test_dns_resolver.py::test_resolve_domain_a_record -v
```

## Architecture

- **`dnsquery/models.py`** — Central data contract: `DnsRecord`, `SoaRecord`, `WhoisInfo`, `QueryResult` dataclasses shared by all layers
- **`dnsquery/dns_resolver.py`** — DNS resolution via `dnspython`. Queries all record types (A, AAAA, MX, CNAME, TXT, SRV, NS, SOA, CAA, DNSKEY, DS, etc). Handles both domain and IP (reverse PTR) input. Non-fatal errors accumulate in `QueryResult.errors` for partial results.
- **`dnsquery/whois_lookup.py`** — WHOIS via `python-whois`. Normalizes inconsistent TLD responses (dates, status codes, contacts) into `WhoisInfo`.
- **`dnsquery/securitytrails.py`** — SecurityTrails API client for subdomain enumeration and domain details. API key is session-only, never stored.
- **`dnsquery/validation.py`** — Cross-references direct DNS queries against SecurityTrails data. Compares A, AAAA, MX, NS, TXT, SOA records.
- **`dnsquery/export.py`** — CSV export with sectioned layout (QUERY INFO, WHOIS, SOA, DNS RECORDS, ERRORS).
- **`dnsquery/gui/`** — Tkinter GUI with `ttk.Notebook` tabs (Summary, Name Servers, SOA, DNS Records, WHOIS, Validation, Errors). DNS/WHOIS queries run on a background `threading.Thread`; results marshal back to the main thread via `root.after(0, callback)`.
- **`dnsquery/web/`** — Flask web app with REST API (`/api/query`, `/api/validate-key`, `/api/export`) and single-page HTML frontend. Served via gunicorn in Docker.
- **`main.py`** — Desktop entry point, launches `DNSQueryApp`.
