# DNSQuery

DNSQuery is a domain-transfer toolkit with desktop and web interfaces. It resolves DNS and
reverse DNS records, normalizes WHOIS details, optionally compares results with
SecurityTrails, and exports a sectioned CSV report.

## Development

```bash
./.venv/bin/python -m pytest -q
~/.local/bin/uvx --from ruff==0.12.12 ruff check .
./.venv/bin/flask --app dnsquery.web.app run --port 8080
```

The Flask API provides `GET /health`, `POST /api/query`, `POST /api/validate-key`, and
`POST /api/export`. Request secrets belong in JSON bodies. CSV exports are generated in a
temporary file which is removed after Flask prepares the response.

## Production

The service is deployed on primary Unraid as the `dnsquery` container, published on port
8080. CI tests and lints before publishing GHCR images. Production deployment should build or
select one reviewed commit image, disable Watchtower for DNSQuery, and use an immutable image
tag; `deploy/docker-compose.yml` accepts that tag through `DNSQUERY_IMAGE`.
