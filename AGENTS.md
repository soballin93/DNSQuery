# DNSQuery contributor guide

DNSQuery provides a Tkinter desktop client and a Flask/Gunicorn web service for DNS, WHOIS,
SecurityTrails validation, and CSV exports. Production runs on primary Unraid as `dnsquery`
on port 8080.

## Validate

Use the existing repository environment on DEV-MASTER:

```bash
./.venv/bin/python -m pytest -q
~/.local/bin/uvx --from ruff==0.12.12 ruff check .
docker build -t dnsquery:test .   # run on a Docker-capable host
```

Route tests must remain offline by monkeypatching DNS, WHOIS, and SecurityTrails calls. API
keys are session-only secrets: accept them in POST JSON bodies and never place them in URLs,
redirects, filenames, logs, or test output. `/api/export` must delete its temporary CSV after
the response is prepared.

## Deploy

Build the exact reviewed commit and give it an immutable local tag. Stop or exclude Watchtower
before replacing the container, then deploy with `DNSQUERY_IMAGE=dnsquery:<commit>` and verify:

```bash
curl -fsS http://unraid:8080/health
curl -fsS -X POST -H 'Content-Type: application/json' \
  --data '{"query":"example.com"}' http://unraid:8080/api/query
```

Do not deploy a moving `latest` tag as the reviewed production artifact. The Compose label
keeps Watchtower disabled for this service.
