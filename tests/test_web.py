from __future__ import annotations

from pathlib import Path

import pytest

import dnsquery.web.app as web_app


@pytest.fixture()
def client():
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as test_client:
        yield test_client


def _stub_query(sample_query_result, calls):
    def run(query, api_key=None):
        calls.append((query, api_key))
        return sample_query_result, None, []

    return run


def test_index_and_health(client):
    index = client.get("/")
    assert index.status_code == 200
    assert b"DNSQuery - Domain Transfer Toolkit" in index.data
    assert b"/api/export?" not in index.data

    health = client.get("/health")
    assert health.status_code == 200
    assert health.get_json() == {"service": "dnsquery", "status": "ok"}


def test_query_requires_json_query(client):
    assert client.post("/api/query").status_code == 400
    assert client.post("/api/query", json={}).status_code == 400


def test_query_accepts_api_key_in_post_body(
    client, monkeypatch, sample_query_result,
):
    calls = []
    monkeypatch.setattr(web_app, "_run_query", _stub_query(sample_query_result, calls))

    response = client.post(
        "/api/query",
        json={"query": " example.com ", "api_key": "test-only-key"},
    )

    assert response.status_code == 200
    assert calls == [("example.com", "test-only-key")]
    assert b"test-only-key" not in response.data


def test_validate_key_requires_post_body(client, monkeypatch):
    assert client.post("/api/validate-key", json={}).status_code == 400

    monkeypatch.setattr(web_app, "ping", lambda key: (key == "valid-key", None))
    response = client.post("/api/validate-key", json={"api_key": "valid-key"})
    assert response.status_code == 200
    assert response.get_json() == {"error": None, "valid": True}


def test_export_is_post_only_and_removes_temporary_csv(
    client, monkeypatch, sample_query_result,
):
    calls = []
    created_paths: list[Path] = []
    original_named_tempfile = web_app.tempfile.NamedTemporaryFile

    def tracked_named_tempfile(*args, **kwargs):
        handle = original_named_tempfile(*args, **kwargs)
        created_paths.append(Path(handle.name))
        return handle

    monkeypatch.setattr(web_app, "_run_query", _stub_query(sample_query_result, calls))
    monkeypatch.setattr(web_app.tempfile, "NamedTemporaryFile", tracked_named_tempfile)

    assert client.get("/api/export?query=example.com&api_key=leaked").status_code == 405
    response = client.post(
        "/api/export",
        json={"query": "example.com", "api_key": "test-only-key"},
        buffered=True,
    )

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert calls == [("example.com", "test-only-key")]
    assert b"QUERY INFO" in response.data
    assert created_paths and all(not path.exists() for path in created_paths)
    assert "example.com_dns_report.csv" in response.headers["Content-Disposition"]


def test_export_requires_query_in_post_body(client):
    assert client.post("/api/export").status_code == 400
    assert client.post("/api/export", json={}).status_code == 400
