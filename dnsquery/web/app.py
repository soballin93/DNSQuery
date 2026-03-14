from __future__ import annotations

import dataclasses
import tempfile

from flask import Flask, jsonify, render_template, request, send_file

from dnsquery.dns_resolver import is_ip_address, resolve_domain, resolve_ip
from dnsquery.export import export_to_csv
from dnsquery.models import QueryResult
from dnsquery.securitytrails import get_domain_details, get_subdomains, ping
from dnsquery.validation import ValidationResult, validate_dns
from dnsquery.whois_lookup import lookup_whois

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


def _run_query(
    query: str,
    api_key: str | None = None,
) -> tuple[QueryResult, ValidationResult | None, list[str]]:
    """Execute a full DNS + WHOIS + optional SecurityTrails query.

    Returns (query_result, validation_result_or_none, extra_errors).
    """
    extra_errors: list[str] = []
    validation_result: ValidationResult | None = None

    if is_ip_address(query):
        result = resolve_ip(query)
        if result.reverse_dns:
            hostname = result.reverse_dns[0].value.rstrip(".")
            whois_info, whois_err = lookup_whois(hostname)
            result.whois = whois_info
            if whois_err:
                result.errors.append(f"WHOIS: {whois_err}")
    else:
        subdomains: list[str] | None = None
        if api_key:
            subdomains, st_err = get_subdomains(query, api_key)
            if st_err:
                extra_errors.append(st_err)
                subdomains = None

        result = resolve_domain(query, subdomains=subdomains)

        # WHOIS lookup (only for domains)
        whois_info, whois_err = lookup_whois(query)
        result.whois = whois_info
        if whois_err:
            result.errors.append(f"WHOIS: {whois_err}")

        # SecurityTrails validation
        if api_key:
            st_dns, st_detail_err = get_domain_details(query, api_key)
            if st_detail_err:
                extra_errors.append(st_detail_err)
            elif st_dns is not None:
                validation_result = validate_dns(result, st_dns)

    return result, validation_result, extra_errors


@app.route("/api/query", methods=["POST"])
def api_query():
    data = request.get_json(silent=True)
    if not data or not data.get("query"):
        return jsonify({"error": "Missing required field: query"}), 400

    query = data["query"].strip()
    api_key = data.get("api_key") or None

    try:
        result, validation_result, extra_errors = _run_query(query, api_key)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    response: dict = {
        "result": dataclasses.asdict(result),
        "validation": dataclasses.asdict(validation_result) if validation_result else None,
        "extra_errors": extra_errors,
    }

    return jsonify(response)


@app.route("/api/validate-key", methods=["POST"])
def api_validate_key():
    data = request.get_json(silent=True)
    if not data or not data.get("api_key"):
        return jsonify({"valid": False, "error": "Missing required field: api_key"}), 400

    api_key = data["api_key"].strip()
    valid, error = ping(api_key)

    return jsonify({"valid": valid, "error": error})


@app.route("/api/export", methods=["GET"])
def api_export():
    query = request.args.get("query", "").strip()
    if not query:
        return jsonify({"error": "Missing required parameter: query"}), 400

    api_key = request.args.get("api_key") or None

    try:
        result, _validation, _extra_errors = _run_query(query, api_key)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Write CSV to a temporary file and send it as a download
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".csv",
        delete=False,
        prefix="dnsquery_",
    )
    tmp.close()
    export_to_csv(result, tmp.name)

    safe_name = query.replace(" ", "_").replace("/", "_")
    download_name = f"{safe_name}_dns_report.csv"

    return send_file(
        tmp.name,
        mimetype="text/csv",
        as_attachment=True,
        download_name=download_name,
    )
