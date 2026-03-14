from __future__ import annotations

import json
import urllib.request
import urllib.error

_BASE_URL = "https://api.securitytrails.com/v1"


def get_subdomains(domain: str, api_key: str) -> tuple[list[str], str | None]:
    """Fetch all known subdomains for *domain* from SecurityTrails.

    Returns (subdomains, None) on success or ([], error_message) on failure.
    Subdomains are returned as FQDNs (e.g. "www.example.com").
    """
    url = f"{_BASE_URL}/domain/{domain}/subdomains?children_only=false&include_inactive=false"
    req = urllib.request.Request(url, method="GET")
    req.add_header("APIKEY", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return [], "Invalid API key."
        if e.code == 429:
            return [], "SecurityTrails rate limit exceeded. Try again later."
        return [], f"SecurityTrails API error: HTTP {e.code}"
    except urllib.error.URLError as e:
        return [], f"Could not reach SecurityTrails: {e.reason}"
    except Exception as e:
        return [], f"SecurityTrails error: {e}"

    raw_subs = data.get("subdomains", [])
    fqdns = [f"{sub}.{domain}" for sub in raw_subs if sub]
    return fqdns, None


def get_domain_details(domain: str, api_key: str) -> tuple[dict | None, str | None]:
    """Fetch current DNS records for *domain* from SecurityTrails.

    Returns (current_dns_dict, None) on success or (None, error_message) on failure.
    """
    url = f"{_BASE_URL}/domain/{domain}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("APIKEY", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, "Invalid API key."
        if e.code == 429:
            return None, "SecurityTrails rate limit exceeded. Try again later."
        return None, f"SecurityTrails API error: HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"Could not reach SecurityTrails: {e.reason}"
    except Exception as e:
        return None, f"SecurityTrails error: {e}"

    current_dns = data.get("current_dns")
    if current_dns is None:
        return None, "No current_dns data in SecurityTrails response."
    return current_dns, None


def ping(api_key: str) -> tuple[bool, str | None]:
    """Verify that an API key is valid by hitting the ping endpoint.

    Returns (True, None) on success or (False, error_message) on failure.
    """
    url = f"{_BASE_URL}/ping"
    req = urllib.request.Request(url, method="GET")
    req.add_header("APIKEY", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
            return True, None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "Invalid API key."
        return False, f"SecurityTrails API error: HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, f"Could not reach SecurityTrails: {e.reason}"
    except Exception as e:
        return False, f"SecurityTrails error: {e}"
