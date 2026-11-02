import base64
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }


def _safe_get(path: str) -> dict:
    if not VT_API_KEY:
        return {
            "enabled": False,
            "error": "VIRUSTOTAL_API_KEY is not configured"
        }

    try:
        response = requests.get(
            f"{VT_BASE_URL}{path}",
            headers=_headers(),
            timeout=15
        )

        if response.status_code == 404:
            return {
                "enabled": True,
                "found": False
            }

        if response.status_code == 429:
            return {
                "enabled": True,
                "rate_limited": True,
                "error": "VirusTotal rate limit reached"
            }

        response.raise_for_status()
        return response.json()

    except requests.RequestException as exc:
        return {
            "enabled": True,
            "error": str(exc)
        }


def _extract_stats(vt_response: dict) -> dict:
    attributes = vt_response.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "reputation": attributes.get("reputation"),
    }


def _url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


def lookup_domain(domain: str) -> dict:
    response = _safe_get(f"/domains/{domain}")

    if response.get("error") or response.get("found") is False:
        return {
            "type": "domain",
            "indicator": domain,
            **response
        }

    return {
        "type": "domain",
        "indicator": domain,
        **_extract_stats(response)
    }


def lookup_hash(file_hash: str) -> dict:
    response = _safe_get(f"/files/{file_hash}")

    if response.get("error") or response.get("found") is False:
        return {
            "type": "hash",
            "indicator": file_hash,
            **response
        }

    return {
        "type": "hash",
        "indicator": file_hash,
        **_extract_stats(response)
    }


def lookup_url(url: str) -> dict:
    url_identifier = _url_id(url)
    response = _safe_get(f"/urls/{url_identifier}")

    if response.get("error") or response.get("found") is False:
        return {
            "type": "url",
            "indicator": url,
            **response
        }

    return {
        "type": "url",
        "indicator": url,
        **_extract_stats(response)
    }


def enrich_iocs_with_virustotal(iocs: dict, max_items_per_type: int = 3) -> dict[str, list[dict[str, Any]]]:
    domains = iocs.get("domains", [])[:max_items_per_type]
    urls = iocs.get("urls", [])[:max_items_per_type]
    hashes = iocs.get("hashes", [])[:max_items_per_type]

    results = {
        "domains": [],
        "urls": [],
        "hashes": []
    }

    for domain in domains:
        results["domains"].append(lookup_domain(domain))
        time.sleep(0.25)

    for url in urls:
        results["urls"].append(lookup_url(url))
        time.sleep(0.25)

    for file_hash in hashes:
        results["hashes"].append(lookup_hash(file_hash))
        time.sleep(0.25)

    return results