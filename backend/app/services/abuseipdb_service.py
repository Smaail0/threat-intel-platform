import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {
            "enabled": False,
            "error": "ABUSEIPDB_API_KEY is not configured"
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": ""
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "enabled": True,
            "ip": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "is_whitelisted": data.get("isWhitelisted"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt")
        }

    except requests.RequestException as exc:
        return {
            "enabled": True,
            "error": str(exc),
            "ip": ip
        }