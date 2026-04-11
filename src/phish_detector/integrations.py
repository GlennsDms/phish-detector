import os
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"


def check_ip_reputation(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set", "ip": ip}

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "unknown"),
            "is_tor": data.get("isTor", False),
            "is_proxy": data.get("usageType", "") in ["VPN Service", "Tor Exit Node", "Proxy"],
        }
    except requests.RequestException as e:
        return {"error": str(e), "ip": ip}


def check_url_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set", "url": url}

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"{VIRUSTOTAL_URL}/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )

        if response.status_code == 404:
            # URL not in VT yet, submit it
            submit = requests.post(
                VIRUSTOTAL_URL,
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                data={"url": url},
                timeout=10,
            )
            submit.raise_for_status()
            return {"url": url, "status": "submitted, not yet analyzed"}

        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        return {
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }

    except requests.RequestException as e:
        return {"error": str(e), "url": url}


def enrich_parsed_email(parsed: dict) -> dict:
    enrichment = {
        "ip_reputation": [],
        "url_reputation": [],
    }

    urls = parsed.get("urls", [])
    for url in urls[:5]:  # limit to first 5 to avoid rate limiting
        result = check_url_virustotal(url)
        enrichment["url_reputation"].append(result)

    return enrichment