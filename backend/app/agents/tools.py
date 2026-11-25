import json
import base64
from datetime import datetime, timezone
from typing import Dict, Any, List
import httpx
import whois
from rapidfuzz import fuzz

from app.core.config import settings


def check_virustotal_url(url: str) -> Dict[str, Any]:
    """Queries VirusTotal v3 API for URL reputation without visiting the URL."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"checked": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        with httpx.Client(timeout=6.0) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                return {
                    "checked": True,
                    "malicious_votes": stats.get("malicious", 0),
                    "suspicious_votes": stats.get("suspicious", 0),
                    "harmless_votes": stats.get("harmless", 0),
                }
            elif resp.status_code == 404:
                return {"checked": True, "status": "not_in_vt_database"}
            return {"checked": False, "status_code": resp.status_code}
    except Exception as exc:
        return {"checked": False, "error": str(exc)}


def check_google_safe_browsing(urls: List[str]) -> Dict[str, Any]:
    """Queries Google Safe Browsing v4 API for known phishing/malware URLs."""
    if not settings.GOOGLE_SAFE_BROWSING_KEY or not urls:
        return {"checked": False, "matches": []}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "phishguard-investigative-system", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:10]],
        },
    }

    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                return {"checked": True, "threat_count": len(matches), "matches": matches}
            return {"checked": False, "status_code": resp.status_code}
    except Exception as exc:
        return {"checked": False, "error": str(exc)}


def check_urlhaus_url(url: str) -> Dict[str, Any]:
    """Queries abuse.ch URLhaus public API (no API key required)."""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "checked": True,
                    "query_status": data.get("query_status"),
                    "threat": data.get("threat"),
                    "tags": data.get("tags"),
                }
            return {"checked": False, "status_code": resp.status_code}
    except Exception as exc:
        return {"checked": False, "error": str(exc)}


def check_domain_age_whois(domain: str) -> Dict[str, Any]:
    """Looks up domain creation date via WHOIS to spot newly registered lookalike domains."""
    if not domain or domain.replace(".", "").isdigit():
        return {"checked": False, "reason": "IP address or empty domain"}
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return {
                "checked": True,
                "creation_date": creation.strftime("%Y-%m-%d"),
                "age_days": age_days,
                "newly_registered": age_days < 60,
            }
        return {"checked": True, "creation_date": "unknown"}
    except Exception as exc:
        return {"checked": False, "error": str(exc)}


def verify_identity_against_directory(
    sender_name: str,
    sender_email: str,
    sender_domain: str,
    reply_to_email: str | None,
) -> Dict[str, Any]:
    """Compares sender display name and domain against the internal organizational directory."""
    with open(settings.ORG_DIRECTORY_PATH, "r", encoding="utf-8") as f:
        directory = json.load(f)

    official_domains = set(directory.get("official_domains", []))
    executives = directory.get("executives", [])

    findings: List[str] = []
    impersonated_exec = None
    domain_typosquat_target = None

    # 1. Check if sender_domain is a lookalike of an official corporate domain
    if sender_domain and sender_domain not in official_domains:
        for official in official_domains:
            sim = fuzz.ratio(sender_domain, official)
            if sim >= 75:
                domain_typosquat_target = official
                findings.append(
                    f"Lookalike domain detected: '{sender_domain}' has {sim:.0f}% similarity to official domain '{official}'."
                )

    # 2. Check if display name matches a known executive while email/domain is unauthorized
    clean_name = sender_name.lower()
    for exec_info in executives:
        exec_name = exec_info["name"].lower()
        if exec_name in clean_name or fuzz.partial_ratio(exec_name, clean_name) >= 88:
            if sender_email.lower() != exec_info["email"].lower():
                impersonated_exec = exec_info
                findings.append(
                    f"Executive impersonation alert: Display name matches {exec_info['name']} ({exec_info['title']}), "
                    f"but actual sender '{sender_email}' does not match official address '{exec_info['email']}'."
                )

    # 3. Check if Reply-To routes to an external/free webmail domain
    if reply_to_email and "@" in reply_to_email:
        reply_domain = reply_to_email.split("@", 1)[1].lower()
        if reply_domain not in official_domains and reply_domain != sender_domain:
            findings.append(
                f"Reply-To header ('{reply_to_email}') diverts replies to an external domain ('{reply_domain}')."
            )

    return {
        "is_official_domain": sender_domain in official_domains,
        "impersonated_executive": impersonated_exec,
        "domain_typosquat_target": domain_typosquat_target,
        "findings": findings,
    }