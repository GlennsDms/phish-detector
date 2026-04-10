import re
from urllib.parse import urlparse
from datetime import datetime


URGENCY_WORDS = [
    "urgent", "immediately", "verify", "suspend", "suspended", "click now",
    "confirm your", "update your", "unusual activity", "unauthorized",
    "your account", "will be closed", "limited time", "act now", "expire",
    "validate", "reactivate", "billing", "payment failed", "security alert"
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "icloud.com"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".jar"
]


def extract_features(parsed: dict) -> dict:
    return {
        # Sender features
        **_sender_features(parsed),
        # URL features
        **_url_features(parsed),
        # Body features
        **_body_features(parsed),
        # Header features
        **_header_features(parsed),
        # Attachment features
        **_attachment_features(parsed),
    }


def _get_domain(email_str: str) -> str:
    match = re.search(r"@([\w.-]+)", email_str)
    return match.group(1).lower() if match else ""


def _sender_features(parsed: dict) -> dict:
    from_addr = parsed.get("from", "")
    reply_to = parsed.get("reply_to", "")
    return_path = parsed.get("return_path", "")

    from_domain = _get_domain(from_addr)
    reply_domain = _get_domain(reply_to)
    return_domain = _get_domain(return_path)

    return {
        "from_domain": from_domain,
        "from_is_free_provider": int(from_domain in FREE_EMAIL_PROVIDERS),
        "reply_to_differs_from": int(
            bool(reply_to) and reply_domain != from_domain
        ),
        "return_path_differs": int(
            bool(return_path) and return_domain != from_domain
        ),
        "from_has_numbers": int(bool(re.search(r"\d{3,}", from_domain))),
        "from_domain_length": len(from_domain),
    }


def _url_features(parsed: dict) -> dict:
    urls = parsed.get("urls", [])
    if not urls:
        return {
            "url_count": 0,
            "urls_with_ip": 0,
            "urls_with_at_symbol": 0,
            "avg_url_length": 0,
            "max_url_length": 0,
            "urls_with_redirect": 0,
            "urls_with_https": 0,
            "urls_with_suspicious_tld": 0,
        }

    suspicious_tlds = [".xyz", ".top", ".club", ".work", ".click", ".loan", ".win"]
    ip_pattern = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")

    urls_with_ip = sum(1 for u in urls if ip_pattern.match(u))
    urls_with_at = sum(1 for u in urls if "@" in u)
    urls_with_redirect = sum(1 for u in urls if "redirect" in u or "url=" in u or "link=" in u)
    urls_with_https = sum(1 for u in urls if u.startswith("https://"))
    urls_suspicious_tld = sum(
        1 for u in urls
        if any(urlparse(u).netloc.endswith(tld) for tld in suspicious_tlds)
    )
    lengths = [len(u) for u in urls]

    return {
        "url_count": len(urls),
        "urls_with_ip": urls_with_ip,
        "urls_with_at_symbol": urls_with_at,
        "avg_url_length": round(sum(lengths) / len(lengths), 2),
        "max_url_length": max(lengths),
        "urls_with_redirect": urls_with_redirect,
        "urls_with_https": urls_with_https,
        "urls_with_suspicious_tld": urls_suspicious_tld,
    }


def _body_features(parsed: dict) -> dict:
    text = parsed.get("body_text", "") or ""
    html = parsed.get("body_html", "") or ""
    text_lower = text.lower()

    urgency_count = sum(1 for w in URGENCY_WORDS if w in text_lower)
    has_html = int(bool(html))
    html_to_text_ratio = round(len(html) / max(len(text), 1), 2)

    return {
        "urgency_word_count": urgency_count,
        "has_html_body": has_html,
        "html_to_text_ratio": html_to_text_ratio,
        "body_length": len(text),
        "body_has_form": int("<form" in html.lower()),
        "body_has_script": int("<script" in html.lower()),
    }


def _header_features(parsed: dict) -> dict:
    spf = parsed.get("spf", "none")
    dkim = parsed.get("dkim", "none")
    dmarc = parsed.get("dmarc", "none")

    return {
        "spf_pass": int(spf == "pass"),
        "dkim_pass": int(dkim == "pass"),
        "dmarc_pass": int(dmarc == "pass"),
        "auth_score": int(spf == "pass") + int(dkim == "pass") + int(dmarc == "pass"),
        "has_x_mailer": int(bool(parsed.get("x_mailer", ""))),
    }


def _attachment_features(parsed: dict) -> dict:
    attachments = parsed.get("attachments", [])
    has_suspicious = any(
        any(att["filename"].endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        for att in attachments
    )
    return {
        "attachment_count": len(attachments),
        "has_suspicious_attachment": int(has_suspicious),
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    from phish_detector.parser import parse_eml

    path = Path(sys.argv[1])
    parsed = parse_eml(path)
    features = extract_features(parsed)
    print(json.dumps(features, indent=2))