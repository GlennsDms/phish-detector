import re
from urllib.parse import urlparse, parse_qs
import ipaddress


URGENCY_WORDS = [
    "urgent", "immediately", "verify", "suspend", "suspended", "click now",
    "confirm your", "update your", "unusual activity", "unauthorized",
    "your account", "will be closed", "limited time", "act now", "expire",
    "validate", "reactivate", "billing", "payment failed", "security alert",
    "account locked", "login attempt", "confirm identity", "reset your password"
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "icloud.com"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".js", ".vbs", ".bat", ".cmd", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".jar", ".msi", ".scr"
]

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd", "v.gd", "bl.ink"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".win",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".pw", ".cc", ".su"
]

# Redirect param names attackers commonly use
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "next",
    "target", "redir", "dest", "destination", "go", "link", "out"
]


def extract_features(parsed: dict) -> dict:
    return {
        **_sender_features(parsed),
        **_url_features(parsed),
        **_body_features(parsed),
        **_header_features(parsed),
        **_attachment_features(parsed),
    }


def _get_domain(email_str: str) -> str:
    match = re.search(r"@([\w.-]+)", str(email_str))
    return match.group(1).lower() if match else ""


def _is_ip_address(host: str) -> bool:
    # Covers IPv4, IPv6, hex-encoded, octal, and decimal representations
    clean = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass
    # Hex encoded IPv4 e.g. 0xC0A80001
    if re.match(r"^0x[0-9a-fA-F]{8}$", clean):
        return True
    # Decimal encoded IPv4 e.g. 3232235521
    if re.match(r"^\d{8,10}$", clean):
        return True
    return False


def _has_redirect(url: str) -> bool:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in REDIRECT_PARAMS:
            if param in params:
                return True
        # Also check if any param value looks like a URL
        for values in params.values():
            for val in values:
                if val.startswith("http"):
                    return True
    except Exception:
        pass
    return False


def _sender_features(parsed: dict) -> dict:
    from_addr = str(parsed.get("from", ""))
    reply_to = str(parsed.get("reply_to", ""))
    return_path = str(parsed.get("return_path", ""))

    from_domain = _get_domain(from_addr)
    reply_domain = _get_domain(reply_to)
    return_domain = _get_domain(return_path)

    return {
        "from_domain": from_domain,
        "from_is_free_provider": int(from_domain in FREE_EMAIL_PROVIDERS),
        "reply_to_differs_from": int(bool(reply_to) and reply_domain != from_domain),
        "return_path_differs": int(bool(return_path) and return_domain != from_domain),
        "from_has_numbers": int(bool(re.search(r"\d{3,}", from_domain))),
        "from_domain_length": len(from_domain),
        "from_display_name_mismatch": _display_name_mismatch(from_addr),
    }


def _display_name_mismatch(from_addr: str) -> int:
    # Checks if display name contains a different domain than the actual address
    # e.g. "PayPal Support <attacker@evil.com>"
    match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_addr)
    if not match:
        return 0
    display_name = match.group(1).lower()
    actual_domain = _get_domain(match.group(2))
    brands = ["paypal", "amazon", "apple", "microsoft", "google", "bank", "netflix"]
    for brand in brands:
        if brand in display_name and brand not in actual_domain:
            return 1
    return 0


def _url_features(parsed: dict) -> dict:
    urls = parsed.get("urls", [])
    if not urls:
        return {
            "url_count": 0,
            "urls_with_ip": 0,
            "urls_with_at_symbol": 0,
            "urls_with_redirect": 0,
            "urls_with_shortener": 0,
            "urls_with_https": 0,
            "urls_with_suspicious_tld": 0,
            "urls_subdomain_depth": 0,
        }

    urls_with_ip = sum(1 for u in urls if _is_ip_address(urlparse(u).hostname or ""))
    urls_with_at = sum(1 for u in urls if "@" in urlparse(u).netloc)
    urls_with_redirect = sum(1 for u in urls if _has_redirect(u))
    urls_with_shortener = sum(
        1 for u in urls if any(s in u for s in KNOWN_SHORTENERS)
    )
    urls_with_https = sum(1 for u in urls if u.startswith("https://"))
    urls_suspicious_tld = sum(
        1 for u in urls
        if any((urlparse(u).netloc or "").endswith(tld) for tld in SUSPICIOUS_TLDS)
    )
    subdomain_depths = []
    for u in urls:
        host = urlparse(u).hostname or ""
        parts = host.split(".")
        subdomain_depths.append(max(0, len(parts) - 2))

    return {
        "url_count": len(urls),
        "urls_with_ip": urls_with_ip,
        "urls_with_at_symbol": urls_with_at,
        "urls_with_redirect": urls_with_redirect,
        "urls_with_shortener": urls_with_shortener,
        "urls_with_https": urls_with_https,
        "urls_with_suspicious_tld": urls_suspicious_tld,
        "urls_subdomain_depth": round(sum(subdomain_depths) / max(len(subdomain_depths), 1), 2),
    }


def _body_features(parsed: dict) -> dict:
    text = parsed.get("body_text", "") or ""
    html = parsed.get("body_html", "") or ""
    text_lower = text.lower()

    urgency_count = sum(1 for w in URGENCY_WORDS if w in text_lower)

    # Safer ratio: only compute if both exist
    if text and html:
        html_to_text_ratio = round(len(html) / len(text), 2)
    else:
        html_to_text_ratio = 0

    return {
        "urgency_word_count": urgency_count,
        "has_html_body": int(bool(html)),
        "html_to_text_ratio": min(html_to_text_ratio, 50),  # cap to avoid newsletter noise
        "body_length": len(text),
        "body_has_form": int("<form" in html.lower()),
        "body_has_script": int("<script" in html.lower()),
        "body_has_hidden_elements": int(
            "display:none" in html.lower() or "visibility:hidden" in html.lower()
        ),
    }


def _header_features(parsed: dict) -> dict:
    spf = parsed.get("spf", "none")
    dkim = parsed.get("dkim", "none")
    dmarc = parsed.get("dmarc", "none")

    return {
        "spf_pass": int(spf == "pass"),
        "dkim_pass": int(dkim == "pass"),
        "dmarc_pass": int(dmarc == "pass"),
        "has_x_mailer": int(bool(parsed.get("x_mailer", ""))),
    }


def _attachment_features(parsed: dict) -> dict:
    attachments = parsed.get("attachments", [])
    has_suspicious = any(
        any(att["filename"].lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        for att in attachments
    )
    return {
        "attachment_count": len(attachments),
        "has_suspicious_attachment": int(has_suspicious),
    }