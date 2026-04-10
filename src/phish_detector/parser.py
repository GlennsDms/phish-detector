import email
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path
from bs4 import BeautifulSoup
import re


def parse_eml(path: Path) -> dict:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    return {
        "subject": _get_subject(msg),
        "from": _get_header(msg, "from"),
        "to": _get_header(msg, "to"),
        "reply_to": _get_header(msg, "reply-to"),
        "return_path": _get_header(msg, "return-path"),
        "x_mailer": _get_header(msg, "x-mailer"),
        "spf": _get_auth_result(msg, "spf"),
        "dkim": _get_auth_result(msg, "dkim"),
        "dmarc": _get_auth_result(msg, "dmarc"),
        "body_text": _get_body(msg, "plain"),
        "body_html": _get_body(msg, "html"),
        "urls": _extract_urls(msg),
        "attachments": _get_attachments(msg),
        "headers_raw": dict(msg.items()),
    }


def _get_header(msg, name: str) -> str:
    value = msg.get(name, "")
    return str(value).strip()


def _get_subject(msg) -> str:
    return _get_header(msg, "subject")


def _get_auth_result(msg, check: str) -> str:
    auth_results = msg.get("authentication-results", "")
    if not auth_results:
        return "none"
    auth_results = auth_results.lower()
    pattern = rf"{check}=(\w+)"
    match = re.search(pattern, auth_results)
    return match.group(1) if match else "none"


def _get_body(msg, content_type: str) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == f"text/{content_type}":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        if msg.get_content_type() == f"text/{content_type}":
            try:
                body = msg.get_content()
            except Exception:
                pass
    return body


def _extract_urls(msg) -> list[str]:
    html_body = _get_body(msg, "html")
    text_body = _get_body(msg, "plain")
    urls = []

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for tag in soup.find_all(href=True):
            urls.append(tag["href"])
        for tag in soup.find_all(src=True):
            urls.append(tag["src"])

    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
    urls += url_pattern.findall(text_body)

    return list(set(urls))


def _get_attachments(msg) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "filename": part.get_filename() or "unknown",
                "content_type": part.get_content_type(),
            })
    return attachments


if __name__ == "__main__":
    import json
    import sys

    path = Path(sys.argv[1])
    result = parse_eml(path)
    print(json.dumps(result, indent=2, default=str))