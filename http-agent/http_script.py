from mitmproxy import http
import uuid
import json
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fluent import sender, event
import getpass
import socket
import os

sender.setup('fluentd.test', host='log-collect-td-agent', port=24224)

EXCLUDE_DOMAINS = [
    "detectportal.firefox.com",
    "mozilla.org",
    "mozilla.com",
    "cdn.mozilla.net",
    "incoming.telemetry.mozilla.org",
    "firefox.settings.services.mozilla.com",
    "push.services.mozilla.com",
    "lencr.org",
    "ocsp.digicert.com",
    "google-analytics.com",
    "safebrowsing.googleapis.com",
    "adcr.shopping.naver.com",
    "cologger.shopping.naver.com",
    "nlog.naver.com"
]

AD_DOMAINS = [
    "tivan.naver.com",
    "veta.naver.com",
    "ad.naver.com",
    "doubleclick.net",
    "googlesyndication.com",
    "adsafeprotected.com",
    "moatads.com",
    "criteo.com"
]

AD_KEYWORDS = [
    "adunit", "vast", "impression", "adinfo",
    "eventtracking", "creative", "adprovider"
]

EXCLUDE_CONTENT_TYPES = [
    "image/", "text/css",
    "application/javascript", "application/x-javascript",
    "application/x-font-ttf", "application/font-woff",
    "application/font-woff2", "application/octet-stream"
]

EXCLUDE_EXTENSIONS = [
    ".ico", ".css", ".js", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".woff", ".ttf", ".avif",
    ".webp", ".eot", ".otf", ".pdf", ".zip", "webm"
]


def get_hostname(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def get_path(url):
    try:
        return urlparse(url).path or ""
    except Exception:
        return ""


def is_useless_json(content) -> bool:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list) and len(parsed) == 1:
            item = parsed[0]
            if (
                item.get("error") is False
                and isinstance(item.get("data"), list)
                and not item["data"]
            ):
                return True
            if item.get("error") is True and "exception" in item:
                return True
    except Exception:
        pass
    return False


def is_ad_related(url, content):
    url = url.lower()
    content = content.lower()
    return (
        any(domain in url for domain in AD_DOMAINS)
        or any(keyword in content for keyword in AD_KEYWORDS)
    )


def should_skip(flow: http.HTTPFlow) -> bool:
    if flow.request.method == "CONNECT":
        return True

    url = flow.request.pretty_url
    hostname = get_hostname(url).lower()
    path = get_path(url).lower()

    for blocked in EXCLUDE_DOMAINS:
        if hostname and blocked in hostname:
            return True

    content_type = flow.response.headers.get("Content-Type", "").lower()

    if any(ct in content_type for ct in EXCLUDE_CONTENT_TYPES):
        return True

    for ext in EXCLUDE_EXTENSIONS:
        if path.endswith(ext):
            return True

    if "application/json" in content_type:
        if is_useless_json(flow.response.text):
            return True

    if is_ad_related(url, flow.response.text):
        return True

    return False


def response(flow: http.HTTPFlow):
    if flow.response is None or should_skip(flow):
        return

    log_entry = {
        "employee_id": os.environ.get("EMPLOYEE_ID") or  getpass.getuser(),
        "pc_id": os.environ.get("PC_ID") or socket.gethostname(),
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "event_type": "http",
        "url": flow.request.pretty_url
    }

    event.Event('http', log_entry)

