from mitmproxy import http
from fluent import sender, event
import datetime
import urllib.parse
import urllib.request
import re
import getpass
import socket
import json
import os

sender.setup('fluentd.test', host='log-collect-td-agent', port=24224)

SENDER_EMAIL = None

def strip_html_tags(html):
    html = re.sub(r'<style.*?>.*?</style>', '', html, flags=re.DOTALL)
    html = re.sub(r'<.*?>', '', html)
    return html.strip()

def extract_email_from_text(text: str) -> str:
    try:
        obj = json.loads(text)
        for key in ("userEmail", "email", "loginEmail", "from"):
            v = obj.get(key)
            if isinstance(v, str) and "@" in v:
                return v
        for k in ("user", "account", "profile"):
            sub = obj.get(k)
            if isinstance(sub, dict):
                for kk in ("email", "loginEmail", "userEmail"):
                    vv = sub.get(kk)
                    if isinstance(vv, str) and "@" in vv:
                        return vv
    except Exception:
        pass
    m = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text or "")
    return m.group(0) if m else ""

def fetch_sender_email_with_cookie(cookie_header: str, ua: str) -> str:
    if not cookie_header:
        return ""
    try:
        req = urllib.request.Request(
                "https://mail.naver.com/json/initData",
                headers={
                    "Cookie": cookie_header,
                    "User-Agent": ua or "Mozilla/5.0",
                    "Accept": "application/json, text/plain, */*"
                    },
                method="GET"
                )
        with urllib.request.urlopen(req, timeout=3) as res:
            text = res.read().decode("utf-8", errors="replace")
        return extract_email_from_text(text)
    except Exception:
        return ""

def request(flow: http.HTTPFlow):
    if "mail.naver.com" in flow.request.pretty_url and "/json/write/send" in flow.request.path:
        try:
            content = flow.request.get_text()
            data = urllib.parse.parse_qs(content)
            raw_body = data.get("body", [""])[0]
            decoded_body = urllib.parse.unquote(raw_body)

            global SENDER_EMAIL
            from_addr = SENDER_EMAIL or fetch_sender_email_with_cookie(
                    flow.request.headers.get("Cookie", ""),
                    flow.request.headers.get("User-Agent", "")
            ) or ""

            if not SENDER_EMAIL and from_addr:
                SENDER_EMAIL = from_addr

            log = {
                    "employee_id": os.environ.get("EMPLOYEE_ID") or getpass.getuser(),
                    "pc_id": os.environ.get("PC_ID") or socket.gethostname(),
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                    "event_type": "email",
                    "from_addr": from_addr,
                    "to": [addr for addr in data.get("to", [""])[0].split(";") if addr.strip()],
                    "cc": [addr for addr in data.get("cc", [""])[0].split(";") if addr.strip()],
                    "bcc": [addr for addr in data.get("bcc", [""])[0].split(";") if addr.strip()],
                    "subject": data.get("subject", [""])[0],
                    "content": strip_html_tags(decoded_body),
                    "attachment": data.get("attachCount", ["0"])[0],
                    "size": len(content)
            }

            event.Event('webmail', log)

        except Exception as e:
            print("Error parsing email:", e)

def response(flow: http.HTTPFlow):
    global SENDER_EMAIL
    if "mail.naver.com" in flow.request.pretty_url and "/json/initData" in flow.request.path:
        try:
            text = flow.response.get_text() or ""
            email_parsed = extract_email_from_text(text)
            if email_parsed:
                SENDER_EMAIL = email_parsed
        except Exception:
            pass
