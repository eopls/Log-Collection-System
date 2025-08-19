import os
import json
import email
from email import policy
from fluent import sender, event
from pathlib import Path
from datetime import datetime
import mimetypes
import getpass
import socket
import re
from email.utils import getaddresses
import gzip
import hashlib  # ★ 추가

# Fluentd 설정
sender.setup('fluentd.test', host='log-collect-td-agent', port=24224)

# Maildir 경로
MAILDIR_BASE = Path('/opt/mail/Maildir')
NEW_DIR = MAILDIR_BASE / 'new'
CUR_DIR = MAILDIR_BASE / 'cur'
NEW_DIR.mkdir(parents=True, exist_ok=True)
CUR_DIR.mkdir(parents=True, exist_ok=True)

# 처리된 파일/메시지 기록용
STATE_DIR = Path('/var/lib/mail-agent')
STATE_DIR.mkdir(parents=True, exist_ok=True)
processed_file = STATE_DIR / 'processed_eml'

# ★ 추가: Message-Id/대체키 중복 방지용
processed_msgids_file = STATE_DIR / 'processed_msgids'
if processed_msgids_file.exists():
    with processed_msgids_file.open('r') as f:
        processed_msgids = set(line.strip() for line in f if line.strip())
else:
    processed_msgids = set()

POSTFIX_LOGS = sorted(map(str, Path("/host/var/log").glob("mail.log*")))

def _iter_log_lines(paths: list[str]):
    for p in paths:
        try:
            if p.endswith(".gz"):
                with gzip.open(p, "rt", errors="ignore") as f:
                    for ln in f:
                        yield ln
            else:
                with open(p, errors="ignore") as f:
                    for ln in f:
                        yield ln
        except FileNotFoundError:
            continue

def _header_emails_only(msg, field: str) -> list[str]:
    vals = msg.get_all(field, []) or []
    return sorted({addr.strip().lower() for _, addr in getaddresses(vals) if addr})

def _extract_msgid(msg) -> str:
    mid = (msg.get('Message-Id') or '').strip()
    return mid[1:-1] if mid.startswith('<') and mid.endswith('>') else mid

def _queue_ids_by_message_id(message_id: str) -> set[str]:
    if not message_id:
        return set()
    qids = set()
    pat = re.compile(r":\s+([A-Z0-9]{5,}):\s+message-id=<([^>]+)>", re.IGNORECASE)
    for line in _iter_log_lines(POSTFIX_LOGS):
        m = pat.search(line)
        if m and m.group(2) == message_id:
            qids.add(m.group(1))
    return qids

def _all_recipients_by_qids(qids: set[str]) -> set[str]:
    recips = set()
    if not qids:
        return recips
    ids = "|".join(map(re.escape, qids))
    # QID 다음 전체 payload를 받아서 key=<value>쌍을 개별 추출
    line_pat = re.compile(rf":\s+({ids}):\s+(.*)", re.IGNORECASE)
    kv_pat   = re.compile(r"\b(orig_to|to)=<([^>]+)>", re.IGNORECASE)

    for line in _iter_log_lines(POSTFIX_LOGS):
        m = line_pat.search(line)
        if not m:
            continue
        payload = m.group(2)
        # 같은 라인 안에 to / orig_to가 모두 있을 수 있음 → dict로 마지막 값 우선
        found = dict((k.lower(), v.strip().lower()) for k, v in kv_pat.findall(payload))
        if "orig_to" in found:
            recips.add(found["orig_to"])
        elif "to" in found:
            recips.add(found["to"])
    return recips

def _x_original_to_from_headers(msg) -> set[str]:
    vals = msg.get_all("X-Original-To", []) or []
    return {addr.strip().lower() for _, addr in getaddresses(vals) if addr}

# ★ 추가: Message-Id가 없을 때를 포함한 “중복 판별 키”
def _canonical_msg_key(msg, eml_path: Path) -> str:
    mid = _extract_msgid(msg)
    return ("mid:" + mid.lower()) if mid else ""

def _rcpts_from_local_copies_by_mid(message_id: str) -> set[str]:
    if not message_id:
        return set()
    rcpts = set()
    # NEW/CUR 둘 다 훑되, 너무 많이 뒤지지 않게 최근 파일 위주로
    candidates = list(sorted((NEW_DIR.glob('*')))) + list(sorted((CUR_DIR.glob('*'))))
    for p in candidates[-200:]:  # 최근 200개만
        try:
            with p.open('rb') as f:
                m = email.message_from_binary_file(f, policy=policy.default)
            mid = (m.get('Message-Id') or '').strip()
            mid = mid[1:-1] if mid.startswith('<') and mid.endswith('>') else mid
            if mid != message_id:
                continue
            for _, addr in getaddresses(m.get_all("X-Original-To", []) or []):
                if addr:
                    rcpts.add(addr.strip().lower())
        except Exception:
            continue
    return rcpts

HEADER_RE = re.compile(r'^(MIME-Version|Content-Type|Content-Transfer-Encoding|Subject|From|To|Cc|Bcc)\b', re.I)
FNAME_RE  = re.compile(r'^[^<>:"\\|?*\r\n]+(?:\.[A-Za-z0-9]{1,16})$')

def get_body_text(msg) -> str:
    """예외 없이 text/plain 본문만 모아 문자열 반환"""
    try:
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                if (part.get_content_type() or "").lower() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        raw = part.get_payload()
                        if isinstance(raw, str):
                            parts.append(raw)
                            continue
                        payload = b""
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        parts.append(payload.decode("utf-8", errors="replace"))
        else:
            if (msg.get_content_type() or "").lower() == "text/plain":
                payload = msg.get_payload(decode=True)
                if payload is None:
                    raw = msg.get_payload()
                    return raw if isinstance(raw, str) else ""
                charset = msg.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="replace")
                except Exception:
                    return payload.decode("utf-8", errors="replace")
        return "\n".join(parts).strip()
    except Exception as e:
        print("WARN get_body_text:", e)
        return ""

def _attachment_names_from_content_prefix(content: str) -> list[str]:
    """content 선두에서 MIME 헤더 직전까지 파일명처럼 보이는 줄만 추출"""
    if not content:
        return []
    names, seen = [], set()
    for raw in content.splitlines():
        s = raw.strip().strip("'").strip('"')
        if not s:
            continue
        if HEADER_RE.match(s):
            break
        if len(s) > 255:
            continue
        if FNAME_RE.match(s):
            if s not in seen:
                names.append(s); seen.add(s)
    return names

def count_attachments_mime(msg) -> int:
    """MIME 구조 기반 첨부 카운트"""
    cnt = 0
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                disp = (part.get_content_disposition() or "").lower()
                has_name = bool(part.get_filename() or part.get_param('name', header='content-type'))
                if disp == "attachment" or has_name:
                    cnt += 1
        else:
            disp = (msg.get_content_disposition() or "").lower()
            has_name = bool(msg.get_filename() or msg.get_param('name', header='content-type'))
            if disp == "attachment" or has_name:
                cnt = 1
    except Exception as e:
        print("WARN count_attachments_mime:", e)
    return cnt

def _first_header_email(msg, field: str) -> str:
    vals = msg.get_all(field, []) or []
    for _, addr in getaddresses(vals):
        if addr:
            return addr.strip().lower()
    return ""

try:
    if processed_file.exists():
        with processed_file.open('r') as f:
            already_parsed = set(line.strip() for line in f if line.strip())
    else:
        already_parsed = set()
except Exception as e:
    print("WARN processed_file:", e)
    already_parsed = set()

# 파일 순회
for eml_path in sorted(NEW_DIR.glob('*')):
    fname = eml_path.name
    if fname in already_parsed or fname.startswith('.'):
        continue

    try:
        with eml_path.open('rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        # ★ 중복 방지: 같은 메시지면 스킵(읽음 처리만)
        key = _canonical_msg_key(msg, eml_path)
        if key and (key in processed_msgids):
            # 파일은 읽음으로만 이동
            with processed_file.open('a') as pf:
                pf.write(fname + '\n'); pf.flush(); os.fsync(pf.fileno())
            cur_name = f"{fname}:2,S"
            if eml_path.exists():
                os.replace(eml_path, CUR_DIR / cur_name)
            continue

        def get_body():
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        return part.get_payload(decode=True).decode(part.get_content_charset('utf-8'))
            else:
                return msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'))
            return ''

        def count_attachments():
            count = 0
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_filename():
                        count += 1
            return count

        message_id = _extract_msgid(msg)
        qids = _queue_ids_by_message_id(message_id)
        all_rcpts = _all_recipients_by_qids(qids)  # envelope 상 모든 수신자
        if not all_rcpts:
            all_rcpts = _rcpts_from_local_copies_by_mid(message_id)
        to_cc = set(_header_emails_only(msg, 'To')) | set(_header_emails_only(msg, 'Cc'))
        ARCHIVE_ADDR = "archive@localhost"  # always_bcc 로 추가된 주소
        bcc_restored = sorted(addr for addr in (all_rcpts - to_cc) if addr != ARCHIVE_ADDR)

        body_text = get_body_text(msg)
        att_from_body = len(_attachment_names_from_content_prefix(body_text))
        att_mime = count_attachments_mime(msg)
        attach_cnt = max(att_mime, att_from_body)

        log = {
            'employee_id': os.environ.get("EMPLOYEE_ID") or getpass.getuser(),
            'pc_id': os.environ.get("PC_ID") or socket.gethostname(),
            'timestamp': datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            'event_type': 'email',
            'from_addr': _first_header_email(msg, 'From'),
            'to': _header_emails_only(msg, 'To'),
            'cc': _header_emails_only(msg, 'Cc'),
            'bcc': bcc_restored,
            'attachment': attach_cnt,
            'size': eml_path.stat().st_size
        }

        try:
            event.Event('mail', log)
        except Exception as ee:
            print("ERROR send fluentd:", ee, "payload=", json.dumps(log, ensure_ascii=False)[:512])

        # 처리 완료 기록 (파일/메시지 키 모두)
        with processed_file.open('a') as pf:
            pf.write(fname + '\n'); pf.flush(); os.fsync(pf.fileno())
        if key:
            with processed_msgids_file.open('a') as kf:
                kf.write(key + '\n'); kf.flush(); os.fsync(kf.fileno())
            processed_msgids.add(key)

        # 읽음으로 이동
        cur_name = f"{fname}:2,S"
        eml_cur = CUR_DIR / cur_name
        if eml_path.exists():
            os.replace(eml_path, eml_cur)

    except FileNotFoundError:
        continue
    except Exception as e:
        print("Error parsing mail:", e)

