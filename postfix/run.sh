#!/usr/bin/env bash
set -euo pipefail

# Maildir 초기화
mkdir -p /opt/mail/Maildir/{new,cur,tmp}
chown -R archive:archive /opt/mail
chmod 700 /opt/mail/Maildir /opt/mail/Maildir/{new,cur,tmp}

# rsyslog가 mail.*를 /var/log/mail.log로 쓰도록 규칙 보장
grep -Eq '^\s*mail\.\*.*\/var\/log\/mail\.log' /etc/rsyslog.d/50-default.conf \
  || printf 'mail.*\t-/var/log/mail.log\n' >> /etc/rsyslog.d/50-default.conf

# 원수신자(orig_to) 기록 + 존재하지 않는 로컬 유저를 archive@localhost로 릴레이
postconf -e \
  "enable_original_recipient=yes" \
  "local_recipient_maps=" \
  "luser_relay=archive@localhost"

# /var/log/mail.log 준비
install -d -m 0755 /var/log
touch /var/log/mail.log
chown root:adm /var/log/mail.log
chmod 664 /var/log/mail.log

# rsyslog 시작
rsyslogd

# Postfix를 포그라운드로 실행(PID 1 유지)
exec /usr/sbin/postfix start-fg

