FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

# 선택 미러(비워두면 기본 ports.ubuntu.com 사용)
ARG UBUNTU_PORTS_MIRROR=""

# sources.list 내 ports 미러 교체(인자 제공시에만)
RUN if [ -n "$UBUNTU_PORTS_MIRROR" ]; then \
      sed -Ei 's|http://ports\.ubuntu\.com/ubuntu-ports|'"$UBUNTU_PORTS_MIRROR"'|g' /etc/apt/sources.list; \
    fi

# apt 갱신 실패(시계/서명 문제)시 fallback 재시도
RUN set -eux; \
  if ! apt-get update; then \
    sed -i '/^deb .*jammy-updates/s/^/#/' /etc/apt/sources.list || true; \
    apt-get update -o Acquire::Check-Date=false -o Acquire::Check-Valid-Until=false; \
  fi; \
  apt-get install -y --no-install-recommends \
      postfix mailutils bsd-mailx rsyslog supervisor; \
  # mail/mailx가 내부적으로 찾는 /usr/lib/sendmail을 Postfix로 고정
  ln -sf /usr/sbin/sendmail /usr/lib/sendmail; \
  # mailutils 기본 메일러도 Postfix로 고정
  printf 'set sendmail="/usr/sbin/sendmail"\n' > /etc/mail.rc; \
  # (권장) 호스트명 고정: 로그/헤더에 일관되게 찍히도록
  echo localhost > /etc/mailname; \
  rm -rf /var/lib/apt/lists/*

# rsyslog: 컨테이너에서 /proc/kmsg 접근 안되므로 imklog 비활성화
RUN sed -i 's/^\s*module(load="imklog")/# module(load="imklog")/' /etc/rsyslog.conf

# archive 사용자 + Maildir
RUN useradd -m -d /opt/mail -s /usr/sbin/nologin archive \
 && mkdir -p /opt/mail/Maildir \
 && chown -R archive:archive /opt/mail \
 && chmod -R 755 /opt/mail

# Postfix 기본 설정 (+ orig_to 복원 위해 필요 설정 포함)
RUN postconf -e "home_mailbox = Maildir/" \
 && postconf -e "always_bcc = archive@localhost" \
 && postconf -e "mydestination = localhost" \
 && postconf -e "inet_interfaces = all" \
 && postconf -e "inet_protocols = all" \
 && postconf -e "enable_original_recipient = yes" \
 && postconf -e "local_recipient_maps =" \
 && postconf -e "luser_relay = archive@localhost"

COPY run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 25
CMD ["/run.sh"]

