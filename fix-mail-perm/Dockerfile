FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

# 선택 미러(비워두면 기본 ports.ubuntu.com 사용)
ARG UBUNTU_PORTS_MIRROR=""

# sources.list 내 ports 미러 교체(인자 제공시에만)
RUN if [ -n "$UBUNTU_PORTS_MIRROR" ]; then \
      sed -Ei 's|http://ports\.ubuntu\.com/ubuntu-ports|'"$UBUNTU_PORTS_MIRROR"'|g' /etc/apt/sources.list; \
    fi

RUN printf 'Acquire::Check-Valid-Until "false";\nAcquire::Check-Date "false";\n' \
    > /etc/apt/apt.conf.d/99no-check-valid-until

RUN apt-get update \
 && apt-get install -y --no-install-recommends inotify-tools \
 && rm -rf /var/lib/apt/lists/*

COPY fix_mail_perm.sh /usr/local/bin/fix_mail_perm.sh
RUN chmod +x /usr/local/bin/fix_mail_perm.sh
CMD ["/usr/local/bin/fix_mail_perm.sh"]

