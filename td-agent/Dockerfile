FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

# 선택 미러(비워두면 기본 ports.ubuntu.com 사용)
ARG UBUNTU_PORTS_MIRROR=""

# sources.list 내 ports 미러 교체(인자 제공시에만)
RUN if [ -n "$UBUNTU_PORTS_MIRROR" ]; then \
      sed -Ei 's|http://ports\.ubuntu\.com/ubuntu-ports|'"$UBUNTU_PORTS_MIRROR"'|g' /etc/apt/sources.list; \
    fi

# 기본 유틸 설치 (fallback 포함)
RUN set -eux; \
  if ! apt-get update; then \
    apt-get update -o Acquire::Check-Date=false -o Acquire::Check-Valid-Until=false; \
  fi; \
  apt-get install -y --no-install-recommends curl gnupg ca-certificates tzdata; \
  rm -rf /var/lib/apt/lists/*

# Treasure Data repo & GPG
RUN set -eux; \
  curl -fsSL https://packages.treasuredata.com/GPG-KEY-td-agent \
    | gpg --dearmor -o /usr/share/keyrings/td-agent.gpg; \
  echo "deb [signed-by=/usr/share/keyrings/td-agent.gpg] https://packages.treasuredata.com/4/ubuntu/jammy/ jammy contrib" \
    > /etc/apt/sources.list.d/treasure-data.list

# td-agent 설치 (update 실패 시 날짜 검사 완화로 재시도)
RUN set -eux; \
  if ! apt-get update; then \
    apt-get update -o Acquire::Check-Date=false -o Acquire::Check-Valid-Until=false; \
  fi; \
  apt-get install -y --no-install-recommends td-agent; \
  rm -rf /var/lib/apt/lists/*

# 로그 디렉토리 권한
RUN install -d -o td-agent -g td-agent -m 0755 /var/log/td-agent

# 설정 복사 (읽기 권한만)
COPY td-agent.conf /etc/td-agent/td-agent.conf
RUN chmod 0644 /etc/td-agent/td-agent.conf

EXPOSE 24224
USER td-agent
CMD ["/usr/sbin/td-agent", "-c", "/etc/td-agent/td-agent.conf", "-v"]

