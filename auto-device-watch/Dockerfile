FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul

RUN apt-get update \
 && apt-get install -y --no-install-recommends inotify-tools util-linux file auditd tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY auto_device_watch.sh /usr/local/bin/auto_device_watch.sh
RUN chmod +x /usr/local/bin/auto_device_watch.sh

CMD ["/usr/local/bin/auto_device_watch.sh"]

