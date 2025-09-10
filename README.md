## VM 로컬 환경 구축
### auditd
```bash
# 설치
$ sudo apt-get update
$ sudo apt-get install -y auditd audispd-plugins

# 기동 및 부팅 시 자동 시작
$ sudo systemctl enable auditd
$ sudo systemctl start auditd

# 상태 확인 (Active: active (running) 확인)
$ sudo systemctl status auditd --no-pager
```

### udisks2, udiskie
```bash
# 설치
$ sudo apt update
$ sudo apt install -y udisks2 udiskie

# 사용자 서비스로 udiskie 띄우기
$ mkdir -p ~/.config/systemd/user
$ cat >~/.config/systemd/user/udiskie.service <<'EOF'
[Unit]
Description=Auto-mount USB drives via udiskie

[Service]
ExecStart=/usr/bin/udiskie -2 -a -s
Restart=on-failure

[Install]
WantedBy=default.target
EOF

# 마운트 옵션 (파일 소유권/권한 안정화)
$ UIDN=$(id -u); GIDN=$(id -g)
$ mkdir -p ~/.config/udiskie
$ cat >~/.config/udiskie/config.yml <<'EOF'
mount_options:
  vfat:  [rw,uid=${UIDN},gid=${GIDN},umask=022,flush]
  exfat: [rw,uid=${UIDN},gid=${GIDN},umask=022]
  ntfs:  [rw,uid=${UIDN},gid=${GIDN},umask=022,big_writes]
  ext2:  [rw]
  ext3:  [rw]
  ext4:  [rw]
device_config:
  default_options: { automount: true }
EOF

$ systemctl --user daemon-reload
$ systemctl --user enable --now udiskie.service
$ sudo loginctl enable-linger "$USER"
```

```bash
# 동적 규칙 생성 스크립트
# /media/ 내 마운트 포인트를 찾아 규칙 파일 생성 및 로드
$ sudo install -d -m 755 /usr/local/sbin

$ sudo tee /usr/local/sbin/update-audit-usb-rules.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

cat > /etc/audit/rules.d/usb.rules <<'EOF'
-a always,exit -F arch=b64 -S mount   -F success=1 -k usb_mount
-a always,exit -F arch=b32 -S mount   -F success=1 -k usb_mount
-a always,exit -F arch=b64 -S umount2 -F success=1 -k usb_umount
-a always,exit -F arch=b32 -S umount2 -F success=1 -k usb_umount
EOF

for mp in /media/*/*; do
  [ -d "$mp" ] || continue
  echo "-a always,exit -F arch=b64 -S open,openat,openat2,creat -F dir=$mp -k usb_copy_watch" >> /etc/audit/rules.d/usb.rules
  echo "-a always,exit -F arch=b32 -S open,openat,          creat -F dir=$mp -k usb_copy_watch" >> /etc/audit/rules.d/usb.rules
  echo "-w $mp -p wa -k usb_copy_watch" >> /etc/audit/rules.usb.rules
done

auditctl -e 1 || true
augenrules --load
BASH

$ sudo chmod +x /usr/local/sbin/update-audit-usb-rules.sh
$ sudo /usr/local/sbin/update-audit-usb-rules.sh # 초기 1회 실행
```
- 참조: `sudo /usr/local/sbin/update-audit-usb-rules.sh` 수행 결과 마지막 줄에 'fstype field is not valid for the filter' 라는 문장이 보이면
  ```bash
  docker ps --format '{{.Names}}' | grep -Ei 'auto[-_]?device[-_]?watch' >/dev/null && \
  docker stop $(docker ps --format '{{.Names}}' | grep -Ei 'auto[-_]?device[-_]?watch') || true
  sudo pkill -f auto_device_watch.sh 2>/dev/null || true
  sudo pkill -f 'auditctl .*fstype'   2>/dev/null || true
  
  sudo rm -f /etc/audit/rules.d/log_rules.rules 2>/dev/null || true
  sudo rm -f /host/etc/audit/rules.d/log_rules.rules 2>/dev/null || true
  sudo rm -rf /etc/audit/rules.d.bak.* 2>/dev/null || true
  sudo rm -f  /etc/audit/audit.rules.back.* 2>/dev/null || true
  
  sudo grep -RIlZ 'fstype=' /etc/audit /host/etc/audit 2>/dev/null \
  | sudo xargs -0 -r sed -i -E -- '/-F[[:space:]]*fstype=/d'
  
  sudo auditctl -D
  ```
  통째로 복사해서 터미널에 붙여넣고 실행 (이전에 `audit-device-watch` (가상 USB 감사 헬퍼 컨테이너) 에서 생성한 가상 USB 감사 규칙과 충돌해서 생긴 문제로, `auto-device-watch` 부분은 지웠기 때문에 수정된 에이전트 올리기 전에 한 번만 실행해 주시면 됩니다!)

```bash
# /media/ 변화 시 규칙 자동 갱신
$ sudo tee /etc/systemd/system/audit-usb-refresh.service >/dev/null <<'UNIT'
[Unit]
Description=Refresh audit USB rules on mount changes
After=auditd.service local-fs.target
Wants=auditd.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/bin/env bash /usr/local/sbin/update-audit-usb-rules.sh

[Install]
WantedBy=multi-user.target
UNIT

$ sudo tee /etc/systemd/system/audit-usb-refresh.path >/dev/null <<'UNIT'
[Unit]
Description=Watch /media for USB mountpoints

[Path]
DirectoryNotEmpty=/media
Unit=audit-usb-refresh.service

[Install]
WantedBy=multi-user.target
UNIT

$ sudo systemctl daemon-reload
$ sudo systemctl enable --now audit-usb-refresh.service
$ sudo systemctl enable --now audit-usb-refresh.path
```

<br />

## 에이전트 환경 구축
### 환경변수 파일 생성 및 환경변수 설정
```bash
$ cp .env.example .env
$ nano .env # 환경에 맞게 환경변수 파일 수정
```
- `API_BASE`: 백엔드 서버 올린 PC와 가상머신이 서로 통신 가능한 IP로 수정 (필수)
- `EMPLOYEE_ID`, `PC_ID`: 엔드포인트 사용자 ID, PC ID
- `TZ`: Asia/Seoul (수정하실 필요 없습니다!)

### 인증서 디렉터리 생성
```bash
$ mkdir -p ./mitmproxy
```

### 로그 수집 에이전트 실행
```bash
$ docker compose pull
$ docker compose up -d
```
- 참조: `docker compose up` 이 권한 문제로 거부될 경우
  1. 도커 데몬 실행 확인
     ```bash
     $ sudo systemctl enable --now docker
     $ sudo systemctl status docker
     ```
  2. `docker` 그룹에 사용자 추가
     ```bash
     $ getent group docker || sudo groupadd docker # docker 그룹이 없으면 생성
     $ sudo usermod -aG docker $USER # 사용자 추가
     ```
  3. 세션에 그룹 반영
     ```bash
     $ newgrp docker
     ```
  4. 권한 및 소켓 확인
     ```bash
     $ ls -l /var/run/docker.sock
     $ docker ps
     ```
  5. `compose` 재실행
     ```bash
     $ docker compose up -d
     ```

### mitmproxy 인증서 설치
- 인증서 설치
  ```bash
  $ ls -al ./mitmproxy # mitmproxy-ca-cert.pem / .cer / .p12 등 생성된 것 확인
  $ sudo cp ./mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
  $ sudo update-ca-certificates
  ```
- 브라우저(Firefox 사용) 프록시 설정
    1. Settings -> Certificates 검색 -> View Certificates... -> Authorities -> Import... -> `Log-Collection-System/mitmproxy/mitmproxy-ca-cert.pem` Open -> 옵션 모두 체크하고 OK
    2. Settings -> Proxy 검색 -> Manual proxy configuration -> HTTP Proxy: 127.0.0.1, Port: 8081, Also use this proxy for HTTPS 체크
