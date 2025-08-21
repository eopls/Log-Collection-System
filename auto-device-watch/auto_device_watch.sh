#!/bin/bash
set -euo pipefail

trap 'rc=$?; echo "[auto-audit] ERR line=$LINENO cmd=${BASH_COMMAND} exit=$rc" >&2' ERR

# ===== 기본 변수 =====
DEFAULT_USER="$(id -un 2>/dev/null || echo root)"
# 우선순위: USER_NAME > EMPLOYEE_ID > HOST_USER > USER > DEFAULT_USER
USER_NAME="${USER_NAME:-${EMPLOYEE_ID:-${HOST_USER:-${USER:-$DEFAULT_USER}}}}"

CLEANUP_ON_UMOUNT="${CLEANUP_ON_UMOUNT:-1}"
FS_TYPES="${FS_TYPES:-ext4,vfat,exfat,ntfs3,fuseblk}"

: "${AUTO_MOUNT:=0}"
: "${PERSIST_RULES:=1}"
: "${MOUNT_IN_HOST:=0}"
: "${AUDIT_KEY:=usb_copy}"
: "${AUDIT_COMM:=cp}"
: "${SCAN_INTERVAL:=2}"
: "${MEDIA_ROOT_WATCH:=1}"   # /media 전역 watch (노이즈 많으면 0)
: "${NO_AUTO_FILE:=/run/auto_device_watch.NO_AUTO}"
: "${DEBOUNCE_SEC:=3}"

# 기본 경로
: "${HOME_BASE:=/home}"
: "${BASE_DIR:=/media}"

if [ -z "${USER_NAME}" ] || [ "${USER_NAME}" = "root" ]; then
  : "${IMG_WATCH_DIR:=${HOME_BASE}}"
  : "${WATCH_DIR:=${BASE_DIR}}"
else
  : "${IMG_WATCH_DIR:=${HOME_BASE}/${USER_NAME}}"
  : "${WATCH_DIR:=${BASE_DIR}/${USER_NAME}}"
fi

echo "[auto-audit] USER_NAME=${USER_NAME:-<none>} IMG_WATCH_DIR=$IMG_WATCH_DIR WATCH_DIR=$WATCH_DIR KEY=$AUDIT_KEY COMM=$AUDIT_COMM PERSIST=$PERSIST_RULES HOSTNS=$MOUNT_IN_HOST"
echo "[auto-audit] WATCH_DIR=$WATCH_DIR KEY=$AUDIT_KEY COMM=$AUDIT_COMM PERSIST=$PERSIST_RULES"

require() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
require inotifywait
require auditctl
require losetup
require findmnt
require flock

: "${LOCK_DIR:=/run/auto_device_watch}"
mkdir -p "$LOCK_DIR"

REQ_RULES=()
for fs in ${FS_TYPES//,/ }; do
  REQ_RULES+=(
    "-a always,exit -F arch=b64 -S mount   -F fstype=${fs} -k usb_mount"
    "-a always,exit -F arch=b32 -S mount   -F fstype=${fs} -k usb_mount"
    "-a always,exit -F arch=b64 -S umount2 -F fstype=${fs} -k usb_umount"
    "-a always,exit -F arch=b32 -S umount2 -F fstype=${fs} -k usb_umount"
  )
done

check_nsenter() {
  if [ "${MOUNT_IN_HOST:-0}" = "1" ]; then
    if nsenter --mount=/proc/1/ns/mnt -- true 2>/dev/null; then
      echo "[auto-audit] nsenter OK (host mount ns reachable)"
    else
      echo "[auto-audit] WARN: nsenter permission denied -> fallback to container mount"
      MOUNT_IN_HOST=0
    fi
  fi
}
check_nsenter

ensure_global_rules() {
  for rule in "${REQ_RULES[@]}"; do
    local arch sys key
    arch=$(grep -o 'arch=[^ ]*' <<<"$rule" | cut -d= -f2)
    sys=$(awk '{for(i=1;i<=NF;i++) if($i=="-S"){print $(i+1)}}' <<<"$rule")
    key=$(awk '{for(i=1;i<=NF;i++) if($i=="-k"){print $(i+1)}}' <<<"$rule" | tr -d '"')
    if auditctl -l 2>/dev/null | grep -qE "arch=${arch}.*-S ${sys}.*key=\"?${key}\"?"; then
      echo "[auto-audit] kernel: exists (${arch} ${sys} ${key})"
    else
      echo "[auto-audit] kernel: add   (${arch} ${sys} ${key})"
      eval "auditctl $rule" || true
    fi
  done
}

ensure_host_path() {
  local mp="$1"
  if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
    nsenter --mount=/proc/1/ns/mnt -- mkdir -p "$mp"
  else
    mkdir -p "$mp"
  fi
}

persist_global_rules() {
  [ "$PERSIST_RULES" = "1" ] || return 0
  local RULES_DIR="/host/etc/audit/rules.d"
  local RULES_FILE="${RULES_DIR}/log_rules.rules"
  mkdir -p "$RULES_DIR"
  touch "$RULES_FILE"
  for rule in "${REQ_RULES[@]}"; do
    local arch sys key
    arch=$(grep -o 'arch=[^ ]*' <<<"$rule" | cut -d= -f2)
    sys=$(awk '{for(i=1;i<=NF;i++) if($i=="-S"){print $(i+1)}}' <<<"$rule")
    key=$(awk '{for(i=1;i<=NF;i++) if($i=="-k"){print $(i+1)}}' <<<"$rule" | tr -d '"')
    if grep -qE "arch=${arch}.*-S ${sys}.*-k ${key}" "$RULES_FILE"; then
      echo "[auto-audit] file:   exists (${arch} ${sys} ${key})"
    else
      echo "$rule" >> "$RULES_FILE"
      echo "[auto-audit] file:   append (${arch} ${sys} ${key})"
    fi
  done
}

# /media 전역 watch (마운트 직후 규칙 붙이기 전 이벤트까지 최소 보호)
ensure_media_watch() {
  [ "${MEDIA_ROOT_WATCH:-0}" = "1" ] || return 0
  local root="$WATCH_DIR"
  mkdir -p "$root"
  auditctl -w "$root" -p wa -k "${AUDIT_KEY}_watch" 2>/dev/null || true
  echo "[auto-audit] watch root: $root (key=${AUDIT_KEY}_watch)"
}

add_rules() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  if auditctl -l 2>/dev/null | awk -v d="$dir" -v k="$AUDIT_KEY" \
      'index($0,"key=\""k"\"") && (index($0,"dir=\""d"\"") || index($0,"dir=" d)) {found=1} END{exit !found}'; then
    echo "[auto-audit] exists: $dir"
    return 0
  fi

  have() { ausyscall "$1" >/dev/null 2>&1; }
  local common=(open openat creat truncate ftruncate rename renameat link linkat unlink unlinkat)

  local sys_b64=()
  for s in "${common[@]}"; do sys_b64+=( -S "$s" ); done
  if have openat2; then sys_b64+=( -S openat2 ); fi

  local sys_b32=()
  for s in "${common[@]}"; do sys_b32+=( -S "$s" ); done

  local ok=1
  auditctl -a always,exit -F arch=b64 "${sys_b64[@]}" -F dir="$dir" -F perm=wa -k "$AUDIT_KEY" 2>/dev/null || ok=0
  auditctl -a always,exit -F arch=b32 "${sys_b32[@]}" -F dir="$dir" -F perm=wa -k "$AUDIT_KEY" 2>/dev/null || ok=0

  auditctl -w "$dir" -p wa -k "${AUDIT_KEY}_watch" 2>/dev/null || true

  if [ "$ok" -eq 1 ]; then
    echo "[auto-audit] added: $dir"
  else
    echo "[auto-audit] WARN: add_rules partially failed for $dir"
  fi

  ( monitor_unmount "$dir" ) &
}

remove_rules() {
  local dir="$1"
  auditctl -d always,exit -F arch=b64 \
    -S open -S openat -S openat2 -S creat -S truncate -S ftruncate \
    -S rename -S renameat -S renameat2 -S link -S linkat -S unlink -S unlinkat \
    -F dir="$dir" -F perm=wa -k "$AUDIT_KEY" 2>/dev/null || true

  auditctl -d always,exit -F arch=b32 \
    -S open -S openat -S creat -S truncate -S ftruncate \
    -S rename -S renameat           -S link -S linkat -S unlink -S unlinkat \
    -F dir="$dir" -F perm=wa -k "$AUDIT_KEY" 2>/dev/null || true

  echo "[auto-audit] removed: $dir"
}

is_mountpoint() {
  local target="$1"
  if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
    nsenter --mount=/proc/1/ns/mnt -- mountpoint -q -- "$target"
  else
    if command -v mountpoint >/dev/null 2>&1; then
      mountpoint -q -- "$target"
    else
      awk -v d="$target" '$2==d{found=1} END{exit !found}' /proc/self/mounts
    fi
  fi
}

detect_fstype() {
  local img="$1"
  if command -v blkid >/dev/null; then
    blkid -p -o value -s TYPE "$img" 2>/dev/null || true
  else
    file -bs "$img" 2>/dev/null | awk '{print tolower($1)}' || true
  fi
}

command -v nsenter >/dev/null 2>&1 || true
do_mount() {
  local src="$1" mp="$2" fstype="$3" opts="${4:-}"
  set +e
  if [ -n "$fstype" ]; then
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      [ -n "$opts" ] && nsenter --mount=/proc/1/ns/mnt -- mount -t "$fstype" -o "$opts" "$src" "$mp" \
                      || nsenter --mount=/proc/1/ns/mnt -- mount -t "$fstype" "$src" "$mp"
    else
      [ -n "$opts" ] && mount -t "$fstype" -o "$opts" "$src" "$mp" \
                      || mount -t "$fstype" "$src" "$mp"
    fi
  else
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      [ -n "$opts" ] && nsenter --mount=/proc/1/ns/mnt -- mount -o "$opts" "$src" "$mp" \
                      || nsenter --mount=/proc/1/ns/mnt -- mount "$src" "$mp"
    else
      [ -n "$opts" ] && mount -o "$opts" "$src" "$mp" \
                      || mount "$src" "$mp"
    fi
  fi
  local rc=$?
  set -e
  return $rc
}

opts_for_fstype() {
  case "$1" in
    ext2|ext3|ext4)  echo "$1;loop" ;;
    xfs|btrfs)       echo "$1;loop" ;;
    vfat|fat|msdos)  echo "vfat;loop,uid=${2},gid=${3},umask=022" ;;
    exfat)           echo "exfat;loop,uid=${2},gid=${3},umask=022" ;;
    ntfs|ntfs-3g)    echo "ntfs-3g;loop,uid=${2},gid=${3},umask=022" ;;
    *)               echo ";loop" ;;
  esac
}

auto_mount_img() {
  local img="$1"
  [ -f "$img" ] || { echo "[auto-audit] WARN: file not found: $img"; return 0; }

  local base mp uid gid t tries
  base="$(basename "$img" .img)"
  mp="/media/$USER_NAME/$base"
  sum=$(printf '%s' "$img" | sha1sum | awk '{print $1}')

  # per-image 락 (동시 이벤트 방지)
  local lockf="$LOCK_DIR/${sum}.lock"
  exec {lfd}>"$lockf" || true
  if ! flock -n "$lfd"; then
    echo "[auto-audit] lock busy -> skip: $img"
    return 0
  fi

  inode="$(stat -Lc '%d:%i' "$img" 2>/dev/null || echo "")"
  if [ -n "$inode" ]; then
    stamp="${LOCK_DIR}/debounce_${inode}"
    now=$(date +%s)
    last=$(cat "$stamp" 2>/dev/null || echo 0)
    if [ $((now-last)) -lt "${DEBOUNCE_SEC}" ]; then
      echo "[auto-audit] debounce(${DEBOUNCE_SEC}s) -> skip: $img"
      flock -u "$lfd"
      return 0
    fi
    echo "$now" > "$stamp"
  fi

  exec {lf_img}<"$img" || exec {lf_img}>"$img"
  if ! flock -n "$lf_img"; then
    echo "[auto-audit] file-lock busy -> skip: $img"
    flock -u "$lfd"
    return 0
  fi

  ensure_host_path "$mp"

  while read -r lp; do
    [ -n "$lp" ] || continue
    if findmnt -n -S "$lp" >/dev/null 2>&1; then
      echo "[auto-audit] already mounted via $lp -> skip: $img"
      flock -u "$lf_img"; flock -u "$lfd"
      return 0
    fi
  done < <(losetup -j "$img" | cut -d: -f1)

  if is_mountpoint "$mp"; then
    src_now="$(findmnt -nro SOURCE --target "$mp" 2>/dev/null || true)"
    if [ -n "$src_now" ] && losetup -j "$img" | cut -d: -f1 | grep -qx "$src_now"; then
      echo "[auto-audit] already mounted: $img -> $mp"
    else
      echo "[auto-audit] mountpoint busy ($mp) -> skip"
    fi
    flock -u "$lf_img"; flock -u "$lfd"
    return 0
  fi

  uid="$(stat -c %u "$img" 2>/dev/null || echo 1000)"
  gid="$(stat -c %g "$img" 2>/dev/null || echo 1000)"

  t=""; tries=0
  while [ $tries -lt 20 ]; do
    if command -v blkid >/dev/null 2>&1; then
      t="$(blkid -p -o value -s TYPE "$img" 2>/dev/null || true)"
    else
      t="$(file -bs "$img" 2>/dev/null | awk '{print tolower($1)}' || true)"
    fi
    [ -n "$t" ] && break
    sleep 0.5; tries=$((tries+1))
  done

  IFS=';' read -r fstype opts <<<"$(opts_for_fstype "$t" "$uid" "$gid")"

  # loop attach (가능하면 --autoclear)
  local loopdev
  if losetup --help 2>&1 | grep -q -- '--autoclear'; then
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      loopdev="$(nsenter --mount=/proc/1/ns/mnt -- losetup --find --show --autoclear "$img")"
    else
      loopdev="$(losetup --find --show --autoclear "$img")"
    fi
  else
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      loopdev="$(nsenter --mount=/proc/1/ns/mnt -- losetup --find --show "$img")"
    else
      loopdev="$(losetup --find --show "$img")"
    fi
  fi

  # opts에서 loop 토큰 제거
  opts="${opts//loop,}"; opts="${opts//,loop}"; [ "$opts" = "loop" ] && opts=""

  if is_mountpoint "$mp"; then
    # 누군가 먼저 올렸으면 내 loop는 즉시 정리
    src_now="$(findmnt -nro SOURCE --target "$mp" 2>/dev/null || true)"
    if [ -n "$src_now" ] && [ "$src_now" != "$loopdev" ]; then
      echo "[auto-audit] raced: $mp already mounted by $src_now -> detach $loopdev"
      losetup -d "$loopdev" 2>/dev/null || true
      flock -u "$lf_img"; flock -u "$lfd"
      return 0
    fi
  fi

  echo "[auto-audit] mounting $img via $loopdev (type=${t:-unknown}, fstype=${fstype:-auto}) -> $mp (opts=${opts:-<none>})"
  if ! do_mount "$loopdev" "$mp" "$fstype" "$opts"; then
    echo "[auto-audit] WARN: mount failed. retry without opts"
    if ! do_mount "$loopdev" "$mp" "$fstype" ""; then
      echo "[auto-audit] ERROR: mount failed for $img -> $mp"
      losetup -d "$loopdev" 2>/dev/null || true
      flock -u "$lf_img"; flock -u "$lfd"
      return 1
    fi
  fi

  case "$t" in
    ext2|ext3|ext4|xfs|btrfs) chown -R "$uid:$gid" "$mp" 2>/dev/null || true ;;
    *) : ;;
  esac

  add_rules "$mp"
  echo "[auto-audit] mounted OK: $mp"

  flock -u "$lf_img"
  flock -u "$lfd"
}

watch_img_and_mount() {
  [ "$AUTO_MOUNT" = "1" ] || return 0
  mkdir -p "$IMG_WATCH_DIR"
  echo "[auto-audit] AUTO_MOUNT=1, watching recursively: $IMG_WATCH_DIR for *.img"

  set +u
  inotifywait -mr -e close_write -e moved_to --format '%w%f' "$IMG_WATCH_DIR" \
  | while IFS= read -r path; do
      [ -f "$NO_AUTO_FILE" ] && { echo "[auto-audit] NO_AUTO set -> skip $path"; continue; }
      p="${path-}"
      [ -n "$p" ] || continue
      case "$p" in
        *.img)
          echo "[auto-audit] detected .img: $p"
          sz_prev=-1
          for _ in $(seq 1 10); do
            sz_now=$(stat -c %s "$p" 2>/dev/null || echo -1)
            [ "$sz_now" -ge 0 ] || { sleep 0.5; continue; }
            [ "$sz_now" -eq "$sz_prev" ] && break
            sz_prev="$sz_now"; sleep 0.5
          done
          auto_mount_img "$p"
          ;;
      esac
    done
  set -u
}

safe_rmdir() {
  local dir="$1"
  case "$dir" in ""|"/"|"$WATCH_DIR") return 0 ;; esac
  case "$dir" in "$WATCH_DIR"/*) ;; *) echo "[auto-audit] skip rmdir (outside WATCH_DIR): $dir"; return 0 ;; esac

  if [ -d "$dir" ]; then
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      nsenter --mount=/proc/1/ns/mnt -- rmdir "$dir" 2>/dev/null \
        && echo "[auto-audit] removed mountpoint: $dir" \
        || echo "[auto-audit] keep dir (not empty): $dir"
    else
      rmdir "$dir" 2>/dev/null \
        && echo "[auto-audit] removed mountpoint: $dir" \
        || echo "[auto-audit] keep dir (not empty): $dir"
    fi
  fi
}

cleanup_loops_for() {
  local mp="$1"
  local src
  if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
    src="$(nsenter --mount=/proc/1/ns/mnt -- awk -v d="$mp" '$2==d{print $1}' /proc/self/mounts | head -n1)"
  else
    src="$(awk -v d="$mp" '$2==d{print $1}' /proc/self/mounts | head -n1)"
  fi
  if [[ "$src" =~ ^/dev/loop[0-9]+$ ]]; then
    echo "[auto-audit] loop detach: $src"
    if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
      nsenter --mount=/proc/1/ns/mnt -- losetup -d "$src" 2>/dev/null || true
    else
      losetup -d "$src" 2>/dev/null || true
    fi
  fi
  if [ "${MOUNT_IN_HOST:-0}" = "1" ] && [ -e /proc/1/ns/mnt ] && command -v nsenter >/dev/null 2>&1; then
    nsenter --mount=/proc/1/ns/mnt -- losetup -D 2>/dev/null || true
  else
    losetup -D 2>/dev/null || true
  fi
}

monitor_unmount() {
  local dir="$1"
  while true; do
    if [ ! -d "$dir" ] || ! is_mountpoint "$dir"; then
      remove_rules "$dir"
      if [ "${CLEANUP_ON_UMOUNT:-1}" = "1" ]; then
        cleanup_loops_for "$dir"
        safe_rmdir "$dir"
      fi
      break
    fi
    sleep "$SCAN_INTERVAL"
  done
}

# ===== 새로 추가: 부팅 시/실행 시 이미 마운트된 것 규칙 붙이기 =====
initial_sweep() {
  [ -d "$WATCH_DIR" ] || return 0
  awk -v base="$WATCH_DIR" '$2 ~ "^"base"(/|$)" {print $2}' /proc/self/mounts \
  | while IFS= read -r mp; do add_rules "$mp"; done
}
# =================================================================

umount_clean() {
  # 자동 재마운트 방지 센티넬
  if [ "${PAUSE_AUTO:-1}" = "1" ]; then
    touch "$NO_AUTO_FILE"
    trap 'rm -f "$NO_AUTO_FILE" 2>/dev/null || true' RETURN
  fi

  [ "$#" -ge 1 ] || { echo "usage: $0 umount-clean <mountpoint|device|img-file> ..."; return 2; }

  # (옵션) 워처 먼저 끄기
  if [ "${KILL_WATCHERS:-1}" = "1" ]; then
    pkill -f "inotifywait.*$WATCH_DIR"      2>/dev/null || true
    pkill -f "inotifywait.*$IMG_WATCH_DIR"  2>/dev/null || true
    pkill -f "inotifywait.*auto_device_watch" 2>/dev/null || true
  fi

  settle() { command -v udevadm >/dev/null && udevadm settle -t 2 -E 2>/dev/null || true; }

  detach_loop_safe() {
    local lp="$1"
    [ -n "$lp" ] || return 0
    for _ in $(seq 1 6); do
      fuser -km "$lp" 2>/dev/null || true
      /usr/bin/umount -l -- "$lp" 2>/dev/null || true
      losetup -d "$lp" 2>/dev/null && { settle; return 0; }
      sleep 0.2
    done
    return 0
  }

  local t
  for t in "$@"; do
    local map
    map="$(awk -v d="$t" '($2==d)||($2 ~ ("^" d "(/|$)")){print $1 "\t" $2}' /proc/self/mounts)"

    # 마운트 지점 점유 프로세스 종료
    printf '%s\n' "$map" | awk -F'\t' '{print $2}' | sort -u | while IFS= read -r mpt; do
      [ -n "$mpt" ] || continue
      fuser -km "$mpt" 2>/dev/null || true
    done

    # 언마운트 (한층씩 떨어지는 케이스를 대비해 반복)
    /usr/bin/umount -R -- "$t" 2>/dev/null || /usr/bin/umount -Rl -- "$t" 2>/dev/null || true
    settle
    for _ in $(seq 1 5); do
      is_mountpoint "$t" || break
      /usr/bin/umount -l -- "$t" 2>/dev/null || true
      settle
      sleep 0.1
    done

    # 소스별 loop/파일 기준 정리
    printf '%s\n' "$map" | while IFS=$'\t' read -r src mpt; do
      [ -n "$src" ] || continue
      if [[ "$src" =~ ^/dev/loop[0-9]+(p[0-9]+)?$ ]]; then
        lp="$(printf '%s' "$src" | sed -E 's#^(/dev/loop[0-9]+).*#\1#')"
        [ -n "$lp" ] || continue
        echo "[auto-audit] loop detach: $lp"
        fuser -km "$lp" 2>/dev/null || true
        /usr/bin/umount -l -- "$lp" 2>/dev/null || true
        losetup -d "$lp" 2>/dev/null || true
      elif [ -f "$src" ]; then
        losetup -j "$src" | cut -d: -f1 | while IFS= read -r lp; do
          [ -n "$lp" ] || continue
          echo "[auto-audit] loop detach: $lp"
          detach_loop_safe "$lp"
        done
      fi
    done

    # t가 파일(.img)이면 매핑 여부와 상관없이 한 번 더 loop 정리
    if [ -f "$t" ]; then
      losetup -j "$t" | cut -d: -f1 | while IFS= read -r lp; do
        [ -n "$lp" ] || continue
        echo "[auto-audit] loop detach: $lp"
        detach_loop_safe "$lp"
      done
    fi

    # 마운트포인트 정리
    printf '%s\n' "$map" | awk -F'\t' '{print $2}' | sort -ur | while IFS= read -r mpt; do
      [ -n "$mpt" ] || continue
      safe_rmdir "$mpt"
    done
    if [ -z "$map" ] && [ -d "$t" ]; then
      safe_rmdir "$t"
    fi
  done

  # 남아있는 미사용 loop 일괄 정리
  losetup -D 2>/dev/null || true
}

ensure_singleton_watch() {
  exec {gfd}>"/run/auto_device_watch/singleton.lock"
  if ! flock -n "$gfd"; then
    echo "[auto-audit] watcher already running -> skip starting another"
    return 1
  fi
  return 0
}

if [ "$#" -gt 0 ]; then
  case "$1" in
    umount-clean) shift; umount_clean "$@"; exit $? ;;
    mount-img)    shift; for img in "$@"; do auto_mount_img "$img"; done; exit $? ;;
  esac
fi

ensure_global_rules
persist_global_rules
initial_sweep
ensure_media_watch

mkdir -p "$WATCH_DIR"
set +u
inotifywait -m -e create -e moved_to --format '%w%f' "$WATCH_DIR" \
| while IFS= read -r path; do
    p="${path-}"
    [ -n "$p" ] || continue
    if [ -d "$p" ]; then
      for _ in $(seq 1 20); do
        if is_mountpoint "$p"; then
          add_rules "$p"
          break
        fi
        sleep 0.5
      done
    fi
  done &
set -u

if [ "$#" -eq 0 ]; then
  ensure_singleton_watch || exit 0
fi

watch_img_and_mount

