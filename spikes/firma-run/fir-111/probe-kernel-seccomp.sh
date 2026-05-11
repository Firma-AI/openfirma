#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  spikes/firma-run/fir-111/probe-kernel-seccomp.sh [--format text|json]
EOF
}

FORMAT="text"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      shift
      [[ $# -gt 0 ]] || { echo "missing value for --format" >&2; exit 1; }
      FORMAT="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
  shift
done

[[ "$(uname -s)" == "Linux" ]] || {
  echo "Linux host required" >&2
  exit 1
}

kernel_release="$(uname -r)"
kernel_version="$(uname -v)"
actions_avail_file="/proc/sys/kernel/seccomp/actions_avail"
actions_logged_file="/proc/sys/kernel/seccomp/actions_logged"

actions_avail=""
actions_logged=""
if [[ -r "$actions_avail_file" ]]; then
  actions_avail="$(cat "$actions_avail_file")"
fi
if [[ -r "$actions_logged_file" ]]; then
  actions_logged="$(cat "$actions_logged_file")"
fi

user_notif_supported="false"
if echo "$actions_avail" | grep -Eq '(^|[[:space:]])user_notif($|[[:space:]])'; then
  user_notif_supported="true"
fi

seccomp_header="/usr/include/linux/seccomp.h"
header_present="false"
notif_addfd_symbol="false"
if [[ -r "$seccomp_header" ]]; then
  header_present="true"
  if grep -q 'SECCOMP_IOCTL_NOTIF_ADDFD' "$seccomp_header"; then
    notif_addfd_symbol="true"
  fi
fi

case "$FORMAT" in
  text)
    cat <<EOF
kernel_release=${kernel_release}
kernel_version=${kernel_version}
actions_avail=${actions_avail}
actions_logged=${actions_logged}
user_notif_supported=${user_notif_supported}
seccomp_header_present=${header_present}
seccomp_notif_addfd_symbol=${notif_addfd_symbol}
EOF
    ;;
  json)
    printf '{'
    printf '"kernel_release":"%s",' "$kernel_release"
    printf '"kernel_version":"%s",' "$kernel_version"
    printf '"actions_avail":"%s",' "$(printf '%s' "$actions_avail" | sed 's/"/\\"/g')"
    printf '"actions_logged":"%s",' "$(printf '%s' "$actions_logged" | sed 's/"/\\"/g')"
    printf '"user_notif_supported":%s,' "$user_notif_supported"
    printf '"seccomp_header_present":%s,' "$header_present"
    printf '"seccomp_notif_addfd_symbol":%s' "$notif_addfd_symbol"
    printf '}\n'
    ;;
  *)
    echo "unsupported format: $FORMAT" >&2
    exit 1
    ;;
esac
