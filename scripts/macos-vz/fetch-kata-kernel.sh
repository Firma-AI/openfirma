#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Fetch the known-good Kata vmlinux used by the local macOS VZ guest examples.

Usage:
  scripts/macos-vz/fetch-kata-kernel.sh [OUT_DIR]

Outputs:
  vmlinux-6.18.15-186

Environment:
  FIRMA_VZ_KATA_VERSION        Kata release version. Default: 3.28.0.
  FIRMA_VZ_KATA_KERNEL_URL     Override the Kata static archive URL.
  FIRMA_VZ_KATA_KERNEL_MEMBER  Override the vmlinux member inside the archive.
  FIRMA_VZ_KATA_KERNEL_SHA256  Override archive checksum verification.
                                Set to an empty value to skip verification.

The default output directory is target/firma-vz-guest/kata.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)"
host_arch="$(uname -m)"
kata_version="${FIRMA_VZ_KATA_VERSION:-3.28.0}"
kata_member="${FIRMA_VZ_KATA_KERNEL_MEMBER:-opt/kata/share/kata-containers/vmlinux-6.18.15-186}"
out_dir="${1:-"$repo_root/target/firma-vz-guest/kata"}"

case "$host_arch" in
  arm64 | aarch64)
    default_kata_url="https://github.com/kata-containers/kata-containers/releases/download/$kata_version/kata-static-$kata_version-arm64.tar.zst"
    default_kata_sha256="f63d54507d1f18635d94475077e4c2330de4d8e05cedf25f7c38f063b0e66a91"
    ;;
  *)
    if [ -z "${FIRMA_VZ_KATA_KERNEL_URL:-}" ]; then
      echo "automatic Kata kernel fetch is currently pinned for Apple Silicon only" >&2
      echo "set FIRMA_VZ_BASIC_EXEC_KERNEL or FIRMA_VZ_GUEST_KERNEL to an existing Kata vmlinux" >&2
      exit 1
    fi
    default_kata_url="$FIRMA_VZ_KATA_KERNEL_URL"
    default_kata_sha256=""
    ;;
esac

kata_url="${FIRMA_VZ_KATA_KERNEL_URL:-$default_kata_url}"
if [ "${FIRMA_VZ_KATA_KERNEL_URL+x}" = x ]; then
  kata_sha256=""
else
  kata_sha256="$default_kata_sha256"
fi
if [ "${FIRMA_VZ_KATA_KERNEL_SHA256+x}" = x ]; then
  kata_sha256="$FIRMA_VZ_KATA_KERNEL_SHA256"
fi
archive="$out_dir/$(basename "$kata_url")"
kernel="$out_dir/$(basename "$kata_member")"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool for Kata kernel extraction: $1" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    echo "missing required tool: shasum or sha256sum" >&2
    exit 1
  fi
}

require_tool awk
require_tool curl
require_tool tar
require_tool zstd

mkdir -p "$out_dir"

if [ ! -f "$archive" ]; then
  echo "downloading Kata static archive"
  echo "  url: $kata_url"
  echo "  out: $archive"
  curl -fL --retry 3 --continue-at - --output "$archive" "$kata_url"
else
  echo "using cached Kata static archive: $archive"
fi

if [ -n "$kata_sha256" ]; then
  actual_sha256="$(sha256_file "$archive")"
  if [ "$actual_sha256" != "$kata_sha256" ]; then
    echo "Kata archive checksum mismatch" >&2
    echo "  expected: $kata_sha256" >&2
    echo "  actual:   $actual_sha256" >&2
    exit 1
  fi
fi

tmp="$kernel.tmp"
rm -f "$tmp"
echo "extracting $kata_member"
zstd -dc "$archive" | tar -xOf - "$kata_member" > "$tmp"
chmod 0644 "$tmp"
mv "$tmp" "$kernel"

echo "Kata vmlinux ready: $kernel"
