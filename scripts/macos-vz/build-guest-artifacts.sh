#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build local OpenFirma macOS VZ Linux guest artifacts.

Usage:
  scripts/macos-vz/build-guest-artifacts.sh [OUT_DIR]

Outputs:
  vmlinuz
  initrd.img
  rootfs.img
  manifest.txt

Environment:
  FIRMA_VZ_GUEST_KERNEL       Path to a known-good Kata vmlinux.
  FIRMA_VZ_BUSYBOX_STATIC     Use an existing static busybox binary.
  FIRMA_VZ_BUSYBOX_STATIC_APK Use an existing busybox-static APK.
  FIRMA_VZ_ROOTFS_SIZE        Rootfs image size in bytes. Default: 67108864.
  RUST_TARGET                 Override the Linux musl target for the guest init.
  RUSTUP_TOOLCHAIN            Optional Rust toolchain passed through to cargo.
  CARGO                       Cargo binary. Default: cargo.
  RUSTC                       Rust compiler used to locate rust-lld. Default: rustc.

The script does not install Rust targets. If the selected target is missing,
run the rustup target add command printed by the failure.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)"
host_arch="$(uname -m)"
cargo_bin="${CARGO:-cargo}"
rustc_bin="${RUSTC:-rustc}"
rootfs_size="${FIRMA_VZ_ROOTFS_SIZE:-67108864}"
default_guest_kernel="$repo_root/target/firma-vz-guest/kata/vmlinux-6.18.15-186"
guest_kernel="${FIRMA_VZ_GUEST_KERNEL:-$default_guest_kernel}"

case "${RUST_TARGET:-$host_arch}" in
  arm64 | aarch64 | aarch64-unknown-linux-musl)
    rust_target="${RUST_TARGET:-aarch64-unknown-linux-musl}"
    alpine_arch="aarch64"
    busybox_static_url="https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-1.36.1-r31.apk"
    busybox_static_sha256="1d8e7a7fc2ed69bdb8eb7be9d962489c21a0f75b72d8a325437c8a09d4cfac70"
    ;;
  x86_64 | x86_64-unknown-linux-musl)
    rust_target="${RUST_TARGET:-x86_64-unknown-linux-musl}"
    alpine_arch="x86_64"
    busybox_static_url="https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/busybox-static-1.36.1-r31.apk"
    busybox_static_sha256="1ca8a2894b073edea2a04231f335ad48795f92617c5eacae59458c51202068ed"
    ;;
  *)
    echo "unsupported host or RUST_TARGET architecture: ${RUST_TARGET:-$host_arch}" >&2
    exit 1
    ;;
esac

out_dir="${1:-"$repo_root/target/firma-vz-guest/$alpine_arch"}"
work_dir="$out_dir/.work"
initramfs_dir="$work_dir/initramfs"
download_dir="$work_dir/downloads"
guest_module_dir="$initramfs_dir/lib/modules/firma-vz"
boot_args="console=hvc0 earlyprintk=hvc0 ignore_loglevel loglevel=8 printk.time=1 rdinit=/firma-init init=/firma-init panic=1 firma.virtiofs_tag=firma firma.launch_contract=/firma-shares/runtime/vz-guest/vz-guest-launch.json firma.network=vsock_sidecar"

if [ -z "$guest_kernel" ]; then
  echo "FIRMA_VZ_GUEST_KERNEL must point to the known-good Kata vmlinux" >&2
  exit 1
fi
if [ ! -f "$guest_kernel" ]; then
  echo "Kata vmlinux does not exist: $guest_kernel" >&2
  echo "run: just macos-vz-kata-kernel" >&2
  exit 1
fi

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
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

clear_macos_xattrs() {
  if command -v xattr >/dev/null 2>&1; then
    xattr -c "$@" 2>/dev/null || true
  fi
}

extract_kernel_module() {
  module_suffix="$1"
  module_output="$guest_module_dir/$(basename "$module_suffix" .gz)"
  module_member="$(
    tar -tf "$kernel_apk" |
      awk -v suffix="/$module_suffix" \
        'substr($0, length($0) - length(suffix) + 1) == suffix { print; exit }'
  )"
  if [ -z "$module_member" ]; then
    echo "kernel APK is missing required module: $module_suffix" >&2
    exit 1
  fi
  tar -xOf "$kernel_apk" "$module_member" | gzip -dc > "$module_output"
  chmod 0644 "$module_output"
}

require_tool "$cargo_bin"
require_tool "$rustc_bin"
require_tool awk
require_tool cpio
require_tool gzip
require_tool find
require_tool sort
require_tool tar
require_tool truncate

if command -v rustup >/dev/null 2>&1; then
  rustup_target_args=(target list --installed)
  if [ -n "${RUSTUP_TOOLCHAIN:-}" ]; then
    rustup_target_args+=(--toolchain "$RUSTUP_TOOLCHAIN")
  fi
  if ! rustup "${rustup_target_args[@]}" | grep -qx "$rust_target"; then
    echo "missing Rust target: $rust_target" >&2
    if [ -n "${RUSTUP_TOOLCHAIN:-}" ]; then
      echo "run: rustup target add $rust_target --toolchain $RUSTUP_TOOLCHAIN" >&2
    else
      echo "run: rustup target add $rust_target" >&2
    fi
    exit 1
  fi
fi

mkdir -p "$out_dir" "$work_dir" "$download_dir"

case "$rust_target" in
  aarch64-unknown-linux-musl)
    linker_env_name="CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
    ;;
  x86_64-unknown-linux-musl)
    linker_env_name="CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
    ;;
  *)
    linker_env_name=""
    ;;
esac

if [ -n "$linker_env_name" ] && [ -z "${!linker_env_name:-}" ]; then
  rust_sysroot="$("$rustc_bin" --print sysroot)"
  rust_host="$("$rustc_bin" -vV | awk '/^host:/ {print $2}')"
  rust_lld="$rust_sysroot/lib/rustlib/$rust_host/bin/rust-lld"
  if [ -x "$rust_lld" ]; then
    ln -sf "$rust_lld" "$work_dir/ld.lld"
    export "$linker_env_name=$work_dir/ld.lld"
  fi
fi

"$cargo_bin" build \
  --manifest-path "$repo_root/Cargo.toml" \
  -p firma-vz-guest-init \
  --bin firma-vz-guest-init \
  --release \
  --target "$rust_target"

guest_init="$repo_root/target/$rust_target/release/firma-vz-guest-init"
if [ ! -x "$guest_init" ]; then
  echo "guest init was not built at $guest_init" >&2
  exit 1
fi

kernel_raw="$work_dir/kernel.raw"
kernel_apk=""
module_bundle="kata-built-in"
cp "$guest_kernel" "$kernel_raw"
kernel_source="$guest_kernel"
kernel_package_sha256="external-kata"

if gzip -t "$kernel_raw" >/dev/null 2>&1; then
  gzip -dc "$kernel_raw" > "$out_dir/vmlinuz"
else
  cp "$kernel_raw" "$out_dir/vmlinuz"
fi
chmod 0644 "$out_dir/vmlinuz"

busybox_static_binary="$work_dir/busybox.static"
busybox_static_apk=""
if [ -n "${FIRMA_VZ_BUSYBOX_STATIC:-}" ]; then
  cp "$FIRMA_VZ_BUSYBOX_STATIC" "$busybox_static_binary"
  busybox_static_source="$FIRMA_VZ_BUSYBOX_STATIC"
  busybox_static_package_sha256="external-binary"
elif [ -n "${FIRMA_VZ_BUSYBOX_STATIC_APK:-}" ]; then
  busybox_static_apk="$FIRMA_VZ_BUSYBOX_STATIC_APK"
  tar -xOf "$busybox_static_apk" bin/busybox.static > "$busybox_static_binary"
  busybox_static_source="$busybox_static_apk#bin/busybox.static"
  busybox_static_package_sha256="$(sha256_file "$busybox_static_apk")"
else
  require_tool curl
  busybox_static_apk="$download_dir/$(basename "$busybox_static_url")"
  curl -fsSL "$busybox_static_url" -o "$busybox_static_apk"
  actual_sha256="$(sha256_file "$busybox_static_apk")"
  if [ "$actual_sha256" != "$busybox_static_sha256" ]; then
    echo "busybox-static APK checksum mismatch for $busybox_static_url" >&2
    echo "expected: $busybox_static_sha256" >&2
    echo "actual:   $actual_sha256" >&2
    exit 1
  fi
  tar -xOf "$busybox_static_apk" bin/busybox.static > "$busybox_static_binary"
  busybox_static_source="$busybox_static_url#bin/busybox.static"
  busybox_static_package_sha256="$actual_sha256"
fi
if [ ! -s "$busybox_static_binary" ]; then
  echo "busybox static binary was not extracted at $busybox_static_binary" >&2
  exit 1
fi
chmod 0755 "$busybox_static_binary"

rm -rf "$initramfs_dir"
mkdir -p "$initramfs_dir/dev" "$initramfs_dir/proc" "$initramfs_dir/sys" \
  "$initramfs_dir/tmp" "$initramfs_dir/firma-shares" "$initramfs_dir/bin" \
  "$initramfs_dir/usr/bin" "$guest_module_dir"
cp "$guest_init" "$initramfs_dir/firma-init"
cp "$guest_init" "$initramfs_dir/init"
cp "$busybox_static_binary" "$initramfs_dir/bin/busybox"
busybox_links=(
  bin/ash
  bin/cat
  bin/chmod
  bin/cp
  bin/date
  bin/echo
  bin/env
  bin/false
  bin/grep
  bin/ls
  bin/mkdir
  bin/mount
  bin/printf
  bin/ps
  bin/pwd
  bin/rm
  bin/sh
  bin/sleep
  bin/test
  bin/touch
  bin/true
  bin/umount
  bin/uname
  bin/wget
  bin/which
  usr/bin/awk
  usr/bin/cat
  usr/bin/env
  usr/bin/grep
  usr/bin/ls
  usr/bin/mkdir
  usr/bin/printf
  usr/bin/rm
  usr/bin/sed
  usr/bin/wget
  usr/bin/which
)
for busybox_link in "${busybox_links[@]}"; do
  rm -f "$initramfs_dir/$busybox_link"
  ln -s /bin/busybox "$initramfs_dir/$busybox_link"
done
cat > "$initramfs_dir/bin/bash" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -lc)
    shift
    exec /bin/sh -c "$@"
    ;;
  -l)
    shift
    exec /bin/sh "$@"
    ;;
  *)
    exec /bin/sh "$@"
    ;;
esac
EOF
ln -s /bin/bash "$initramfs_dir/usr/bin/bash"
chmod 0755 "$initramfs_dir/firma-init" "$initramfs_dir/init" \
  "$initramfs_dir/bin/busybox" "$initramfs_dir/bin/bash"
if [ -n "$kernel_apk" ]; then
  extract_kernel_module "kernel/drivers/virtio/virtio.ko.gz"
  extract_kernel_module "kernel/drivers/virtio/virtio_ring.ko.gz"
  extract_kernel_module "kernel/drivers/virtio/virtio_pci_legacy_dev.ko.gz"
  extract_kernel_module "kernel/drivers/virtio/virtio_pci_modern_dev.ko.gz"
  extract_kernel_module "kernel/drivers/virtio/virtio_pci.ko.gz"
  extract_kernel_module "kernel/drivers/virtio/virtio_mmio.ko.gz"
  extract_kernel_module "kernel/drivers/block/virtio_blk.ko.gz"
  extract_kernel_module "kernel/drivers/char/virtio_console.ko.gz"
  extract_kernel_module "kernel/fs/fuse/fuse.ko.gz"
  extract_kernel_module "kernel/fs/fuse/virtiofs.ko.gz"
fi
find "$initramfs_dir" -exec touch -h -t 202001010000.00 {} +

(
  cd "$initramfs_dir"
  find . -print | LC_ALL=C sort | cpio -o -H newc | gzip -n > "$out_dir/initrd.img"
)
chmod 0644 "$out_dir/initrd.img"

: > "$out_dir/rootfs.img"
truncate -s "$rootfs_size" "$out_dir/rootfs.img"
chmod 0644 "$out_dir/rootfs.img"
clear_macos_xattrs "$out_dir/vmlinuz" "$out_dir/initrd.img" "$out_dir/rootfs.img"

cat > "$out_dir/manifest.txt" <<EOF
kernel_source=$kernel_source
kernel_package_sha256=$kernel_package_sha256
kernel_sha256=$(sha256_file "$out_dir/vmlinuz")
initrd_sha256=$(sha256_file "$out_dir/initrd.img")
rootfs_sha256=$(sha256_file "$out_dir/rootfs.img")
module_bundle=$module_bundle
busybox_static_source=$busybox_static_source
busybox_static_package_sha256=$busybox_static_package_sha256
busybox_static_sha256=$(sha256_file "$initramfs_dir/bin/busybox")
shell_tools=/bin/sh,/bin/bash,/bin/cat,/bin/printf,/bin/ls,/bin/mkdir,/bin/rm,/bin/grep,/bin/wget,/usr/bin/env,/usr/bin/which
rust_target=$rust_target
rootfs_size=$rootfs_size
boot_args=$boot_args
EOF
chmod 0644 "$out_dir/manifest.txt"
clear_macos_xattrs "$out_dir/manifest.txt"

cat <<EOF
OpenFirma macOS VZ guest artifacts written to:
  $out_dir

Artifacts:
  kernel:   $out_dir/vmlinuz
  initrd:   $out_dir/initrd.img
  rootfs:   $out_dir/rootfs.img
  manifest: $out_dir/manifest.txt

Use with:
  FIRMA_RUN_VZ_GUEST_KERNEL=$out_dir/vmlinuz
  FIRMA_RUN_VZ_GUEST_INITRD=$out_dir/initrd.img
  FIRMA_RUN_VZ_GUEST_ROOTFS=$out_dir/rootfs.img
EOF
