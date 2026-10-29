#!/bin/sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TEST_ROOT=$(mktemp -d 2>/dev/null || mktemp -d -t firma-installer-test)
trap 'rm -rf "$TEST_ROOT"' EXIT INT HUP TERM

SYSTEM_PATH=/usr/bin:/bin
MOCK_BIN="${TEST_ROOT}/mock-bin"
mkdir -p "$MOCK_BIN"

cat > "${MOCK_BIN}/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
    -s) printf '%s\n' "${MOCK_OS:-Linux}" ;;
    -m) printf '%s\n' "${MOCK_ARCH:-x86_64}" ;;
    *) printf '%s\n' "${MOCK_OS:-Linux}" ;;
esac
EOF

# Models `sysctl -n hw.optional.arm64`: 1 on Apple silicon (also under
# Rosetta), and an unknown-oid failure on Intel Macs.
cat > "${MOCK_BIN}/sysctl" <<'EOF'
#!/bin/sh
[ "$*" = '-n hw.optional.arm64' ] && [ -n "${MOCK_SYSCTL_ARM64:-}" ] || exit 1
printf '%s\n' "$MOCK_SYSCTL_ARM64"
EOF

cat > "${MOCK_BIN}/curl" <<'EOF'
#!/bin/sh
set -eu
dest=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) shift; dest=$1 ;;
        http://*|https://*) url=$1 ;;
    esac
    shift
done
[ -n "$url" ] || exit 2
if [ -z "$dest" ]; then
    printf '%s\n' "https://github.com/Firma-AI/openfirma/releases/tag/${MOCK_LATEST_VERSION}"
    exit 0
fi
asset=${url##*/}
release=${url%/*}
release=${release##*/}
[ -f "${MOCK_ASSET_DIR}/${release#v}/${asset}" ] || exit 22
[ -z "${MOCK_CURL_LOG:-}" ] || printf '%s\n' "$url" >> "$MOCK_CURL_LOG"
cp "${MOCK_ASSET_DIR}/${release#v}/${asset}" "$dest"
EOF

cat > "${MOCK_BIN}/mkdir" <<'EOF'
#!/bin/sh
case "$*" in
    *"${MOCK_FAIL_MKDIR_PATTERN:-__never_match__}"*) exit 1 ;;
esac
exec /bin/mkdir "$@"
EOF

cat > "${MOCK_BIN}/mv" <<'EOF'
#!/bin/sh
for arg do dest=$arg; done
case "$dest" in
    *"${MOCK_HOLD_MV_PATTERN:-__never_match__}"*)
        : > "$MOCK_HOLD_READY"
        while [ ! -e "$MOCK_HOLD_RELEASE" ]; do sleep 0.05; done
        ;;
esac
case "$dest" in
    *"${MOCK_FAIL_MV_PATTERN:-__never_match__}"*) exit 1 ;;
esac
exec /bin/mv "$@"
EOF
chmod 0755 "${MOCK_BIN}/uname" "${MOCK_BIN}/sysctl" "${MOCK_BIN}/curl" "${MOCK_BIN}/mkdir" "${MOCK_BIN}/mv"

make_archive() {
    version=$1
    target=$2
    include_shim=$3
    naming=$4
    fixture_dir="${TEST_ROOT}/fixture-${version}-${target}"
    archive_root="${fixture_dir}/firma-${version}-${target}"
    rm -rf "$fixture_dir"
    mkdir -p "$archive_root"
    cat > "${archive_root}/firma" <<EOF
#!/bin/sh
if [ "\${1:-}" = fixture-runtime-shim ]; then
    exec "\$(dirname "\$0")/libexec/openfirma/secret-shims/${target}/firma-secret-shim"
fi
printf '%s\n' 'firma ${version}'
EOF
    chmod 0755 "${archive_root}/firma"
    if [ "$include_shim" = "1" ]; then
        printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'fixture-shim-${version}'" > "${archive_root}/firma-secret-shim"
        chmod 0755 "${archive_root}/firma-secret-shim"
    fi
    asset_dir="${MOCK_ASSET_DIR}/${version}"
    mkdir -p "$asset_dir"
    case "$naming" in
        current) archive="${asset_dir}/firma-${target}.tar.gz" ;;
        legacy) archive="${asset_dir}/firma-${version}-${target}.tar.gz" ;;
        *) exit 2 ;;
    esac
    tar -czf "$archive" -C "$fixture_dir" "$(basename "$archive_root")"
    sha256sum "$archive" | awk '{print $1}' > "${archive}.sha256"
}

seed_old_pair() {
    install_dir=$1
    label=$2
    target=${3:-x86_64-unknown-linux-musl}
    shim_dir="${install_dir}/libexec/openfirma/secret-shims/${target}"
    mkdir -p "$shim_dir"
    printf '%s\n' '#!/bin/sh' "printf '%s\\n' '${label}-cli'" > "${install_dir}/firma"
    printf '%s\n' '#!/bin/sh' "printf '%s\\n' '${label}-shim'" > "${shim_dir}/firma-secret-shim"
    chmod 0755 "${install_dir}/firma" "${shim_dir}/firma-secret-shim"
}

assert_old_pair() {
    install_dir=$1
    label=$2
    target=${3:-x86_64-unknown-linux-musl}
    test "$("${install_dir}/firma")" = "${label}-cli"
    test "$("${install_dir}/libexec/openfirma/secret-shims/${target}/firma-secret-shim")" = "${label}-shim"
}

run_installer() {
    (exec_installer "$@")
}

# Replaces the calling shell with the installer. Background it directly so `$!`
# names the installer process rather than a wrapper subshell that a signal
# would terminate without reaching the installer.
exec_installer() {
    version=$1
    install_dir=$2
    os=${3:-Linux}
    exec env \
        MOCK_ASSET_DIR="$MOCK_ASSET_DIR" \
        MOCK_OS="$os" \
        PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
        FIRMA_NO_INIT=1 \
        FIRMA_NO_MODIFY_PATH=1 \
        sh "${REPO_ROOT}/install.sh" --version "$version" --install-dir "$install_dir"
}

MOCK_ASSET_DIR="${TEST_ROOT}/legacy-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.2 x86_64-unknown-linux-musl 0 legacy
legacy_install="${TEST_ROOT}/legacy/bin"
run_installer v0.1.2 "$legacy_install" > "${TEST_ROOT}/legacy.out" 2>&1
! grep -F -i -e shim -e CLI-only "${TEST_ROOT}/legacy.out"
test -x "${legacy_install}/firma"
test ! -e "${legacy_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim"

legacy_latest_install="${TEST_ROOT}/legacy-latest/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_LATEST_VERSION=v0.1.2 \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$legacy_latest_install" \
    > "${TEST_ROOT}/legacy-latest.out" 2>&1
! grep -F -i -e shim -e CLI-only "${TEST_ROOT}/legacy-latest.out"
test "$("${legacy_latest_install}/firma")" = 'firma 0.1.2'
test ! -e "${legacy_latest_install}/libexec"

make_archive 0.1.9 x86_64-unknown-linux-musl 0 current
unknown_install="${TEST_ROOT}/unknown-new/bin"
if run_installer v0.1.9 "$unknown_install" > "${TEST_ROOT}/unknown-new.out" 2>&1; then
    printf '%s\n' 'expected an unknown new shim-less release to fail' >&2
    exit 1
fi
grep -F 'refusing to partially install v0.1.9' "${TEST_ROOT}/unknown-new.out"

if FIRMA_INSTALLER_RELEASE_TAG_GUARD=v0.1.2 sh "${REPO_ROOT}/install.sh" > "${TEST_ROOT}/release-guard-old.out" 2>&1; then
    printf '%s\n' 'expected publishing guard to reject an allowlisted tag' >&2
    exit 1
fi
grep -F 'legacy CLI-only allowlist' "${TEST_ROOT}/release-guard-old.out"
FIRMA_INSTALLER_RELEASE_TAG_GUARD=v0.1.9 sh "${REPO_ROOT}/install.sh"

MOCK_ASSET_DIR="${TEST_ROOT}/modern-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 0 current
modern_install="${TEST_ROOT}/modern/bin"
mkdir -p "$modern_install"
printf '%s\n' keep > "${modern_install}/sentinel"
printf '%s\n' '#!/bin/sh' 'printf old-cli' > "${modern_install}/firma"
chmod 0755 "${modern_install}/firma"
if run_installer v0.1.7 "$modern_install" > "${TEST_ROOT}/modern.out" 2>&1; then
    printf '%s\n' 'expected a shim-less modern archive to fail' >&2
    exit 1
fi
grep -F "refusing to partially install v0.1.7" "${TEST_ROOT}/modern.out"
test "$(cat "${modern_install}/sentinel")" = keep
test "$("${modern_install}/firma")" = old-cli
test ! -e "${modern_install}/libexec"

MOCK_ASSET_DIR="${TEST_ROOT}/complete-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
complete_install="${TEST_ROOT}/complete/bin"
run_installer v0.1.7 "$complete_install" >/dev/null
test -x "${complete_install}/firma"
test -x "${complete_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim"
test ! -e "${complete_install}/firma-secret-shim"
# Cross the installed CLI boundary using the same executable-relative private
# target directory consumed by runtime shim discovery.
test "$("${complete_install}/firma" fixture-runtime-shim)" = fixture-shim-0.1.7

mkdir_failure_install="${TEST_ROOT}/mkdir-failure/bin"
seed_old_pair "$mkdir_failure_install" mkdir-old
if MOCK_FAIL_MKDIR_PATTERN=secret-shims run_installer v0.1.7 "$mkdir_failure_install" \
    > "${TEST_ROOT}/mkdir-failure.out" 2>&1; then
    printf '%s\n' 'expected destination mkdir failure' >&2
    exit 1
fi
assert_old_pair "$mkdir_failure_install" mkdir-old

mv_failure_install="${TEST_ROOT}/mv-failure/bin"
seed_old_pair "$mv_failure_install" mv-old
if MOCK_FAIL_MV_PATTERN=/firma-secret-shim run_installer v0.1.7 "$mv_failure_install" \
    > "${TEST_ROOT}/mv-failure.out" 2>&1; then
    printf '%s\n' 'expected destination shim move failure' >&2
    exit 1
fi
assert_old_pair "$mv_failure_install" mv-old

cli_failure_install="${TEST_ROOT}/cli-failure/bin"
seed_old_pair "$cli_failure_install" cli-old
if MOCK_FAIL_MV_PATTERN="${cli_failure_install}/firma" run_installer v0.1.7 "$cli_failure_install" \
    > "${TEST_ROOT}/cli-failure.out" 2>&1; then
    printf '%s\n' 'expected final CLI move failure' >&2
    exit 1
fi
assert_old_pair "$cli_failure_install" cli-old
test ! -e "${cli_failure_install}/firma.install.lock"
for residue in "${cli_failure_install}"/.firma.new.* \
    "${cli_failure_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl"/.firma-secret-shim.*; do
    test ! -e "$residue"
done

new_cli_failure_install="${TEST_ROOT}/new-cli-failure/bin"
if MOCK_FAIL_MV_PATTERN="${new_cli_failure_install}/firma" run_installer v0.1.7 "$new_cli_failure_install" \
    > "${TEST_ROOT}/new-cli-failure.out" 2>&1; then
    printf '%s\n' 'expected new-install final CLI move failure' >&2
    exit 1
fi
test ! -e "$new_cli_failure_install"

stale_install="${TEST_ROOT}/stale-lock/bin"
seed_old_pair "$stale_install" stale-old
stale_pid=999999
while kill -0 "$stale_pid" 2>/dev/null; do stale_pid=$((stale_pid + 1)); done
mkdir "${stale_install}/firma.install.lock"
printf '%s\n' "$stale_pid" > "${stale_install}/firma.install.lock/owner"
run_installer v0.1.7 "$stale_install" > "${TEST_ROOT}/stale-lock.out" 2>&1
grep -F "reclaimed stale installer lock from absent PID $stale_pid" "${TEST_ROOT}/stale-lock.out"
test "$("${stale_install}/firma")" = 'firma 0.1.7'
test "$("${stale_install}/firma" fixture-runtime-shim)" = fixture-shim-0.1.7

ambiguous_install="${TEST_ROOT}/ambiguous-lock/bin"
seed_old_pair "$ambiguous_install" ambiguous-old
mkdir "${ambiguous_install}/firma.install.lock"
printf '%s\n' not-a-pid > "${ambiguous_install}/firma.install.lock/owner"
if run_installer v0.1.7 "$ambiguous_install" > "${TEST_ROOT}/ambiguous-lock.out" 2>&1; then
    printf '%s\n' 'expected ambiguous lock owner to fail closed' >&2
    exit 1
fi
grep -F 'unreadable or ambiguous owner' "${TEST_ROOT}/ambiguous-lock.out"
assert_old_pair "$ambiguous_install" ambiguous-old

concurrent_install="${TEST_ROOT}/concurrent/bin"
seed_old_pair "$concurrent_install" concurrent-old
hold_ready="${TEST_ROOT}/concurrent.ready"
hold_release="${TEST_ROOT}/concurrent.release"
MOCK_HOLD_MV_PATTERN=.firma.new MOCK_HOLD_READY=$hold_ready MOCK_HOLD_RELEASE=$hold_release \
    run_installer v0.1.7 "$concurrent_install" > "${TEST_ROOT}/concurrent-winner.out" 2>&1 &
winner_pid=$!
wait_count=0
while [ ! -e "$hold_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$hold_ready"
if run_installer v0.1.7 "$concurrent_install" > "${TEST_ROOT}/concurrent-loser.out" 2>&1; then
    printf '%s\n' 'expected concurrent installer loser to fail' >&2
    exit 1
fi
grep -F 'another firma installer' "${TEST_ROOT}/concurrent-loser.out"
touch "$hold_release"
wait "$winner_pid"
test "$("${concurrent_install}/firma")" = 'firma 0.1.7'
test "$("${concurrent_install}/firma" fixture-runtime-shim)" = fixture-shim-0.1.7

signal_install="${TEST_ROOT}/signal/bin"
seed_old_pair "$signal_install" signal-old
hold_ready="${TEST_ROOT}/signal.ready"
hold_release="${TEST_ROOT}/signal.release"
MOCK_HOLD_MV_PATTERN="${signal_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim" \
    MOCK_HOLD_READY=$hold_ready MOCK_HOLD_RELEASE=$hold_release \
    exec_installer v0.1.7 "$signal_install" > "${TEST_ROOT}/signal.out" 2>&1 &
signal_pid=$!
wait_count=0
while [ ! -e "$hold_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$hold_ready"
kill -TERM "$signal_pid"
touch "$hold_release"
if wait "$signal_pid"; then
    printf '%s\n' 'expected caught TERM to fail the installation' >&2
    exit 1
fi
assert_old_pair "$signal_install" signal-old
test ! -e "${signal_install}/firma.install.lock"
grep -F 'caught TERM; restoring the previous installation' "${TEST_ROOT}/signal.out"

signal_cli_install="${TEST_ROOT}/signal-cli/bin"
seed_old_pair "$signal_cli_install" signal-cli-old
hold_ready="${TEST_ROOT}/signal-cli.ready"
hold_release="${TEST_ROOT}/signal-cli.release"
MOCK_HOLD_MV_PATTERN="${signal_cli_install}/firma" \
    MOCK_HOLD_READY=$hold_ready MOCK_HOLD_RELEASE=$hold_release \
    exec_installer v0.1.7 "$signal_cli_install" > "${TEST_ROOT}/signal-cli.out" 2>&1 &
signal_cli_pid=$!
wait_count=0
while [ ! -e "$hold_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$hold_ready"
kill -TERM "$signal_cli_pid"
touch "$hold_release"
if wait "$signal_cli_pid"; then
    printf '%s\n' 'expected TERM during final CLI replacement to fail the installation' >&2
    exit 1
fi
assert_old_pair "$signal_cli_install" signal-cli-old
test ! -e "${signal_cli_install}/firma.install.lock"
grep -F 'caught TERM; restoring the previous installation' "${TEST_ROOT}/signal-cli.out"

MOCK_ASSET_DIR="${TEST_ROOT}/darwin-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-apple-darwin 0 current
make_archive 0.1.7 x86_64-unknown-linux-musl 0 current
darwin_install="${TEST_ROOT}/darwin/bin"
mkdir -p "$darwin_install"
printf '%s\n' '#!/bin/sh' 'printf old-darwin-cli' > "${darwin_install}/firma"
chmod 0755 "${darwin_install}/firma"
if run_installer v0.1.7 "$darwin_install" Darwin > "${TEST_ROOT}/darwin.out" 2>&1; then
    printf '%s\n' 'expected a shim-less Darwin guest archive to fail' >&2
    exit 1
fi
grep -F 'refusing to partially install v0.1.7' "${TEST_ROOT}/darwin.out"
test "$("${darwin_install}/firma")" = old-darwin-cli
test ! -e "${darwin_install}/libexec"

MOCK_ASSET_DIR="${TEST_ROOT}/darwin-complete-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-apple-darwin 0 current
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
darwin_mv_install="${TEST_ROOT}/darwin-mv-failure/bin"
seed_old_pair "$darwin_mv_install" darwin-mv-old
if MOCK_FAIL_MV_PATTERN=/firma-secret-shim run_installer v0.1.7 "$darwin_mv_install" Darwin \
    > "${TEST_ROOT}/darwin-mv-failure.out" 2>&1; then
    printf '%s\n' 'expected Darwin destination shim move failure' >&2
    exit 1
fi
assert_old_pair "$darwin_mv_install" darwin-mv-old

# Under Rosetta, `uname -m` reports x86_64 on Apple silicon. Only arm64 assets
# exist here, so picking the Intel build fails the download.
MOCK_ASSET_DIR="${TEST_ROOT}/rosetta-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 aarch64-apple-darwin 0 current
make_archive 0.1.7 aarch64-unknown-linux-musl 1 current
rosetta_install="${TEST_ROOT}/rosetta/bin"
MOCK_ARCH=x86_64 MOCK_SYSCTL_ARM64=1 run_installer v0.1.7 "$rosetta_install" Darwin \
    > "${TEST_ROOT}/rosetta.out" 2>&1
grep -F 'target: aarch64-apple-darwin' "${TEST_ROOT}/rosetta.out"
test "$("${rosetta_install}/firma")" = 'firma 0.1.7'
test -x "${rosetta_install}/libexec/openfirma/secret-shims/aarch64-unknown-linux-musl/firma-secret-shim"

# An Intel Mac installs the x86_64 build when the latest release resolves
# without --version, and fetches the matching Linux guest archive for the shim.
MOCK_ASSET_DIR="${TEST_ROOT}/darwin-complete-assets"
intel_install="${TEST_ROOT}/intel-darwin/bin"
intel_curl_log="${TEST_ROOT}/intel-darwin-curl.log"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_LATEST_VERSION=v0.1.7 \
    MOCK_CURL_LOG=$intel_curl_log PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$intel_install" \
    > "${TEST_ROOT}/intel-darwin.out" 2>&1
grep -F 'target: x86_64-apple-darwin' "${TEST_ROOT}/intel-darwin.out"
test "$("${intel_install}/firma")" = 'firma 0.1.7'
test -x "${intel_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim"
grep -F '/download/v0.1.7/firma-x86_64-unknown-linux-musl.tar.gz' "$intel_curl_log"

# A checksum mismatch aborts before the previous installation changes.
MOCK_ASSET_DIR="${TEST_ROOT}/checksum-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
printf '%064d  %s\n' 0 firma-x86_64-unknown-linux-musl.tar.gz \
    > "${MOCK_ASSET_DIR}/0.1.7/firma-x86_64-unknown-linux-musl.tar.gz.sha256"
checksum_install="${TEST_ROOT}/checksum/bin"
seed_old_pair "$checksum_install" checksum-old
if run_installer v0.1.7 "$checksum_install" > "${TEST_ROOT}/checksum.out" 2>&1; then
    printf '%s\n' 'expected a checksum mismatch to fail' >&2
    exit 1
fi
grep -F 'checksum mismatch for firma-x86_64-unknown-linux-musl.tar.gz' "${TEST_ROOT}/checksum.out"
assert_old_pair "$checksum_install" checksum-old

# Existing-install contract for the install dir: a complete same-version
# install exits early, --force reinstalls it, and a different version is
# replaced without a terminal. The retired --no-brew opt-outs stay accepted.
MOCK_ASSET_DIR="${TEST_ROOT}/complete-assets"
contract_install="${TEST_ROOT}/contract/bin"
run_installer v0.1.7 "$contract_install" >/dev/null
run_installer v0.1.7 "$contract_install" > "${TEST_ROOT}/contract-same.out" 2>&1
grep -F 'firma 0.1.7 already installed. Use --force to reinstall.' "${TEST_ROOT}/contract-same.out"
if grep -F 'installing to' "${TEST_ROOT}/contract-same.out"; then
    printf '%s\n' 'expected the same-version rerun to skip installation' >&2
    exit 1
fi
FIRMA_FORCE=1 run_installer v0.1.7 "$contract_install" > "${TEST_ROOT}/contract-force.out" 2>&1
grep -F 'reinstalling firma 0.1.7 over firma 0.1.7 (--force)' "${TEST_ROOT}/contract-force.out"
grep -F "installed: ${contract_install}/firma" "${TEST_ROOT}/contract-force.out"
make_archive 0.1.8 x86_64-unknown-linux-musl 1 current
MOCK_ASSET_DIR=$MOCK_ASSET_DIR PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_BREW=1 FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --no-brew --version v0.1.8 --install-dir "$contract_install" \
    < /dev/null > "${TEST_ROOT}/contract-replace.out" 2>&1
grep -F 'replacing firma 0.1.7 with 0.1.8' "${TEST_ROOT}/contract-replace.out"
test "$("${contract_install}/firma")" = 'firma 0.1.8'
test "$("${contract_install}/firma" fixture-runtime-shim)" = fixture-shim-0.1.8

# A firma elsewhere on PATH, such as a `cargo install` copy, does not block a
# non-interactive install and is left alone. When it comes before the already
# listed install dir, the installer warns that it shadows the new one.
cargo_bin="${TEST_ROOT}/cargo/bin"
mkdir -p "$cargo_bin"
printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'firma 0.0.1'" > "${cargo_bin}/firma"
chmod 0755 "${cargo_bin}/firma"
shadowed_install="${TEST_ROOT}/shadowed/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR PATH="${cargo_bin}:${shadowed_install}:${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --version v0.1.7 --install-dir "$shadowed_install" \
    < /dev/null > "${TEST_ROOT}/shadowed.out" 2>&1
test "$("${shadowed_install}/firma")" = 'firma 0.1.7'
test "$("${cargo_bin}/firma")" = 'firma 0.0.1'
grep -F "${cargo_bin}/firma comes earlier on PATH and shadows ${shadowed_install}/firma" "${TEST_ROOT}/shadowed.out"

# When the install dir is not on PATH yet, the rc block prepends it, so the
# new firma wins in new shells and no shadow warning is printed.
fresh_home="${TEST_ROOT}/fresh-home"
mkdir -p "$fresh_home"
fresh_install="${fresh_home}/.local/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR HOME=$fresh_home SHELL=/bin/zsh ZDOTDIR=$fresh_home \
    PATH="${cargo_bin}:${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 \
    sh "${REPO_ROOT}/install.sh" --version v0.1.7 \
    < /dev/null > "${TEST_ROOT}/fresh.out" 2>&1
test "$("${fresh_install}/firma")" = 'firma 0.1.7'
grep -F "export PATH=\"${fresh_install}:\$PATH\"" "${fresh_home}/.zshrc"
if grep -F 'shadows' "${TEST_ROOT}/fresh.out"; then
    printf '%s\n' 'expected no shadow warning when the rc block prepends the install dir' >&2
    exit 1
fi

printf '%s\n' 'mocked install.sh smoke tests passed'
