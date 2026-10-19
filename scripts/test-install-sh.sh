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
chmod 0755 "${MOCK_BIN}/uname" "${MOCK_BIN}/curl" "${MOCK_BIN}/mkdir" "${MOCK_BIN}/mv"

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
        FIRMA_NO_BREW=1 \
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
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_BREW=1 FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
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

cat > "${MOCK_BIN}/brew" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
    info)
        [ "${MOCK_BREW_FAIL_STEP:-}" != info ] || exit 1
        printf '%s\n' "{\"formulae\":[{\"versions\":{\"stable\":\"${MOCK_BREW_VERSION}\"}}]}"
        ;;
    ruby)
        cat >/dev/null
        [ "${MOCK_BREW_FAIL_STEP:-}" != ruby ] || exit 1
        printf '%s\n' "$MOCK_BREW_VERSION"
        ;;
    install)
        printf '%s\n' install >> "$MOCK_BREW_LOG"
        [ -z "$MOCK_BREW_EXPECTED_SHIM" ] || [ -x "$MOCK_BREW_EXPECTED_SHIM" ]
        if [ "${MOCK_BREW_SIGNAL:-0}" = 1 ]; then
            kill -TERM "$PPID"
            sleep 0.1
            exit 1
        fi
        if [ "${MOCK_BREW_HOLD:-0}" = 1 ]; then
            : > "$MOCK_BREW_HOLD_READY"
            while [ ! -e "$MOCK_BREW_HOLD_RELEASE" ]; do sleep 0.05; done
        fi
        [ "${MOCK_BREW_INSTALL_FAIL:-0}" != 1 ] || exit 1
        mkdir -p "$(dirname "$MOCK_BREW_NEW_FIRMA_BIN")"
        printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'not-a-firma-version'" > "$MOCK_BREW_NEW_FIRMA_BIN"
        chmod 0755 "$MOCK_BREW_NEW_FIRMA_BIN"
        printf '%s\n' "$MOCK_BREW_NEW_FIRMA_BIN" > "$MOCK_BREW_ACTIVE_STATE"
        ;;
    list)
        printf '%s\n' list >> "$MOCK_BREW_LOG"
        exit 99
        ;;
    --prefix)
        [ "${MOCK_BREW_FAIL_STEP:-}" != prefix ] || exit 1
        printf '%s\n' "$MOCK_BREW_PREFIX"
        ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 "${MOCK_BIN}/brew"
brew_prefix="${TEST_ROOT}/brew"
brew_old_bin="${brew_prefix}/Cellar/firma/0.1.6/bin/firma"
brew_new_bin="${brew_prefix}/Cellar/firma/0.1.7/bin/firma"
brew_old_dir=$(dirname "$brew_old_bin")
brew_new_dir=$(dirname "$brew_new_bin")
brew_active_state="${TEST_ROOT}/brew-active"
brew_shim="${brew_prefix}/var/openfirma/secret-shims/0.1.7/x86_64-unknown-linux-musl/firma-secret-shim"
seed_old_pair "$brew_old_dir" brew-old
printf '%s\n' "$brew_old_bin" > "$brew_active_state"

MOCK_ASSET_DIR="${TEST_ROOT}/brew-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 0 current
brew_log="${TEST_ROOT}/brew.log"
if MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim \
    MOCK_LATEST_VERSION=v0.1.7 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew/bin" \
    > "${TEST_ROOT}/brew.out" 2>&1; then
    printf '%s\n' 'expected Homebrew preflight without a shim to fail' >&2
    exit 1
fi
grep -F 'refusing to partially install v0.1.7' "${TEST_ROOT}/brew.out"
grep -F 'falling back to verified tarball v0.1.7' "${TEST_ROOT}/brew.out"
test ! -e "$brew_log"
test ! -e "${TEST_ROOT}/brew/bin"
test "$(cat "$brew_active_state")" = "$brew_old_bin"
assert_old_pair "$brew_old_dir" brew-old
test ! -e "$brew_shim"

MOCK_ASSET_DIR="${TEST_ROOT}/brew-complete-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
brew_log="${TEST_ROOT}/brew-shim-failure.log"
if MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim \
    MOCK_LATEST_VERSION=v0.1.7 MOCK_FAIL_MKDIR_PATTERN=var/openfirma \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew-unused/bin" \
    > "${TEST_ROOT}/brew-shim-failure.out" 2>&1; then
    printf '%s\n' 'expected Homebrew private shim preflight mkdir failure' >&2
    exit 1
fi
test ! -e "$brew_log"
grep -F 'falling back to verified tarball v0.1.7' "${TEST_ROOT}/brew-shim-failure.out"
test "$(cat "$brew_active_state")" = "$brew_old_bin"
assert_old_pair "$brew_old_dir" brew-old

brew_log="${TEST_ROOT}/brew-shim-mv-failure.log"
if MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim \
    MOCK_LATEST_VERSION=v0.1.7 MOCK_FAIL_MV_PATTERN=.firma-secret-shim.new \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew-mv-unused/bin" \
    > "${TEST_ROOT}/brew-shim-mv-failure.out" 2>&1; then
    printf '%s\n' 'expected Homebrew private shim preflight move failure' >&2
    exit 1
fi
test ! -e "$brew_log"
grep -F 'falling back to verified tarball v0.1.7' "${TEST_ROOT}/brew-shim-mv-failure.out"
test "$(cat "$brew_active_state")" = "$brew_old_bin"
assert_old_pair "$brew_old_dir" brew-old

rm -rf "$(dirname "$(dirname "$(dirname "$brew_shim")")")"
brew_log="${TEST_ROOT}/brew-success.log"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim \
    MOCK_LATEST_VERSION=v0.1.7 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew-success-unused/bin" >/dev/null
test "$(cat "$brew_log")" = install
test "$(cat "$brew_active_state")" = "$brew_new_bin"
test "$("$brew_new_bin")" = 'not-a-firma-version'
test -x "$brew_shim"
test ! -e "${brew_new_dir}/libexec"
assert_old_pair "$brew_old_dir" brew-old

MOCK_ASSET_DIR="${TEST_ROOT}/brew-legacy-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.2 x86_64-unknown-linux-musl 0 legacy
brew_legacy_bin="${brew_prefix}/Cellar/firma/0.1.2/bin/firma"
brew_log="${TEST_ROOT}/brew-legacy.log"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.2 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_legacy_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM='' \
    MOCK_LATEST_VERSION=v0.1.2 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew-legacy-unused/bin" \
    > "${TEST_ROOT}/brew-legacy.out" 2>&1
grep -F 'Homebrew installed firma 0.1.2' "${TEST_ROOT}/brew-legacy.out"
test "$(cat "$brew_log")" = install
test "$(cat "$brew_active_state")" = "$brew_legacy_bin"
test ! -e "${brew_prefix}/var/openfirma/secret-shims/0.1.2"
test ! -e "${TEST_ROOT}/brew-legacy-unused"

MOCK_ASSET_DIR="${TEST_ROOT}/brew-fallback-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
make_archive 0.1.8 x86_64-apple-darwin 0 current
make_archive 0.1.8 x86_64-unknown-linux-musl 1 current
printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'preinstalled-brew-resource'" > "$brew_shim"
chmod 0755 "$brew_shim"
seed_old_pair "$brew_old_dir" fallback-old
printf '%s\n' "$brew_old_bin" > "$brew_active_state"
rm -rf "$(dirname "$brew_new_dir")"
brew_log="${TEST_ROOT}/brew-fallback.log"
curl_log="${TEST_ROOT}/brew-fallback-curl.log"
fallback_install="${TEST_ROOT}/brew-fallback/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$brew_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim \
    MOCK_BREW_INSTALL_FAIL=1 \
    MOCK_LATEST_VERSION=v0.1.8 MOCK_CURL_LOG=$curl_log PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$fallback_install" >/dev/null
test "$("${fallback_install}/firma")" = 'firma 0.1.8'
test -x "${fallback_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim"
grep -F '/download/v0.1.8/firma-x86_64-unknown-linux-musl.tar.gz' "$curl_log"
test "$(cat "$brew_active_state")" = "$brew_old_bin"
assert_old_pair "$brew_old_dir" fallback-old
test ! -e "$brew_new_bin"
test "$("$brew_shim")" = preinstalled-brew-resource

for fail_step in info ruby prefix; do
    step_install="${TEST_ROOT}/brew-${fail_step}-fallback/bin"
    MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-${fail_step}.log" \
        MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
        MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
        MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_BREW_FAIL_STEP=$fail_step \
        MOCK_LATEST_VERSION=v0.1.8 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
        FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
        sh "${REPO_ROOT}/install.sh" --install-dir "$step_install" \
        > "${TEST_ROOT}/brew-${fail_step}.out" 2>&1
    test "$("${step_install}/firma")" = 'firma 0.1.8'
    grep -F 'falling back to verified tarball v0.1.8' "${TEST_ROOT}/brew-${fail_step}.out"
    test "$("$brew_shim")" = preinstalled-brew-resource
done

download_failure_install="${TEST_ROOT}/brew-download-fallback/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-download.log" \
    MOCK_BREW_VERSION=0.1.10 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_LATEST_VERSION=v0.1.8 \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$download_failure_install" \
    > "${TEST_ROOT}/brew-download.out" 2>&1
test "$("${download_failure_install}/firma")" = 'firma 0.1.8'
grep -F 'falling back to verified tarball v0.1.8' "${TEST_ROOT}/brew-download.out"

make_archive 0.1.11 x86_64-unknown-linux-musl 1 current
printf '%064d  %s\n' 0 firma-x86_64-unknown-linux-musl.tar.gz \
    > "${MOCK_ASSET_DIR}/0.1.11/firma-x86_64-unknown-linux-musl.tar.gz.sha256"
verification_failure_install="${TEST_ROOT}/brew-verification-fallback/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-verification.log" \
    MOCK_BREW_VERSION=0.1.11 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_LATEST_VERSION=v0.1.8 \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$verification_failure_install" \
    > "${TEST_ROOT}/brew-verification.out" 2>&1
test "$("${verification_failure_install}/firma")" = 'firma 0.1.8'
grep -F 'falling back to verified tarball v0.1.8' "${TEST_ROOT}/brew-verification.out"

signal_resource_install="${TEST_ROOT}/brew-signal-fallback/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-signal.log" \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_BREW_SIGNAL=1 \
    MOCK_LATEST_VERSION=v0.1.8 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$signal_resource_install" \
    > "${TEST_ROOT}/brew-signal.out" 2>&1
test "$("${signal_resource_install}/firma")" = 'firma 0.1.8'
test "$("$brew_shim")" = preinstalled-brew-resource
grep -F 'caught TERM during Homebrew installation' "${TEST_ROOT}/brew-signal.out"

top_signal_install="${TEST_ROOT}/brew-top-signal/bin"
brew_hold_ready="${TEST_ROOT}/brew-top-signal.ready"
brew_hold_release="${TEST_ROOT}/brew-top-signal.release"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-top-signal.log" \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_BREW_HOLD=1 \
    MOCK_BREW_HOLD_READY=$brew_hold_ready MOCK_BREW_HOLD_RELEASE=$brew_hold_release \
    MOCK_LATEST_VERSION=v0.1.8 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$top_signal_install" \
    > "${TEST_ROOT}/brew-top-signal.out" 2>&1 &
top_signal_pid=$!
wait_count=0
while [ ! -e "$brew_hold_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$brew_hold_ready"
kill -TERM "$top_signal_pid"
touch "$brew_hold_release"
if wait "$top_signal_pid"; then
    printf '%s\n' 'expected top-level caught TERM to stop Homebrew installation' >&2
    exit 1
fi
grep -F 'caught TERM; waiting for the Homebrew installation to finish' "${TEST_ROOT}/brew-top-signal.out"
test "$(cat "$brew_active_state")" = "$brew_new_bin"
test "$("$brew_shim")" = fixture-shim-0.1.7
test ! -e "${brew_prefix}/.openfirma-installer.lock"
test ! -e "$top_signal_install"

printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'preinstalled-brew-resource'" > "$brew_shim"
chmod 0755 "$brew_shim"
printf '%s\n' "$brew_old_bin" > "$brew_active_state"
rm -f "$brew_new_bin"
published_ready="${TEST_ROOT}/brew-published.ready"
published_release="${TEST_ROOT}/brew-published.release"
published_signal_install="${TEST_ROOT}/brew-published-signal/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-published-signal.log" \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_LATEST_VERSION=v0.1.8 \
    FIRMA_INSTALLER_TEST_BREW_PUBLISHED_READY=$published_ready \
    FIRMA_INSTALLER_TEST_BREW_PUBLISHED_RELEASE=$published_release \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$published_signal_install" \
    > "${TEST_ROOT}/brew-published-signal.out" 2>&1 &
published_signal_pid=$!
wait_count=0
while [ ! -e "$published_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$published_ready"
test "$(cat "$brew_active_state")" = "$brew_new_bin"
test -d "${brew_prefix}/.openfirma-installer.lock"
kill -TERM "$published_signal_pid"
touch "$published_release"
if wait "$published_signal_pid"; then
    printf '%s\n' 'expected post-publication TERM to report interruption' >&2
    exit 1
fi
grep -F 'caught TERM after Homebrew installation completed' "${TEST_ROOT}/brew-published-signal.out"
test "$(cat "$brew_active_state")" = "$brew_new_bin"
test "$("$brew_new_bin")" = not-a-firma-version
test "$("$brew_shim")" = fixture-shim-0.1.7
test -x "$brew_shim"
test ! -e "${brew_prefix}/.openfirma-installer.lock"
test -z "$(find "$(dirname "$brew_shim")" -name '.firma-secret-shim.*' -print)"
test ! -e "$published_signal_install"

printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'preinstalled-brew-resource'" > "$brew_shim"
chmod 0755 "$brew_shim"
printf '%s\n' "$brew_old_bin" > "$brew_active_state"
rm -f "$brew_new_bin"
concurrent_brew_ready="${TEST_ROOT}/brew-concurrent.ready"
concurrent_brew_release="${TEST_ROOT}/brew-concurrent.release"
concurrent_a_log="${TEST_ROOT}/brew-concurrent-a.log"
concurrent_b_log="${TEST_ROOT}/brew-concurrent-b.log"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$concurrent_a_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_BREW_HOLD=1 \
    MOCK_BREW_HOLD_READY=$concurrent_brew_ready MOCK_BREW_HOLD_RELEASE=$concurrent_brew_release \
    MOCK_LATEST_VERSION=v0.1.8 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "${TEST_ROOT}/brew-concurrent-a/bin" \
    > "${TEST_ROOT}/brew-concurrent-a.out" 2>&1 &
concurrent_a_pid=$!
wait_count=0
while [ ! -e "$concurrent_brew_ready" ] && [ "$wait_count" -lt 100 ]; do
    sleep 0.05
    wait_count=$((wait_count + 1))
done
test -e "$concurrent_brew_ready"
brew_lock="${brew_prefix}/.openfirma-installer.lock"
test -r "${brew_lock}/owner"
brew_lock_owner=$(cat "${brew_lock}/owner")
test "$brew_lock_owner" != "$concurrent_a_pid"
kill -0 "$brew_lock_owner"

concurrent_b_install="${TEST_ROOT}/brew-concurrent-b/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG=$concurrent_b_log \
    MOCK_BREW_VERSION=0.1.7 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_shim MOCK_LATEST_VERSION=v0.1.8 \
    PATH="${MOCK_BIN}:${SYSTEM_PATH}" FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$concurrent_b_install" \
    > "${TEST_ROOT}/brew-concurrent-b.out" 2>&1
test ! -e "$concurrent_b_log"
grep -F "another firma installer (PID $brew_lock_owner) owns $brew_lock" "${TEST_ROOT}/brew-concurrent-b.out"
grep -F 'falling back to verified tarball v0.1.8' "${TEST_ROOT}/brew-concurrent-b.out"
test "$("${concurrent_b_install}/firma")" = 'firma 0.1.8'
test "$("$brew_shim")" = fixture-shim-0.1.7

touch "$concurrent_brew_release"
wait "$concurrent_a_pid"
test "$(cat "$concurrent_a_log")" = install
test "$(cat "$brew_active_state")" = "$brew_new_bin"
test "$("$brew_shim")" = fixture-shim-0.1.7
test -x "$brew_shim"
test ! -e "$brew_lock"

make_archive 0.1.9 x86_64-unknown-linux-musl 1 current
brew_new_resource="${brew_prefix}/var/openfirma/secret-shims/0.1.9/x86_64-unknown-linux-musl/firma-secret-shim"
new_resource_install="${TEST_ROOT}/brew-new-resource-fallback/bin"
MOCK_ASSET_DIR=$MOCK_ASSET_DIR MOCK_OS=Darwin MOCK_BREW_LOG="${TEST_ROOT}/brew-new-resource.log" \
    MOCK_BREW_VERSION=0.1.9 MOCK_BREW_PREFIX=$brew_prefix \
    MOCK_BREW_NEW_FIRMA_BIN=$brew_new_bin MOCK_BREW_ACTIVE_STATE=$brew_active_state \
    MOCK_BREW_EXPECTED_SHIM=$brew_new_resource MOCK_BREW_INSTALL_FAIL=1 \
    MOCK_LATEST_VERSION=v0.1.8 PATH="${MOCK_BIN}:${SYSTEM_PATH}" \
    FIRMA_NO_INIT=1 FIRMA_NO_MODIFY_PATH=1 \
    sh "${REPO_ROOT}/install.sh" --install-dir "$new_resource_install" >/dev/null
test "$("${new_resource_install}/firma")" = 'firma 0.1.8'
test ! -e "$brew_new_resource"
test ! -e "${brew_prefix}/var/openfirma/secret-shims/0.1.9"

printf '%s\n' 'mocked install.sh smoke tests passed'
