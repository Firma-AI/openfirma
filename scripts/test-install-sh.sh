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
printf '%s\n' 'firma ${version}'
EOF
    chmod 0755 "${archive_root}/firma"
    if [ "$include_shim" = "1" ]; then
        printf '%s\n' '#!/bin/sh' 'exit 0' > "${archive_root}/firma-secret-shim"
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
    version=$1
    install_dir=$2
    os=${3:-Linux}
    MOCK_ASSET_DIR=$MOCK_ASSET_DIR \
    MOCK_OS=$os \
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
legacy_output=$(run_installer v0.1.2 "$legacy_install" 2>&1)
printf '%s\n' "$legacy_output" | grep -F 'predates private secret-shim packaging'
test -x "${legacy_install}/firma"
test ! -e "${legacy_install}/libexec/openfirma/secret-shims/x86_64-unknown-linux-musl/firma-secret-shim"

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
    info) printf '%s\n' "{\"formulae\":[{\"versions\":{\"stable\":\"${MOCK_BREW_VERSION}\"}}]}" ;;
    ruby) cat >/dev/null; printf '%s\n' "$MOCK_BREW_VERSION" ;;
    install)
        printf '%s\n' install >> "$MOCK_BREW_LOG"
        [ -x "$MOCK_BREW_EXPECTED_SHIM" ]
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
    --prefix) printf '%s\n' "$MOCK_BREW_PREFIX" ;;
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

MOCK_ASSET_DIR="${TEST_ROOT}/brew-fallback-assets"
mkdir -p "$MOCK_ASSET_DIR"
make_archive 0.1.7 x86_64-unknown-linux-musl 1 current
make_archive 0.1.8 x86_64-apple-darwin 0 current
make_archive 0.1.8 x86_64-unknown-linux-musl 1 current
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
test -x "$brew_shim"

printf '%s\n' 'mocked install.sh smoke tests passed'
