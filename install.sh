#!/bin/sh
# install.sh — install the firma CLI on Linux and macOS.
#
# Usage:
#   curl -fsSL https://<host>/install.sh | sh
#   curl -fsSL https://<host>/install.sh | sh -s -- --no-init
#   ./install.sh --version v0.7.0 --install-dir /opt/firma/bin

# shellcheck disable=SC2034
# Globals declared here are consumed by later install stages
# (tool gate, version resolve, brew branch, PATH editing, post-install).

set -eu

VERSION=""
GITHUB_VERSION=""
VERSION_EXPLICIT=0
INSTALL_DIR=""
NO_BREW=0
NO_MODIFY_PATH=0
NO_INIT=0
FORCE=0
DRY_RUN=0
TARGET=""
GUEST_SHIM_TARGET=""
SHA256_TOOL=""
DOWNLOAD_TOOL=""
ARCHIVE_NAME=""
ARCHIVE_PATH=""
CHECKSUM_PATH=""
TMP_DIR=""
INSTALLED_FIRMA_BIN=""
CLI_ONLY_INSTALL=0
PREPARED_PRIVATE_SHIM=""
BREW_UPDATE_PREPARED=0
BREW_PREFIX=""

QUICKSTART_URL="https://firma-ai.github.io/openfirma/quickstart/"
GITHUB_REPO="Firma-AI/openfirma"
BREW_FORMULA="Firma-AI/openfirma/firma"
SENTINEL='# firma-installer: add install dir to PATH'

info() { printf '[firma-installer] %s\n' "$*"; }
warn() { printf '[firma-installer] warning: %s\n' "$*" >&2; }
err()  { printf '[firma-installer] error: %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'EOF'
Install the firma CLI.

Usage: install.sh [options]

Options:
  --version <v>          Install a specific release tag (e.g. v0.7.0).
                         Default: latest release. Env: FIRMA_VERSION.
  --install-dir <path>   Install location. Default: $HOME/.local/bin.
                         Env: FIRMA_INSTALL_DIR.
  --no-brew              Do not use Homebrew even if available.
                         Env: FIRMA_NO_BREW=1.
  --no-modify-path       Do not edit shell rc files. Print manual hint.
                         Env: FIRMA_NO_MODIFY_PATH=1.
  --no-init              Do not prompt to run 'firma config'.
                         Env: FIRMA_NO_INIT=1.
  --force                Overwrite an existing install without prompting.
                         Env: FIRMA_FORCE=1.
  --dry-run              Print planned actions only. No I/O on disk.
                         Env: FIRMA_DRY_RUN=1.
  -h, --help             Show this message.

Quickstart: https://firma-ai.github.io/openfirma/quickstart/
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)         shift; VERSION="${1:-}"; [ -n "$VERSION" ] || die "--version requires a value"; VERSION_EXPLICIT=1 ;;
            --version=*)       VERSION="${1#*=}"; [ -n "$VERSION" ] || die "--version requires a value"; VERSION_EXPLICIT=1 ;;
            --install-dir)     shift; INSTALL_DIR="${1:-}"; [ -n "$INSTALL_DIR" ] || die "--install-dir requires a value" ;;
            --install-dir=*)   INSTALL_DIR="${1#*=}"; [ -n "$INSTALL_DIR" ] || die "--install-dir requires a value" ;;
            --no-brew)         NO_BREW=1 ;;
            --no-modify-path)  NO_MODIFY_PATH=1 ;;
            --no-init)         NO_INIT=1 ;;
            --force)           FORCE=1 ;;
            --dry-run)         DRY_RUN=1 ;;
            -h|--help)         usage; exit 0 ;;
            *) die "unknown option: $1 (use --help)" ;;
        esac
        shift
    done

    if [ -n "${FIRMA_VERSION:-}" ] && [ -z "$VERSION" ]; then
        VERSION="$FIRMA_VERSION"
        VERSION_EXPLICIT=1
    fi
    if [ -n "${FIRMA_INSTALL_DIR:-}" ] && [ -z "$INSTALL_DIR" ]; then
        INSTALL_DIR="$FIRMA_INSTALL_DIR"
    fi
    [ "${FIRMA_NO_BREW:-0}"        = "1" ] && NO_BREW=1
    [ "${FIRMA_NO_MODIFY_PATH:-0}" = "1" ] && NO_MODIFY_PATH=1
    [ "${FIRMA_NO_INIT:-0}"        = "1" ] && NO_INIT=1
    [ "${FIRMA_FORCE:-0}"          = "1" ] && FORCE=1
    [ "${FIRMA_DRY_RUN:-0}"        = "1" ] && DRY_RUN=1

    if [ -z "$INSTALL_DIR" ]; then
        INSTALL_DIR="${HOME}/.local/bin"
    fi
}

run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '[dry-run] %s\n' "$*"
    else
        eval "$*"
    fi
}

require_tool() {
    # require_tool <name> [<install-hint>]
    if ! command -v "$1" >/dev/null 2>&1; then
        if [ -n "${2:-}" ]; then
            die "missing required tool: $1 ($2)"
        else
            die "missing required tool: $1"
        fi
    fi
}

# Sets SHA256_TOOL to "sha256sum" or "shasum -a 256".
detect_sha_tool() {
    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_TOOL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHA256_TOOL="shasum -a 256"
    else
        die "need sha256sum or shasum on PATH"
    fi
}

# Sets DOWNLOAD_TOOL: "curl" or "wget".
detect_download_tool() {
    if command -v curl >/dev/null 2>&1; then
        DOWNLOAD_TOOL="curl"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOAD_TOOL="wget"
    else
        die "need curl or wget on PATH"
    fi
}

# fetch_to <url> <dest-path>
# GitHub access token (env GITHUB_TOKEN) is added as a Bearer auth header
# when present, so CI runs against a private repo work without user setup.
fetch_to() {
    if [ "$DOWNLOAD_TOOL" = "curl" ]; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            run "curl -fsSL --proto '=https' --tlsv1.2 -H 'Authorization: Bearer ${GITHUB_TOKEN}' -o '$2' '$1'"
        else
            run "curl -fsSL --proto '=https' --tlsv1.2 -o '$2' '$1'"
        fi
    else
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            run "wget -q --header='Authorization: Bearer ${GITHUB_TOKEN}' -O '$2' '$1'"
        else
            run "wget -q -O '$2' '$1'"
        fi
    fi
}

# fetch_redirect <url> -> prints final URL after redirects
fetch_redirect() {
    if [ "$DOWNLOAD_TOOL" = "curl" ]; then
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            curl -sILo /dev/null -w '%{url_effective}' --proto '=https' --tlsv1.2 \
                -H "Authorization: Bearer ${GITHUB_TOKEN}" -L "$1"
        else
            curl -sILo /dev/null -w '%{url_effective}' --proto '=https' --tlsv1.2 -L "$1"
        fi
    else
        # --spider issues HEAD-equivalent. Server-response captures Location.
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            wget --spider --max-redirect=0 -S \
                --header="Authorization: Bearer ${GITHUB_TOKEN}" "$1" 2>&1 \
                | awk 'tolower($1)=="location:"{print $2; exit}'
        else
            wget --spider --max-redirect=0 -S "$1" 2>&1 \
                | awk 'tolower($1)=="location:"{print $2; exit}'
        fi
    fi
}

# Sets TARGET to the release-asset triple for the running platform.
detect_target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64)        TARGET="x86_64-unknown-linux-musl" ;;
                aarch64|arm64)       TARGET="aarch64-unknown-linux-musl" ;;
                *) die "unsupported linux arch: $arch (file an issue with: $os $arch)" ;;
            esac
            GUEST_SHIM_TARGET="$TARGET"
            ;;
        Darwin)
            case "$arch" in
                x86_64)
                    TARGET="x86_64-apple-darwin"
                    GUEST_SHIM_TARGET="x86_64-unknown-linux-musl"
                    ;;
                arm64|aarch64)
                    TARGET="aarch64-apple-darwin"
                    GUEST_SHIM_TARGET="aarch64-unknown-linux-musl"
                    ;;
                *) die "unsupported darwin arch: $arch (file an issue with: $os $arch)" ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*)
            die "Windows detected. Use install.ps1: iwr -useb https://<host>/install.ps1 | iex"
            ;;
        *)
            die "unsupported OS: $os (see https://github.com/${GITHUB_REPO}/releases for manual download)"
            ;;
    esac
}

# Sets VERSION to a tag like "v0.7.0".
resolve_version() {
    if [ -n "$VERSION" ]; then
        case "$VERSION" in
            v*) : ;;
            *)  VERSION="v$VERSION" ;;
        esac
        info "version (pinned): $VERSION"
        return
    fi
    info "resolving latest release ..."
    final_url=$(fetch_redirect "https://github.com/${GITHUB_REPO}/releases/latest")
    [ -n "$final_url" ] || die "could not resolve latest release URL"
    candidate=${final_url##*/}
    case "$candidate" in
        v[0-9]*) VERSION="$candidate" ;;
        *) die "unexpected latest-release URL: $final_url" ;;
    esac
    info "version: $VERSION"
}

# These published releases have Linux archives, but their tagged source and
# archive contents predate firma-secret-shim. Keep this list bounded so an
# absent shim in any newer or unknown release remains a hard failure.
release_predates_secret_shim() {
    [ "$VERSION_EXPLICIT" = "1" ] || return 1
    case "$VERSION" in
        v0.0.0|v0.1.0|v0.1.1|v0.1.2|v0.1.3|v0.1.4|v0.1.5|v0.1.6) return 0 ;;
        *) return 1 ;;
    esac
}

# Returns 0 if firma is already installed at the same version (handled);
# returns 0 after prompting/overwriting otherwise; calls die on refusal.
check_existing() {
    command -v firma >/dev/null 2>&1 || return 0
    current=$(firma --version 2>/dev/null | awk '{print $2}')
    [ -n "$current" ] || current="unknown"
    target_ver=${VERSION#v}
    if [ "$current" = "$target_ver" ] && [ "$FORCE" != "1" ]; then
        current_bin=$(command -v firma)
        current_dir=$(dirname "$current_bin")
        current_shim="${current_dir}/libexec/openfirma/secret-shims/${GUEST_SHIM_TARGET}/firma-secret-shim"
        if [ -x "$current_shim" ]; then
            info "firma $current already installed. Use --force to reinstall."
            exit 0
        fi
        if release_predates_secret_shim; then
            info "firma $current CLI-only release already installed. Use --force to reinstall."
            exit 0
        fi
        info "firma $current is installed without its private secret shim; repairing the installation"
        return 0
    fi
    if [ "$FORCE" = "1" ]; then
        info "replacing firma $current with $target_ver (--force)"
        return 0
    fi
    if [ -t 0 ]; then
        printf '[firma-installer] replace firma %s with %s? [y/N] ' "$current" "$target_ver"
        read -r ans
        case "$ans" in
            y|Y|yes|YES) return 0 ;;
            *) die "aborted by user" ;;
        esac
    else
        die "firma $current already on PATH. Re-run with --force to replace, or --version to pin."
    fi
}

setup_tmp() {
    TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t firma-installer)
    if [ -z "$TMP_DIR" ] || [ ! -d "$TMP_DIR" ]; then
        die "could not create temporary directory"
    fi
    trap 'rm -rf "$TMP_DIR"' EXIT INT HUP TERM
}

download_archive() {
    archive_target="$1"
    ARCHIVE_NAME="firma-${archive_target}.tar.gz"
    ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
    base="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    info "downloading ${ARCHIVE_NAME} ..."
    if ! fetch_to "${base}/${ARCHIVE_NAME}" "$ARCHIVE_PATH"; then
        rm -f "$ARCHIVE_PATH"
        version_bare=${VERSION#v}
        ARCHIVE_NAME="firma-${version_bare}-${archive_target}.tar.gz"
        ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
        info "cargo-dist archive unavailable; trying legacy archive ${ARCHIVE_NAME} ..."
        fetch_to "${base}/${ARCHIVE_NAME}" "$ARCHIVE_PATH" \
            || die "could not download a release archive for ${VERSION} (${archive_target})"
    fi

    CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
    fetch_to "${base}/${ARCHIVE_NAME}.sha256"   "$CHECKSUM_PATH"
}

verify_archive() {
    info "verifying checksum ..."
    if [ "$DRY_RUN" = "1" ]; then
        info "(dry-run) skipping verification"
        return
    fi
    expected=$(awk '{print $1}' < "$CHECKSUM_PATH")
    [ -n "$expected" ] || die "empty checksum file: $CHECKSUM_PATH"
    # SHA256_TOOL is "sha256sum" or "shasum -a 256" — intentional word-split.
    # shellcheck disable=SC2086
    actual=$( ( cd "$TMP_DIR" && $SHA256_TOOL "$ARCHIVE_NAME" ) | awk '{print $1}' )
    if [ "$expected" != "$actual" ]; then
        die "checksum mismatch for ${ARCHIVE_NAME}: expected $expected, got $actual"
    fi
    info "checksum ok"
}

require_archive_secret_shim() {
    if [ "$DRY_RUN" = "1" ]; then
        return
    fi
    if tar -tzf "$ARCHIVE_PATH" | awk -F/ '$NF == "firma-secret-shim" { found=1; exit } END { exit !found }'; then
        return
    fi
    if release_predates_secret_shim; then
        CLI_ONLY_INSTALL=1
        warn "${VERSION} predates private secret-shim packaging; installing this explicitly requested release as CLI-only"
        return
    fi
    die "could not find 'firma-secret-shim' inside ${ARCHIVE_NAME}; refusing to partially install ${VERSION}"
}

install_binary() {
    info "installing to ${INSTALL_DIR}/firma ..."
    extract_dir="${TMP_DIR}/extract"
    run "mkdir -p '$extract_dir'"
    run "tar -xzf '$ARCHIVE_PATH' -C '$extract_dir'"

    # Locate the extracted binaries. The release tarball ships `firma` as the
    # user-facing CLI. Secret-shim binaries are private implementation details
    # deployed under a libexec directory, not as installed commands.
    if [ "$DRY_RUN" != "1" ]; then
        binary_path=$(find "$extract_dir" -maxdepth 2 -type f -name firma -print | head -n1)
        [ -n "$binary_path" ] || die "could not find 'firma' inside ${ARCHIVE_NAME}"
    else
        binary_path="${extract_dir}/firma"
    fi

    # Resolve every required archive member before changing the destination.
    if [ "$TARGET" = "$GUEST_SHIM_TARGET" ] && [ "$CLI_ONLY_INSTALL" != "1" ]; then
        if [ "$DRY_RUN" != "1" ]; then
            shim_path=$(find "$extract_dir" -maxdepth 2 -type f -name firma-secret-shim -print | head -n1)
            [ -n "$shim_path" ] || die "could not find 'firma-secret-shim' inside ${ARCHIVE_NAME}"
        else
            shim_path="${extract_dir}/firma-secret-shim"
        fi
    fi

    if [ "$CLI_ONLY_INSTALL" = "1" ]; then
        run "mkdir -p '$INSTALL_DIR'"
        if [ "$DRY_RUN" != "1" ] && [ ! -w "$INSTALL_DIR" ]; then
            die "install dir not writable: $INSTALL_DIR (re-run with FIRMA_INSTALL_DIR=<path>, or run the install command yourself with sudo)"
        fi
        run "mv '$binary_path' '${INSTALL_DIR}/firma'"
        run "chmod 0755 '${INSTALL_DIR}/firma'"
    else
        if [ "$TARGET" != "$GUEST_SHIM_TARGET" ]; then
            shim_path="$PREPARED_PRIVATE_SHIM"
        fi
        install_modern_pair "$binary_path" "$shim_path" "${INSTALL_DIR}/firma" "$GUEST_SHIM_TARGET" \
            || die "could not transactionally install firma and its private secret shim; the previous installation was preserved"
    fi
    INSTALLED_FIRMA_BIN="${INSTALL_DIR}/firma"
    info "installed: ${INSTALL_DIR}/firma"
}

install_modern_pair() {
    cli_source="$1"
    shim_source="$2"
    firma_bin="$3"
    shim_target="$4"
    firma_dir=$(dirname "$firma_bin")
    libexec_dir="${firma_dir}/libexec/openfirma/secret-shims/${shim_target}"
    installed_shim="${libexec_dir}/firma-secret-shim"
    staged_cli="${firma_dir}/.firma.new.$$"
    staged_shim="${libexec_dir}/.firma-secret-shim.new.$$"
    previous_shim="${TMP_DIR}/previous-firma-secret-shim"
    had_previous_shim=0

    if [ "$DRY_RUN" = "1" ]; then
        run "mkdir -p '$firma_dir' '$libexec_dir'"
        run "mv '$cli_source' '$staged_cli'"
        run "mv '$shim_source' '$staged_shim'"
        run "chmod 0755 '$staged_cli' '$staged_shim'"
        run "mv '$staged_shim' '$installed_shim'"
        run "mv '$staged_cli' '$firma_bin'"
        return 0
    fi

    mkdir -p "$firma_dir" "$libexec_dir" || return 1
    [ -w "$firma_dir" ] && [ -w "$libexec_dir" ] || return 1
    rm -f "$staged_cli" "$staged_shim"
    mv "$cli_source" "$staged_cli" || return 1
    if ! mv "$shim_source" "$staged_shim"; then
        rm -f "$staged_cli"
        return 1
    fi
    if ! chmod 0755 "$staged_cli" "$staged_shim"; then
        rm -f "$staged_cli" "$staged_shim"
        return 1
    fi
    if [ -e "$installed_shim" ]; then
        cp -p "$installed_shim" "$previous_shim" || {
            rm -f "$staged_cli" "$staged_shim"
            return 1
        }
        had_previous_shim=1
    fi
    if ! mv "$staged_shim" "$installed_shim"; then
        rm -f "$staged_cli" "$staged_shim"
        return 1
    fi
    if mv "$staged_cli" "$firma_bin"; then
        return 0
    fi

    if [ "$had_previous_shim" = "1" ]; then
        cp -p "$previous_shim" "$installed_shim" || return 1
    else
        rm -f "$installed_shim"
    fi
    rm -f "$staged_cli"
    return 1
}

prepare_private_shim_from_archive() {
    shim_target="$1"
    [ "$CLI_ONLY_INSTALL" = "1" ] && return
    if [ "$DRY_RUN" != "1" ]; then
        shim_member=$(tar -tzf "$ARCHIVE_PATH" | awk -F/ '$NF == "firma-secret-shim" { print; exit }')
        [ -n "$shim_member" ] || die "could not find 'firma-secret-shim' inside ${ARCHIVE_NAME}"
    else
        shim_member="firma-secret-shim"
    fi

    PREPARED_PRIVATE_SHIM="${TMP_DIR}/firma-secret-shim-${shim_target}"
    # Stream only the shim member out of the verified Linux archive. Do not
    # unpack its other Linux binaries onto the macOS host.
    run "tar -xOzf '$ARCHIVE_PATH' '$shim_member' > '$PREPARED_PRIVATE_SHIM'"
    run "chmod 0755 '$PREPARED_PRIVATE_SHIM'"
}

install_prepared_private_shim() {
    private_root="$1"
    shim_target="$2"
    shim_version=${VERSION#v}

    libexec_dir="${private_root}/${shim_version}/${shim_target}"
    installed_shim="${libexec_dir}/firma-secret-shim"
    staged_shim="${libexec_dir}/.firma-secret-shim.new.$$"
    if [ "$DRY_RUN" = "1" ]; then
        run "mkdir -p '$libexec_dir'"
        run "mv '$PREPARED_PRIVATE_SHIM' '$staged_shim'"
        run "mv '$staged_shim' '$installed_shim'"
        return 0
    fi
    mkdir -p "$libexec_dir" || return 1
    [ -w "$libexec_dir" ] || return 1
    rm -f "$staged_shim"
    mv "$PREPARED_PRIVATE_SHIM" "$staged_shim" || return 1
    if mv "$staged_shim" "$installed_shim"; then
        PREPARED_PRIVATE_SHIM=""
        return 0
    fi
    rm -f "$staged_shim"
    return 1
}

# Returns 0 if $1 is already a colon-segment in $PATH.
path_contains() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Picks the rc file for the user's shell. Echoes path or empty.
detect_rc_file() {
    shell_name=$(basename "${SHELL:-}")
    case "$shell_name" in
        bash)
            case "$(uname -s)" in
                Darwin) printf '%s' "${HOME}/.bash_profile" ;;
                *)      printf '%s' "${HOME}/.bashrc" ;;
            esac
            ;;
        zsh)
            zdir="${ZDOTDIR:-$HOME}"
            printf '%s' "${zdir}/.zshrc"
            ;;
        fish)
            cfg="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish"
            printf '%s' "$cfg"
            ;;
        *) printf '' ;;
    esac
}

append_path_block() {
    rc="$1"
    if [ "$(basename "$rc")" = "config.fish" ]; then
        block="$SENTINEL
fish_add_path -gP \"$INSTALL_DIR\""
    else
        # The `\$PATH` below is intentionally a literal in the generated rc
        # line; expansion must happen at shell startup, not at install time.
        # shellcheck disable=SC2016
        block="$SENTINEL
export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
    if [ "$DRY_RUN" = "1" ]; then
        info "(dry-run) would append to $rc:"
        printf '%s\n' "$block"
        return
    fi
    mkdir -p "$(dirname "$rc")"
    {
        printf '\n%s\n' "$block"
    } >> "$rc"
    info "appended PATH block to $rc"
}

ensure_path() {
    if path_contains "$INSTALL_DIR"; then
        info "${INSTALL_DIR} already on PATH"
        return
    fi
    if [ "$NO_MODIFY_PATH" = "1" ]; then
        warn "${INSTALL_DIR} is not on PATH. Add it manually, e.g.:"
        # `$PATH` here is a literal hint for the user's shell, not expansion.
        # shellcheck disable=SC2016
        printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR" >&2
        return
    fi
    rc=$(detect_rc_file)
    if [ -z "$rc" ]; then
        warn "could not detect shell rc file (SHELL=${SHELL:-unset}). Add manually:"
        # `$PATH` here is a literal hint for the user's shell, not expansion.
        # shellcheck disable=SC2016
        printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR" >&2
        return
    fi
    if [ -f "$rc" ] && grep -F "$SENTINEL" "$rc" >/dev/null 2>&1; then
        info "PATH block already present in $rc"
        return
    fi
    append_path_block "$rc"
    info "restart your shell or run: source $rc"
}

installed_firma_bin() {
    if [ -n "$INSTALLED_FIRMA_BIN" ] && [ -x "$INSTALLED_FIRMA_BIN" ]; then
        printf '%s\n' "$INSTALLED_FIRMA_BIN"
        return 0
    fi
    if [ -x "${INSTALL_DIR}/firma" ]; then
        printf '%s\n' "${INSTALL_DIR}/firma"
        return 0
    fi
    if command -v firma >/dev/null 2>&1; then
        command -v firma
        return 0
    fi
    return 1
}

firma_supports_config() {
    bin=$(installed_firma_bin) || return 1
    "$bin" help config >/dev/null 2>&1
}

next_step_cmd() {
    if firma_supports_config; then
        printf 'firma config\n'
    else
        printf 'firma --help\n'
    fi
}

maybe_run_init() {
    if [ "$NO_INIT" = "1" ]; then
        return 1
    fi
    if [ ! -t 0 ]; then
        # Not a terminal (piped through curl|sh). Skip init.
        return 1
    fi
    if ! firma_supports_config; then
        return 1
    fi
    # shellcheck disable=SC2016
    printf '[firma-installer] run `firma config` now? [Y/n] '
    read -r ans
    case "$ans" in
        ""|y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

post_install() {
    info "firma installed."
    info "quickstart: ${QUICKSTART_URL}"
    if maybe_run_init; then
        if [ "$DRY_RUN" = "1" ]; then
            info "(dry-run) would exec: firma config"
            return
        fi
        # Use the freshly installed binary, not whatever was on PATH before.
        exec "$(installed_firma_bin)" config
    else
        info "next step: $(next_step_cmd)"
    fi
}

resolve_brew_version() {
    formula_json=$(brew info --json=v2 "$BREW_FORMULA") \
        || die "could not resolve the Homebrew formula version"
    brew_version=$(printf '%s' "$formula_json" | brew ruby -rjson -e \
        'puts JSON.parse(STDIN.read).fetch("formulae").first.fetch("versions").fetch("stable")') \
        || die "could not parse the Homebrew formula version"
    [ -n "$brew_version" ] || die "Homebrew formula reported an empty version"
    VERSION="v${brew_version#v}"
    info "Homebrew formula version: $VERSION"
}

try_brew() {
    [ "$NO_BREW" = "1" ] && return 1
    [ "$VERSION_EXPLICIT" = "1" ] && return 1
    [ "$BREW_UPDATE_PREPARED" = "1" ] || return 1
    command -v brew >/dev/null 2>&1 || return 1
    info "Homebrew detected - installing via tap ${BREW_FORMULA%/firma}"
    if run "HOMEBREW_NO_AUTO_UPDATE=1 brew install '${BREW_FORMULA}'"; then
        INSTALLED_FIRMA_BIN="${BREW_PREFIX}/bin/firma"
        info "Homebrew installed firma ${VERSION#v} with its preinstalled guest shim"
        return 0
    fi
    warn "brew install failed; falling back to tarball"
    return 1
}

main() {
    parse_args "$@"
    info "install dir: $INSTALL_DIR"
    [ "$DRY_RUN" = "1" ] && info "dry-run mode: no files will be written"

    require_tool tar "install via your package manager"
    require_tool mktemp
    require_tool uname
    detect_download_tool
    detect_sha_tool
    detect_target
    info "target: $TARGET"

    resolve_version
    GITHUB_VERSION="$VERSION"
    check_existing

    setup_tmp

    # Homebrew owns versioned kegs and may select a new keg only while it runs.
    # Install the matching resource in a version-qualified, prefix-stable path
    # first so nothing after Brew needs to mutate or reconstruct package state.
    if [ "$NO_BREW" != "1" ] && [ "$VERSION_EXPLICIT" != "1" ] && command -v brew >/dev/null 2>&1; then
        resolve_brew_version
        download_archive "$GUEST_SHIM_TARGET"
        verify_archive
        require_archive_secret_shim
        prepare_private_shim_from_archive "$GUEST_SHIM_TARGET"
        BREW_PREFIX=$(brew --prefix) || die "could not resolve the Homebrew prefix"
        brew_private_root="${BREW_PREFIX}/var/openfirma/secret-shims"
        install_prepared_private_shim "$brew_private_root" "$GUEST_SHIM_TARGET" \
            || die "could not preinstall the private secret shim; Homebrew was not invoked"
        BREW_UPDATE_PREPARED=1
    fi
    brew_result=0
    try_brew || brew_result=$?
    if [ "$brew_result" = "0" ]; then
        post_install
        exit 0
    fi
    if [ "$BREW_UPDATE_PREPARED" = "1" ]; then
        VERSION="$GITHUB_VERSION"
        CLI_ONLY_INSTALL=0
        PREPARED_PRIVATE_SHIM=""
        info "restored GitHub release version for tarball fallback: $VERSION"
    fi

    download_archive "$TARGET"
    verify_archive
    primary_archive_name="$ARCHIVE_NAME"
    primary_archive_path="$ARCHIVE_PATH"
    primary_checksum_path="$CHECKSUM_PATH"

    if [ "$TARGET" = "$GUEST_SHIM_TARGET" ]; then
        require_archive_secret_shim
    else
        download_archive "$GUEST_SHIM_TARGET"
        verify_archive
        require_archive_secret_shim
        prepare_private_shim_from_archive "$GUEST_SHIM_TARGET"
        ARCHIVE_NAME="$primary_archive_name"
        ARCHIVE_PATH="$primary_archive_path"
        CHECKSUM_PATH="$primary_checksum_path"
    fi

    install_binary
    ensure_path
    post_install
}

main "$@"
