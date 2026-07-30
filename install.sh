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
INSTALL_DIR=""
NO_BREW=0
NO_MODIFY_PATH=0
NO_INIT=0
FORCE=0
DRY_RUN=0
TARGET=""
SHA256_TOOL=""
DOWNLOAD_TOOL=""
ARCHIVE_NAME=""
ARCHIVE_PATH=""
CHECKSUM_PATH=""
TMP_DIR=""

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
            --version)         shift; VERSION="${1:-}"; [ -n "$VERSION" ] || die "--version requires a value" ;;
            --version=*)       VERSION="${1#*=}"; [ -n "$VERSION" ] || die "--version requires a value" ;;
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
            ;;
        Darwin)
            case "$arch" in
                x86_64)              TARGET="x86_64-apple-darwin" ;;
                arm64|aarch64)       TARGET="aarch64-apple-darwin" ;;
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

# Returns 0 if firma is already installed at the same version (handled);
# returns 0 after prompting/overwriting otherwise; calls die on refusal.
check_existing() {
    command -v firma >/dev/null 2>&1 || return 0
    current=$(firma --version 2>/dev/null | awk '{print $2}')
    [ -n "$current" ] || current="unknown"
    target_ver=${VERSION#v}
    if [ "$current" = "$target_ver" ] && [ "$FORCE" != "1" ]; then
        info "firma $current already installed. Use --force to reinstall."
        exit 0
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
    ARCHIVE_NAME="firma-${TARGET}.tar.gz"
    ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
    base="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
    info "downloading ${ARCHIVE_NAME} ..."
    if ! fetch_to "${base}/${ARCHIVE_NAME}" "$ARCHIVE_PATH"; then
        rm -f "$ARCHIVE_PATH"
        version_bare=${VERSION#v}
        ARCHIVE_NAME="firma-${version_bare}-${TARGET}.tar.gz"
        ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
        info "cargo-dist archive unavailable; trying legacy archive ${ARCHIVE_NAME} ..."
        fetch_to "${base}/${ARCHIVE_NAME}" "$ARCHIVE_PATH" \
            || die "could not download a release archive for ${VERSION} (${TARGET})"
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

install_binary() {
    info "installing to ${INSTALL_DIR}/firma ..."
    extract_dir="${TMP_DIR}/extract"
    run "mkdir -p '$extract_dir'"
    run "tar -xzf '$ARCHIVE_PATH' -C '$extract_dir'"

    # Locate the extracted binary. The release tarball ships a single `firma`
    # at the root; guard against future layout changes.
    if [ "$DRY_RUN" != "1" ]; then
        binary_path=$(find "$extract_dir" -maxdepth 2 -type f -name firma -print | head -n1)
        [ -n "$binary_path" ] || die "could not find 'firma' inside ${ARCHIVE_NAME}"
    else
        binary_path="${extract_dir}/firma"
    fi

    run "mkdir -p '$INSTALL_DIR'"
    if [ "$DRY_RUN" != "1" ] && [ ! -w "$INSTALL_DIR" ]; then
        die "install dir not writable: $INSTALL_DIR (re-run with FIRMA_INSTALL_DIR=<path>, or run the install command yourself with sudo)"
    fi
    run "mv '$binary_path' '${INSTALL_DIR}/firma'"
    run "chmod 0755 '${INSTALL_DIR}/firma'"
    info "installed: ${INSTALL_DIR}/firma"
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

try_brew() {
    [ "$NO_BREW" = "1" ] && return 1
    command -v brew >/dev/null 2>&1 || return 1
    info "Homebrew detected — installing via tap ${BREW_FORMULA%/firma}"
    if run "brew install '${BREW_FORMULA}'"; then
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
    check_existing

    if try_brew; then
        post_install
        exit 0
    fi

    setup_tmp
    download_archive
    verify_archive
    install_binary
    ensure_path
    post_install
}

main "$@"
