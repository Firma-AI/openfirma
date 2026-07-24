#!/usr/bin/env bash
# Regenerate Formula/firma.rb in Firma-AI/homebrew-openfirma for a release.
#
# Usage:
#   ./scripts/update-homebrew-tap.sh 0.1.0 [/path/to/homebrew-openfirma]
#
# Requires: curl, sha256sum or shasum

set -euo pipefail

VERSION="${1:?usage: $0 <version-without-v> [tap-checkout-dir]}"
TAP_DIR="${2:-../homebrew-openfirma}"
REPO="${GITHUB_REPO:-Firma-AI/openfirma}"
FORMULA="${TAP_DIR}/Formula/firma.rb"

if [ ! -d "$TAP_DIR" ]; then
  echo "error: tap checkout not found at $TAP_DIR" >&2
  echo "clone with: git clone https://github.com/Firma-AI/homebrew-openfirma.git $TAP_DIR" >&2
  exit 1
fi

sha_for() {
  local target="$1"
  local url="https://github.com/${REPO}/releases/download/v${VERSION}/firma-${VERSION}-${target}.tar.gz"
  local tmp
  tmp=$(mktemp)
  curl -fsSL "$url" -o "$tmp"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$tmp" | awk '{print $1}'
  else
    shasum -a 256 "$tmp" | awk '{print $1}'
  fi
  rm -f "$tmp"
}

echo "==> resolving checksums for v${VERSION}" >&2
SHA_AARCH64_DARWIN=$(sha_for aarch64-apple-darwin)
SHA_X86_64_DARWIN=$(sha_for x86_64-apple-darwin)
SHA_AARCH64_LINUX=$(sha_for aarch64-unknown-linux-musl)
SHA_X86_64_LINUX=$(sha_for x86_64-unknown-linux-musl)

mkdir -p "$(dirname "$FORMULA")"
cat >"$FORMULA" <<EOF
class Firma < Formula
  desc "Governed runtime for AI agents"
  homepage "https://github.com/${REPO}"
  license "GPL-3.0-only"

  on_macos do
    on_arm do
      url "https://github.com/${REPO}/releases/download/v${VERSION}/firma-${VERSION}-aarch64-apple-darwin.tar.gz"
      sha256 "${SHA_AARCH64_DARWIN}"
    end
    on_intel do
      url "https://github.com/${REPO}/releases/download/v${VERSION}/firma-${VERSION}-x86_64-apple-darwin.tar.gz"
      sha256 "${SHA_X86_64_DARWIN}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/${REPO}/releases/download/v${VERSION}/firma-${VERSION}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "${SHA_AARCH64_LINUX}"
    end
    on_intel do
      url "https://github.com/${REPO}/releases/download/v${VERSION}/firma-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "${SHA_X86_64_LINUX}"
    end
  end

  def install
    bin.install "firma"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/firma --version")
    assert_match "config", shell_output("#{bin}/firma --help")
  end
end
EOF

echo "==> wrote ${FORMULA}" >&2
