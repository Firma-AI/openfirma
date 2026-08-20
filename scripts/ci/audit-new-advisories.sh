#!/usr/bin/env bash
set -euo pipefail

base_revision="${1:?usage: audit-new-advisories.sh BASE_REVISION}"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

git show "$base_revision:Cargo.lock" > "$temp_dir/base-Cargo.lock"

# Fetch the advisory database once so both revisions are evaluated against the
# same snapshot and current audit policy. cargo-audit exits non-zero when it
# finds an advisory, so the JSON reports, rather than those exit codes,
# determine the result below.
cargo audit --deny warnings --json > "$temp_dir/current.json" || true
cargo audit --file "$temp_dir/base-Cargo.lock" --no-fetch --deny warnings --json > "$temp_dir/base.json" || true

validate_report() {
  jq -e '
    (.vulnerabilities.list | type == "array")
      and (.warnings | type == "object")
  ' "$1" > /dev/null
}

extract_findings() {
  jq -r '
    ([.vulnerabilities.list[]? | "advisory:" + .advisory.id]
      + [.warnings[]?[]?
          | if .advisory.id then
              "advisory:" + .advisory.id
            else
              "yanked:" + .package.name + "@" + .package.version
            end])
    | unique[]
  ' "$1"
}

validate_report "$temp_dir/current.json"
validate_report "$temp_dir/base.json"
extract_findings "$temp_dir/current.json" > "$temp_dir/current-findings"
extract_findings "$temp_dir/base.json" > "$temp_dir/base-findings"
comm -23 "$temp_dir/current-findings" "$temp_dir/base-findings" > "$temp_dir/new-findings"

if [[ -s "$temp_dir/new-findings" ]]; then
  echo "::error::This change introduces new cargo-audit findings:"
  sed 's/^/  - /' "$temp_dir/new-findings"
  echo
  echo "Full audit report for the proposed change:"
  cargo audit --no-fetch --deny warnings || true
  exit 1
fi

echo "No cargo-audit findings were introduced by this change."
