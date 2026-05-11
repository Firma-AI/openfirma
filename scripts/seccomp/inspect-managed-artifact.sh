#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/seccomp/inspect-managed-artifact.sh \
    --artifact /abs/path/policy.bpf \
    --metadata /abs/path/policy.metadata.json

Validates the artifact checksum against metadata and prints a compact summary.
EOF
}

fail() { printf '[fail] %s\n' "$1" >&2; exit 1; }

ARTIFACT=""
METADATA=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT="${2:-}"
      shift 2
      ;;
    --metadata)
      METADATA="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$ARTIFACT" ]] || fail "--artifact is required"
[[ -n "$METADATA" ]] || fail "--metadata is required"
[[ -f "$ARTIFACT" ]] || fail "artifact not found: $ARTIFACT"
[[ -f "$METADATA" ]] || fail "metadata not found: $METADATA"

python3 - "$ARTIFACT" "$METADATA" <<'PY'
import hashlib
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
metadata_path = pathlib.Path(sys.argv[2])

artifact_bytes = artifact_path.read_bytes()
artifact_sha = hashlib.sha256(artifact_bytes).hexdigest()
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

expected = metadata.get("sha256")
if not isinstance(expected, str) or not expected:
    raise SystemExit(f"[fail] invalid metadata sha256 in {metadata_path}")
if artifact_sha != expected:
    raise SystemExit(
        f"[fail] checksum mismatch: expected={expected} actual={artifact_sha}"
    )

policy_id = metadata.get("policy_id", "")
policy_version = metadata.get("policy_version", "")
target_arch = metadata.get("target_arch", "")
default_action = metadata.get("default_action", "")
compiler_version = metadata.get("compiler_version", "")
denied = metadata.get("denied_syscalls", [])
if not isinstance(denied, list):
    raise SystemExit(f"[fail] metadata denied_syscalls must be an array: {metadata_path}")

print(f"artifact={artifact_path}")
print(f"metadata={metadata_path}")
print(f"policy_id={policy_id}")
print(f"policy_version={policy_version}")
print(f"target_arch={target_arch}")
print(f"default_action={default_action}")
print(f"compiler_version={compiler_version}")
print(f"artifact_sha256={artifact_sha}")
print(f"denied_syscalls_count={len(denied)}")
print(f"denied_syscalls={','.join(map(str, denied))}")
print("[ok] managed seccomp artifact integrity verified")
PY
