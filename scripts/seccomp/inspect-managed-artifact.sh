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
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

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

required_fields = {
    "policy_schema_version": int,
    "policy_id": str,
    "policy_version": str,
    "sha256": str,
    "generated_at": str,
    "compiler_version": str,
    "target_arch": str,
    "default_action": str,
    "source_policy_refs": list,
    "source_policy_sha256": str,
    "denied_syscalls": list,
}
for key, expected_type in required_fields.items():
    if key not in metadata:
        raise SystemExit(f"[fail] missing metadata field '{key}' in {metadata_path}")
    if not isinstance(metadata[key], expected_type):
        raise SystemExit(
            f"[fail] metadata field '{key}' has invalid type "
            f"{type(metadata[key]).__name__}; expected {expected_type.__name__}"
        )

policy_id = metadata["policy_id"]
policy_version = metadata["policy_version"]
target_arch = metadata["target_arch"]
default_action = metadata["default_action"]
compiler_version = metadata["compiler_version"]
denied = metadata["denied_syscalls"]

if metadata["policy_schema_version"] < 1:
    raise SystemExit("[fail] policy_schema_version must be >= 1")
if default_action != "allow":
    raise SystemExit(f"[fail] unsupported default_action in metadata: {default_action}")
if target_arch not in ("x86_64", "aarch64"):
    raise SystemExit(f"[fail] unsupported target_arch in metadata: {target_arch}")
if not all(isinstance(item, str) for item in denied):
    raise SystemExit("[fail] denied_syscalls must contain only strings")
if not all(isinstance(item, str) for item in metadata["source_policy_refs"]):
    raise SystemExit("[fail] source_policy_refs must contain only strings")
if len(metadata["source_policy_sha256"]) != 64:
    raise SystemExit("[fail] source_policy_sha256 must be a 64-char hex digest")
if len(expected) != 64:
    raise SystemExit("[fail] sha256 must be a 64-char hex digest")

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
