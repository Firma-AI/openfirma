#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def load_toml(path: Path) -> dict:
    with path.open("rb") as file:
        return tomllib.load(file)


def current_version() -> str:
    return load_toml(ROOT / "Cargo.toml")["workspace"]["package"]["version"]


def cargo_metadata(*, manifest: Path | None = None, locked: bool) -> dict:
    arguments = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
    if manifest is not None:
        arguments.extend(("--manifest-path", str(manifest)))
    if locked:
        arguments.append("--locked")
    return json.loads(run(*arguments).stdout)


def bump(level: str) -> str:
    run(
        "cargo",
        "release",
        "version",
        level,
        "--workspace",
        "--execute",
        "--no-confirm",
    )
    version = current_version()
    metadata = cargo_metadata(locked=False)
    workspace_ids = set(metadata["workspace_members"])
    workspace_names = {
        package["name"]
        for package in metadata["packages"]
        if package["id"] in workspace_ids
    }
    stale_fuzz_packages = stale_lockfile_packages(
        ROOT / "fuzz/Cargo.lock", workspace_names, version
    )
    if stale_fuzz_packages:
        run(
            "cargo",
            "update",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "-p",
            stale_fuzz_packages[0],
        )
    return version


def path_dependency_versions(value: object) -> list[str]:
    versions = []
    if isinstance(value, dict):
        if "path" in value and "version" in value:
            versions.append(str(value["version"]))
        for nested in value.values():
            versions.extend(path_dependency_versions(nested))
    elif isinstance(value, list):
        for nested in value:
            versions.extend(path_dependency_versions(nested))
    return versions


def stale_lockfile_packages(
    path: Path, workspace_names: set[str], expected: str
) -> list[str]:
    packages = load_toml(path).get("package", [])
    found = {
        package["name"]
        for package in packages
        if package["name"] in workspace_names and package["version"] == expected
    }
    present = {
        package["name"] for package in packages if package["name"] in workspace_names
    }
    return sorted(present - found)


def verify_lockfile(path: Path, workspace_names: set[str], expected: str) -> None:
    mismatched = stale_lockfile_packages(path, workspace_names, expected)
    if mismatched:
        raise ValueError(
            f"{path} has stale workspace versions for: " + ", ".join(mismatched)
        )


def verify(expected: str) -> None:
    if SEMVER.fullmatch(expected) is None:
        raise ValueError(f"'{expected}' is not a valid SemVer version")
    actual = current_version()
    if actual != expected:
        raise ValueError(f"workspace version is {actual}, expected {expected}")

    metadata = cargo_metadata(locked=True)
    workspace_ids = set(metadata["workspace_members"])
    workspace_packages = [
        package for package in metadata["packages"] if package["id"] in workspace_ids
    ]
    mismatched_packages = sorted(
        package["name"]
        for package in workspace_packages
        if package["version"] != expected
    )
    if mismatched_packages:
        raise ValueError(
            "workspace packages have stale versions: " + ", ".join(mismatched_packages)
        )

    dependency_versions = path_dependency_versions(load_toml(ROOT / "Cargo.toml"))
    dependency_versions.extend(
        path_dependency_versions(
            load_toml(ROOT / "crates/firma-config-loader/Cargo.toml")
        )
    )
    if any(version != expected for version in dependency_versions):
        raise ValueError("one or more versioned path dependencies are stale")

    cargo_metadata(manifest=ROOT / "fuzz" / "Cargo.toml", locked=True)
    workspace_names = {package["name"] for package in workspace_packages}
    verify_lockfile(ROOT / "Cargo.lock", workspace_names, expected)
    verify_lockfile(ROOT / "fuzz/Cargo.lock", workspace_names, expected)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("current")
    bump_parser = commands.add_parser("bump")
    bump_parser.add_argument("level", choices=("patch", "minor", "major"))
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("version")
    return root


def main() -> None:
    args = parser().parse_args()
    if args.command == "current":
        print(current_version())
    elif args.command == "bump":
        print(bump(args.level))
    else:
        verify(args.version)
        print(f"workspace and lockfiles consistently report {args.version}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
