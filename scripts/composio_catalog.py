#!/usr/bin/env python3
"""Refresh and validate pinned Composio tool catalogs."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API_BASE = "https://backend.composio.dev/api/v3.1/tools"
ACTION_CLASS_SOURCE = (
    pathlib.Path(__file__).resolve().parent.parent
    / "crates"
    / "firma-core"
    / "src"
    / "action_class.rs"
)


class CatalogError(RuntimeError):
    """A sanitized catalog maintenance failure."""


def known_action_classes() -> set[str]:
    """Read the canonical class names straight from the Rust registry.

    Keeping one source of truth stops the maintenance script from drifting
    away from `ActionClass`, which is what actually validates a catalog at
    Sidecar startup.
    """
    try:
        source = ACTION_CLASS_SOURCE.read_text(encoding="utf-8")
    except OSError as error:
        raise CatalogError("cannot read the canonical action class registry") from error
    classes = set(re.findall(r'=>\s*"([a-z0-9_.]+)"', source))
    if not classes:
        raise CatalogError("canonical action class registry looks empty")
    return classes


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError(f"cannot read catalog file {path}") from error
    if not isinstance(value, dict):
        raise CatalogError(f"catalog file {path} must contain a JSON object")
    return value


def _write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _fetch_page(
    api_key: str, toolkit: str, version: str, cursor: str | None
) -> dict[str, Any]:
    query: list[tuple[str, str]] = [
        ("toolkit_slug", toolkit),
        (f"toolkit_versions[{toolkit}]", version),
        ("include_deprecated", "true"),
        ("limit", "1000"),
    ]
    if cursor:
        query.append(("cursor", cursor))
    request = urllib.request.Request(
        f"{API_BASE}?{urllib.parse.urlencode(query)}",
        headers={"Accept": "application/json", "x-api-key": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise CatalogError("Composio catalog request failed") from error
    if not isinstance(value, dict):
        raise CatalogError("Composio catalog response was not an object")
    return value


def fetch_catalog(api_key: str, toolkit: str, version: str) -> dict[str, Any]:
    """Fetch every page and retain only reviewable, non-secret metadata."""
    tools: dict[str, dict[str, str]] = {}
    cursor: str | None = None
    while True:
        page = _fetch_page(api_key, toolkit, version, cursor)
        items = page.get("items")
        if not isinstance(items, list):
            raise CatalogError("Composio catalog response omitted its item list")
        for item in items:
            if not isinstance(item, dict):
                raise CatalogError("Composio catalog contained a malformed tool")
            slug = item.get("slug")
            name = item.get("name")
            description = item.get("description")
            item_toolkit = item.get("toolkit")
            if isinstance(item_toolkit, dict):
                item_toolkit = item_toolkit.get("slug")
            if (
                not isinstance(slug, str)
                or not isinstance(name, str)
                or not isinstance(description, str)
                or item_toolkit != toolkit
            ):
                raise CatalogError("Composio catalog contained invalid tool metadata")
            if slug in tools:
                raise CatalogError("Composio catalog contained duplicate tool slugs")
            tools[slug] = {
                "description": description,
                "name": name,
                "slug": slug,
                "toolkit": toolkit,
                "version": version,
            }
        next_cursor = page.get("next_cursor")
        if next_cursor is None:
            break
        if not isinstance(next_cursor, str) or not next_cursor:
            raise CatalogError("Composio catalog returned an invalid cursor")
        cursor = next_cursor
    return {
        "toolkit": toolkit,
        "tools": [tools[slug] for slug in sorted(tools)],
        "version": version,
    }


def refresh_mapping(
    mapping_path: pathlib.Path, toolkit: str, version: str, slugs: set[str]
) -> dict[str, Any]:
    """Preserve reviewed mappings and make every new slug explicitly unmapped."""
    existing: dict[str, Any] = {}
    if mapping_path.exists():
        existing_value = _read_json(mapping_path)
        mappings = existing_value.get("mappings")
        if isinstance(mappings, dict):
            existing = mappings
    return {
        "mappings": {slug: existing.get(slug) for slug in sorted(slugs)},
        "toolkit": toolkit,
        "version": version,
    }


def validate_pair(snapshot_path: pathlib.Path, mapping_path: pathlib.Path) -> None:
    """Validate one source snapshot and its complete manual classification."""
    snapshot = _read_json(snapshot_path)
    mapping = _read_json(mapping_path)
    toolkit = snapshot.get("toolkit")
    version = snapshot.get("version")
    if not isinstance(toolkit, str) or not isinstance(version, str):
        raise CatalogError("catalog toolkit and version must be strings")
    if mapping.get("toolkit") != toolkit or mapping.get("version") != version:
        raise CatalogError("catalog source and mapping versions differ")
    tools = snapshot.get("tools")
    mappings = mapping.get("mappings")
    if not isinstance(tools, list) or not isinstance(mappings, dict):
        raise CatalogError("catalog source or mappings have an invalid shape")
    prefix = f"{toolkit.upper()}_"
    slugs: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise CatalogError("catalog contains a malformed tool")
        slug = tool.get("slug")
        if (
            not isinstance(slug, str)
            or not slug.startswith(prefix)
            or tool.get("toolkit") != toolkit
            or tool.get("version") != version
        ):
            raise CatalogError("catalog contains a mismatched toolkit tool")
        if slug in slugs:
            raise CatalogError("catalog contains duplicate tool slugs")
        slugs.add(slug)
    if set(mappings) != slugs:
        raise CatalogError("catalog source and mapping slug sets differ")
    known = known_action_classes()
    for slug, action_class in mappings.items():
        if action_class is None:
            raise CatalogError(f"{slug} is not manually classified")
        if action_class not in known:
            raise CatalogError(f"{slug} uses an unknown action class")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh = subparsers.add_parser("refresh")
    refresh.add_argument("--toolkit", required=True)
    refresh.add_argument("--version", required=True)
    refresh.add_argument("--snapshot", type=pathlib.Path, required=True)
    refresh.add_argument("--mapping", type=pathlib.Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--snapshot", type=pathlib.Path, required=True)
    validate.add_argument("--mapping", type=pathlib.Path, required=True)
    return parser


def main() -> int:
    """Run catalog refresh or validation without exposing credentials."""
    args = _parser().parse_args()
    try:
        if args.command == "refresh":
            api_key = os.environ.get("COMPOSIO_API_KEY", "").strip()
            if not api_key:
                raise CatalogError("COMPOSIO_API_KEY is required")
            snapshot = fetch_catalog(api_key, args.toolkit, args.version)
            slugs = {tool["slug"] for tool in snapshot["tools"]}
            mapping = refresh_mapping(
                args.mapping, args.toolkit, args.version, slugs
            )
            _write_json(args.snapshot, snapshot)
            _write_json(args.mapping, mapping)
            return 0
        validate_pair(args.snapshot, args.mapping)
        return 0
    except CatalogError as error:
        print(f"catalog error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
