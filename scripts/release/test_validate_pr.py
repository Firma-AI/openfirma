#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import re
import unittest
from pathlib import Path

import tomllib
from validate_pr import ALLOWED_TYPES, validate_title

ROOT = Path(__file__).resolve().parents[2]


class ValidateTitleTests(unittest.TestCase):
    def test_accepts_supported_titles(self) -> None:
        validate_title("feat(sidecar): enforce policy")
        validate_title("fix!: reject invalid tokens")
        validate_title("ai: update agent guidance")
        validate_title("style: format policy")

    def test_rejects_malformed_and_unsupported_titles(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match"):
            validate_title("Fix policy")
        with self.assertRaisesRegex(ValueError, "must match"):
            validate_title("deps: update dependencies")

    def test_rejects_breaking_marker_for_internal_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "breaking marker"):
            validate_title("refactor!: replace API")

    def test_changelog_parsers_match_allowed_types(self) -> None:
        config = tomllib.loads((ROOT / ".release-plz.toml").read_text())
        parsers = config["changelog"]["commit_parsers"]
        typed_parsers = [parser for parser in parsers if not parser.get("skip", False)]
        parsed_types = {
            match.group(1)
            for parser in typed_parsers
            if (match := re.match(r"^\^([a-z]+)", parser["message"])) is not None
        }

        self.assertEqual(parsed_types, set(ALLOWED_TYPES))
        for type_ in ALLOWED_TYPES:
            matching = [
                parser
                for parser in typed_parsers
                if re.match(parser["message"], f"{type_}: description")
            ]
            self.assertEqual(len(matching), 1, type_)
            self.assertIsNone(
                re.match(matching[0]["message"], f"{type_}x: description"), type_
            )

    def test_documented_types_match_allowed_types(self) -> None:
        contributing = (ROOT / "CONTRIBUTING.md").read_text()
        documented = re.search(r"Accepted types are (.*?)\.", contributing, re.DOTALL)
        self.assertIsNotNone(documented)
        contributing_types = set(re.findall(r"`([a-z]+)`", documented.group(1)))

        template = (ROOT / ".github/pull_request_template.md").read_text()
        template_list = re.search(
            r"- Types: (.*?)\n- 1-3 sentences", template, re.DOTALL
        )
        self.assertIsNotNone(template_list)
        template_types = set(re.findall(r"[a-z]+", template_list.group(1)))

        expected = set(ALLOWED_TYPES)
        self.assertEqual(contributing_types, expected)
        self.assertEqual(template_types, expected)


if __name__ == "__main__":
    unittest.main()
