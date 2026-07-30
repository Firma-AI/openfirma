#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import unittest

from validate_pr import validate_title


class ValidateTitleTests(unittest.TestCase):
    def test_accepts_supported_titles(self) -> None:
        validate_title("feat(sidecar): enforce policy")
        validate_title("fix!: reject invalid tokens")
        validate_title("ai: update agent guidance")

    def test_rejects_malformed_and_unsupported_titles(self) -> None:
        with self.assertRaisesRegex(ValueError, "must match"):
            validate_title("Fix policy")
        with self.assertRaisesRegex(ValueError, "must match"):
            validate_title("style: format policy")

    def test_rejects_breaking_marker_for_excluded_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "breaking marker"):
            validate_title("refactor!: replace API")


if __name__ == "__main__":
    unittest.main()
