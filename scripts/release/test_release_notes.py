import unittest

from release_notes import release_notes

CHANGELOG = """# Changelog

User-facing changes are listed first.

## [1.3.0-rc1](https://github.com/o/r/compare/v1.2.0...v1.3.0-rc1) - 2026-10-29

### Fixed

- **installer:** Pin the release

## [1.2.0](https://github.com/o/r/compare/v1.1.0...v1.2.0) - 2026-09-10

- Older entry
"""


class ReleaseNotesTest(unittest.TestCase):
    def test_uses_only_the_requested_section_and_pins_the_tag(self) -> None:
        title, notes = release_notes(CHANGELOG, "1.3.0-rc1", "o/r")

        self.assertEqual(title, "1.3.0-rc1 - 2026-10-29")
        self.assertIn("- **installer:** Pin the release", notes)
        self.assertNotIn("Older entry", notes)
        self.assertIn(
            "curl -fsSL https://raw.githubusercontent.com/o/r/v1.3.0-rc1/install.sh"
            " | sh -s -- --version v1.3.0-rc1",
            notes,
        )
        self.assertIn(
            "$env:FIRMA_VERSION = 'v1.3.0-rc1'; "
            "irm https://raw.githubusercontent.com/o/r/v1.3.0-rc1/install.ps1 | iex",
            notes,
        )

    def test_selects_an_older_section_up_to_the_end_of_the_file(self) -> None:
        title, notes = release_notes(CHANGELOG, "1.2.0", "o/r")

        self.assertEqual(title, "1.2.0 - 2026-09-10")
        self.assertIn("- Older entry", notes)
        self.assertNotIn("Pin the release", notes)

    def test_rejects_a_version_missing_from_the_changelog(self) -> None:
        with self.assertRaisesRegex(ValueError, "no release heading for '1.3.0'"):
            release_notes(CHANGELOG, "1.3.0", "o/r")


if __name__ == "__main__":
    unittest.main()
