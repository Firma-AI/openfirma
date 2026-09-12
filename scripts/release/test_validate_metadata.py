import tempfile
import unittest
from pathlib import Path

from validate_metadata import validate

MESSAGE = """chore(release): sync OpenFirma v1.2.3

Firma-Team-Source: 0123456789abcdef0123456789abcdef01234567
OpenFirma-Tree-SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"""


class ValidateMetadataTest(unittest.TestCase):
    def fixture(self, version: str = "1.2.3", changelog: str = "1.2.3") -> Path:
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (directory / "Cargo.toml").write_text(
            f'[workspace]\n[workspace.package]\nversion = "{version}"\n'
        )
        (directory / "CHANGELOG.md").write_text(
            f"# Changelog\n\n## [{changelog}] - 2026-09-10\n"
        )
        return directory

    def test_accepts_matching_metadata_and_provenance(self) -> None:
        self.assertEqual(validate(self.fixture(), MESSAGE), "1.2.3")

    def test_rejects_mismatched_changelog(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate(self.fixture(changelog="1.2.2"), MESSAGE)

    def test_rejects_non_release_snapshot_subject(self) -> None:
        with self.assertRaisesRegex(ValueError, "commit subject"):
            validate(
                self.fixture(),
                MESSAGE.replace(
                    "chore(release): sync OpenFirma v1.2.3",
                    "chore: preview OpenFirma snapshot",
                ),
            )

    def test_rejects_missing_or_malformed_provenance(self) -> None:
        for message in (
            "chore(release): sync OpenFirma v1.2.3",
            MESSAGE.replace("01234567\n", "xyz\n", 1),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, "trailer"),
            ):
                validate(self.fixture(), message)

    def test_rejects_duplicate_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            validate(self.fixture(), MESSAGE + "Firma-Team-Source: " + "a" * 40 + "\n")


if __name__ == "__main__":
    unittest.main()
