#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import tempfile
import unittest
from pathlib import Path

from version import path_dependency_versions, verify_lockfile


class VersionTests(unittest.TestCase):
    def test_finds_versioned_path_dependencies(self) -> None:
        manifest = {
            "dependencies": {
                "firma-core": {"path": "../firma-core", "version": "1.2.3"},
                "serde": {"version": "1"},
            },
            "target": {
                "cfg(unix)": {
                    "dependencies": {
                        "firma-fs": {
                            "path": "../firma-fs",
                            "version": "1.2.3",
                        }
                    }
                }
            },
        }
        self.assertEqual(path_dependency_versions(manifest), ["1.2.3", "1.2.3"])

    def test_rejects_stale_lockfile_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "Cargo.lock"
            lockfile.write_text(
                'version = 4\n\n[[package]]\nname = "firma-core"\nversion = "1.2.2"\n'
            )
            with self.assertRaisesRegex(ValueError, "firma-core"):
                verify_lockfile(lockfile, {"firma-core"}, "1.2.3")


if __name__ == "__main__":
    unittest.main()
