from __future__ import annotations

import re
import unittest
from pathlib import Path

from zapret_keenetic.version import TARGET_NFQWS2_VERSION, TARGET_ZAPRET2_VERSION, __version__


class MetadataTest(unittest.TestCase):
    def test_pyproject_and_package_versions_match(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)

    def test_target_versions_are_pinned(self) -> None:
        for value in (TARGET_NFQWS2_VERSION, TARGET_ZAPRET2_VERSION, __version__):
            self.assertRegex(value, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
