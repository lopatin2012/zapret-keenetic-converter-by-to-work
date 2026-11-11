from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zapret_keenetic.discovery import find_flowseal_source, has_profiles
from zapret_keenetic.settings_store import load_settings, save_settings


class SettingsStoreTest(unittest.TestCase):
    def test_round_trip_and_atomic_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "settings.json"
            self.assertEqual(load_settings(target), {})
            save_settings({"source": "C:/flowseal", "install_after_convert": False}, target)
            self.assertEqual(
                load_settings(target),
                {"source": "C:/flowseal", "install_after_convert": False},
            )
            save_settings({"source": "C:/other"}, target)
            self.assertEqual(load_settings(target), {"source": "C:/other"})
            self.assertFalse((Path(temporary) / "settings.json.tmp").exists())


class DiscoveryTest(unittest.TestCase):
    def make_profile(self, directory: Path) -> None:
        directory.mkdir(parents=True)
        (directory / "general.bat").write_text(
            'start "z" "%~dp0bin\\winws.exe" --filter-tcp=443 --dpi-desync=fake\n',
            encoding="utf-8",
        )

    def test_finds_direct_and_nested_flowseal_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            direct = root / "flowseal"
            self.make_profile(direct)
            self.assertTrue(has_profiles(direct))
            self.assertIsNone(find_flowseal_source(roots=[root / "empty"]))
            self.assertEqual(find_flowseal_source(roots=[direct]), direct)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "zapret-discord-youtube-1.10.4"
            self.make_profile(nested)
            self.assertEqual(find_flowseal_source(roots=[root]), nested)

    def test_rejects_directory_without_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "readme.txt").write_text("no profiles\n", encoding="utf-8")
            self.assertFalse(has_profiles(root))
            self.assertIsNone(find_flowseal_source(roots=[root]))


if __name__ == "__main__":
    unittest.main()
