from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zapret_keenetic.tester import (
    StrategyResult,
    Target,
    TargetResult,
    build_winws_command,
    load_targets,
    prepare_user_lists,
    run_strategy_tests,
    sort_results,
)


class FakeProcess:
    def __init__(self, *args, **kwargs):
        self.terminated = False
        self.killed = False
        self.stderr = None

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class TesterTest(unittest.TestCase):
    def make_source(self, root: Path) -> Path:
        source = root / "flowseal"
        (source / "bin").mkdir(parents=True)
        (source / "lists").mkdir()
        (source / "bin" / "winws.exe").write_bytes(b"exe")
        (source / "bin" / "tls.bin").write_bytes(b"tls")
        (source / "lists" / "list.txt").write_text("youtube.com\n", encoding="utf-8")
        (source / "general.bat").write_text(
            'start "zapret" "%~dp0bin\\winws.exe" --wf-tcp=80,443,%GameFilterTCP% ^\n'
            '--filter-tcp=443 --hostlist="%LISTS%list.txt" --hostlist="%LISTS%list-exclude-user.txt" '
            '--dpi-desync=fake --dpi-desync-fake-tls="%BIN%tls.bin" --new ^\n'
            '--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic="%BIN%tls.bin"\n',
            encoding="utf-8",
        )
        return source

    def test_build_command_resolves_paths_and_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = self.make_source(Path(temporary))
            command, cwd = build_winws_command(source, source / "general.bat")
            self.assertTrue(command[0].endswith("winws.exe"))
            self.assertEqual(cwd, source / "bin")
            self.assertIn("--wf-tcp=80,443,12", command)
            hostlist = next(item for item in command if item.startswith("--hostlist="))
            self.assertTrue(hostlist.endswith("list.txt"))
            self.assertIn("--new", command)
            self.assertEqual(command.count("--new"), 1)
            self.assertTrue(any(item.startswith("--dpi-desync-fake-tls=") for item in command))

    def test_load_targets_ignores_ping_only_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = self.make_source(Path(temporary))
            utils = source / "utils"
            utils.mkdir()
            (utils / "targets.txt").write_text(
                '# comment\n'
                'YouTube = "https://www.youtube.com"\n'
                'Discord = "https://discord.com"\n'
                'Duplicate = "https://discord.com"\n'
                'DNS = "PING:1.1.1.1"\n',
                encoding="utf-8",
            )
            targets = load_targets(source)
            self.assertEqual([item.name for item in targets], ["YouTube", "Discord"])

    def test_load_targets_falls_back_to_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = self.make_source(Path(temporary))
            targets = load_targets(source)
            self.assertGreaterEqual(len(targets), 8)
            self.assertTrue(all(item.url.startswith("https://") for item in targets))

    def test_prepare_user_lists_redirects_missing_files_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.make_source(root)
            existing = source / "lists" / "list-general-user.txt"
            existing.write_text("keep.example\n", encoding="utf-8")
            overrides = prepare_user_lists(source, root / "temp-lists")
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep.example\n")
            self.assertNotIn(existing, overrides)
            self.assertIn(source / "lists" / "list-exclude-user.txt", overrides)
            self.assertTrue(overrides[source / "lists" / "list-exclude-user.txt"].is_file())
            command, _ = build_winws_command(source, source / "general.bat", overrides=overrides)
            self.assertTrue(
                any(str(overrides[source / "lists" / "list-exclude-user.txt"]) in item for item in command)
            )

    def test_strategy_scoring_and_sorting(self) -> None:
        full = StrategyResult(
            "full.bat",
            [TargetResult("A", "https://a", True, 200, 0.2), TargetResult("B", "https://b", True, 200, 0.4)],
        )
        partial = StrategyResult(
            "partial.bat",
            [TargetResult("A", "https://a", True, 200, 0.1), TargetResult("B", "https://b", False, error="timeout")],
        )
        broken = StrategyResult("broken.bat", error="winws failed")
        self.assertEqual(full.ok_count, 2)
        self.assertEqual(full.verdict, "работает")
        self.assertEqual(partial.verdict, "частично")
        self.assertEqual(broken.verdict, "ошибка")
        self.assertEqual(sort_results([partial, broken, full])[0].profile, "full.bat")

    def test_default_targets_are_https(self) -> None:
        targets = [Target("YouTube", "https://www.youtube.com")]
        self.assertTrue(targets[0].url.startswith("https://"))

    def test_run_strategy_tests_orchestrates_process_and_cleans_up(self) -> None:
        process = FakeProcess()
        with tempfile.TemporaryDirectory() as temporary:
            source = self.make_source(Path(temporary))
            with (
                mock.patch("zapret_keenetic.tester.is_admin", return_value=True),
                mock.patch("zapret_keenetic.tester.running_winws", return_value=False),
                mock.patch("zapret_keenetic.tester._curl_path", return_value="curl"),
                mock.patch("zapret_keenetic.tester.subprocess.Popen", return_value=process),
                mock.patch("zapret_keenetic.tester.time.sleep", return_value=None),
                mock.patch(
                    "zapret_keenetic.tester.check_targets",
                    return_value=[TargetResult("Test", "https://test", True, 200, 0.1)],
                ),
            ):
                results = run_strategy_tests(
                    source,
                    profiles=["general.bat"],
                    targets=[Target("Test", "https://test")],
                    startup_delay=0,
                )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].ok_count, 1)
            self.assertTrue(process.terminated or process.killed)


if __name__ == "__main__":
    unittest.main()
