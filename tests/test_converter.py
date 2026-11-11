from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from zapret_keenetic.converter import ConversionError, ConverterSettings, convert, parse_batch
from zapret_keenetic.gui import discover_profiles, suggest_output
from zapret_keenetic.hybrid import build_hybrid_keenetic_config


PROFILE = r'''@echo off
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
start "zapret" "%BIN%winws.exe" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic.bin" --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude="%LISTS%list-general-user.txt" --dpi-desync=fake,multisplit --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl=5 --dpi-desync-split-seqovl-pattern="%BIN%tls.bin" --dpi-desync-fake-tls="%BIN%tls.bin" --new ^
--filter-tcp=%GameFilterTCP% --ipset="%LISTS%ipset-all.txt" --dpi-desync=multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n4 --dpi-desync-split-pos=2
'''


class ConverterTest(unittest.TestCase):
    def make_source(self, root: Path) -> Path:
        source = root / "flowseal"
        (source / "bin").mkdir(parents=True)
        (source / "lists").mkdir()
        (source / "general.bat").write_text(PROFILE, encoding="utf-8")
        (source / "bin" / "quic.bin").write_bytes(b"quic")
        (source / "bin" / "tls.bin").write_bytes(b"tls")
        (source / "lists" / "list-general.txt").write_text("youtube.com\n", encoding="utf-8")
        (source / "lists" / "ipset-all.txt").write_text("203.0.113.113/32\n", encoding="utf-8")
        (source / "lists" / "ipset-all.txt.backup").write_text("1.1.1.1/32\n", encoding="utf-8")
        return source

    def test_parser_splits_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = self.make_source(Path(temp))
            global_options, profiles = parse_batch(source / "general.bat")
            self.assertEqual([item.name for item in global_options], ["wf-tcp", "wf-udp"])
            self.assertEqual(len(profiles), 3)

    def test_gui_discovers_profiles_and_suggests_unique_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "helper.bat").write_text("@echo off\necho service helper\n", encoding="utf-8")
            (source / "service.bat").write_text(
                '@echo off\ntasklist | find "winws.exe"\ncurl --silent --output version.txt https://example.org\n',
                encoding="utf-8",
            )
            self.assertEqual(discover_profiles(source), ["general.bat"])

            moment = datetime(2026, 8, 13, 12, 30, 45)
            first = suggest_output(source, "general.bat", "keenetic", moment)
            self.assertEqual(first.name, "general-keenetic-20260813-123045")
            first.mkdir(parents=True)
            second = suggest_output(source, "general.bat", "keenetic", moment)
            self.assertEqual(second.name, "general-keenetic-20260813-123045-2")

    def test_conversion_creates_native_nfqws2_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            output = root / "result"
            result = convert(
                ConverterSettings(
                    source=source,
                    profile="general.bat",
                    output=output,
                    interface="ppp0",
                    game_filter="disabled",
                )
            )
            config = result.config.read_text(encoding="utf-8")
            self.assertEqual(result.profiles_read, 3)
            self.assertEqual(result.profiles_written, 2)
            self.assertIn("--lua-desync=fake:blob=quic", config)
            self.assertIn("--lua-desync=multisplit:pos=1,midsld:seqovl=5", config)
            self.assertIn("tcp_ts=-600000", config)
            self.assertNotIn("--dpi-desync", config)
            self.assertNotIn("TCP_PORTS=12", config)
            self.assertIn("ISP_INTERFACE='ppp0'", config)
            self.assertTrue((output / "blobs" / "quic.bin").is_file())
            self.assertTrue((output / "lists" / "list-general.txt").is_file())

            web_config_path = output / "web-import" / "nfqws2.conf"
            web_config = web_config_path.read_text(encoding="utf-8")
            self.assertIn("--blob=quic:0x71756963", web_config)
            self.assertIn("--blob=tls:0x746c73", web_config)
            self.assertNotIn("/blobs/", web_config)
            self.assertIn("/lists/list-general.list", web_config)
            self.assertNotIn("/lists/list-general.txt", web_config)
            self.assertIn("/lists/list-general-user.list", web_config)
            self.assertEqual(
                (output / "web-import" / "lists" / "list-general.list").read_text(encoding="utf-8"),
                "youtube.com\n",
            )
            self.assertEqual(
                (output / "web-import" / "lists" / "list-general-user.list").read_text(encoding="utf-8"),
                "",
            )
            self.assertTrue((output / "web-import" / "README.md").is_file())

    def test_game_and_ipset_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            output = root / "result"
            result = convert(
                ConverterSettings(
                    source=source,
                    profile="general.bat",
                    output=output,
                    game_filter="all",
                )
            )
            self.assertEqual(result.profiles_written, 3)
            self.assertIn("1024-65535", result.tcp_ports)
            self.assertEqual((output / "lists" / "ipset-all.txt").read_text().strip(), "1.1.1.1/32")
            self.assertEqual(
                (output / "web-import" / "lists" / "ipset-all.list").read_text().strip(),
                "1.1.1.1/32",
            )

    def test_current_ipset_mode_preserves_disabled_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            output = root / "result"
            convert(
                ConverterSettings(
                    source=source,
                    profile="general.bat",
                    output=output,
                    game_filter="all",
                    ipset_mode="current",
                )
            )
            self.assertEqual(
                (output / "lists" / "ipset-all.txt").read_text().strip(),
                "203.0.113.113/32",
            )

    def test_archive_keeps_dotted_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            output = root / "general-1.10.1-keenetic"
            result = convert(
                ConverterSettings(source=source, profile="general.bat", output=output, archive=True)
            )
            self.assertEqual(result.archive.name, "general-1.10.1-keenetic.zip")
            self.assertTrue(result.archive.is_file())

    def test_hybrid_keeps_discord_and_stock_adaptive_profiles(self) -> None:
        stock = r'''NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua\n                 --blob=quic_initial:@/opt/etc/nfqws2/blobs/quic_initial.bin"
NFQWS_ARGS="--filter-tcp=443\n                 --lua-desync=circular"
NFQWS_ARGS_QUIC="--filter-udp=443"
NFQWS_ARGS_UDP="--filter-udp=3478-3481"
NFQWS_EXTRA_ARGS="\$MODE_AUTO"
NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list\n                 --ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list"
NFQWS_ARGS_CUSTOM=""
'''
        converted = '''NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua\n                 --blob=discord:0xc500"
NFQWS_ARGS="--filter-tcp=443\n                 --ipset=/opt/etc/nfqws2/lists/ipset-all.list"
NFQWS_ARGS_CUSTOM="--filter-udp=443\n                 --hostlist=/opt/etc/nfqws2/lists/list-general.list\n                 --new\n                 --filter-tcp=443\n                 --hostlist=/opt/etc/nfqws2/lists/list-google.list\n                 --new\n                 --filter-l7=discord,stun"
'''
        hybrid = build_hybrid_keenetic_config(stock, converted)
        self.assertIn("--blob=discord:0xc500", hybrid)
        self.assertIn("--hostlist=/opt/etc/nfqws2/lists/list-general.list", hybrid)
        self.assertIn("--filter-l7=discord,stun", hybrid)
        self.assertNotIn("list-google.list", hybrid)
        self.assertIn("--lua-desync=circular", hybrid)
        self.assertIn("--ipset=/opt/etc/nfqws2/lists/ipset-all.list", hybrid)

    def test_hybrid_applies_user_network_settings_and_unions_ports(self) -> None:
        from zapret_keenetic.hybrid import _assignment

        stock = r'''ISP_INTERFACE="eth3"
IPV6_ENABLED=1
POLICY_NAME="nfqws"
POLICY_EXCLUDE=0
NFQUEUE_NUM=300
TCP_PORTS=80,443
UDP_PORTS=443,3478:3481
NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua"
NFQWS_ARGS="--filter-tcp=443"
NFQWS_ARGS_IPSET="--ipset=/opt/etc/nfqws2/lists/ipset.list"
NFQWS_ARGS_CUSTOM=""
'''
        converted = r'''ISP_INTERFACE='ppp0'
IPV6_ENABLED=0
POLICY_NAME='custom-policy'
POLICY_EXCLUDE=1
NFQUEUE_NUM=400
TCP_PORTS=443,8443
UDP_PORTS=443,50000:50100
NFQWS_BASE_ARGS="--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua"
NFQWS_ARGS="--filter-tcp=443"
NFQWS_ARGS_CUSTOM="--filter-l7=discord,stun"
'''
        hybrid = build_hybrid_keenetic_config(stock, converted)
        self.assertEqual(_assignment(hybrid, "ISP_INTERFACE").value, "ppp0")
        self.assertEqual(_assignment(hybrid, "IPV6_ENABLED").value, "0")
        self.assertEqual(_assignment(hybrid, "POLICY_NAME").value, "custom-policy")
        self.assertEqual(_assignment(hybrid, "POLICY_EXCLUDE").value, "1")
        self.assertEqual(_assignment(hybrid, "NFQUEUE_NUM").value, "400")
        self.assertEqual(_assignment(hybrid, "TCP_PORTS").value, "80,443,8443")
        self.assertEqual(_assignment(hybrid, "UDP_PORTS").value, "443,3478:3481,50000:50100")
        self.assertIn("custom-policy", hybrid)
        self.assertIn("50000:50100", hybrid)

    def test_syndata_and_relative_dp0_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            profile = source / "syndata.bat"
            profile.write_text(
                r'''start "zapret" "%~dp0bin\winws.exe" --wf-tcp=443 ^
--filter-tcp=443 --hostlist="%~dp0lists\list-general.txt" --dpi-desync=syndata,multidisorder''',
                encoding="utf-8",
            )
            result = convert(
                ConverterSettings(source=source, profile=profile.name, output=root / "result")
            )
            config = result.config.read_text(encoding="utf-8")
            self.assertIn("--payload=empty", config)
            self.assertIn("--lua-desync=syndata", config)
            self.assertIn("--lua-desync=multidisorder", config)
            self.assertEqual(result.warning_count, 0)

    def test_rejects_invalid_nfqueue_number(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            with self.assertRaisesRegex(ConversionError, "queue_num"):
                convert(
                    ConverterSettings(
                        source=source,
                        profile="general.bat",
                        output=root / "result",
                        queue_num=65536,
                    )
                )

    def test_failed_strict_conversion_does_not_leave_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "strict.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake '
                '--dpi-desync-fake-tls="%BIN%missing.bin"\n',
                encoding="utf-8",
            )
            output = root / "result"
            with self.assertRaisesRegex(ConversionError, "Строгий режим"):
                convert(
                    ConverterSettings(source=source, profile="strict.bat", output=output, strict=True)
                )
            self.assertFalse(output.exists())
            self.assertEqual([path for path in root.glob(".result.tmp-*")], [])

            # The same output path must be usable after a failed attempt.
            result = convert(ConverterSettings(source=source, profile="strict.bat", output=output))
            self.assertTrue(result.config.is_file())

    def test_existing_empty_output_directory_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            output = root / "result"
            output.mkdir()
            result = convert(ConverterSettings(source=source, profile="general.bat", output=output))
            self.assertTrue(result.config.is_file())
            self.assertEqual(result.output, output.resolve())

    def test_archive_uses_forward_slash_paths_and_includes_report_json(self) -> None:
        import zipfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            result = convert(
                ConverterSettings(source=source, profile="general.bat", output=root / "result", archive=True)
            )
            with zipfile.ZipFile(result.archive) as archive:
                names = archive.namelist()
            self.assertTrue(all("\\" not in name for name in names))
            self.assertIn("web-import/nfqws2.conf", names)
            self.assertIn("report.json", names)

    def test_report_json_lists_itself(self) -> None:
        import json

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            result = convert(ConverterSettings(source=source, profile="general.bat", output=root / "result"))
            report = json.loads((result.output / "report.json").read_text(encoding="utf-8"))
            self.assertIn("report.json", report["files"])

    def test_same_list_basename_gets_unique_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "a").mkdir()
            (source / "b").mkdir()
            (source / "a" / "list.txt").write_text("a.example\n", encoding="utf-8")
            (source / "b" / "list.txt").write_text("b.example\n", encoding="utf-8")
            (source / "collision.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x16 '
                '--hostlist="%~dp0a\\list.txt" --hostlist="%~dp0b\\list.txt"\n',
                encoding="utf-8",
            )
            result = convert(
                ConverterSettings(source=source, profile="collision.bat", output=root / "result")
            )
            copied = sorted((result.output / "lists").iterdir())
            self.assertEqual(len(copied), 2)
            self.assertEqual(sorted(path.read_text(encoding="utf-8").strip() for path in copied),
                             ["a.example", "b.example"])
            config = result.config.read_text(encoding="utf-8")
            self.assertEqual(config.count("--hostlist="), 2)

    def test_duplicate_list_option_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "duplicate.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x16 '
                '--hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general.txt"\n',
                encoding="utf-8",
            )
            result = convert(
                ConverterSettings(source=source, profile="duplicate.bat", output=root / "result")
            )
            config = result.config.read_text(encoding="utf-8")
            self.assertEqual(config.count("--hostlist="), 1)
            self.assertIn("duplicate-list-skipped", [item.code for item in result.diagnostics])

    def test_blob_offset_is_materialized_as_sliced_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "bin" / "offset.bin").write_bytes(b"ABCDEFGH")
            (source / "offset.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake '
                '--dpi-desync-fake-tls="+3@%BIN%offset.bin"\n',
                encoding="utf-8",
            )
            result = convert(ConverterSettings(source=source, profile="offset.bat", output=root / "result"))
            blob = result.output / "blobs" / "offset_ofs3.bin"
            self.assertEqual(blob.read_bytes(), b"DEFGH")
            config = result.config.read_text(encoding="utf-8")
            self.assertIn("--blob=offset_ofs3:@", config)
            web = (result.output / "web-import" / "nfqws2.conf").read_text(encoding="utf-8")
            self.assertIn("--blob=offset_ofs3:0x4445464748", web)

    def test_unresolved_variable_is_reported_and_strict_mode_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "variable.bat").write_text(
                'winws.exe --filter-udp=%UnknownPort% --dpi-desync=fake --dpi-desync-fake-tls=0x16\n',
                encoding="utf-8",
            )
            result = convert(
                ConverterSettings(source=source, profile="variable.bat", output=root / "nonstrict")
            )
            self.assertIn("unresolved-variable", [item.code for item in result.diagnostics])
            self.assertIn("%UnknownPort%", result.config.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(ConversionError, "Строгий режим"):
                convert(
                    ConverterSettings(
                        source=source, profile="variable.bat", output=root / "strict", strict=True
                    )
                )

    def test_supported_and_unsupported_fooling_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "fooling.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=0x16 '
                '--dpi-desync-fooling=hopbyhop,datanoack\n',
                encoding="utf-8",
            )
            result = convert(ConverterSettings(source=source, profile="fooling.bat", output=root / "result"))
            config = result.config.read_text(encoding="utf-8")
            self.assertIn("ip6_hopbyhop", config)
            warnings = [item for item in result.diagnostics if item.code == "unsupported-fooling"]
            self.assertEqual(len(warnings), 1)
            self.assertIn("datanoack", warnings[0].message)

    def test_hostfakesplit_altorder_gets_compatibility_initializer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_source(root)
            (source / "alt.bat").write_text(
                'winws.exe --filter-tcp=443 --dpi-desync=fake,hostfakesplit '
                '--dpi-desync-fake-tls=0x16 '
                '--dpi-desync-hostfakesplit-mod=host=mail.ru,altorder=1\n',
                encoding="utf-8",
            )
            result = convert(ConverterSettings(source=source, profile="alt.bat", output=root / "result"))
            config = result.config.read_text(encoding="utf-8")
            self.assertIn("--lua-desync=zk_hostfakesplit_alt1:host=mail.ru", config)
            self.assertIn("assert(load(", config)
            self.assertNotIn("--new", config.split("NFQWS_BASE_ARGS=", 1)[1].split("\n\n", 1)[0])
            self.assertEqual(result.warning_count, 0)

    def test_profile_in_nested_directory_resolves_variables_relative_to_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "flowseal"
            nested = source / "zapret-discord-youtube-1.10.4"
            (nested / "bin").mkdir(parents=True)
            (nested / "lists").mkdir()
            (nested / "bin" / "tls.bin").write_bytes(b"tls")
            (nested / "lists" / "list.txt").write_text("example.org\n", encoding="utf-8")
            (nested / "general.bat").write_text(
                'winws.exe --filter-tcp=443 --hostlist="%~dp0lists\\list.txt" '
                '--dpi-desync=fake --dpi-desync-fake-tls="%~dp0bin\\tls.bin"\n',
                encoding="utf-8",
            )
            result = convert(
                ConverterSettings(
                    source=source,
                    profile="zapret-discord-youtube-1.10.4/general.bat",
                    output=root / "result",
                )
            )
            self.assertEqual(result.warning_count, 0)
            self.assertTrue((result.output / "lists" / "list.txt").is_file())
            self.assertTrue((result.output / "blobs" / "tls.bin").is_file())
            config = result.config.read_text(encoding="utf-8")
            self.assertIn("/lists/list.txt", config)
            self.assertIn("/blobs/tls.bin", config)


if __name__ == "__main__":
    unittest.main()
