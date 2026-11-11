"""Check the generated configuration contract against current upstream files.

Run: python scripts/check_upstream.py
Exits nonzero when nfqws2-keenetic removed or renamed a variable the converter
writes, or when the upstream release cannot be read at all.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from zapret_keenetic.config_format import ConfigFormatError, assignment
from zapret_keenetic.version import TARGET_NFQWS2_VERSION, TARGET_ZAPRET2_VERSION


RAW = "https://raw.githubusercontent.com/nfqws/nfqws2-keenetic/master"
ZAPRET2_RELEASE = "https://api.github.com/repos/bol-van/zapret2/releases/latest"
REQUIRED_KEYS = (
    "ISP_INTERFACE",
    "NFQWS_BASE_ARGS",
    "NFQWS_ARGS",
    "NFQWS_ARGS_QUIC",
    "NFQWS_ARGS_UDP",
    "NFQWS_EXTRA_ARGS",
    "NFQWS_ARGS_IPSET",
    "NFQWS_ARGS_CUSTOM",
    "IPV6_ENABLED",
    "TCP_PORTS",
    "UDP_PORTS",
    "POLICY_NAME",
    "POLICY_EXCLUDE",
    "NFQUEUE_NUM",
    "CONFIG_VERSION",
)


def _fetch(url: str, timeout: float = 30.0) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "zapret-keenetic-converter"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="use a local nfqws2.conf instead of downloading")
    parser.add_argument("--skip-zapret2", action="store_true")
    args = parser.parse_args(argv)

    try:
        config = args.config.read_text(encoding="utf-8") if args.config else _fetch(f"{RAW}/etc/nfqws2/nfqws2.conf")
        upstream_version = _fetch(f"{RAW}/VERSION").strip()
    except OSError as error:
        print(f"Не удалось прочитать upstream nfqws2-keenetic: {error}", file=sys.stderr)
        return 2

    missing = []
    for key in REQUIRED_KEYS:
        try:
            assignment(config, key)
        except ConfigFormatError:
            missing.append(key)
    print(f"nfqws2-keenetic upstream: {upstream_version}; target: {TARGET_NFQWS2_VERSION}")
    if upstream_version != TARGET_NFQWS2_VERSION:
        print(
            "Предупреждение: целевая версия nfqws2-keenetic отличается от upstream. "
            "Проверьте совместимость и обновите version.py.",
            file=sys.stderr,
        )
    if missing:
        print(f"В upstream конфиге отсутствуют переменные: {', '.join(missing)}", file=sys.stderr)
        return 1

    if not args.skip_zapret2:
        try:
            release = json.loads(_fetch(ZAPRET2_RELEASE))
            zapret2_version = str(release.get("tag_name", "")).lstrip("v")
        except (OSError, json.JSONDecodeError) as error:
            print(f"Не удалось проверить последний zapret2: {error}", file=sys.stderr)
            return 2
        print(f"zapret2 upstream: {zapret2_version}; target: {TARGET_ZAPRET2_VERSION}")
        if zapret2_version != TARGET_ZAPRET2_VERSION:
            print(
                "Предупреждение: целевая версия zapret2 отличается от последнего релиза. "
                "Проверьте Lua-совместимость и обновите version.py.",
                file=sys.stderr,
            )
    print("Контракт конфигурации nfqws2-keenetic совпадает.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
