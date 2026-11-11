"""Check a local Flowseal corpus without executing its batch files or using a router.

Run: python -m scripts.check_flowseal SOURCE [--json REPORT.json] [--strict]
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from zapret_keenetic.converter import ConversionError, ConverterSettings, convert
from zapret_keenetic.discovery import discover_profiles


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail the whole run on the first warning (uses converter strict mode)",
    )
    args = parser.parse_args()
    names = discover_profiles(args.source)
    if not names:
        parser.error("no winws profiles found")
    results = []
    errors = []
    for name in names:
        for target in ("keenetic", "openwrt"):
            for game in ("disabled", "all", "tcp", "udp"):
                for tls_mode, limit in (("source", None), ("clone", 3)):
                    try:
                        with tempfile.TemporaryDirectory() as temporary:
                            result = convert(ConverterSettings(
                                source=args.source, profile=name, output=Path(temporary),
                                target=target, game_filter=game, strict=args.strict,
                                tls_fake_mode=tls_mode, fake_repeats_limit=limit,
                            ))
                    except (ConversionError, OSError) as error:
                        errors.append({
                            "profile": name, "target": target, "game_filter": game,
                            "tls_fake_mode": tls_mode, "fake_repeats_limit": limit,
                            "error": str(error),
                        })
                        continue
                    results.append({"profile": name, "target": target, "game_filter": game,
                                    "tls_fake_mode": tls_mode, "fake_repeats_limit": limit,
                                    "profiles_written": result.profiles_written,
                                    "warnings": result.warning_count})
    warning_total = sum(item["warnings"] for item in results)
    report = {
        "source_profiles": len(names),
        "conversions_passed": len(results),
        "conversions_failed": len(errors),
        "warnings": warning_total,
        "results": results,
        "errors": errors,
    }
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"Passed {len(results)} conversions from {len(names)} source profiles; "
        f"warnings: {warning_total}; failed: {len(errors)}."
    )
    for item in errors:
        print(f"  {item['profile']} / {item['target']}: {item['error']}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
