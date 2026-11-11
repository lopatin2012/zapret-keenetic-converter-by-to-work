"""Compare Flowseal winws strategies by running them and checking endpoints.

The tester is intentionally conservative: it only runs on Windows, requires
administrator rights (WinDivert needs them), refuses to run while another
``winws.exe`` is active, and always terminates the process it started.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .converter import ConverterSettings, resolve_variables
from .discovery import discover_profiles
from .errors import ConversionError
from .parser import Option, parse_batch


class TesterError(RuntimeError):
    """The strategy test cannot be started or completed safely."""


@dataclass(frozen=True)
class Target:
    name: str
    url: str


@dataclass
class TargetResult:
    name: str
    url: str
    ok: bool
    status: int | None = None
    seconds: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "seconds": self.seconds,
            "error": self.error,
        }


@dataclass
class StrategyResult:
    profile: str
    targets: list[TargetResult] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0

    @property
    def ok_count(self) -> int:
        return sum(item.ok for item in self.targets)

    @property
    def total(self) -> int:
        return len(self.targets)

    @property
    def average_seconds(self) -> float:
        values = [item.seconds for item in self.targets if item.ok and item.seconds is not None]
        return sum(values) / len(values) if values else 0.0

    @property
    def verdict(self) -> str:
        if self.error:
            return "ошибка"
        if not self.total:
            return "нет проверок"
        if self.ok_count == self.total:
            return "работает"
        if self.ok_count == 0:
            return "не работает"
        return "частично"

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "ok": self.ok_count,
            "total": self.total,
            "average_seconds": round(self.average_seconds, 3),
            "verdict": self.verdict,
            "error": self.error,
            "duration_seconds": round(self.duration, 2),
            "targets": [item.to_dict() for item in self.targets],
        }


ProgressCallback = Callable[[str], None]

DEFAULT_TARGETS = (
    Target("YouTube Web", "https://www.youtube.com"),
    Target("YouTube Short", "https://youtu.be"),
    Target("YouTube Image", "https://i.ytimg.com"),
    Target("YouTube Video Redirect", "https://redirector.googlevideo.com"),
    Target("Discord Main", "https://discord.com"),
    Target("Discord Gateway", "https://gateway.discord.gg"),
    Target("Discord CDN", "https://cdn.discordapp.com"),
    Target("Discord Updates", "https://updates.discord.com"),
    Target("Google Main", "https://www.google.com"),
    Target("Cloudflare Web", "https://www.cloudflare.com"),
    Target("Cloudflare CDN", "https://cdnjs.cloudflare.com"),
)
TARGET_RE = re.compile(r'^\s*(\w+)\s*=\s*"(.+)"\s*$')


def load_targets(source: Path) -> list[Target]:
    """Load Flowseal targets.txt, falling back to built-in HTTPS targets."""
    path = source / "utils" / "targets.txt"
    targets: list[Target] = []
    seen: set[str] = set()
    if path.is_file():
        try:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                match = TARGET_RE.match(line)
                if not match:
                    continue
                name, value = match.group(1), match.group(2).strip()
                if value.upper().startswith("PING:") or not value.lower().startswith("https://"):
                    continue
                if value in seen:
                    continue
                seen.add(value)
                targets.append(Target(name, value))
        except OSError:
            targets = []
    return targets or list(DEFAULT_TARGETS)


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def running_winws() -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq winws.exe", "/NH"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "winws.exe" in result.stdout.lower()


def prepare_user_lists(source: Path, temp_dir: Path) -> dict[Path, Path]:
    """Return temporary substitutes for optional Flowseal user lists.

    The original Flowseal folder is not modified. Missing ``*-user.txt`` files
    are redirected to empty files in a temporary directory.
    """
    overrides: dict[Path, Path] = {}
    lists = source / "lists"
    for name in ("list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt"):
        original = lists / name
        if original.exists():
            continue
        temporary = temp_dir / name
        try:
            temporary.parent.mkdir(parents=True, exist_ok=True)
            temporary.touch()
        except OSError as error:
            raise TesterError(f"Не удалось создать временный список {name}: {error}") from error
        overrides[original] = temporary
    return overrides


def build_winws_command(
    source: Path,
    profile_path: Path,
    game_filter: str = "disabled",
    overrides: dict[Path, Path] | None = None,
) -> tuple[list[str], Path]:
    """Build a direct winws command from a Flowseal .bat profile."""
    source = source.resolve()
    profile_path = profile_path.resolve()
    settings = ConverterSettings(
        source=source,
        profile=str(profile_path),
        output=source / ".tester-output",
        game_filter=game_filter,
    )
    global_options, profiles = parse_batch(profile_path)

    def render(option: Option) -> str:
        if option.value is None:
            return f"--{option.name}"
        value = resolve_variables(option.value, settings, profile_path.parent)
        if overrides:
            for original, replacement in overrides.items():
                value = value.replace(str(original), str(replacement))
        if "%" in value:
            raise TesterError(f"В {profile_path.name} осталась неизвестная переменная: {value}")
        return f"--{option.name}={value}"

    bin_dir = profile_path.parent / "bin"
    if not bin_dir.is_dir():
        bin_dir = source / "bin"
    executable = bin_dir / "winws.exe"
    if not executable.is_file():
        raise TesterError(f"Не найден winws.exe: {executable}")
    if not profiles:
        raise TesterError(f"В {profile_path.name} не найдены профили winws")

    command = [str(executable)]
    command.extend(render(option) for option in global_options)
    for index, profile in enumerate(profiles):
        if index:
            command.append("--new")
        command.extend(render(option) for option in profile)
    return command, bin_dir


def _curl_path() -> str:
    path = shutil.which("curl.exe") or shutil.which("curl")
    if not path:
        raise TesterError("Не найден curl.exe. Установите curl или обновите Windows.")
    return path


def check_target(curl: str, target: Target, timeout: float) -> TargetResult:
    command = [
        curl,
        "-I",
        "-sS",
        "--noproxy",
        "*",
        "-m",
        str(max(1, int(timeout))),
        "--connect-timeout",
        str(max(1, min(3, int(timeout)))),
        "-o",
        os.devnull,
        "-w",
        "%{http_code} %{time_total}",
        target.url,
    ]
    started = time.perf_counter()
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
    except subprocess.TimeoutExpired:
        return TargetResult(target.name, target.url, False, error="тайм-аут")
    except OSError as error:
        return TargetResult(target.name, target.url, False, error=str(error))

    elapsed = time.perf_counter() - started
    parts = process.stdout.strip().split()
    status: int | None = None
    seconds: float | None = None
    if parts and parts[0].isdigit():
        status = int(parts[0])
    if len(parts) > 1:
        try:
            seconds = float(parts[1])
        except ValueError:
            seconds = None
    ok = process.returncode == 0 and status not in (None, 0)
    error = None
    if not ok:
        error = (process.stderr.strip() or f"HTTP {status or 0:03d}")[:300]
    return TargetResult(target.name, target.url, ok, status, seconds or elapsed, error)


def check_targets(
    curl: str,
    targets: list[Target],
    timeout: float,
    cancel: threading.Event | None = None,
) -> list[TargetResult]:
    if not targets:
        return []
    workers = min(8, len(targets))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_target, curl, target, timeout) for target in targets]
        results: list[TargetResult] = []
        for future in futures:
            if cancel is not None and cancel.is_set():
                future.cancel()
                continue
            try:
                results.append(future.result())
            except Exception as error:  # pragma: no cover - defensive
                results.append(TargetResult("unknown", "", False, error=str(error)))
        return results


def _emit(callback: ProgressCallback | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def run_strategy_tests(
    source: Path,
    profiles: list[str] | None = None,
    targets: list[Target] | None = None,
    timeout: float = 5.0,
    progress: ProgressCallback | None = None,
    cancel: threading.Event | None = None,
    game_filter: str = "disabled",
    startup_delay: float = 2.0,
) -> list[StrategyResult]:
    """Run each strategy and check the target list. Windows only."""
    if os.name != "nt":
        raise TesterError("Тестер стратегий доступен только в Windows.")
    if not is_admin():
        raise TesterError("Запустите конвертер от имени администратора: для winws нужен WinDivert.")
    if running_winws():
        raise TesterError(
            "Найден запущенный winws.exe. Остановите Zapret/Flowseal (или службу zapret) перед тестом."
        )
    source = source.resolve()
    if not source.is_dir():
        raise TesterError(f"Папка Flowseal не найдена: {source}")
    names = list(profiles) if profiles else discover_profiles(source)
    if not names:
        raise TesterError("В папке Flowseal не найдены рабочие стратегии.")
    selected_targets = list(targets) if targets else load_targets(source)
    if not selected_targets:
        raise TesterError("Не найдены цели для проверки.")
    curl = _curl_path()
    temporary = Path(tempfile.mkdtemp(prefix="zapret-strategy-test-"))
    try:
        overrides = prepare_user_lists(source, temporary)
        return _run_profiles(
            source,
            names,
            selected_targets,
            curl,
            timeout,
            progress,
            cancel,
            game_filter,
            startup_delay,
            overrides,
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _run_profiles(
    source: Path,
    names: list[str],
    targets: list[Target],
    curl: str,
    timeout: float,
    progress: ProgressCallback | None,
    cancel: threading.Event | None,
    game_filter: str,
    startup_delay: float,
    overrides: dict[Path, Path],
) -> list[StrategyResult]:
    results: list[StrategyResult] = []
    total = len(names)
    for index, name in enumerate(names, start=1):
        if cancel is not None and cancel.is_set():
            break
        profile_path = source / name
        _emit(progress, f"[{index}/{total}] {name}: запуск winws…")
        started = time.perf_counter()
        process: subprocess.Popen[str] | None = None
        try:
            command, cwd = build_winws_command(source, profile_path, game_filter, overrides)
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            time.sleep(startup_delay)
            if process.poll() is not None:
                stderr = process.stderr.read().strip() if process.stderr else ""
                raise TesterError(f"winws завершился до проверки. {stderr[:300]}".strip())
            _emit(progress, f"[{index}/{total}] {name}: проверка {len(targets)} целей…")
            target_results = check_targets(curl, targets, timeout, cancel)
            result = StrategyResult(name, target_results, duration=time.perf_counter() - started)
            results.append(result)
            _emit(
                progress,
                f"[{index}/{total}] {name}: {result.ok_count}/{result.total}, {result.verdict}",
            )
        except TesterError as error:
            results.append(StrategyResult(name, error=str(error), duration=time.perf_counter() - started))
            _emit(progress, f"[{index}/{total}] {name}: ошибка — {error}")
        except OSError as error:
            results.append(
                StrategyResult(name, error=f"Не удалось запустить winws: {error}", duration=time.perf_counter() - started)
            )
            _emit(progress, f"[{index}/{total}] {name}: ошибка — {error}")
        finally:
            if process is not None:
                _stop_process(process)
        if cancel is not None and cancel.is_set():
            break
    return results


def sort_results(results: list[StrategyResult]) -> list[StrategyResult]:
    return sorted(
        results,
        key=lambda item: (
            item.error is not None,
            -item.ok_count,
            item.average_seconds or 9999.0,
            item.profile.lower(),
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zapret-keenetic-test",
        description="Проверить стратегии Flowseal на Windows и выбрать лучшую.",
    )
    parser.add_argument("source", type=Path, help="папка zapret-discord-youtube")
    parser.add_argument("--profiles", nargs="*", help="профили .bat; по умолчанию все найденные")
    parser.add_argument("--timeout", type=float, default=5.0, help="тайм-аут одной проверки, секунды")
    parser.add_argument("--json", type=Path, help="сохранить результаты в JSON")
    args = parser.parse_args(argv)

    try:
        results = run_strategy_tests(
            args.source,
            profiles=args.profiles,
            timeout=args.timeout,
            progress=print,
        )
    except TesterError as error:
        print(f"Ошибка тестера: {error}", file=sys.stderr)
        return 2
    except ConversionError as error:
        print(f"Ошибка профиля: {error}", file=sys.stderr)
        return 2

    ordered = sort_results(results)
    print()
    print(f"{'Стратегия':45} {'OK':>5} {'Всего':>6} {'Среднее':>9}  Вердикт")
    for item in ordered:
        average = f"{item.average_seconds:.2f}s" if item.average_seconds else "—"
        print(f"{item.profile[:45]:45} {item.ok_count:5} {item.total:6} {average:>9}  {item.verdict}")
    if ordered:
        print(f"\nЛучшая стратегия: {ordered[0].profile}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(
                {"source": str(args.source), "results": [item.to_dict() for item in ordered]},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
