from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Iterable, Sequence

from .errors import ConversionError
from .parser import Option, VAR_RE, parse_batch
from .renderer import _render_config, _render_report, _render_web_import, _write_archive
from .version import TARGET_ZAPRET2_VERSION, __version__


@dataclass
class Diagnostic:
    level: str
    code: str
    message: str
    profile: int | None = None
    option: str | None = None


@dataclass
class ConvertedProfile:
    source_number: int
    arguments: list[str]


@dataclass
class ConverterSettings:
    source: Path
    profile: str
    output: Path
    target: str = "keenetic"
    interface: str = "eth3"
    game_filter: str = "disabled"
    ipset_mode: str = "loaded"
    ipv6: bool = True
    policy_name: str = "nfqws"
    policy_exclude: bool = False
    queue_num: int = 300
    strict: bool = False
    archive: bool = False
    tls_fake_mode: str = "source"
    fake_repeats_limit: int | None = None


@dataclass
class ConversionResult:
    output: Path
    config: Path
    report: Path
    archive: Path | None
    profiles_read: int
    profiles_written: int
    tcp_ports: list[str]
    udp_ports: list[str]
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def warning_count(self) -> int:
        return sum(d.level == "warning" for d in self.diagnostics)


# Flowseal ships ipset-all.txt in a deliberately disabled state and keeps the
# populated list beside it as ipset-all.txt.backup. TEST-NET-3 is a sentinel,
# not a useful public network range.
IPSET_DISABLED_SENTINELS = {"203.0.113.113/32"}

PASS_OPTIONS = {
    "filter-l3",
    "filter-l7",
    "filter-tcp",
    "filter-udp",
    "hostlist",
    "hostlist-domains",
    "hostlist-exclude",
    "hostlist-exclude-domains",
    "ipset",
    "ipset-exclude",
}
FILE_OPTIONS = {"hostlist", "hostlist-exclude", "ipset", "ipset-exclude"}
CONSUMED_OPTIONS = {
    "dpi-desync",
    "dpi-desync-any-protocol",
    "dpi-desync-badseq-increment",
    "dpi-desync-badack-increment",
    "dpi-desync-cutoff",
    "dpi-desync-fake-discord",
    "dpi-desync-fake-http",
    "dpi-desync-fake-quic",
    "dpi-desync-fake-stun",
    "dpi-desync-fake-tls",
    "dpi-desync-fake-tls-mod",
    "dpi-desync-fake-unknown",
    "dpi-desync-fake-unknown-udp",
    "dpi-desync-fakedsplit-pattern",
    "dpi-desync-fooling",
    "dpi-desync-hostfakesplit-midhost",
    "dpi-desync-hostfakesplit-mod",
    "dpi-desync-repeats",
    "dpi-desync-split-pos",
    "dpi-desync-split-seqovl",
    "dpi-desync-split-seqovl-pattern",
    "dpi-desync-ts-increment",
    "ip-id",
}
FAKE_PAYLOADS = {
    "dpi-desync-fake-http": "http_req",
    "dpi-desync-fake-tls": "tls_client_hello",
    "dpi-desync-fake-quic": "quic_initial",
    "dpi-desync-fake-discord": "discord_ip_discovery",
    "dpi-desync-fake-stun": "stun",
    "dpi-desync-fake-unknown": "unknown",
    "dpi-desync-fake-unknown-udp": "unknown",
}
BUILTIN_BLOBS = {
    "http_req": "fake_default_http",
    "tls_client_hello": "fake_default_tls",
    "quic_initial": "fake_default_quic",
    "discord_ip_discovery": "0x00000000000000000000000000000000",
    "stun": "0x00000000000000000000000000000000",
    "unknown": "0x00000000000000000000000000000000",
}
L7_PAYLOADS = {
    "http": ["http_req"],
    "tls": ["tls_client_hello"],
    "quic": ["quic_initial"],
    "discord": ["discord_ip_discovery"],
    "stun": ["stun"],
    "wireguard": ["wireguard_initiation", "wireguard_response", "wireguard_cookie"],
    "mtproto": ["mtproto_initial"],
    "unknown": ["unknown"],
}
SUPPORTED_FOOLING = {"ts", "badseq", "md5sig", "badsum", "hopbyhop", "hopbyhop2", "none"}


def _values(options: Sequence[Option], name: str) -> list[str]:
    return [item.value or "" for item in options if item.name == name]


def _last(options: Sequence[Option], name: str, default: str | None = None) -> str | None:
    values = _values(options, name)
    return values[-1] if values else default


def _replace_variables(value: str, settings: ConverterSettings, base_dir: Path | None = None) -> str:
    base = base_dir or settings.source
    game_enabled = {
        "disabled": {"gamefiltertcp": "12", "gamefilterudp": "12"},
        "all": {"gamefiltertcp": "1024-65535", "gamefilterudp": "1024-65535"},
        "tcp": {"gamefiltertcp": "1024-65535", "gamefilterudp": "12"},
        "udp": {"gamefiltertcp": "12", "gamefilterudp": "1024-65535"},
    }[settings.game_filter]
    replacements = {
        "bin": str(base / "bin") + "\\",
        "lists": str(base / "lists") + "\\",
        **game_enabled,
    }

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).lower()
        return replacements.get(key, match.group(0))

    source_prefix = str(base) + "\\"
    value = re.sub(re.escape("%~dp0"), lambda _: source_prefix, value, flags=re.IGNORECASE)
    return VAR_RE.sub(replace, value)


def _resolved_options(
    options: Sequence[Option],
    settings: ConverterSettings,
    base_dir: Path | None = None,
) -> list[Option]:
    return [
        Option(
            item.name,
            _replace_variables(item.value, settings, base_dir) if item.value is not None else None,
        )
        for item in options
    ]


def resolve_variables(value: str, settings: ConverterSettings, base_dir: Path | None = None) -> str:
    """Resolve %~dp0/%BIN%/%LISTS% for callers outside the converter."""
    return _replace_variables(value, settings, base_dir)


def _profile_is_disabled_game(options: Sequence[Option]) -> bool:
    filters = _values(options, "filter-tcp") + _values(options, "filter-udp")
    return bool(filters) and all(value == "12" for value in filters)


def _port_sort_key(value: str) -> tuple[int, int, str]:
    first = re.split(r"[-:]", value, maxsplit=1)[0]
    try:
        return (int(first), 0 if "-" not in value and ":" not in value else 1, value)
    except ValueError:
        return (65536, 2, value)


def _collect_ports(profiles: Sequence[Sequence[Option]], transport: str) -> list[str]:
    result: set[str] = set()
    for profile in profiles:
        for value in _values(profile, f"filter-{transport}"):
            for port in value.split(","):
                port = port.strip()
                if port and port != "12" and "%" not in port:
                    result.add(port)
    return sorted(result, key=_port_sort_key)


class _Bundle:
    def __init__(self, settings: ConverterSettings, diagnostics: list[Diagnostic]):
        self.settings = settings
        self.diagnostics = diagnostics
        self.router_root = "/opt/etc/nfqws2" if settings.target == "keenetic" else "/etc/nfqws2"
        # Blobs are keyed by source and offset: "+3@tls.bin" and "tls.bin"
        # are different payloads and must not share a copied file.
        self.blobs: dict[tuple[Path, int], tuple[str, str]] = {}
        self.lists: dict[Path, Path] = {}
        self.list_destinations: set[Path] = set()
        self.missing_reported: set[tuple[str, Path]] = set()
        self.ipset_reported: set[Path] = set()

    def _source_path(self, raw: str) -> tuple[str, Path] | None:
        value = raw.strip('"')
        offset = ""
        if value.startswith("+") and "@" in value:
            offset, value = value.split("@", 1)
            offset += "@"
        elif value.startswith("@"):
            value = value[1:]
        if value.startswith("0x") or value == "!":
            return None
        path = Path(value.replace("\\", "/"))
        return offset, path

    def _offset_bytes(self, offset: str, profile_no: int, option: str) -> int:
        if not offset:
            return 0
        digits = offset.lstrip("+").rstrip("@")
        try:
            value = int(digits)
            if value < 0:
                raise ValueError
            return value
        except ValueError:
            self.diagnostics.append(
                Diagnostic(
                    "warning",
                    "invalid-blob-offset",
                    f"Некорректное смещение blob {offset}; используется начало файла.",
                    profile_no,
                    option,
                )
            )
            return 0

    def _choose_ipset(self, source: Path) -> Path:
        if self.settings.ipset_mode != "loaded" or source.name.lower() != "ipset-all.txt":
            return source
        backup = source.with_name(source.name + ".backup")
        current_entries = _substantive_lines(source)
        current_is_disabled = not current_entries or set(current_entries) <= IPSET_DISABLED_SENTINELS
        if current_is_disabled and backup.exists() and _substantive_line_count(backup) > 0:
            if source not in self.ipset_reported:
                self.ipset_reported.add(source)
                self.diagnostics.append(
                    Diagnostic("info", "ipset-backup", f"Пустой {source.name} заменён наполненным {backup.name}")
                )
            return backup
        return source

    def _unique_list_destination(self, source: Path, destination_name: str) -> Path:
        destination = self.settings.output / "lists" / destination_name
        if destination not in self.list_destinations:
            self.list_destinations.add(destination)
            return destination
        original = Path(destination_name)
        digest = hashlib.sha1(str(source).encode()).hexdigest()[:7]
        candidate_name = f"{original.stem}-{digest}{original.suffix}"
        candidate = self.settings.output / "lists" / candidate_name
        counter = 2
        while candidate in self.list_destinations:
            candidate_name = f"{original.stem}-{digest}-{counter}{original.suffix}"
            candidate = self.settings.output / "lists" / candidate_name
            counter += 1
        self.list_destinations.add(candidate)
        return candidate

    def copy_list(self, raw: str, profile_no: int, option: str) -> str:
        parsed = self._source_path(raw)
        if parsed is None:
            return raw
        _, source = parsed
        if not source.is_absolute():
            source = self.settings.source / source
        source = self._choose_ipset(source)
        if source in self.lists:
            return f"{self.router_root}/lists/{self.lists[source].name}"

        destination_name = "ipset-all.txt" if source.name.endswith(".backup") else source.name
        destination = self._unique_list_destination(source, destination_name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.exists():
            shutil.copy2(source, destination)
        else:
            destination.touch(exist_ok=True)
            marker = ("list", source)
            if marker not in self.missing_reported:
                self.missing_reported.add(marker)
                is_user_list = source.stem.lower().endswith("-user")
                self.diagnostics.append(
                    Diagnostic(
                        "info" if is_user_list else "warning",
                        "empty-user-list" if is_user_list else "missing-list",
                        (
                            f"Необязательный {source.name} отсутствует; создан пустой файл."
                            if is_user_list
                            else f"Файл {source.name} отсутствует; создан пустой файл. Заполните его перед установкой."
                        ),
                        profile_no,
                        option,
                    )
                )
        self.lists[source] = destination
        return f"{self.router_root}/lists/{destination.name}"

    def blob(self, raw: str, profile_no: int, option: str) -> str:
        raw = raw.strip('"')
        if raw == "!":
            return "fake_default_tls"
        if raw.startswith("0x") or raw in set(BUILTIN_BLOBS.values()):
            return raw
        parsed = self._source_path(raw)
        if parsed is None:
            return raw
        offset, source = parsed
        if not source.is_absolute():
            source = self.settings.source / source
        offset_value = self._offset_bytes(offset, profile_no, option)
        key = (source, offset_value)
        if key in self.blobs:
            return self.blobs[key][0]
        if not source.exists():
            marker = ("blob", source)
            if marker not in self.missing_reported:
                self.missing_reported.add(marker)
                self.diagnostics.append(
                    Diagnostic(
                        "warning",
                        "missing-blob",
                        f"Не найден бинарный шаблон {source}",
                        profile_no,
                        option,
                    )
                )
            return "0x00"

        stem = re.sub(r"[^a-zA-Z0-9_]", "_", source.stem).strip("_").lower() or "blob"
        if offset_value:
            stem = f"{stem}_ofs{offset_value}"
        name = stem
        used_names = {item[0] for item in self.blobs.values()}
        if name in used_names:
            suffix = hashlib.sha1(f"{source}:{offset}".encode()).hexdigest()[:7]
            name = f"{name}_{suffix}"
        destination_name = source.name
        if offset_value:
            destination_name = f"{source.stem}_ofs{offset_value}{source.suffix}"
        used_destinations = {item[1] for item in self.blobs.values()}
        if destination_name in used_destinations:
            suffix = hashlib.sha1(f"{source}:{offset}".encode()).hexdigest()[:7]
            destination_name = f"{source.stem}_{suffix}{source.suffix}"

        destination = self.settings.output / "blobs" / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if offset_value:
            data = source.read_bytes()
            if offset_value >= len(data):
                self.diagnostics.append(
                    Diagnostic(
                        "warning",
                        "blob-offset-past-end",
                        f"Смещение {offset_value} выходит за размер {source.name}; шаблон пуст.",
                        profile_no,
                        option,
                    )
                )
            destination.write_bytes(data[offset_value:])
        else:
            shutil.copy2(source, destination)
        self.blobs[key] = (name, destination_name)
        return name

    def blob_declarations(self) -> list[str]:
        result = []
        for _, (name, destination_name) in sorted(self.blobs.items(), key=lambda item: item[1][0]):
            result.append(f"--blob={name}:@{self.router_root}/blobs/{destination_name}")
        return result


def _substantive_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def _substantive_line_count(path: Path) -> int:
    return len(_substantive_lines(path))


def _append_arg(parts: list[str], key: str, value: str | None = None) -> None:
    parts.append(f"--{key}" if value is None else f"--{key}={value}")


def _fooling_args(options: Sequence[Option]) -> list[str]:
    result: list[str] = []
    modes = [mode.strip() for mode in (_last(options, "dpi-desync-fooling", "") or "").split(",") if mode.strip()]
    for mode in modes:
        if mode == "ts":
            result.append(f"tcp_ts={_last(options, 'dpi-desync-ts-increment', '-600000')}")
        elif mode == "badseq":
            seq = _last(options, "dpi-desync-badseq-increment", "-10000")
            ack = _last(options, "dpi-desync-badack-increment", "-66000")
            if seq != "0":
                result.append(f"tcp_seq={seq}")
            result.extend((f"tcp_ack={ack}", "tcp_ts_up"))
        elif mode == "md5sig":
            result.append("tcp_md5")
        elif mode == "badsum":
            result.append("badsum")
        elif mode == "hopbyhop":
            result.append("ip6_hopbyhop")
        elif mode == "hopbyhop2":
            result.append("ip6_hopbyhop2")
    return result


def _common_lua_args(options: Sequence[Option], include_repeats: bool = False) -> list[str]:
    result = _fooling_args(options)
    ip_id = _last(options, "ip-id")
    if ip_id:
        result.append(f"ip_id={ip_id}")
    if include_repeats:
        repeats = _last(options, "dpi-desync-repeats")
        if repeats:
            result.append(f"repeats={repeats}")
    return result


def _lua(function: str, arguments: Iterable[str]) -> str:
    args = [arg for arg in arguments if arg]
    return function if not args else function + ":" + ":".join(args)


def _fake_specs(options: Sequence[Option]) -> list[tuple[str, str, str | None, str]]:
    """Return (source option, payload, tls mod, blob value), preserving source order."""
    specs: list[list[str | None]] = []
    current_tls_mod: str | None = None
    last_tls_index: int | None = None
    for item in options:
        if item.name == "dpi-desync-fake-tls-mod":
            current_tls_mod = item.value
            if last_tls_index is not None:
                specs[last_tls_index][2] = current_tls_mod
        elif item.name in FAKE_PAYLOADS and item.value is not None:
            tls_mod = current_tls_mod if item.name == "dpi-desync-fake-tls" else None
            specs.append([item.name, FAKE_PAYLOADS[item.name], tls_mod, item.value])
            if item.name == "dpi-desync-fake-tls":
                last_tls_index = len(specs) - 1
    return [(str(a), str(b), c, str(d)) for a, b, c, d in specs]


def _inferred_payloads(options: Sequence[Option], any_protocol: bool) -> list[str]:
    if any_protocol:
        return ["all"]
    payloads: list[str] = []
    l7 = _last(options, "filter-l7")
    if l7:
        for name in l7.split(","):
            payloads.extend(L7_PAYLOADS.get(name.strip(), []))
    if not payloads:
        tcp = ",".join(_values(options, "filter-tcp"))
        udp = ",".join(_values(options, "filter-udp"))
        if tcp:
            if "443" in tcp:
                payloads.append("tls_client_hello")
            if "80" in tcp.split(",") or tcp.startswith("80,"):
                payloads.append("http_req")
            if not payloads:
                payloads.append("tls_client_hello")
        elif udp:
            payloads.extend(spec[1] for spec in _fake_specs(options))
    return list(dict.fromkeys(payloads or ["known"]))


def _translate_profile(
    options: Sequence[Option], profile_no: int, bundle: _Bundle, diagnostics: list[Diagnostic]
) -> ConvertedProfile | None:
    if _profile_is_disabled_game(options):
        diagnostics.append(Diagnostic("info", "game-profile-skipped", "Игровой профиль отключён", profile_no))
        return None

    result: list[str] = []
    seen_file_options: set[tuple[str, str]] = set()
    for item in options:
        if item.name in PASS_OPTIONS:
            if item.value is None:
                diagnostics.append(Diagnostic("warning", "missing-value", f"У --{item.name} нет значения", profile_no, item.name))
                continue
            if item.name in FILE_OPTIONS:
                value = bundle.copy_list(item.value, profile_no, item.name)
                key = (item.name, value)
                if key in seen_file_options:
                    diagnostics.append(
                        Diagnostic(
                            "info",
                            "duplicate-list-skipped",
                            f"Повторный --{item.name}={value} в одном профиле пропущен.",
                            profile_no,
                            item.name,
                        )
                    )
                    continue
                seen_file_options.add(key)
            else:
                value = item.value
            _append_arg(result, item.name, value)

    any_protocol = (_last(options, "dpi-desync-any-protocol", "0") or "0") not in {"", "0"}
    cutoff = _last(options, "dpi-desync-cutoff")
    if cutoff:
        _append_arg(result, "out-range", f"-{cutoff}")

    modes = [mode.strip() for mode in (_last(options, "dpi-desync", "") or "").split(",") if mode.strip()]
    if not modes:
        diagnostics.append(Diagnostic("warning", "no-strategy", "В профиле отсутствует --dpi-desync", profile_no))
        return ConvertedProfile(profile_no, result)

    for fooling in [part.strip() for part in (_last(options, "dpi-desync-fooling", "") or "").split(",") if part.strip()]:
        if fooling not in SUPPORTED_FOOLING:
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "unsupported-fooling",
                    f"Режим dpi-desync-fooling={fooling} не перенесён; проверьте стратегию.",
                    profile_no,
                    "dpi-desync-fooling",
                )
            )

    fake_specs = _fake_specs(options)
    inferred_payloads = _inferred_payloads(options, any_protocol)
    tls_mod_default = _last(options, "dpi-desync-fake-tls-mod")

    for mode in modes:
        if mode == "fake":
            specs = list(fake_specs)
            if not specs:
                specs = [
                    ("builtin", payload, tls_mod_default if payload == "tls_client_hello" else None, BUILTIN_BLOBS.get(payload, "0x00"))
                    for payload in inferred_payloads
                    if payload not in {"all", "known"}
                ]
            if not specs:
                specs = [("builtin", "known", None, "0x00")]
            cloned_tls = False
            for source_option, payload, tls_mod, raw_blob in specs:
                clone = payload == "tls_client_hello" and bundle.settings.tls_fake_mode == "clone"
                if clone and cloned_tls:
                    continue
                _append_arg(result, "payload", payload)
                if clone:
                    cloned_tls = True
                    blob = "zk_live_tls"
                    _append_arg(result, "lua-desync", f"tls_client_hello_clone:blob={blob}")
                    diagnostics.append(Diagnostic(
                        "info", "experimental-tls-clone",
                        "Эксперимент: TLS fake-шаблоны заменены одним живым ClientHello с rnd,rndsni,dupsid; "
                        "это изменённая стратегия. HTTP/QUIC/seqovl-шаблоны сохранены.", profile_no,
                    ))
                else:
                    blob = bundle.blob(raw_blob, profile_no, source_option)
                args = [f"blob={blob}", *_common_lua_args(options, include_repeats=True)]
                if clone:
                    args.extend(("optional", "tls_mod=rnd,rndsni,dupsid"))
                elif payload == "tls_client_hello" and tls_mod and tls_mod != "none":
                    args.append(f"tls_mod={tls_mod}")
                _append_arg(result, "lua-desync", _lua("fake", args))
            continue

        if mode == "syndata":
            _append_arg(result, "payload", "empty")
            _append_arg(result, "lua-desync", "syndata")
            continue

        _append_arg(result, "payload", ",".join(inferred_payloads))
        common = _common_lua_args(options, include_repeats=mode in {"fakedsplit", "fakeddisorder", "hostfakesplit"})
        if mode in {"multisplit", "multidisorder"}:
            # nfqws1 applies fooling/repeats to fakes, not these real segments.
            common = [arg for arg in common if arg.startswith("ip_id=") or arg == "tcp_ts_up"]
        split_pos = _last(options, "dpi-desync-split-pos")
        seqovl = _last(options, "dpi-desync-split-seqovl")
        seqovl_pattern = _last(options, "dpi-desync-split-seqovl-pattern")

        if mode in {"multisplit", "multidisorder", "fakedsplit", "fakeddisorder"}:
            args: list[str] = []
            if split_pos:
                args.append(f"pos={split_pos}")
            if mode in {"multisplit", "multidisorder", "fakedsplit", "fakeddisorder"} and seqovl:
                args.append(f"seqovl={seqovl}")
            if seqovl_pattern:
                args.append(f"seqovl_pattern={bundle.blob(seqovl_pattern, profile_no, 'dpi-desync-split-seqovl-pattern')}")
            if mode in {"fakedsplit", "fakeddisorder"}:
                pattern = _last(options, "dpi-desync-fakedsplit-pattern")
                if pattern:
                    args.append(f"pattern={bundle.blob(pattern, profile_no, 'dpi-desync-fakedsplit-pattern')}")
            function = "multidisorder_legacy" if mode == "multidisorder" else mode
            _append_arg(result, "lua-desync", _lua(function, [*args, *common]))
        elif mode == "hostfakesplit":
            args = []
            mod = _last(options, "dpi-desync-hostfakesplit-mod", "") or ""
            altorder = False
            for component in mod.split(","):
                component = component.strip()
                if component.startswith("host="):
                    args.append(component)
                elif component == "altorder=1":
                    altorder = True
                elif component == "altorder=0":
                    altorder = False
                elif component and component != "none":
                    raise ConversionError(
                        f"Профиль {profile_no}: неподдерживаемый модификатор hostfakesplit {component}"
                    )
            midhost = _last(options, "dpi-desync-hostfakesplit-midhost")
            if midhost:
                args.append(f"midhost={midhost}")
            if altorder:
                diagnostics.append(
                    Diagnostic(
                        "info",
                        "hostfakesplit-altorder",
                        f"altorder=1 сохранён встроенной Lua-функцией совместимости (zapret2 v{TARGET_ZAPRET2_VERSION}).",
                        profile_no,
                        "dpi-desync-hostfakesplit-mod",
                    )
                )
            function = "zk_hostfakesplit_alt1" if altorder else "hostfakesplit"
            _append_arg(result, "lua-desync", _lua(function, [*args, *common]))
        else:
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "unsupported-mode",
                    f"Режим dpi-desync={mode} не поддержан и пропущен",
                    profile_no,
                    "dpi-desync",
                )
            )

    known = PASS_OPTIONS | CONSUMED_OPTIONS | {"wf-tcp", "wf-udp"}
    for item in options:
        if item.name not in known:
            diagnostics.append(
                Diagnostic("warning", "unsupported-option", f"Параметр --{item.name} пропущен", profile_no, item.name)
            )
    limit = bundle.settings.fake_repeats_limit
    if limit is not None:
        limited = False
        def cap_repeats(match: re.Match[str]) -> str:
            nonlocal limited
            count = int(match.group(1))
            limited = limited or count > limit
            return f":repeats={min(count, limit)}"
        result = [re.sub(r":repeats=(\d+)(?=:|$)", cap_repeats, arg) for arg in result]
        if limited:
            diagnostics.append(Diagnostic(
                "info", "experimental-repeat-limit",
                f"Эксперимент: число повторов fake-пакетов ограничено до {limit}; стратегия изменена.", profile_no,
            ))
    return ConvertedProfile(profile_no, result)


def _resolve_profiles(
    raw_profiles: Sequence[Sequence[Option]],
    settings: ConverterSettings,
    diagnostics: list[Diagnostic],
    base_dir: Path | None = None,
) -> list[list[Option]]:
    """Resolve %VARIABLES% and report the ones that remain unknown."""
    resolved: list[list[Option]] = []
    reported: set[tuple[int, str, str]] = set()
    for number, profile in enumerate(raw_profiles, start=1):
        items = _resolved_options(profile, settings, base_dir)
        for item in items:
            if item.value is None:
                continue
            for match in VAR_RE.finditer(item.value):
                name = match.group(1)
                marker = (number, item.name, name)
                if marker in reported:
                    continue
                reported.add(marker)
                diagnostics.append(
                    Diagnostic(
                        "warning",
                        "unresolved-variable",
                        f"Не удалось подставить %{name}% в --{item.name}; значение сохранено как есть.",
                        number,
                        item.name,
                    )
                )
        resolved.append(items)
    return resolved


def convert(settings: ConverterSettings) -> ConversionResult:
    settings.source = settings.source.resolve()
    settings.output = settings.output.resolve()
    if settings.target not in {"keenetic", "openwrt"}:
        raise ConversionError("target должен быть keenetic или openwrt")
    if settings.game_filter not in {"disabled", "all", "tcp", "udp"}:
        raise ConversionError("game_filter должен быть disabled, all, tcp или udp")
    if settings.ipset_mode not in {"loaded", "current"}:
        raise ConversionError("ipset_mode должен быть loaded или current")
    if settings.tls_fake_mode not in {"source", "clone"}:
        raise ConversionError("tls_fake_mode должен быть source или clone")
    if settings.fake_repeats_limit is not None and (
        not isinstance(settings.fake_repeats_limit, int) or settings.fake_repeats_limit < 1
    ):
        raise ConversionError("fake_repeats_limit должен быть положительным целым числом")
    if not 0 <= settings.queue_num <= 65535:
        raise ConversionError("queue_num должен быть от 0 до 65535")
    if not settings.source.is_dir():
        raise ConversionError(f"Каталог Flowseal не найден: {settings.source}")

    profile_path = Path(settings.profile)
    if not profile_path.is_absolute():
        profile_path = settings.source / profile_path
    if profile_path.suffix.lower() != ".bat":
        profile_path = profile_path.with_suffix(".bat")
    if not profile_path.is_file():
        raise ConversionError(f"Профиль не найден: {profile_path}")

    _, raw_profiles = parse_batch(profile_path)
    diagnostics: list[Diagnostic] = []
    resolved_profiles = _resolve_profiles(raw_profiles, settings, diagnostics, profile_path.parent)
    final_output = settings.output
    if final_output.exists() and any(final_output.iterdir()):
        raise ConversionError(
            f"Выходной каталог не пуст: {final_output}. "
            "Выберите новую папку или очистите её."
        )

    # Build in a sibling directory. A failed or strict conversion must not
    # leave a half-filled result that blocks the next attempt.
    staging = final_output.parent / f".{final_output.name}.tmp-{uuid.uuid4().hex[:8]}"
    try:
        staging.mkdir(parents=True, exist_ok=False)
        build_settings = replace(settings, output=staging)
        bundle = _Bundle(build_settings, diagnostics)

        converted: list[ConvertedProfile] = []
        for number, profile in enumerate(resolved_profiles, start=1):
            item = _translate_profile(profile, number, bundle, diagnostics)
            if item is not None and item.arguments:
                converted.append(item)

        if not converted:
            raise ConversionError("После конвертации не осталось ни одного рабочего профиля")
        tcp_ports = _collect_ports(resolved_profiles, "tcp")
        udp_ports = _collect_ports(resolved_profiles, "udp")
        for transport, ports in (("TCP", tcp_ports), ("UDP", udp_ports)):
            multiport_slots = sum(2 if "-" in port or ":" in port else 1 for port in ports)
            if multiport_slots > 15:
                diagnostics.append(
                    Diagnostic(
                        "warning",
                        "multiport-limit",
                        f"{transport}_PORTS использует {multiport_slots} слотов, но xt_multiport допускает не более 15.",
                    )
                )
        if settings.strict and any(item.level == "warning" for item in diagnostics):
            messages = "; ".join(item.message for item in diagnostics if item.level == "warning")
            raise ConversionError(f"Строгий режим: {messages}")

        config_text = _render_config(build_settings, bundle, converted, tcp_ports, udp_ports)
        (staging / "nfqws2.conf").write_text(config_text, encoding="utf-8", newline="\n")
        _render_web_import(config_text, build_settings, bundle)

        report_text = _render_report(
            build_settings, profile_path, len(raw_profiles), len(converted), tcp_ports, udp_ports, diagnostics
        )
        (staging / "REPORT.md").write_text(report_text, encoding="utf-8", newline="\n")
        files = [
            path.relative_to(staging).as_posix()
            for path in sorted(staging.rglob("*"))
            if path.is_file()
        ]
        files.append("report.json")
        files = sorted(set(files))
        machine_report = {
            "version": __version__,
            "source": profile_path.as_posix(),
            "target": settings.target,
            "profiles_read": len(raw_profiles),
            "profiles_written": len(converted),
            "tls_fake_mode": settings.tls_fake_mode,
            "fake_repeats_limit": settings.fake_repeats_limit,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "diagnostics": [asdict(item) for item in diagnostics],
            "files": files,
        }
        (staging / "report.json").write_text(
            json.dumps(machine_report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    try:
        if final_output.exists():
            final_output.rmdir()
        staging.rename(final_output)
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        try:
            final_output.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        raise ConversionError(f"Не удалось создать выходной каталог {final_output}: {error}") from error

    config_path = final_output / "nfqws2.conf"
    report_path = final_output / "REPORT.md"
    archive_path = _write_archive(final_output) if settings.archive else None
    return ConversionResult(
        final_output,
        config_path,
        report_path,
        archive_path,
        len(raw_profiles),
        len(converted),
        tcp_ports,
        udp_ports,
        diagnostics,
    )
