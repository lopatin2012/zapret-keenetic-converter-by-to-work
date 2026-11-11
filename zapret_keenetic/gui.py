from __future__ import annotations

import os
import queue
import json
import subprocess
import sys
import threading
import traceback
from pathlib import Path
from tkinter import BooleanVar, IntVar, StringVar, TclError, Tk, filedialog, messagebox

from . import __version__
from .converter import ConversionError, ConversionResult, ConverterSettings, convert
from .deployer import (
    DeploymentResult,
    DeploymentSettings,
    deploy_bundle,
    deployment_report,
)
from .discovery import discover_profiles, find_flowseal_source, suggest_output
from .settings_store import load_settings, save_settings
from .tester import TesterError, is_admin, running_winws, run_strategy_tests, sort_results


TARGET_LABELS = {
    "Keenetic / Entware": "keenetic",
    "OpenWrt": "openwrt",
}
GAME_FILTER_LABELS = {
    "Выключен": "disabled",
    "TCP и UDP": "all",
    "Только TCP": "tcp",
    "Только UDP": "udp",
}
IPSET_LABELS = {
    "Загруженный список (.backup, если основной пуст или отключён)": "loaded",
    "Текущий ipset-all.txt без замены": "current",
}
INSTALL_MODE_LABELS = {
    "Точный: полностью заменить конфиг выбранной стратегией": "exact",
    "Гибридный: Discord Flowseal + адаптивный YouTube": "hybrid",
}


def _open_path(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


class ConverterApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(f"Flowseal → nfqws2 — конвертер {__version__}")
        self.root.geometry("1060x780")
        self.root.minsize(920, 650)
        self.root.option_add("*tearOff", False)

        self.source = StringVar()
        self.profile = StringVar()
        self.output = StringVar()
        self.target_label = StringVar(value="Keenetic / Entware")
        self.interface = StringVar(value="eth3")
        self.game_filter_label = StringVar(value="Выключен")
        self.ipset_label = StringVar(value="Загруженный список (.backup, если основной пуст или отключён)")
        self.ipv6 = BooleanVar(value=True)
        self.policy_name = StringVar(value="nfqws")
        self.policy_exclude = BooleanVar(value=False)
        self.queue_num = IntVar(value=300)
        self.strict = BooleanVar(value=False)
        self.clone_tls = BooleanVar(value=False)
        self.fake_repeats_limit = StringVar(value="0")
        self.archive = BooleanVar(value=False)
        self.open_result = BooleanVar(value=True)
        self.install_after_convert = BooleanVar(value=False)
        self.install_mode_label = StringVar(value=next(iter(INSTALL_MODE_LABELS)))
        self.router_url = StringVar(value="http://192.168.1.1:90/")
        self.router_user = StringVar(value="root")
        self.router_password = StringVar()
        self.check_services = BooleanVar(value=True)
        self.status = StringVar(value="Выберите папку zapret-discord-youtube")
        self.test_status = StringVar(value="Готово к проверке")
        self.last_output: Path | None = None
        self._output_was_selected = False
        self._busy = False
        self._test_busy = False
        self._test_cancel = threading.Event()
        self._test_messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker_messages: queue.Queue[tuple[str, object]] = queue.Queue()

        self._configure_style()
        self._build()
        self.target_label.trace_add("write", self._on_target_changed)
        self._restore_preferences()

    def _configure_style(self) -> None:
        from .gui_layout import configure_style
        configure_style(self.root)

    def _build(self) -> None:
        from .gui_layout import build
        build(self, __version__, TARGET_LABELS, GAME_FILTER_LABELS, IPSET_LABELS, INSTALL_MODE_LABELS)

    @staticmethod
    def _select_label(mapping: dict[str, str], value: object, variable: StringVar) -> None:
        for label, raw in mapping.items():
            if raw == value:
                variable.set(label)
                return

    def _restore_preferences(self) -> None:
        """Restore remembered choices and try to locate Flowseal automatically."""
        saved = load_settings()
        source = saved.get("source")
        if isinstance(source, str) and Path(source).expanduser().is_dir():
            self.source.set(source)
            self._scan_profiles(quiet=True)
            profile = saved.get("profile")
            if isinstance(profile, str) and profile in tuple(self.profile_box["values"]):
                self.profile.set(profile)

        target = saved.get("target")
        if target in TARGET_LABELS.values():
            self.target_label.set(next(label for label, raw in TARGET_LABELS.items() if raw == target))

        interface = saved.get("interface")
        if isinstance(interface, str):
            self.interface.set(interface)
        self._select_label(GAME_FILTER_LABELS, saved.get("game_filter"), self.game_filter_label)
        self._select_label(IPSET_LABELS, saved.get("ipset_mode"), self.ipset_label)
        self._select_label(INSTALL_MODE_LABELS, saved.get("install_mode"), self.install_mode_label)

        for variable, key in (
            (self.ipv6, "ipv6"),
            (self.policy_exclude, "policy_exclude"),
            (self.strict, "strict"),
            (self.archive, "archive"),
            (self.open_result, "open_result"),
            (self.check_services, "check_services"),
        ):
            value = saved.get(key)
            if isinstance(value, bool):
                variable.set(value)
        if isinstance(saved.get("policy_name"), str):
            self.policy_name.set(saved["policy_name"])
        queue_num = saved.get("queue_num")
        if isinstance(queue_num, int) and 0 <= queue_num <= 65535:
            self.queue_num.set(queue_num)
        repeats = saved.get("fake_repeats_limit")
        if isinstance(repeats, (str, int)):
            self.fake_repeats_limit.set(str(repeats))
        if isinstance(saved.get("router_url"), str):
            self.router_url.set(saved["router_url"])
        if isinstance(saved.get("router_user"), str):
            self.router_user.set(saved["router_user"])
        clone = saved.get("tls_fake_mode") == "clone"
        self.clone_tls.set(clone)
        if target == "keenetic" and isinstance(saved.get("install_after_convert"), bool):
            self.install_after_convert.set(saved["install_after_convert"])
        else:
            self.install_after_convert.set(False)
        self._on_install_changed()

        if not self.profile.get():
            detected = find_flowseal_source()
            if detected is not None:
                self.source.set(str(detected))
                self._output_was_selected = False
                self._scan_profiles(quiet=True)
                self.status.set(
                    "Найдена папка Flowseal. Проверьте стратегию и нажмите «Конвертировать»."
                )
            elif self.source.get().strip():
                self._scan_profiles(quiet=True)
        self._refresh_output()

    def _save_preferences(self) -> None:
        try:
            queue_num = int(self.queue_num.get())
        except (TclError, TypeError, ValueError):
            queue_num = 300
        data = {
            "source": self.source.get().strip(),
            "profile": self.profile.get().strip(),
            "target": TARGET_LABELS.get(self.target_label.get(), "keenetic"),
            "interface": self.interface.get().strip(),
            "game_filter": GAME_FILTER_LABELS.get(self.game_filter_label.get(), "disabled"),
            "ipset_mode": IPSET_LABELS.get(self.ipset_label.get(), "loaded"),
            "ipv6": self.ipv6.get(),
            "policy_name": self.policy_name.get().strip(),
            "policy_exclude": self.policy_exclude.get(),
            "queue_num": queue_num,
            "strict": self.strict.get(),
            "archive": self.archive.get(),
            "open_result": self.open_result.get(),
            "tls_fake_mode": "clone" if self.clone_tls.get() else "source",
            "fake_repeats_limit": self.fake_repeats_limit.get(),
            "install_after_convert": self.install_after_convert.get(),
            "install_mode": INSTALL_MODE_LABELS.get(self.install_mode_label.get(), "exact"),
            "router_url": self.router_url.get().strip(),
            "router_user": self.router_user.get().strip(),
            "check_services": self.check_services.get(),
        }
        try:
            save_settings(data)
        except OSError as error:
            self._write_log(f"Не удалось сохранить настройки: {error}\n")

    def _choose_source(self) -> None:
        initial = self.source.get() or str(Path.home())
        selected = filedialog.askdirectory(title="Выберите папку zapret-discord-youtube", initialdir=initial)
        if not selected:
            return
        self.source.set(selected)
        self._output_was_selected = False
        self._scan_profiles()

    def _scan_profiles(self, quiet: bool = False) -> None:
        source = Path(self.source.get().strip()).expanduser()
        self.status.set("Поиск стратегий…")
        self.root.update_idletasks()
        profiles = discover_profiles(source)
        self.profile_box["values"] = profiles
        if profiles:
            current = self.profile.get()
            self.profile.set(current if current in profiles else profiles[0])
            self.status.set(f"Найдено стратегий: {len(profiles)}")
            self._refresh_output()
        else:
            self.profile.set("")
            self.status.set("Рабочие .bat-стратегии не найдены")
            if not quiet:
                messagebox.showwarning(
                    "Стратегии не найдены",
                    "В выбранной папке не найдены .bat-файлы с распознаваемой командой winws.exe.",
                )

    def _choose_output(self) -> None:
        initial = self.output.get() or str(Path.home())
        selected = filedialog.askdirectory(title="Выберите пустую папку результата", initialdir=initial)
        if selected:
            self.output.set(selected)
            self._output_was_selected = True

    def _on_profile_changed(self, _event: object | None = None) -> None:
        self._output_was_selected = False
        self._refresh_output()

    def _on_target_changed(self, *_args: object) -> None:
        target = TARGET_LABELS[self.target_label.get()]
        if target == "openwrt" and self.interface.get() == "eth3":
            self.interface.set("pppoe-wan")
        elif target == "keenetic" and self.interface.get() == "pppoe-wan":
            self.interface.set("eth3")
        state = "normal" if target == "keenetic" else "disabled"
        self.policy_entry.configure(state=state)
        self.policy_exclude_button.configure(state=state)
        if target != "keenetic":
            self.install_after_convert.set(False)
        self._on_install_changed()
        if not self._output_was_selected:
            self._refresh_output()

    def _on_install_changed(self) -> None:
        enabled = self.install_after_convert.get() and TARGET_LABELS[self.target_label.get()] == "keenetic"
        self.install_check.configure(state="normal" if TARGET_LABELS[self.target_label.get()] == "keenetic" else "disabled")
        if enabled:
            self.auth_panel.pack(fill="x")
        else:
            self.auth_panel.pack_forget()
        self.install_summary.configure(text="Автоматически после конвертации" if enabled else "Вручную через web-интерфейс")
        state = "readonly" if enabled else "disabled"
        self.install_mode_box.configure(state=state)
        entry_state = "normal" if enabled else "disabled"
        self.router_url_entry.configure(state=entry_state)
        self.router_user_entry.configure(state=entry_state)
        self.router_password_entry.configure(state=entry_state)
        self.check_services_button.configure(state=entry_state)
        self.convert_button.configure(
            text="Конвертировать и установить" if enabled else "Конвертировать"
        )

    def _refresh_output(self) -> None:
        source_text = self.source.get().strip()
        profile = self.profile.get().strip()
        if not source_text or not profile or self._output_was_selected:
            return
        target = TARGET_LABELS[self.target_label.get()]
        self.output.set(str(suggest_output(Path(source_text).expanduser(), profile, target)))

    def _settings(self) -> ConverterSettings:
        source_text = self.source.get().strip()
        profile = self.profile.get().strip()
        output_text = self.output.get().strip()
        interface = self.interface.get().strip()
        policy_name = self.policy_name.get().strip()
        try:
            queue_num = int(self.queue_num.get())
        except (TypeError, ValueError, TclError) as error:
            raise ConversionError("Номер NFQUEUE должен быть целым числом") from error
        if not source_text:
            raise ConversionError("Выберите папку zapret-discord-youtube")
        source = Path(source_text).expanduser()
        if not source.is_dir():
            raise ConversionError("Выберите существующую папку zapret-discord-youtube")
        if not profile:
            raise ConversionError("Выберите стратегию")
        if not output_text:
            raise ConversionError("Выберите папку результата")
        output = Path(output_text).expanduser()
        if not interface:
            raise ConversionError("Укажите WAN-интерфейс")
        if not 0 <= queue_num <= 65535:
            raise ConversionError("Номер NFQUEUE должен быть от 0 до 65535")
        target = TARGET_LABELS[self.target_label.get()]
        if target == "keenetic" and not policy_name:
            raise ConversionError("Укажите имя политики Keenetic")
        try:
            repeats_limit = int(self.fake_repeats_limit.get())
        except ValueError as error:
            raise ConversionError("Лимит повторов должен быть целым числом") from error
        if repeats_limit < 0:
            raise ConversionError("Лимит повторов не может быть отрицательным")
        return ConverterSettings(
            source=source,
            profile=profile,
            output=output,
            target=target,
            interface=interface,
            game_filter=GAME_FILTER_LABELS[self.game_filter_label.get()],
            ipset_mode=IPSET_LABELS[self.ipset_label.get()],
            ipv6=self.ipv6.get(),
            policy_name=policy_name or "nfqws",
            policy_exclude=self.policy_exclude.get() if target == "keenetic" else False,
            queue_num=queue_num,
            strict=self.strict.get(),
            archive=self.archive.get(),
            tls_fake_mode="clone" if self.clone_tls.get() else "source",
            fake_repeats_limit=repeats_limit or None,
        )

    def _deployment_settings(self, conversion: ConverterSettings) -> DeploymentSettings | None:
        if not self.install_after_convert.get():
            return None
        if conversion.target != "keenetic":
            raise ConversionError("Автоматическая установка через Web API поддерживается только для Keenetic")
        router_url = self.router_url.get().strip()
        username = self.router_user.get().strip()
        password = self.router_password.get()
        if not router_url:
            raise ConversionError("Укажите адрес web-интерфейса nfqws2")
        if not username:
            raise ConversionError("Укажите пользователя web-интерфейса nfqws2")
        if not password:
            raise ConversionError("Введите пароль web-интерфейса nfqws2")
        return DeploymentSettings(
            bundle=conversion.output,
            router_url=router_url,
            username=username,
            password=password,
            mode=INSTALL_MODE_LABELS[self.install_mode_label.get()],
            check_services=self.check_services.get(),
        )

    def _start_conversion(self) -> None:
        if self._busy:
            return
        try:
            settings = self._settings()
            deployment = self._deployment_settings(settings)
        except (ConversionError, OSError) as error:
            messagebox.showerror("Не заполнены параметры", str(error))
            return
        if deployment and not messagebox.askyesno(
            "Подтверждение установки",
            "Программа создаст локальную резервную копию, загрузит списки и nfqws2.conf "
            "на роутер, затем перезапустит службу. Продолжить?",
        ):
            return
        self._busy = True
        self.convert_button.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.report_button.configure(state="disabled")
        self.progress.start(12)
        self.status.set("Конвертация…")
        self._write_log("Запуск конвертации…\n", clear=True)
        threading.Thread(target=self._convert_worker, args=(settings, deployment), daemon=True).start()
        self.root.after(100, self._poll_worker)

    def _convert_worker(
        self, settings: ConverterSettings, deployment: DeploymentSettings | None
    ) -> None:
        try:
            conversion = convert(settings)
        except Exception as error:
            self._worker_messages.put(("conversion_error", (str(error), traceback.format_exc())))
            return

        installed: DeploymentResult | None = None
        if deployment:
            try:
                installed = deploy_bundle(
                    deployment,
                    progress=lambda message: self._worker_messages.put(("progress", message)),
                )
                report_path = conversion.output / "deployment.json"
                report_path.write_text(
                    json.dumps(deployment_report(installed), ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
            except Exception as error:
                self._worker_messages.put(
                    ("deployment_error", (conversion, str(error), traceback.format_exc()))
                )
                return
        self._worker_messages.put(("success", (conversion, installed)))

    def _poll_worker(self) -> None:
        try:
            kind, payload = self._worker_messages.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_worker)
            return
        if kind == "progress":
            self.status.set(str(payload))
            self._write_log(str(payload) + "\n")
            self.root.after(100, self._poll_worker)
        elif kind == "success" and isinstance(payload, tuple):
            conversion, deployment = payload
            self._conversion_finished(conversion, deployment)
        elif kind == "conversion_error" and isinstance(payload, tuple) and len(payload) == 2:
            self._conversion_failed(str(payload[0]), str(payload[1]))
        elif kind == "deployment_error" and isinstance(payload, tuple) and len(payload) == 3:
            self._deployment_failed(payload[0], str(payload[1]), str(payload[2]))
        elif kind == "error" and isinstance(payload, tuple) and len(payload) == 2:
            self._conversion_failed(str(payload[0]), str(payload[1]))
        else:
            self._conversion_failed(str(payload))

    def _deployment_failed(self, conversion: ConversionResult, message: str, detail: str = "") -> None:
        self._busy = False
        self.tabs.select(self.journal_tab)
        self.progress.stop()
        self.convert_button.configure(state="normal")
        self.open_button.configure(state="normal")
        self.report_button.configure(state="normal")
        self.last_output = conversion.output
        self.status.set("Установка не выполнена")
        self._write_log(f"ОШИБКА УСТАНОВКИ: {message}\n")
        if detail:
            self._write_log(detail + "\n")
        self._write_log(f"Конвертированный результат сохранён: {conversion.output}\n")
        self.router_password.set("")
        messagebox.showerror(
            "Установка не выполнена",
            f"{message}\n\nКонвертация уже выполнена. Результат сохранён:\n{conversion.output}\n\n"
            "Для гибридного режима нужен nfqws2.conf-opkg на роутере; выберите точный режим "
            "или установите пакет nfqws2-keenetic заново.",
        )
        if not self._output_was_selected:
            self._refresh_output()

    def _conversion_failed(self, message: str, detail: str = "") -> None:
        self._busy = False
        self.tabs.select(self.journal_tab)
        self.progress.stop()
        self.convert_button.configure(state="normal")
        if self.last_output and self.last_output.exists():
            self.open_button.configure(state="normal")
            self.report_button.configure(state="normal")
        self.status.set("Ошибка конвертации")
        self._write_log(f"ОШИБКА: {message}\n")
        if detail:
            self._write_log(detail + "\n")
        self.router_password.set("")
        messagebox.showerror("Конвертация не выполнена", message)
        if not self._output_was_selected:
            self._refresh_output()

    def _conversion_finished(
        self, conversion: ConversionResult, deployment: DeploymentResult | None = None
    ) -> None:
        self._busy = False
        self.tabs.select(self.journal_tab)
        self.progress.stop()
        self.convert_button.configure(state="normal")
        self.open_button.configure(state="normal")
        self.report_button.configure(state="normal")
        self.last_output = conversion.output
        self.status.set("Установлено на роутер" if deployment else "Готово")
        lines = [
            f"Результат: {conversion.output}",
            f"Профили: {conversion.profiles_written}/{conversion.profiles_read}",
            f"Предупреждения: {conversion.warning_count}",
            f"Конфиг: {conversion.config.name}",
            f"Отчёт: {conversion.report.name}",
        ]
        if conversion.archive:
            lines.append(f"ZIP: {conversion.archive}")
        if TARGET_LABELS[self.target_label.get()] == "keenetic":
            lines.append("Веб-интерфейс: web-import/nfqws2.conf")
        if deployment:
            lines.extend(
                (
                    f"Установка: {deployment.mode}",
                    f"Загружено файлов: {len(deployment.files_uploaded)}",
                    f"nfqws2: {deployment.service_version or 'работает'}",
                    f"Резервная копия: {deployment.backup}",
                )
            )
            for check in deployment.connectivity:
                outcome = f"HTTP {check.status}" if check.ok else f"ОШИБКА: {check.error}"
                lines.append(f"Проверка {check.url}: {outcome}")
        for diagnostic in conversion.diagnostics:
            where = f", профиль {diagnostic.profile}" if diagnostic.profile else ""
            lines.append(f"[{diagnostic.level.upper()} / {diagnostic.code}{where}] {diagnostic.message}")
        self._write_log("\n".join(lines) + "\n", clear=True)
        self.router_password.set("")
        self._save_preferences()
        if not self._output_was_selected:
            # Prepare a fresh timestamped path for the next run. The current
            # result stays in last_output and is still available via buttons.
            self._refresh_output()
        if self.open_result.get():
            try:
                _open_path(conversion.output)
            except OSError as error:
                self._write_log(f"Не удалось открыть папку результата: {error}\n")
        messagebox.showinfo(
            "Установка завершена" if deployment else "Конвертация завершена",
            (
                f"Готово. Создано профилей: {conversion.profiles_written}.\n"
                f"Предупреждений: {conversion.warning_count}.\n\n"
                + (
                    f"Конфигурация установлена, nfqws2 работает.\nРезервная копия: {deployment.backup}"
                    if deployment
                    else "Перед установкой откройте REPORT.md."
                )
            ),
        )

    def _start_strategy_test(self) -> None:
        if self._busy or self._test_busy:
            return
        if sys.platform != "win32":
            messagebox.showinfo("Тест стратегий", "Тестер стратегий доступен только в Windows.")
            return
        source_text = self.source.get().strip()
        if not source_text:
            messagebox.showerror("Нет папки Flowseal", "Сначала выберите папку zapret-discord-youtube.")
            return
        source = Path(source_text).expanduser()
        if not source.is_dir():
            messagebox.showerror("Нет папки Flowseal", "Выбранная папка не существует.")
            return
        if not is_admin():
            messagebox.showerror(
                "Нужны права администратора",
                "Тестер запускает winws.exe через WinDivert, поэтому программу нужно "
                "запустить от имени администратора. Закройте конвертер и запустите его снова "
                "командой «Запуск от имени администратора».",
            )
            return
        if running_winws():
            messagebox.showerror(
                "winws уже запущен",
                "Остановите Zapret/Flowseal (или службу zapret) перед тестом. "
                "Тестер не будет останавливать чужой процесс.",
            )
            return
        if not messagebox.askyesno(
            "Запустить тест стратегий",
            "Будет по очереди запускаться winws.exe с каждой стратегией, а сетевой трафик "
            "временно перехватываться. Закройте VPN и сохраните работу.\n\n"
            "Тест может занять несколько минут. Продолжить?",
        ):
            return

        self._test_busy = True
        self._busy = True
        self._test_cancel.clear()
        self._test_messages = queue.Queue()
        self.convert_button.configure(state="disabled")
        self.test_button.configure(state="disabled")
        self.test_stop_button.configure(state="normal")
        self.test_apply_button.configure(state="disabled")
        self.test_tree.delete(*self.test_tree.get_children())
        self._write_test_log("Запуск теста стратегий…\n", clear=True)
        self.test_status.set("Запуск winws…")
        self.progress.start(12)
        threading.Thread(
            target=self._strategy_test_worker,
            args=(source,),
            daemon=True,
        ).start()
        self.root.after(100, self._poll_test_worker)

    def _strategy_test_worker(self, source: Path) -> None:
        try:
            results = run_strategy_tests(
                source,
                progress=lambda message: self._test_messages.put(("progress", message)),
                cancel=self._test_cancel,
            )
        except Exception as error:
            self._test_messages.put(("error", (str(error), traceback.format_exc())))
            return
        self._test_messages.put(("success", results))

    def _poll_test_worker(self) -> None:
        try:
            kind, payload = self._test_messages.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_test_worker)
            return
        if kind == "progress":
            self.test_status.set(str(payload))
            self._write_test_log(str(payload) + "\n")
            self.root.after(100, self._poll_test_worker)
        elif kind == "success":
            self._test_finished(payload if isinstance(payload, list) else [])
        elif kind == "error" and isinstance(payload, tuple) and len(payload) == 2:
            self._test_failed(str(payload[0]), str(payload[1]))
        else:
            self._test_failed(str(payload))

    def _test_finished(self, results: list) -> None:
        self._test_busy = False
        self._busy = False
        self.progress.stop()
        self.convert_button.configure(state="normal")
        self.test_button.configure(state="normal")
        self.test_stop_button.configure(state="disabled")
        self.test_tree.delete(*self.test_tree.get_children())
        ordered = sort_results(results)
        for index, item in enumerate(ordered):
            average = f"{item.average_seconds:.2f}s" if item.average_seconds else "—"
            tags = ("best",) if index == 0 and item.error is None else ()
            if item.error is not None:
                tags = ("failed",)
            self.test_tree.insert(
                "",
                "end",
                values=(item.profile, item.ok_count, item.total, average, item.verdict),
                tags=tags,
            )
        if ordered:
            self.test_apply_button.configure(state="normal")
            best = ordered[0]
            self.test_status.set(
                f"Лучшая: {best.profile} — {best.ok_count}/{best.total}, {best.verdict}"
            )
            self._write_test_log(f"\nЛучшая стратегия: {best.profile}\n", clear=False)
            if best.error:
                self._write_test_log(f"Ошибка запуска: {best.error}\n")
        else:
            self.test_status.set("Тест остановлен или не дал результатов")
        self._write_test_log("Тест завершён. Выберите строку и нажмите «Применить выбранную».\n")

    def _test_failed(self, message: str, detail: str = "") -> None:
        self._test_busy = False
        self._busy = False
        self.progress.stop()
        self.convert_button.configure(state="normal")
        self.test_button.configure(state="normal")
        self.test_stop_button.configure(state="disabled")
        self.test_status.set("Ошибка теста")
        self._write_test_log(f"ОШИБКА: {message}\n")
        if detail:
            self._write_test_log(detail + "\n")
        messagebox.showerror("Тест стратегий не выполнен", message)

    def _stop_strategy_test(self) -> None:
        if not self._test_busy:
            return
        self._test_cancel.set()
        self.test_stop_button.configure(state="disabled")
        self.test_status.set("Останавливаю после текущей проверки…")

    def _apply_test_strategy(self) -> None:
        selection = self.test_tree.selection()
        if not selection:
            messagebox.showinfo("Тест стратегий", "Выберите строку с нужной стратегией.")
            return
        values = self.test_tree.item(selection[0], "values")
        if values:
            self.profile.set(str(values[0]))
            self.tabs.select(0)
            self.status.set(f"Выбрана стратегия {values[0]}. Проверьте WAN-интерфейс и конвертируйте.")

    def _write_test_log(self, text: str, clear: bool = False) -> None:
        self.test_log.configure(state="normal")
        if clear:
            self.test_log.delete("1.0", "end")
        self.test_log.insert("end", text)
        self.test_log.see("end")
        self.test_log.configure(state="disabled")

    def _on_close(self) -> None:
        if self._busy or self._test_busy:
            messagebox.showwarning(
                "Операция выполняется",
                "Дождитесь завершения конвертации, установки или теста стратегий. "
                "Закрытие окна сейчас может оставить winws или роутер в промежуточном состоянии.",
            )
            return
        self._save_preferences()
        self.root.destroy()

    def _write_log(self, text: str, clear: bool = False) -> None:
        self.log.configure(state="normal")
        if clear:
            self.log.delete("1.0", "end")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _open_result(self) -> None:
        if self.last_output and self.last_output.exists():
            try:
                _open_path(self.last_output)
            except OSError as error:
                messagebox.showerror("Не удалось открыть папку", str(error))

    def _open_report(self) -> None:
        if self.last_output:
            report = self.last_output / "REPORT.md"
            if report.is_file():
                try:
                    _open_path(report)
                except OSError as error:
                    messagebox.showerror("Не удалось открыть отчёт", str(error))
                return
        messagebox.showinfo("Отчёт", "Сначала выполните конвертацию.")


def main() -> int:
    if sys.version_info < (3, 10):
        print(
            "Требуется Python 3.10 или новее. Обновите Python и запустите программу снова.",
            file=sys.stderr,
        )
        return 4
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    try:
        root = Tk()
    except TclError as error:
        print(
            "Не удалось открыть графический интерфейс Tcl/Tk. "
            "Установите обычный Python с поддержкой tkinter или используйте CLI.\n"
            f"Техническая ошибка: {error}",
            file=sys.stderr,
        )
        return 3
    app = ConverterApp(root)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
