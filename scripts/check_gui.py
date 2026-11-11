"""Exercise desktop controls without connecting to a router. Requires Tcl/Tk."""
import os
import tempfile
from tkinter import Tk
from pathlib import Path
from tempfile import TemporaryDirectory

from zapret_keenetic.converter import ConversionError
from zapret_keenetic.gui import ConverterApp
from zapret_keenetic.settings_store import load_settings

SETTINGS_PATH = Path(tempfile.gettempdir()) / f"zapret-keenetic-gui-check-{os.getpid()}.json"
os.environ["ZAPRET_CONVERTER_SETTINGS"] = str(SETTINGS_PATH)


def main():
    root = Tk()
    root.withdraw()
    try:
        app = ConverterApp(root)
        root.update_idletasks()
        assert [app.tabs.tab(tab, "text") for tab in app.tabs.tabs()] == [
            "Конвертация",
            "Установка",
            "Тест",
            "Журнал",
        ]
        assert app.test_button.instate(["!disabled"])
        assert app.test_stop_button.instate(["disabled"])
        assert app.test_apply_button.instate(["disabled"])
        assert not app._test_busy
        app.test_status.set("Проверка статуса")
        assert app.test_status.get() == "Проверка статуса"
        assert app.test_status_label.cget("textvariable") == str(app.test_status)
        assert not app.auth_panel.winfo_manager()
        assert app.report_button.instate(["disabled"])
        assert app.open_result.get()
        app.install_after_convert.set(True)
        app._on_install_changed()
        assert app.auth_panel.winfo_manager() == "pack"
        app.target_label.set("OpenWrt")
        assert not app.install_after_convert.get()
        assert not app.auth_panel.winfo_manager()
        assert app.policy_entry.instate(["disabled"])
        assert app.install_check.instate(["disabled"])
        app.target_label.set("Keenetic / Entware")
        assert not app.policy_entry.instate(["disabled"])
        for button in (app.advanced_button, app.experiments_button, app.faq_button):
            button.invoke()
            assert button.cget("text").startswith("▾")
            button.invoke()
            assert button.cget("text").startswith("▸")
        with TemporaryDirectory() as temporary:
            app.source.set(temporary)
            app.profile.set("general.bat")
            app.output.set(str(Path(temporary) / "result"))
            app.ipv6.set(False)
            app.archive.set(True)
            app.policy_exclude.set(True)
            app.strict.set(True)
            app.clone_tls.set(True)
            app.fake_repeats_limit.set("3")
            settings = app._settings()
            assert not settings.ipv6 and settings.archive and settings.policy_exclude and settings.strict
            assert settings.tls_fake_mode == "clone" and settings.fake_repeats_limit == 3
            app.queue_num.set("")
            try:
                app._settings()
            except ConversionError:
                pass
            else:
                raise AssertionError("empty NFQUEUE must be rejected, not crash with TclError")
            app.queue_num.set(300)
            assert not app._busy
            occupied = Path(temporary) / "occupied"
            occupied.mkdir()
            (occupied / "old.txt").write_text("old", encoding="utf-8")
            app.output.set(str(occupied))
            app._output_was_selected = False
            app._refresh_output()
            assert app.output.get() != str(occupied)
            assert not Path(app.output.get()).exists()
            app._save_preferences()
            saved = load_settings()
            assert saved["source"] == temporary
            assert saved["profile"] == "general.bat"
            assert "password" not in str(saved).lower()
        app._write_log("GUI check", clear=True)
        assert app.log.get("1.0", "end").strip() == "GUI check"
        root.update_idletasks()
        print("GUI: tabs, disclosures, installation, platform switching, option binding, settings and log passed.")
    finally:
        root.destroy()
        try:
            SETTINGS_PATH.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()
