# Запуск и первый запуск

## Что нужно

- Python 3.10 или новее с Tkinter.
- Отдельно распакованная папка `zapret-discord-youtube` (Flowseal).
- Для автоматической установки — Keenetic с пакетом `nfqws2-keenetic`.

## Запуск из исходников

1. На странице репозитория нажмите **Code → Download ZIP** или клонируйте его:

   ```powershell
   git clone https://github.com/lopatin2012/zapret-keenetic-converter-by-to-work.git
   cd zapret-keenetic-converter-by-to-work
   ```

2. Запустите приложение:

   ```powershell
   .\Запустить конвертер.cmd
   ```

   или:

   ```powershell
   py -3 -m zapret_keenetic.gui
   ```

3. Отдельно распакуйте Flowseal и выберите его папку в приложении.

Готовой Windows-сборки в этом репозитории пока нет — релизы не публиковались.
Запускать нужно из исходников; Python и Tkinter должны быть установлены.

## Установка через pip

```powershell
py -3 -m pip install .
zapret-keenetic-gui
```

Или без установки, из папки проекта:

```powershell
py -3 -m zapret_keenetic.gui
```

## Если появится готовый релиз

Сборка для Windows описана в `.github/workflows/release.yml` и создаётся при
публикации тега `v*`. Если в разделе **Releases** появится ZIP, сверяйте его
SHA-256 с `SHA256SUMS.txt` и не запускайте файл из постороннего источника.
Неподписанный `.exe` может вызвать предупреждение SmartScreen.
