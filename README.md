# NVIDIA_APP — диагностика оверлея для записи (NVIDIA App / Shadow Play / Instant Replay)

Симптом, под который заточен инструмент: **оверлей NVIDIA App не запускается, запись/реплей не стартует**
(Alt+Z молчит, или окно есть, а «Начать запись» серая/сразу отваливается).

В репозитории два файла:

| файл | зачем |
|---|---|
| `nvidia_overlay_diag.py` | самодостатический скрипт (только стандартная библиотека). `scan`/`logs` ничего не меняют; `fix` — умеет чинить, но только переименованием/бэкапом и с журналом отката |
| `run_diag.bat` | «двойной клик» для Windows: сам поднимает права админа, гоняет `selftest` + `scan`, в конце открывает папку `Результат` |
| `run_fix.bat` | «двойной клик, сделай всё сам»: план → автопочинка стека → сам отправляет Alt+Z и проверяет окно. `run_fix.bat undo` — откатить |
| `tests/windows_smoke.py` | смоук-тест Windows-веток на Linux/macOS (фейковый `powershell.exe` + фейковый `winreg`): `python3 tests/windows_smoke.py` |

---

## 1. Быстрый старт (Windows)

```powershell
# PowerShell, из папки, где лежат скрипты
python nvidia_overlay_diag.py scan
```

Готово: в консоли — отчёт с **вердиктом** (ранжированный список причин + план действий), а рядом со скриптом
создана папка **`Результат`** — её и архивируй целиком, этого мне достаточно:

```
Результат/
├── incoming/                 ← сюда кидаешь свои логи/архивы — подхватываются сами
│   └── processed/            ← сюда уходят разобранные (запуск с --inbox-done)
└── run_20261113-193008/      ← один прогон = одна папка (ротация старых: --keep-runs N)
    ├── report.txt            полный отчёт: находки, улики, план, команды
    ├── verdict.txt           только вердикт + план (короткий, для чтения)
    ├── report.json           машиночитаемая версия (находки, snapshot систем, гипотезы, argv)
    ├── manifest.txt          что внутри, чего не хватило, хэш скрипта, как отправить
    ├── logs/                 копии именно тех логов, которые разбирались
    ├── logs_from_zip/        содержимое .zip/.gz из incoming (распаковка без path-slip)
    └── send_to_assistant.zip если хочется один файл вместо папки (--bundle)
```

Вне `Результат/` файлов не появляется: `-o my.txt` пишется внутрь папки прогона (абсолютный путь уважаем),
`--no-sink` — не писать вообще ничего.

Поток «положил лог → разобрал»:

```powershell
copy C:\NVIDIA\Logs\nvlog*.log Результат\incoming\    # или перетащи файлы в incoming мышкой
python nvidia_overlay_diag.py logs --inbox-done         # разберёт всё из incoming и почистит его
```

Полезные варианты:

```powershell
python nvidia_overlay_diag.py scan                     # полный отчёт в консоль
python nvidia_overlay_diag.py scan -o report.txt       # сохранить (UTF-8, Notepad-совместимо)
python nvidia_overlay_diag.py scan --json -o report.json   # машиночитаемый вариант
python nvidia_overlay_diag.py scan --only-problems     # скрыть «всё в порядке»-строки
python nvidia_overlay_diag.py scan --no-logs --no-events   # только живые проверки
python nvidia_overlay_diag.py scan --elevate           # перезапуститься с правами админа
python nvidia_overlay_diag.py logs "C:\ProgramData\NVIDIA Corporation" --context 8
python nvidia_overlay_diag.py logs - < fragment.log    # разобрать вставленный кусок лога
python nvidia_overlay_diag.py hypotheses --from report.json   # перезаказать вердикт из сохранённого отчёта
python nvidia_overlay_diag.py logs --inbox-done               # разобрать incoming и почистить его
python nvidia_overlay_diag.py scan --out-dir D:\Diag --keep-runs 5 --copy-mb 40
python nvidia_overlay_diag.py verify --wait 40         # после правок: дожидается процесса NVIDIA Overlay.exe
python nvidia_overlay_diag.py fix --dry-run            # что он собирается сделать (ничего не трогая)
python nvidia_overlay_diag.py fix                      # делает сам: сервисы/Drs/кэш/конфиг/хоткеи + Alt+Z
python nvidia_overlay_diag.py fix --undo               # откатить последний прогон по fix_journal.json
python nvidia_overlay_diag.py selftest                 # проверка, что сам парсер/база исправны
python nvidia_overlay_diag.py list-signatures          # что именно ищется в логах
```

Флаги: `--json`, `-o FILE`, `--bundle [ZIP]`, `--only-problems`, `--quiet`, `--width`, `--context`, `--tail-kb`,
`--max-files`, `--all-files`, `--days`, `--no-logs`, `--no-events`, `--elevate`, `--out-dir DIR`, `--no-sink`,
`--no-zip`, `--inbox-done`, `--keep-runs N`, `--copy-mb N`, `--kb FILE`, `--keep-foreign`.
Для `fix`: `--dry-run`, `--yes` (по умолчанию и так делает без вопросов), `--ask` (спрашивать каждый шаг),
`--only ids` / `--skip ids`, `--wait N`, `--keys alt+z`, `--reinstall`, `--undo`, `--elevate`.

`--keep-foreign` — не пропускать заведомо чужие логи. По умолчанию файл, в первых 400 строках которого нет ни
одного NVIDIA-маркера (или видны признаки телеметрии Office/браузера), помечается как `log.not_nvidia` и не
разбирается: такие файлы рождают ложные CRITICAL («краш», «NVENC»), которых у NVIDIA нет.

Папка результатов по умолчанию — `<откуда запустил>\Результат` (переопределение: `--out-dir` или переменная
окружения `NVIDIA_DIAG_OUT`). Если создать её нельзя (права, сетевой путь) — скрипт пишет только в консоль
и сообщает причину в `manifest.txt` и в блоке «Заметки сбора». Объём копий логов ограничен `--copy-mb`
(по умолчанию 18 МБ) — для «всего сразу» ставь `--copy-mb 60`.

Только Python, без зависимостей: **Python 3.9+**. `logs`, `list-signatures`, `selftest`, `--from`
работают на любой ОС (можно разобрать логи, снятые с Windows, из-под Linux/macOS).
`scan`/`verify` имеют смысл только в Windows.

## 2. Что именно проверяется

**Живые проверки (`scan`)**

1. Сборка Windows (NVIDIA App требует 19041+), права (админ/не админ), **тип сессии** — `Console` vs RDP.
2. Наличие компонентов: `NVIDIA Overlay.exe` (ищется рекурсивно по `Program Files\NVIDIA Corporation`, глубина ограничена),
   `nvcontainer.exe`, признаки «NVIDIA App + GeForce Experience стоят вместе», подозрительно маленькие exe.
3. Видеодрайвер/GPU: `Win32_VideoController` (статус, версия, разрешение), `nvidia-smi`,
   **гибридная графика** (2+ активных адаптера = Optimus/MUX — типичная причина чёрного кадра и «оверлея нет»).
4. Все сервисы NVIDIA: кто `Running`, кто `Stopped`, кто **отключён твикерами** (`StartMode=Disabled/Manual`) —
   с разбором по критичным для оверлея (`NVDisplay.ContainerLocalSystem`, App/Telemetry-контейнеры).
5. Процессы: запущен ли `NVIDIA Overlay.exe`, `nvcontainer.exe`, сам NVIDIA App; какие аргументы у процесса.
6. Конфигы: поиск `Settings.json`/`*.json` настроек в ProgramData/Program Files/LocalAppData, парсинг JSON,
   поиск флагов `overlay/capture/record/replay = false` и путей вида `D:\...`, проверка этих путей
   (существование, свободное место, OneDrive, «ожидается папка, а тут файл»), битый JSON → отдельная находка.
7. Реестр: обход `HKLM\SOFTWARE\NVIDIA Corporation`, `HKLM\SOFTWARE\Policies\NVIDIA Corporation`,
   `HKCU\Software\NVIDIA Corporation` с поиском значений по ключевым словам (overlay/capture/record/…) —
   находятся «выключатели» и **корпоративные политики** (в приложении галки при них серые).
8. Защитники: активные AV из `SecurityCenter2`, **Controlled Folder Access**, записи `Get-MpThreatDetection`
   по NVIDIA, SmartScreen, а также **Code Integrity (WDAC)** в журнале.
9. Конфликтующий софт в процессах: RTSS/Afterburner, Steam, Discord, Game Bar, Nahimic/Sonic, Razer, iCUE,
   G Hub, OBS, XSplit, Fraps/Bandicam, EVGA, Special K / Lossless Scaling / MangoHUD, AutoHotkey/PowerToys, HWiNFO.
10. Куда пишется: папка «Видео» (через `User Shell Folders`), свободное место, политики `GameDVR`/Game Bar.
11. Журнал событий за `--days` (по умолчанию 3): `nvlddmkm` (TDR/`ID 4101`), ошибки уровня Critical/Error в System,
    `Application Error/Hang/WER` с NVIDIA-строками (**Faulting module** — по нему видно, чья это DLL), CodeIntegrity-блокировки,
    Kernel-Power 41.
12. Автопоиск и разбор самых свежих логов (`nvlog*`, `NvContainer*`, `*overlay*`, `*installer*`, `*.etl`, …) —
    см. раздел 3.

**Разбор логов (`scan` + `logs`)** — 27 сигнатур, каждая = регексп + «что это значит» + конкретные шаги + голос за гипотезу:

`log.cef` (CEF/GPU-process оверлея падает) · `log.overlay_fail` · `log.overlay_disabled` · `log.hook_blocked`
(инъекция/`SetWindowsHookEx`) · `log.conflict_software` · `log.access_denied`/`log.session_isolation` ·
`log.desktop_duplication` (DXGI/DuplicateOutput) · `log.display_enum` · `log.nvenc` · `log.gpu_lost` (device lost/TDR) ·
`log.container` (nvcontainer/pipe/IPC) · `log.storage` · `log.config_corrupt` · `log.plugin_missing` · `log.av_block` ·
`log.net` · `log.installer` · `log.oom` · `log.timeout` · `log.crash_generic` · `log.record_fail` · `log.hotkey` ·
`log.hdr` · `log.driver` · `log.os_unsupported` · `log.power_graphic` · `log.first_severe` + `log.unknown_errors`.

Две эвристики, которые обычно и дают правильный ответ:

* **`log.first_severe`** — корень каскада почти всегда в *самой верхней* CRITICAL/HIGH ошибке; всё, что ниже
  («retry», «failed to start», «timeout»), — последствия. Эта строка получает максимальный вес и становится вердиктом №1.
* **`log.unknown_errors`** — строки, похожие на ошибку, но не описанные базой: нормализуются (цифры → `N`),
  группируются и печатаются с номерами строк. Именно их текст стоит дослать мне, чтобы я добавил сигнатуру.

**Вердикт.** Находки голосуют за 15 гипотез-причин (`svc`, `overlay_proc`, `disabled`, `elevated`, `conflict`,
`blocked`, `capture_target`, `encoder`, `storage`, `driver`, `app_ver`, `config_corrupt`, `hotkey`, `log_nothing`, `unknown`)
весом своей серьёзности; лог-улики чуть слабее живых проверок. На выходе — отсортированный список
«вот это, похоже, причина → делай по шагам», без дублей шагов между гипотезами.

## 3. Где искать логи (скрипт делает это сам)

Корни автопоиска (пути могут отличаться от твоей сборки — поэтому ищется по маске имён, а не по жёсткому списку):

```
C:\ProgramData\NVIDIA Corporation\**
C:\Program Files\NVIDIA Corporation\**
C:\Program Files (x86)\NVIDIA Corporation\**
%LOCALAPPDATA%\NVIDIA Corporation\**   %APPDATA%\NVIDIA Corporation\**
%TEMP%\**                              C:\Windows\Temp\**
```

Дополнительно: `C:\Windows\Logs\NVDisplay*`, `C:\Program Files\NVIDIA Corporation\Installer2\*.log`,
`C:\Windows\INF\setupapi.dev.log` (для драйвера). Если лог лежит в необычном месте — добавь путь аргументом:

```powershell
python nvidia_overlay_diag.py scan "D:\Logs" "C:\Users\me\Downloads\nvlog_2026-11-13.log" --bundle diag.zip
```

## 4. Режим `fix` — «пусть скрипт делает всё сам»

`fix` сначала делает полную диагностику (как `scan`), потом выполняет шаги починки **по порядку** и в конце
**сам отправляет Alt+Z** (SendInput) и проверяет, появилось ли окно оверлея. Каждый шаг изолирован: упал —
записали находку и идём дальше.

| шаг | что делает | обратимость |
|---|---|---|
| `kill` | `taskkill /f /t /im "NVIDIA Overlay.exe" /t` + завершает `NVIDIA App.exe` (убивает zombie-хосты, из-за которых App обращается не к тому pid) | не требуется |
| `svc` | `Restart-Service NVDisplay.ContainerLocalSystem,NvContainerLocalSystem -Force` | не требуется |
| `drs` | переименовывает `C:\ProgramData\NVIDIA Corporation\Drs` → `Drs.diagbak-<дата>`; драйвер пересоздаёт базу профилей (лечит `NVAPI error -132`, `isEnableHook: 0`, `unknown DRV value: 'none'`) | `--undo` вернёт имя |
| `cef` | переименовывает кэш UI-рантайма (`Cache`, `GPUCache`, `Code Cache`, `ShaderCache`, `blob_storage`, `Network`) в `*.diagbak-<дата>` | `--undo` |
| `settings` | в JSON-конфиге App включает **уже существующие** ключи `overlay` / `instant_replay` / `record` (ложь → правда); чужие ключи не создаёт, файл сначала копирует в бэкап | бэкап в `%TEMP%`, путь в журнале |
| `hotkey` | удаляет **пустые** значения хоткеев в `HKLM\HKCU\...\NVIDIA Corporation\...\Hotkey...` (у тебя в логах `GetHotkeyProperty: reg read failed` и `Hotkey:  State: OpenIGO` — привязка пустая) | старое значение (пусто) в журнале |
| `reinstall` | только с флагом `--reinstall`: находит в кэше загрузок `setup.exe` полного пакета и запускает его — тебе остаётся нажать «Выборочная установка» и включить захват. Это **решающий** шаг, когда `Installer2\Stripped\ShadowPlay = 1` | — |
| `app` | стартует `NVIDIA App.exe` (одним экземпляром) | — |
| `probe` | отправляет клавиши (`--keys`, по умолчанию `alt+z`), ждёт `--wait` с, ищет видимое окно процесса `NVIDIA Overlay.exe` через `EnumWindows`, и считает, **наросло** ли число ошибок в `CaptureCore.log` | — |

Что важно про безопасность:

* **ничего не удаляется** — только `rename` с суффиксом `.diagbak-<дата>` и бэкапы; `undo` возвращает как было;
* без прав администратора (`net session` / `IsUserAnAdmin`) `fix` автоматически уходит в режим плана и пишет об этом;
* `--dry-run` = только план (команды видны в `fix_report.txt`, ничего не выполняется); `--ask` = спросить перед каждым шагом;
* после прогона в папке прогона лежат `fix_journal.json` (что и в каком порядке сделано, для отката) и `fix_report.txt`
  (план, команды, «до → после» по метрикам, итог пробы Alt+Z);
* код возврата: `0` — окно оверлея появилось (или проб не было), `2` — окно не появилось (`.bat` по этому коду
  подсказывает следующий шаг).

Метрики «до → после» считаются по живым логам: `wait_overlay_ready`, `showgfe_fail`, `ipc_sync_err`, `ddi_shim`,
`window_gone`, `drs_132`, `hooks_off` — если после `fix` прирост нулевой, стек живой; если `wait_overlay_ready`
продолжает расти — дело в недоустановленном компоненте (`--reinstall`).

```powershell
python nvidia_overlay_diag.py fix --dry-run        # посмотреть план
python nvidia_overlay_diag.py fix                  # сделать всё самому, с Alt+Z в конце
python nvidia_overlay_diag.py fix --only drs,cef   # только конкретные шаги
python nvidia_overlay_diag.py fix --reinstall      # + запустить установщик полного пакета
python nvidia_overlay_diag.py fix --keys "alt+\"   # своя клавиша открытия
python nvidia_overlay_diag.py fix --undo           # откатить последний прогон
run_fix.bat                                        # то же самое двойным кликом (сам поднимет админа)
run_fix.bat undo                                   # откат
```

---

## 5. Как со мной работать (поток «лог → решение»)

1. `python nvidia_overlay_diag.py scan` (или `run_diag.bat` — он то же самое + откроет папку `Результат`).
2. Заархивируй **папку `Результат`** (или только `run_<дата>/`) и пришли целиком. Не выжимай цитаты: мне нужен
   `report.json` (вся картина) и `logs/` (первоисточник), а `manifest.txt` покажет, если чего-то не хватило.
3. Я скажу, какую правку сделать, и добавлю новую сигнатуру в базу, если твой случай не описан.
4. Проверяем: `python nvidia_overlay_diag.py verify --wait 40` (он ждёт появления `NVIDIA Overlay.exe` пока ты жмёшь Alt+Z)
   и затем `scan` ещё раз — сравним «до/после».

Если логи не нашлись (в `manifest.txt` будет «копий логов 0») — минимум, который уже решает: 200+ строк лога от
момента запуска NVIDIA App до нажатия Alt+Z. Положи их в `Результат\incoming\` и запусти `logs`, либо вставь прямо
в консоль: `python nvidia_overlay_diag.py logs -` (PowerShell: Ctrl+Z + Enter; bash: Ctrl+D).

## 6. Расширение базы сигнатур

`list-signatures` показывает формат; своя база подключается без правки скрипта:

```powershell
python nvidia_overlay_diag.py scan --kb my_rules.json
```

```json
[
  {
    "re": "(?i)MyGameProtection\.dll.{0,40}(block|reject)",
    "code": "my.av_hook_block",
    "sev": "HIGH",
    "hyp": "conflict",
    "title": "Мой AV режет инжект оверлея",
    "why": "Пояснение для отчёта.",
    "fixes": ["Добавить исключение на папку NVIDIA App"]
  }
]
```

`sev`: `CRITICAL|HIGH|MEDIUM|LOW|INFO`; `hyp` — id гипотезы из таблицы выше (`unknown` принимает любое своё имя,
но тогда оно не попадёт в «планы» типовых гипотез).

## 7. Типовой чек-лист (если хочется быстро, до запуска скрипта)

1. Alt+Z не открывает оверлей, но `NVIDIA Overlay.exe` в процессах есть → конфликт оверлеев (RTSS/Game Bar/Discord) или перехват клавиши → смени клавишу.
2. Процеса оверлея нет вообще → `services.msc`: `NVIDIA Display Container LS` должен быть Running/Automatic.
3. Оверлей открывается, «Начать запись» нажать нельзя → профиль/разрешение/диск: свободное место и путь без OneDrive.
4. Оверлей открывается только на рабочем столе, в игре — нет → игра от администратора, античит, или «Захват рабочего стола» вместо «Захват игры».
5. Запись начинается и тут же падает/чёрный экран → HDR, HAGS, Optimus/MUX, другой DXGI-захватчик (OBS/Discord/Parsec), TDR (разгон).
6. Всё «зелёное», но ничего не работает после «оптимизаций Windows» → твикеры выключают сервисы/телеметрию и режут `HKLM\SOFTWARE\Policies\NVIDIA Corporation`.
7. Ноутбук: режим «только iGPU/Eco» → оверлея не будет, нужен dGPU-only/MUX.
8. После любых правок — полная перезагрузка, не «Завершение работы» (Fast Startup оставляет состояние).

## 8. Ограничения (важно, чтобы не было ложных надежд)

* Скрипт **читает, но не чинит**: никаких `Set-Service`/реестра/файлов. Команды он только печатает.
* Часть проверок требует админа (сервисы, журнал событий, ProgramData других профилей). Без админа скрипт сам пишет, что ограничено.
* Совпадение сигнатуры = «похоже на причину», а не доказательство: регекспы по логам — эвристики.
* На `logs` читается **хвост** файла (`--tail-kb`, по умолчанию 900 КБ/файл, `--max-files` 25) — свежее важнее.
* `tests/windows_smoke.py` гоняет все Windows-сборщики на заглушках — после правок стоит запускать и его, и `selftest`.
* `selftest` покрывает парсер, базу, вердикт, JSON и `--bundle`; Windows-специфичные сборщики проверяются только прогоном `scan` на реальном ПК.
