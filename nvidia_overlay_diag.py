#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvidia_overlay_diag.py — диагностика оверлея NVIDIA App (запись / Instant Replay / Studio Mode).

Зачем:
  Оверлей для записи не запускается по ограниченному числу причин: не поднят nvcontainer /
  Display Container, убит или не запущен NVIDIA Overlay.exe (CEF), конфликт стороннего
  оверлея/хуков, блокировка антивирусом или Controlled Folder Access, запись из-под
  непривилегированной сессии в повышенно-запущенную игру, HDR/Desktop Duplication,
  NVENC/неподдерживаемый GPU, нехватка места, кривые/устаревшие настройки и остатки драйвера.
  Скрипт собирает всё это в один отчёт и по логам сопоставляет строки с базой сигнатур.

Режимы:
  scan            живая диагностика системы (Windows) + разбор самых свежих логов + журнал событий
  logs ФАЙЛ|ПАПКА разбор логов по базе сигнатур (работает на любой ОС; ПАПКА обходится по маске имён)
  logs -          прочитать лог из stdin (удобно вставить кусок лога)
  verify          короткая проверка "починилось или нет": сервисы + ожидание процесса NVIDIA Overlay.exe
  list-signatures показать базу сигнатур (можно расширять своим файлом: --kb mine.json)
  hypotheses      только вероятные причины и порядок действий (можно из сохранённого отчёта: --from report.json)
  selftest        самопроверка парсера/базы на встроенной фикстуре (полезно после правок сигнатур)

Примеры (PowerShell):
  python nvidia_overlay_diag.py scan --bundle diag.zip
  python nvidia_overlay_diag.py scan --json -o report.json
  python nvidia_overlay_diag.py logs "C:\\ProgramData\\NVIDIA Corporation" --only-problems
  python nvidia_overlay_diag.py verify --wait 40
  python nvidia_overlay_diag.py selftest

Выход — текстовый отчёт с вердиктом (ТОП гипотез + план действий). Прикладывай report.txt/zip —
разберу и подскажу правку.

Права: скрипт ничего не меняет в системе, только читает. Флагов "почини сам" намеренно нет.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import dataclasses
import datetime as dt
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# --------------------------------------------------------------------------------------
# Мелкая утилитарная инфраструктура
# --------------------------------------------------------------------------------------

IS_WIN = os.name == "nt"

if IS_WIN:
    try:  # pragma: no cover - зависит от консоли
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

try:  # Windows-only
    import winreg  # type: ignore

    HAS_WINREG = True
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore
    HAS_WINREG = False


# Уровни важности находок (используются и для веса гипотез).
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
SEV_WEIGHT = {"CRITICAL": 9, "HIGH": 6, "MEDIUM": 3, "LOW": 2, "INFO": 1, "OK": 0}
SEV_MARK = {
    "CRITICAL": "[!!]",
    "HIGH": "[!!]",
    "MEDIUM": "[! ]",
    "LOW": "[~ ]",
    "INFO": "[i ]",
    "OK": "[ok]",
}


def now_iso() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat(sep=" ")


@dataclasses.dataclass
class Finding:
    """Одна находка диагностики (из системы или из лога)."""

    severity: str
    code: str            # машинный id, например "svc.stopped"
    title: str           # человекочитаемо
    detail: str = ""     # что именно увидели
    evidence: list[str] = dataclasses.field(default_factory=list)
    fixes: list[str] = dataclasses.field(default_factory=list)
    source: str = "system"   # system | log:<имя файла> | events
    hypothesis: str = "?"    # id гипотезы, к которой относится находка

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["weight"] = SEV_WEIGHT.get(self.severity, 1)
        return d

    def render(self, width: int = 100, verbose: bool = True) -> str:
        out = [f"{SEV_MARK.get(self.severity, '[? ]')} {self.severity:<8} {self.title}  <{self.code}>"]
        if self.detail:
            out.append(_indent(_wrap(self.detail, width - 6), "       "))
        if verbose and self.evidence:
            out.append(_indent("улики:", "       "))
            for e in self.evidence[:8]:
                out.append(_indent(f"- {e}", "         "))
            if len(self.evidence) > 8:
                out.append(_indent(f"... ещё {len(self.evidence) - 8}", "         "))
        if verbose and self.fixes:
            out.append(_indent("что делать:", "       "))
            for i, f in enumerate(self.fixes, 1):
                out.append(_indent(f"{i}) {f}", "         "))
        return "\n".join(out)


def _wrap(text: str, width: int) -> str:
    width = max(40, width)
    return "\n".join(textwrap.fill(line, width) for line in str(text).splitlines() if line.strip())


def _indent(text: str, pad: str) -> str:
    return "\n".join(pad + line if line.strip() else line for line in text.splitlines())


# --------------------------------------------------------------------------------------
# Гипотезы (корневые причины). Находки голосуют за них весом своей серьёзности.
# --------------------------------------------------------------------------------------

HYPOTHESES: dict[str, dict[str, Any]] = {
    "svc": {
        "title": "Не работает сервис/контейнер NVIDIA (nvcontainer / Display Container)",
        "fixes": [
            "PowerShell (админ): Get-Service *NVIDIA*,*Nv* | Select Name,Status,StartType — все NVIDIA-сервисы должны быть Running/Automatic.",
            "Перезапусти: Restart-Service NVDisplay.ContainerLocalSystem -Force; если есть NVIDIA App Container / NvidiaAppContainer — его тоже.",
            "Если сервис остановлен/отключён (StartType=Disabled): Set-Service <Имя> -StartupType Automatic; Start-Service <Имя>.",
            "Если не стартует — переустанови драйвер с галкой 'Чистая установка' (NVIDIA App → Драйверы), либо 'Изменить установки' → восстановить Component.",
        ],
    },
    "overlay_proc": {
        "title": "Не запускается сам процесс оверлея (NVIDIA Overlay.exe / CEF)",
        "fixes": [
            "Проверь, что файл существует: C:\\Program Files\\NVIDIA Corporation\\NVIDIA App\\CEF\\NVIDIA Overlay.exe",
            "Запусти NVIDIA App и нажми Alt+Z; подожди 10-20 с, затем Task Manager → детали → NVIDIA Overlay.exe.",
            "Добавь папку C:\\Program Files\\NVIDIA Corporation\\NVIDIA App в исключения антивируса/Defender (папку целиком, не один exe).",
            "Отключи режим 'Экономия памяти'/совместимости, удали переменные окружения CEF_* и --disable-gpu-аккуратно: NVIDIA Overlay падает без аппаратного ускорения.",
            "Если в логах виден 'GPU process crash'/CEF assert → полный цикл: DDU (безопасный режим) → свежий драйвер с сайта NVIDIA App.",
        ],
    },
    "disabled": {
        "title": "Оверлей/запись выключены в настройках NVIDIA App (или политиками/реестром)",
        "fixes": [
            "NVIDIA App → Настройки → 'Внутриигровой оверлей' → включить; 'Запись' / Instant Replay → включить и выбрать горячую клавишу.",
            "Проверь, что не стоит 'Только Studio Mode'/'Только скриншоты' и что выбран профиль записи.",
            "GPO: HKLM\\SOFTWARE\\Policies\\NVIDIA Corporation — если там есть значения Overlay/Capture/Privacy=0, это политика ИТ-отдела, снимай через gpedit.",
            "После изменений выйди из NVIDIA App полностью (трей → Выход) и запусти заново, а не только закрой окно.",
        ],
    },
    "elevated": {
        "title": "Привилегии: игра/приложение запущены с повышенными правами, а оверлей — нет",
        "fixes": [
            "Оверлей не может показаться и перехватывать клавиши в окне, запущенном 'От имени администратора', если сам он обычный.",
            "Запусти NVIDIA App от имени администратора (или убери 'От имени администратора' с ярлыка игры).",
            "Отключи UAC-обход только для игры; не держи весь Windows под админом.",
            "Игры из Microsoft Store/UWP и античит-защищённые (EAC/Vanguard) часто режут оверлеи — там нужен режим совместимости игры в окне.",
        ],
    },
    "conflict": {
        "title": "Конфликт другого оверлея/хука/захвата (RTSS, Steam, Discord, Nahimic и т.п.)",
        "fixes": [
            "Выключи по одному и проверяй Alt+Z: MSI Afterburner + RivaTuner (RTSS), Steam Overlay, Discord Game Overlay, Xbox Game Bar, Nahimic/Sonic Studio, Razer, iCUE, Special K, Lossless Scaling, MangoHUD, OBS-виртуальная камера.",
            "RTSS: сними галку 'Application-specific' и 'CustomDirectX'/'On-Screen Display disabled'; чаще всего именно он первым занимает хук.",
            "Xbox Game Bar: Параметры → Игры → Xbox Game Bar → выкл + HKCU\\Software\\Microsoft\\GameBar 'AllowGameDVR'=0.",
            "Антивирус/фильтры: ESET/DrWeb/Kaspersky/Avast 'Экран памяти', 'Anti-stealth', 'Защита веб-камеры' — отключи на тест.",
        ],
    },
    "blocked": {
        "title": "Блокировка запуска/инъекции защитником Windows (Controlled Folder Access, SmartScreen, Code Integrity/WDAC) или антивирусом",
        "fixes": [
            "Безопасность Windows → Защита вируса и угрозы → Управление приложениями и файлами (Controlled Folder Access) → 'Разрешить взаимодействие с приложением' → добавь NVIDIA App.exe и NVIDIA Overlay.exe.",
            "Просмотрите 'Журнал защиты' на предмет 'Заблокировано' для путей C:\\Program Files\\NVIDIA Corporation.",
            "Если стоит LRWDAC/WDAC/Policy Rule из корпоративной сборки — нужен исключительный policy для C:\\Program Files\\NVIDIA Corporation.",
            "Проверь, не в карантине ли NVIDIA Overlay.exe / nvcontainer.exe.",
        ],
    },
    "capture_target": {
        "title": "Не с чем захватывать: Desktop Duplication / RDP / HDR / мультимонитор-гибрид (Optimus)",
        "fixes": [
            "Запись через RDP, быстрый запуск/выход из учётки, сессия 'Другой пользователь', виртуалка без GPU — оверлей не работает по дизайну.",
            "Ноутбук с Optimus/гибридной графикой: переключи вывод экрана на дискретную nVidia (MUX/dGPU-only), либо запиши через 'Захват рабочего стола' вместо 'Захват игры'.",
            "Выключи HDR (Параметры → Дисплей → HDR) и 'Аппаратное ускоречение планирования графического процесса' (HAGS) на тест, затем верни по одному.",
            "Закрой всё, что тоже делает DXGI duplication: OBS (проектор/витрина), Discord стрим, Xbox Game Bar запись, Miracast, удалённый доступ (Parsec/Sunshine/Moonlight).",
            "В мультимониторных схемах 'только второй экран' оверлей иногда цепляется не за тот вывод — попробуй 'Расширить эти экраны'.",
        ],
    },
    "encoder": {
        "title": "Проблема кодировщика/видеоядра (NVENC, unsupported GPU, драйвер без видеодрайвера)",
        "fixes": [
            "nvidia-smi должен показывать GPU и версию драйвера; 'No devices were found' = проблема драйвера/Device Manager Code 43.",
            "Проверь, что NVENC сессии не заняты (OBS/xsplit/шаринг). NVIDIA Consumer-драйвер лимитировал число параллельных NVENC-сессий; закрой лишние захватчики.",
            "Снизь кодек H.265 → H.264 и битрейт/разрешение на тест; на очень старых GPU (GT/GTS, Kepler без NVENC gen) запись может быть недоступна.",
            "Обнови драйвер (Studio/Game Ready — как используешь), при 'Driver-NVENC timeout' — отключи 'Низкая задержка' и 'Whisper Mode'.",
        ],
    },
    "storage": {
        "title": "Куда писать: папка записи недоступна/нет места/сеть-диск/OneDrive",
        "fixes": [
            "Оставь минимум 20-30 ГБ свободных на диске записи; 'Capture folder' не должна быть на сетевом, съемном или зашифрованном (BitLocker-removable) диске.",
            "Убери папку записи из OneDrive/виртуальных папок 'Файлы по требованию' — иначе запись падает на середине.",
            "Путь без юникода/пробелов/символов # и & на время теста: D:\\NVCapture.",
            "Проверь, что на папке есть Full Control для твоего пользователя (свойства → Безопасность).",
        ],
    },
    "driver": {
        "title": "Кривая/остаточная установка драйвера или версия ниже требуемой",
        "fixes": [
            "Свежий драйвер (не Windows Update), установка 'Выборочная' → 'Чистая установка'.",
            "После 'Чистой установки' перезагрузись и включи оверлей заново в NVIDIA App.",
            "Видишь в System Event Log 'nvlddmkm ... stopped responding' (TDR, ID 4101) — снизь разгон/UNDERT, отключи 'PowerMizer' тюнинг, MSI-Afterburner кривые.",
            "Если ставил модифицированные драйверы/NVCleanstInstall/NoDVA — верни официальные для теста.",
        ],
    },
    "app_ver": {
        "title": "NVIDIA App / GeForce Experience не установлен полностью или версии рассинхронизированы",
        "fixes": [
            "NVIDIA App и GFE одновременно ставить нельзя — останется 'висящая' установка, у которой оверлей не поднимается. Удали одно из двух (Параметры → Приложения).",
            "Помогает: удалить NVIDIA App, перегрузиться, поставить свежий установщик с nvidia.ru, выбрать 'Драйвер + NVIDIA App'.",
            "Если установка падает (Error 1606 / 'older version installed') — см. C:\\Program Files\\NVIDIA Corporation\\Installer2\\*.log",
        ],
    },
    "config_corrupt": {
        "title": "Повреждены настройки/кэш NVIDIA App (Settings.json, кэш CEF, конфиг профиля записи)",
        "fixes": [
            "Закрой NVIDIA App (трей → Выход), переименуй C:\\ProgramData\\NVIDIA Corporation\\NVIDIA App\\ (или GeForce Experience\\) в *.bak и запусти приложение заново — настройки пересоздадутся.",
            "Локальный кэш: удали %LOCALAPPDATA%\\NVIDIA Corporation\\NVIDIA App\\ (или 'NVIDIA GeForce Experience') — слетают настройки интерфейса, но часто чинит CEF-краш.",
            "Проверь, что папки ProgramData не 'Read-only' и пользователь имеет право записи.",
        ],
    },
    "hotkey": {
        "title": "Горячая клавиша не регистрируется / не тот ввод (Alt+Z перехвачен)",
        "fixes": [
            "Смени клавишу в NVIDIA App → Настройки → Горячие клавиши (например на F9), затем проверь в игре и на рабочем столе.",
            "Перехватчики: iCUE/Razer Synapse/Logitech G Hub/AutoHotkey/PowerToys FancyZones+Keyboard Manager, 'Win+G' назначенный другому.",
            "Раскладка: Alt+Z может 'теряться' при русской раскладке — переключись на EN и проверь.",
            "Если оверлей открывается, а клавиша нет — это не 'не запускается', а именно конфликт клавиш.",
        ],
    },
    "log_nothing": {
        "title": "Оверлей вообще не пытается стартовать: в логах нет ни одной строки Overlay/Capture",
        "fixes": [
            "Значит проблема до оверлея: не поднят NVIDIA App (автозагрузка выключена) или убит его контейнер — см. Task Manager → Startup.",
            "Включи подробное логирование и повтори запуск: NVIDIA App → Помощь → 'Собрать отчёт' (или запусти NVIDIA App.exe с --debug).",
            "Проверь, что служба автозапуска не отключена оптимизаторами (Watcher/Predator/'ускорители Windows').",
        ],
    },
    "unknown": {
        "title": "Причина не сводится к типовым — нужен разбор лога",
        "fixes": [
            "Пришли report.txt и папку логов (scan --bundle diag.zip) — разберём строки перед первым 'fail'.",
        ],
    },
}


# --------------------------------------------------------------------------------------
# База сигнатур логов.
#
# Каждая запись: re (регексп), sev, code, title, why, fixes, hyp (гипотеза).
# Это эвристики: совпадение = "похоже на X", а не доказанный факт. База расширяемая:
# свой файл через --kb file.json (тот же формат, без поля "re_namedgroups").
# --------------------------------------------------------------------------------------

SIGNATURES: list[dict[str, Any]] = [
    # ---- процесс/рантайм оверлея (CEF) ----
    dict(
        re=r"(?i)(libcef|cef[a-z ]*(runtime|initiali[sz]ation)|cef\.log|createbrowser|gpu process|(render|browser) process.*(crash|exit|fail)|cef_status)",
        sev="HIGH",
        code="log.cef",
        hyp="overlay_proc",
        title="CEF (UI-рантайм оверлея) падает или не инициализируется",
        why="Оверлей NVIDIA — это CEF-браузер; если libcef/GPU-process не стартует, окно Alt+Z не появится вообще, даже когда всё остальное здорово.",
        fixes=[
            "Удали кэш CEF: %LOCALAPPDATA%\\NVIDIA Corporation\\NVIDIA App (переименуй) и перезапусти приложение.",
            "Убедись, что 'Аппаратный рендеринг' не блокируется: временно отключи HAGS и антивирусный 'защиту браузера'.",
            "Проверь, нет ли переменной окружения, ломающей GPU: CEF_* / --disable-gpu-свичи в 'Ярлык → Объект'.",
            "Крайний шаг: переустановка NVIDIA App начисто.",
        ],
    ),
    dict(
        re=r"(?i)(nvidia\s*overlay|overlay\s*(process|app|window|ui|runtime|host)).{0,80}(fail|error|unable|could\s?not|crash|exit(ed)?|terminat|refus|abort|denied|invalid|missing)",
        sev="HIGH",
        code="log.overlay_fail",
        hyp="overlay_proc",
        title="Прямая ошибка запуска/работы оверлея",
        why="Лог ругается именно на оверлей-компонент — это ядро проблемы, а не побочный шум.",
        fixes=[
            "Смотри 20-40 строк ПЕРЕД этой (скрипт печатает контекст с --context) — там обычно настоящая причина (exception/Access denied).",
            "Проверь наличие и запуск NVIDIA Overlay.exe; добавь папку NVIDIA App в исключения AV.",
        ],
    ),
    dict(
        re=r"(?i)overlay.{0,40}(disabled|not\s+enabled|is\s+off|turn(ed)?\s+on|enable)",
        sev="MEDIUM",
        code="log.overlay_disabled",
        hyp="disabled",
        title="Оверлей выключен в настройках",
        why="Компонент цел, но взведён флаг 'выключено' — процесс не поднимается по настройке.",
        fixes=["NVIDIA App → Настройки → внутриигровой оверлей → Вкл; затем полный выход из приложения и запуск."],
    ),
    # ---- инъекция / хуки / чужие оверлеи ----
    dict(
        re=r"(?i)(hook|inject|detour|SetWindowsHookEx|CreateRemoteThread|LoadLibrary.{0,30}(fail|error)|attach.{0,15}(process|game)|dxgi\.dll|d3d9\.dll|present\s*hook).{0,60}(fail|error|denied|timeout|blocked|unable)",
        sev="HIGH",
        code="log.hook_blocked",
        hyp="conflict",
        title="Не удалось внедрить хук в игру (инъекция заблокирована или занята)",
        why="Оверлей работает через перехват Present/DXGI. Если хуки не ставятся — ни окна, ни записи не будет. Типично для конфликта оверлеев, античита или AV.",
        fixes=[
            "Отключи RTSS/MSI Afterburner, Steam Overlay, Discord Overlay, Xbox Game Bar, Special K, MangoHUD — по одному.",
            "Античит (EAC/BattlEye/Vanguard/Faceit): играй в оконном режиме 'без рамки' или добавь исключения на стороне игры.",
            "Антивирус 'Anti-stealth/защита памяти/блокировка инжектов' → выключить на тест.",
            "Игра от админа + оверлей не от админа = гарантированный отказ инъекции.",
        ],
    ),
    dict(
        re=r"(?i)(riva\s?tuner|rtss|afterburner|nahimic|sonic\s?studio|sonic\s?radar|razer|icue|corsair|steam(?:works)?\s?overlay|gameoverlayrenderer|discord.{0,15}overlay|xbox\s?game\s?bar|gamerdvr|special\s?k|mangohud|lossless\s?scaling|xsplit|evga)\w*",
        sev="MEDIUM",
        code="log.conflict_software",
        hyp="conflict",
        title="В логе засветился потенциальный конкурент оверлея",
        why="Сторонние оверлеи и 'улучшайзеры' звука/графикы дерутся за те же хуки и за DXGI Present.",
        fixes=[
            "Выключи перечисленное полностью (не только 'не показывать HUD') и проверь Alt+Z.",
            "Nahimic/Sonic Studio на материнках MSI/ASUS часто ломают оверлеи — отключи службу NahimicSvc.",
        ],
    ),
    # ---- привилегии / доступ ----
    dict(
        re=r"(?i)(access\s+is\s+denied|accessdenied|error\s+(5|1314)\b|privilege|elevation|not\s+elevated|requires?.{0,20}(admin|administrator|elevat)|se_debug|openprocess.{0,20}(fail|access))",
        sev="HIGH",
        code="log.access_denied",
        hyp="elevated",
        title="Отказано в доступе / не хватает привилегий",
        why="Обычно значит: цель (игра/окно) в более высоком уровне целостности, чем оверлей, либо права на файл/папку/ключ реестра.",
        fixes=[
            "Запусти NVIDIA App от администратора на время теста; убери 'Запуск от имени администратора' с ярлыка игры.",
            "Проверь права на папку записи и на C:\\Program Files\\NVIDIA Corporation\\NVIDIA App.",
        ],
    ),
    dict(
        re=r"(?i)(session\s*0|non-interactive\s+desktop|protected\s+mode|integrity\s+level|virtual\s+desktop|medal\.?tv|(uac|uiac).{0,40}(block|denied|fail|prevent))",
        sev="MEDIUM",
        code="log.session_isolation",
        hyp="capture_target",
        title="Изоляция сессии/рабочего стола мешает оверлею",
        why="Оверлей не может отрисоваться в чужой/служебной сессии или защищённом процессе.",
        fixes=["Не управляй ПК через RDP/'Быстрый запуск' сессий; работай в локальной консоли.", "Закрывай виртуальные десктопы/UVaC-песочницы на тест."],
    ),
    # ---- захват экрана ----
    dict(
        re=r"(?i)(desktop\s?duplication|duplicateoutput|DXGI_ERROR_NOT_CURRENTLY_AVAILABLE|DXGI_ERROR_(INVALID_CALL|NOT_CURRENTLY|UNSUPPORTED|unsupported)|acquisition\s?(failed|error)|(frame\s?pool|shared\s?texture).{0,40}(fail|error|invalid)|CreateDXGIFactory.{0,30}fail)",
        sev="CRITICAL",
        code="log.desktop_duplication",
        hyp="capture_target",
        title="Не удаётся создать Desktop Duplication / DXGI-захват",
        why="Всё видео-путешествие кадра начинается с DXGI. Эта ошибка = 'нет источника кадра', и ни о каком старте записи речи не идёт.",
        fixes=[
            "Закрой все, кто дублирует экран: OBS/Discord/Parsec/Sunshine/Miracast/Xbox-запись/удалёнка.",
            "Выключи HDR и HAGS, перезагрузись; в гибридных ноутбуках переключи на dGPU (MUX).",
            "Убедись, что монитор физически активен (не 'Отключить второй экран' с закрытой крышкой).",
        ],
    ),
    dict(
        re=r"(?i)(no\s+(compatible|supported|valid)\s+(display|monitor|output|adapter)|(display|monitor|output)\s*( enumeration\s*failed|not\s+found|is\s+empty)|SetWin32PathInformation|NvAPI_(Display|GPU)_\w+\s*(error|=|:)\s*-?\d+)",
        sev="HIGH",
        code="log.display_enum",
        hyp="capture_target",
        title="Не перечислились дисплеи/выводы (NvAPI/DXGI enumeration)",
        why="Оверлей не знает, 'на какой экран' цепляться — типично для доков, MHMD, выключенных мониторов, гибридной графики.",
        fixes=["Переподключи монитор / выйди из дока на тест", "Отключи виртуальные адаптеры (Parsec Virtual Display, Apple/AMD 'Virtual' драйверы) в Диспетчере устройств."],
    ),
    # ---- кодек / GPU ----
    dict(
        re=r"(?i)(nvenc|nvv4l2|encoders?d|encode.{0,15}(fail|error)|NvEncodeAPI|MaxNumTranscode|session\s*(limit|creation)\s*(failed|error)|too\s+many\s+(concurrent\s+)?sessions)",
        sev="CRITICAL",
        code="log.nvenc",
        hyp="encoder",
        title="Ошибка NVENC (кодировщик недоступен/занят/не поддерживается)",
        why="Запись невозможна без кодера. Либо лимит параллельных NVENC-сессий, либо GPU/драйвер не даёт создать сессию.",
        fixes=[
            "Закрой другие пользователи NVENC: OBS, XSplit, Chrome 'аппаратное ускорение' при стриме, Discord 'аппаратное кодирование'.",
            "nvidia-smi → 'Encoder Stats'; если сессии заняты — ищи кто.",
            "Смени кодек H.265→H.264, сними 4K/120fps на 1080p60 на время теста.",
            "Полностью обнови драйвер (чистая установка).",
        ],
    ),
    dict(
        re=r"(?i)(device\s*lost|DXGI_ERROR_DEVICE_REMOVED|DXGI_ERROR_DEVICE_HUNG|TDR|nvlddmkm|display\s+driver\s+.*(stopped|crash)|GPU.*\bhang\b)",
        sev="CRITICAL",
        code="log.gpu_lost",
        hyp="encoder",
        title="ГПУ/драйвер роняет устройство в момент захвата (device lost / TDR)",
        why="Драйвер не выдерживает нагрузку или разгон — оверлей умирает вместе с ним.",
        fixes=[
            "Сбрось разгон GPU/VRAM и кривые MSI Afterburner; верни Power Limit 100%.",
            "Увеличь TdrDelay только как диагностику, чини причину: питание, температура, память.",
            "Проверь 'Event Viewer → System → nvlddmkm 4101' — сколько раз и в какие моменты.",
        ],
    ),
    # ---- сервисы ----
    dict(
        re=r"(?i)((nvcontainer|nvservicemodel|display\s?container|telemetry\s?container|NvTelemetry).{0,90}(fail|error|unable|not\s+running|stopped|does\s+not\s+exist|exited|exit\s+code|crash|denied|refus|timeout)|service.{0,30}(not\s+running|failed\s+to\s+(start|connect)|does\s+not\s+exist)|RPC_S_SERVER_UNAVAILABLE|pipe.{0,25}(not\s+found|timed\s+out|timeout|access\s+denied))",
        sev="CRITICAL",
        code="log.container",
        hyp="svc",
        title="Сбой обращения к контейнеру/сервису NVIDIA (IPC/pipe)",
        why="Все функции NVIDIA App идут через nvcontainer. Нет контейнера — нет оверлея, независимо от драйвера.",
        fixes=[
            "Start-Service NVDisplay.ContainerLocalSystem (от админа) и проверь, что он не падает через 5 сек.",
            "Помогает переустановка 'только' компонентов: установщик драйвера → Выборочно → Graphics Driver + NVIDIA App.",
        ],
    ),
    # ---- диск / файлы ----
    dict(
        re=r"(?i)((not\s+enough|insufficient|no)\s+(free\s+)?(disk\s+)?space|ERROR_DISK_FULL|disk\s*full|write.{0,25}(fail|error|denied).{0,40}(mp4|mov|rec|path|folder)|path.{0,20}(not\s+found|does\s+not\s+exist|invalid)|ERROR_PATH_NOT_FOUND|share\s*access\s*violation|file\s+in\s+use)",
        sev="HIGH",
        code="log.storage",
        hyp="storage",
        title="Проблема с папкой/диском записи",
        why="Буфер Instant Replay пишется непрерывно; при отказе записи оверлей часто 'тихо' не стартует.",
        fixes=[
            "Освободи 20-30 ГБ и/или переназначь папку записи на локальный NTFS-диск.",
            "Убери из OneDrive/сети; добавь исключения для *.mp4 в AV.",
            "Проверь, что путь не длиннее 240 символов и не содержит запрещённых символов.",
        ],
    ),
    # ---- конфиг ----
    dict(
        re=r"(?i)(settings?\.json|config.{0,20}(corrupt|invalid|parse|malformed|unexpected|missing|read\s+fail)|json\s*(decode|parse)\s*error|failed\s+to\s+(load|open)\s+(the\s+)?(config|settings|profile))",
        sev="HIGH",
        code="log.config_corrupt",
        hyp="config_corrupt",
        title="Повреждён конфиг/настройки",
        why="Приложение не может прочитать свой профиль → компонент оверлея не инициализируется.",
        fixes=["Переименуй папку с Settings.json (ProgramData\\NVIDIA Corporation\\...) и дай приложению создать её заново."],
    ),
    dict(
        re=r"(?i)(plugin|module|component|feature).{0,40}(not\s+(installed|found|registered)|failed\s+to\s+(load|register|start)|disabled|missing)",
        sev="HIGH",
        code="log.plugin_missing",
        hyp="app_ver",
        title="Компонент/плагин оверлея не установлен или не загрузился",
        why="Оверлей в NVIDIA App — отдельный устанавливаемый компонент; 'выборочная установка' без него даёт именно такую картину.",
        fixes=[
            "Запусти установщик драйвера → 'Выборочная' → включи NVIDIA App (и 'Optimize...'/Video, если есть) → восстановление.",
            "Или просто: NVIDIA App → Помощь → 'Переустановить приложение'.",
        ],
    ),
    # ---- защита ----
    dict(
        re=r"(?i)((blocked|block(ed)?|quarantin(e|ed)|threat|malware|heuristic|virus|trojan|suspi[cz]ious).{0,80}(nvidia|overlay|nvcontainer|nvstream|\\\w+\.exe|file\b|action\b)|(controlle[d]?\s+folder|defender.{0,30}(action|block|threat)|smartscreen.{0,20}(block|warn)))",
        sev="HIGH",
        code="log.av_block",
        hyp="blocked",
        title="Похоже на блокировку защитником (файл/операция)",
        why="Оверлей легален, но 'инжект в чужой процесс + запись экрана' — классика для поведенческих эвристик.",
        fixes=[
            "Исключение на папку C:\\Program Files\\NVIDIA Corporation и на папку записи; 'Контроль папок' → разрешить приложение.",
            "Проверь 'Журнал защиты'/'Карантин' на наличие NVIDIA Overlay.exe / nvcontainer.exe.",
        ],
    ),
    # ---- сеть/аккаунт (для полных функций) ----
    dict(
        re=r"(?i)(tls|ssl|certificate|handshake|revocation|CRL|winhttp|ERROR_INTERNET|proxy|offline|sign[- ]?in|authenticat).{0,60}(fail|error|refus|block|expired|unreachable|time)",
        sev="LOW",
        code="log.net",
        hyp="unknown",
        title="Сетевой/авторизационный сбой",
        why="Локальную запись сеть не требует, но часть UI NVIDIA App не поднимается без ответа серверов/входа — выглядит как 'оверлей не открывается'.",
        fixes=["Проверь время/дат (ошибки TLS), DNS, отсутствие MITM-прокси (Kaspersky Web Traffic, Palo Alto, Zscaler).", "Попробуй 'Не входить'/'локальный режим', если доступен."],
    ),
    # ---- установка/версии ----
    dict(
        re=r"(?i)(install(er|ation).{0,40}(fail|error|abort|rollback)|error\s+1[0-9]{3}|older\s+version|newer\s+version|MSI[A-Z0-9_ ]*return\s+value\s+16|Setup\s+failed)",
        sev="HIGH",
        code="log.installer",
        hyp="app_ver",
        title="Следы неудачной установки/обновления NVIDIA App или драйвера",
        why="Недолитая установка = отсутствующие DLL оверлея при 'работоспособном' ярлыке.",
        fixes=[
            "C:\\Program Files\\NVIDIA Corporation\\Installer2\\*.log и C:\\Windows\\Temp\\NVIDIA Install.log — посмотри последние ошибки.",
            "Переустанови начисто: удалить приложение → DDU в безопасном режиме → свежий драйвер + NVIDIA App.",
        ],
    ),
    # ---- память/нагрузка ----
    dict(
        re=r"(?i)(out\s+of\s+memory|bad_alloc|std::(bad_|length)_|page\s?file|VirtualAlloc.{0,20}fail|Low\s+memory|memory\s+(usage|pressure).{0,20}(high|critical))",
        sev="MEDIUM",
        code="log.oom",
        hyp="unknown",
        title="Нехватка памяти (RAM/файл подкачки) при старте оверлея",
        why="CEF + кодер просят ~1-2 ГБ; при забитой памяти оверлей стартует и сразу умирает.",
        fixes=["Закрой лишнее, увеличь файл подкачки (системный managed), проверь 32-бит/4ГБ-ограничения."],
    ),
    dict(
        re=r"(?i)(\b(timeout|timed\s+out|watchdog|deadlock|hang|stuck|not\s+responding)\b.{0,60}\b(fail|error|exceed|expire|abort|retry|unable|reached|while)\b|\b(fail(ed)?|error|exceed|expire|unable|abort)\b.{0,60}\b(timeout|timed\s+out|watchdog|deadlock|hang)\b|wait.{0,15}(expired|failed))",
        sev="MEDIUM",
        code="log.timeout",
        hyp="svc",
        title="Таймаут/зависание при обращении к компоненту",
        why="Обычно 'ждёт и не дождётся' ответа контейнера или кодера: либо сервис под нагрузкой, либо IPC блокируется защитником.",
        fixes=["Перезапусти сервисы NVIDIA; повтори Alt+Z.", "Проверь, не стоит ли на запуске долгий антивирусный скан/обновление Windows."],
    ),
    dict(
        re=r"(?i)(unhandled|uncaught|\bfatal\b|exception|\babort(ed)?\b|assert(ion)\s?fail|stack\s?trace|crashpad|minidump|\bWER\b|faulting\s+(module|application)|\.dmp\b)",
        sev="HIGH",
        code="log.crash_generic",
        hyp="unknown",
        title="Аварийное завершение (exception/assert/minidump)",
        why="Есть краш — нужен модуль-виновник: по нему понятно, чья это библиотека (nvidia / cef / сторонняя).",
        fixes=[
            "Посмотри 'Имена сбойных пакетов' в Журнале Windows → Приложение (Application Error) — там Faulting module.",
            "Если модуль не nvidia*.dll — это конфликт стороннего софта, удаляй/отключай его.",
        ],
    ),
    # ---- запись / реплей ----
    dict(
        re=r"(?i)(instant\s?replay|shadow ?play|replay\s?buffer|record(ing|er)?|capture|\.mp4|\.mov).{0,60}(fail|error|unable|could\s?not|start(ed)?\s?fail|stopped\s+unexpected|not\s+available|denied|discard|corrupt|too\s+small|empty\s+file|0\s+bytes)",
        sev="HIGH",
        code="log.record_fail",
        hyp="capture_target",
        title="Запись/буфер реплея не стартует или обрывается",
        why="Ключевой симптом твоей проблемы: конвейер захвата инициализируется, но не может начать поток кадров.",
        fixes=[
            "Сравни: 'Захват игры' vs 'Захват рабочего стола' — если рабочий стол пишется, а игра нет, дело в инъекции (см. конфликт/привилегии).",
            "Снизь качество до 1080p30/H.264/50 Мбит — проверь, не упирается ли в лимит.",
            "Отключи 'Автовыключение записи при потере фокуса' и 'Запись только в полноэкранном режиме'.",
        ],
    ),
    dict(
        re=r"(?i)(hot\s?key|shortcut|alt\+z|key\s?binding|registerhotkey).{0,50}(fail|conflict|already|taken|unable|error)",
        sev="MEDIUM",
        code="log.hotkey",
        hyp="hotkey",
        title="Не удалось зарегистрировать горячую клавишу",
        why="Оверлей работает, но ты его не вызываешь — ощущается как 'не запускается'.",
        fixes=["Смени клавишу в настройках NVIDIA App; освободи её от iCUE/Synapse/G Hub/PowerToys/AutoHotkey."],
    ),
    dict(
        re=r"(?i)(hdr|WCG|advanced\s+color|10[- ]?bit|yuv ?4:2:0|color\s?(space|format|depth)).{0,50}(fail|error|unsuppor|not\s+support|invalid|mismatch)",
        sev="MEDIUM",
        code="log.hdr",
        hyp="capture_target",
        title="Конфликт формата кадра (HDR/10-бит/color space)",
        why="Часть конвейеров NVIDIA App не умеет захват HDR-цепочки — оверлей молча отваливается.",
        fixes=["Параметры → Дисплей → HDR → выкл на тест; в NVIDIA App отключи 'HDR' в настройках записи."],
    ),
    dict(
        re=r"(?i)(driver).{0,40}(not\s+installed|missing|unsupported|incompatible|too\s+old|version\s+mismatch|outdated|failed\s+to\s+(load|open|init)|NvAPI_Initialize)",
        sev="CRITICAL",
        code="log.driver",
        hyp="driver",
        title="Драйвер/видеоядро недоступно для компонентов NVIDIA",
        why="Оверлей поверх NvAPI; если NvAPI_initialize падает, всё остальное бессмысленно.",
        fixes=[
            "nvidia-smi в админ-консоли; 'no devices found' → Device Manager → Код 43 / не тот драйвер.",
            "Установи свежий драйвер с 'Чистой установкой', затем перезагрузись (не 'Завершение работы' с Fast Startup).",
        ],
    ),
    dict(
        re=r"(?i)(windows\s+(10|11)).{0,40}(build|version).{0,20}(unsupported|too\s+old|lower|require)|requires?\s+windows",
        sev="MEDIUM",
        code="log.os_unsupported",
        hyp="unknown",
        title="Версия Windows ниже требуемой для NVIDIA App",
        why="NVIDIA App требует Windows 10 2004+ (19041) и выше; на LTSC/обрезанных сборках оверлей не поднимается.",
        fixes=["winver → если меньше 19041 — обнови Windows или откатись на GeForce Experience."],
    ),
    dict(
        re=r"(?i)(power\s?plan|powermizer|battery\s?saver|eco\s?mode|hybrid\s?mode|dGPU|iGPU|Optimus|MUX|switchable\s?graphics)",
        sev="MEDIUM",
        code="log.power_graphic",
        hyp="capture_target",
        title="Гибридная графика/энергосбережение режет оверлей",
        why="На Optimus кадр игры идёт через iGPU, а NVENC/hook хотят dGPU → 'оверлей не запускается' или чёрный кадр.",
        fixes=[
            "Параметры → Дисплей → Графика → выставь для игры 'Высокая производительность (NVIDIA)'.",
            "В BIOS/фирменной утилите (Legion Toolkit, MyASUS, Alienware Command) переключи 'dGPU only'/MUX.",
            "Питание → 'Максимальная производительность', не 'Экономия' на тест.",
        ],
    ),
]

# Общий «чёрный список» строк, которые считаются ошибочными, даже если не совпали
# ни с одной сигнатурой — их топ берётся в отчёт как «неизвестные ошибки».
GENERIC_ERROR_RE = re.compile(
    r"(?i)\b(error|errors|err\b|fatal|critic(al)?|severe|fail(ed|ure|s)?|exception|denied|invalid|unable|cannot|refus|unavailable|timed\s+out|timeout|crash|abort|corrupt|missing|not\s+found|not\s+supported|unsupported|broken)\b"
)


def compile_signatures(sigs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for s in sigs:
        c = dict(s)
        c["_re"] = re.compile(s["re"])
        out.append(c)
    return out


COMPILED_SIGNATURES = compile_signatures(SIGNATURES)


def load_extra_kb(path: Path | None) -> list[dict[str, Any]]:
    """Подгрузка пользовательской базы сигнатур (JSON: [{"re":..., "code":..., ...}])."""
    if not path:
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] не удалось прочитать --kb {path}: {exc}", file=sys.stderr)
        return []
    if isinstance(raw, dict):
        raw = raw.get("signatures", [])
    if isinstance(raw, list) and raw and isinstance(raw[0], list):  # терпимо к [[...]]
        raw = [x for sub in raw for x in (sub if isinstance(sub, list) else [sub])]
    good = []
    for item in raw:
        if isinstance(item, dict) and item.get("re"):
            item.setdefault("sev", "MEDIUM")
            item.setdefault("code", "kb." + re.sub(r"\W+", "_", item["re"])[:24])
            item.setdefault("title", "Совпадение с пользовательской сигнатурой")
            item.setdefault("why", "")
            item.setdefault("fixes", [])
            item.setdefault("hyp", "unknown")
            good.append(item)
    return good


# --------------------------------------------------------------------------------------
# Отчёт
# --------------------------------------------------------------------------------------


@dataclasses.dataclass
class Report:
    mode: str
    findings: list[Finding] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)
    snapshot: dict[str, Any] = dataclasses.field(default_factory=dict)
    started: str = dataclasses.field(default_factory=now_iso)
    _seen: set[tuple[Any, ...]] = dataclasses.field(default_factory=set, repr=False)

    def add(self, severity: str, code: str, title: str, **kw: Any) -> Finding:
        f = Finding(severity=severity, code=code, title=title, **kw)
        key = (f.code, f.title, f.detail, f.source)
        if key in self._seen:
            return f
        self._seen.add(key)
        self.findings.append(f)
        return f

    def note(self, text: str) -> None:
        if text:
            self.notes.append(text)

    def by_severity(self) -> Counter[str]:
        return Counter(f.severity for f in self.findings)

    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]

    # ---- гипотезы ----
    def hypotheses(self) -> list[dict[str, Any]]:
        weights: Counter[str] = Counter()
        support: defaultdict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            if f.severity == "OK":
                continue
            h = f.hypothesis if f.hypothesis in HYPOTHESES else "unknown"
            w = SEV_WEIGHT.get(f.severity, 1)
            # Лог-улики чуть слабее живых проверок: то же событие в логе видели один раз.
            if f.source.startswith("log"):
                w = max(1, w - 1)
            weights[h] += w
            support[h].append(f)
        total = sum(weights.values()) or 1
        out = []
        for h, w in weights.most_common():
            meta = HYPOTHESES.get(h, HYPOTHESES["unknown"])
            fs = sorted(support[h], key=lambda x: -SEV_WEIGHT.get(x.severity, 0))
            fixes = list(meta.get("fixes", []))
            for f in fs:
                for fix in f.fixes:
                    if fix not in fixes:
                        fixes.append(fix)
            out.append(
                {
                    "id": h,
                    "title": meta.get("title", h),
                    "weight": w,
                    "confidence": round(100.0 * w / total),
                    "finding_codes": [f.code for f in fs],
                    "evidence": [f"{SEV_MARK.get(f.severity,'[? ]')} {f.title}" for f in fs],
                    "fixes": fixes,
                }
            )
        return out

    # ---- вывод ----
    def render_text(self, width: int = 100, verbose: bool = True, only_problems: bool = False) -> str:
        bar = "=" * width
        L: list[str] = [bar, "ДИАГНОСТИКА ОВЕРЛЕЯ NVIDIA APP (запись/Instant Replay)", bar]
        L.append(f"режим: {self.mode}    дата: {self.started}")
        if self.snapshot.get("platform"):
            L.append(
                "ОС: {os}   Python {py}   админ: {admin}".format(
                    os=self.snapshot.get("os_pretty", "?"),
                    py=sys.version.split()[0],
                    admin="да" if self.snapshot.get("is_admin") else "нет",
                )
            )
        counts = self.by_severity()
        summary = "  ".join(f"{k}:{counts[k]}" for k in SEV_ORDER if counts.get(k))
        L += ["", f"Находки: {len(self.findings)}   ({summary or 'нет'})"]

        hyps = self.hypotheses()
        L += ["", bar, "ВЕРДИКТ — вероятные причины (по убыванию веса улик)", bar]
        if not hyps:
            L.append("Критичных находок нет. См. блок 'Что проверено' ниже.")
        for i, h in enumerate(hyps, 1):
            L.append(f"\n{i}. {h['title']}")
            tag = "   ← начинай отсюда" if i == 1 else ""
            L.append(f"   вес улик {h['weight']} (доля {h['confidence']}%): {', '.join(h['finding_codes'][:6])}{tag}")
            if verbose and h["evidence"]:
                for e in h["evidence"][:6]:
                    L.append(f"     • {e}")
            L.append("   план:")
            for j, f in enumerate(h["fixes"][:6], 1):
                L.append(_indent(f"{j}) {f}", "     "))

        shown = self.findings if not only_problems else self.problems()
        L += ["", bar, "НАХОДКИ" + (" (только проблемы)" if only_problems else ""), bar]
        if not shown:
            L.append("— пусто —")
        order = {s: i for i, s in enumerate(SEV_ORDER)}
        for f in sorted(shown, key=lambda x: (order.get(x.severity, 9), x.code)):
            L.append("")
            L.append(f.render(width=width, verbose=verbose))
            if f.source != "system":
                L.append(f"       источник: {f.source}")

        if self.notes:
            L += ["", bar, "ЗАМЕТКИ СБОРА ДАННЫХ", bar]
            L += [f"- {n}" for n in self.notes]

        L += [
            "",
            bar,
            "ЧТО ПРИСЛАТЬ, ЧТОБЫ Я ДОРЕШИЛ ПРОБЛЕМУ",
            bar,
            "1) python nvidia_overlay_diag.py scan --bundle diag.zip      — один архив: отчёт + свежие логи",
            "2) или только отчёт: python nvidia_overlay_diag.py scan -o report.txt   (файл в UTF-8)",
            "3) или кусок лога:   python nvidia_overlay_diag.py logs - < fragment.log",
            "После моих правок — проверка: python nvidia_overlay_diag.py verify --wait 40",
            "",
        ]
        return "\n".join(L)

    def to_json(self) -> dict[str, Any]:
        return {
            "tool": "nvidia_overlay_diag",
            "version": "1.0",
            "mode": self.mode,
            "started": self.started,
            "snapshot": self.snapshot,
            "counts": dict(self.by_severity()),
            "findings": [f.to_dict() for f in self.findings],
            "hypotheses": self.hypotheses(),
            "notes": self.notes,
            "signatures_version": len(SIGNATURES),
        }


# --------------------------------------------------------------------------------------
# Чтение логов (кроссплатформенное)
# --------------------------------------------------------------------------------------

TS_RES = [
    re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"),
    re.compile(r"(\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\s+\d{1,2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)"),
    re.compile(r"(\[\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\])"),
]

LEVEL_RE = re.compile(r"(?im)^.{0,40}?[\[(]?\b(debug|verbose|trace|info|notice|warn(ing)?|error|fail(fatal)?|fatal|critical|severe|panic)\b[\]):]?")


def sniff_read_text(path: Path, max_bytes: int | None = None) -> tuple[list[str], str]:
    """Читает лог, угадывая кодировку (UTF-16 BOM / UTF-8 / cp1251 / latin-1)."""
    with open(path, "rb") as fh:
        head = fh.read(4096)
    enc = "utf-8"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16"
    elif b"\x00" in head[:64]:
        enc = "utf-16-le"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [], f"read error: {exc}"
    if max_bytes and len(raw) > max_bytes:
        raw = raw[-max_bytes:]  # хвост интереснее: свежий лог
    for e in (enc, "utf-8-sig", "utf-8", "cp1251", "latin-1"):
        try:
            text = raw.decode(e)
            enc = e
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:  # pragma: no cover
        text = raw.decode("latin-1", "replace")
    return text.splitlines(), enc


def line_timestamp(line: str) -> str | None:
    for rx in TS_RES:
        m = rx.search(line)
        if m:
            return m.group(1)
    return None


def level_of(line: str) -> str | None:
    m = LEVEL_RE.search(line)
    if not m:
        return None
    lv = m.group(1).lower()
    if lv in ("fail", "failure", "error"):
        return "error"
    if lv.startswith("warn"):
        return "warning"
    if lv in ("fatal", "critical", "severe", "panic"):
        return "fatal"
    return lv


def scan_lines(lines: Sequence[str], sigs: Sequence[dict[str, Any]], context: int = 0) -> tuple[list[Finding], dict[str, Any]]:
    """Прогон строк по базе сигнатур + сводка неизвестных ошибок."""
    findings: list[Finding] = []
    hits: defaultdict[str, list[int]] = defaultdict(list)
    err_lines = 0
    level_counts: Counter[str] = Counter()
    unknown_errors: list[tuple[str, int]] = []

    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        lvl = level_of(line)
        if lvl:
            level_counts[lvl] += 1
        if GENERIC_ERROR_RE.search(line):
            err_lines += 1
        matched = False
        for s in sigs:
            if s["_re"].search(line):
                hits[s["code"]].append(idx)
                matched = True
        if not matched and lvl in ("error", "fatal"):
            key = re.sub(r"\d+", "N", line.strip())[:160]
            unknown_errors.append((key, idx))

    first_ts, last_ts = None, None
    for line in lines:
        ts = line_timestamp(line)
        if ts:
            if first_ts is None:
                first_ts = ts
            last_ts = ts

    stats = {
        "lines": len(lines),
        "error_like_lines": err_lines,
        "levels": dict(level_counts),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "hits": {k: len(v) for k, v in hits.items()},
    }

    by_code = {s["code"]: s for s in sigs}
    for code, idxs in hits.items():
        s = by_code[code]
        ev = []
        for i in idxs[:6]:
            ts = line_timestamp(lines[i])
            ev.append(f"L{i + 1}{' ' + ts if ts else ''}: {lines[i].strip()[:220]}")
        if context and idxs:
            lo = max(0, idxs[0] - context)
            hi = min(len(lines), idxs[0] + context + 1)
            ev.append("--- контекст первого совпадения ---")
            ev += [f"  {lines[j].strip()[:200]}" for j in range(lo, hi) if lines[j].strip()][: 2 * context + 1]
        findings.append(
            Finding(
                severity=s["sev"],
                code=code,
                title=s["title"],
                detail=s.get("why", ""),
                evidence=ev,
                fixes=list(s.get("fixes", [])),
                hypothesis=s.get("hyp", "unknown"),
                source="log",
            )
        )

    # Эвристика "первая серьёзная ошибка": почти всегда корень каскада — самое верхнее
    # CRITICAL/HIGH совпадение, всё остальное ниже — его последствия.
    by_code_map = {s["code"]: s for s in sigs}
    first_idx: int | None = None
    first_sig: dict[str, Any] | None = None
    for code, idxs in hits.items():
        sg = by_code_map.get(code)
        if not sg or sg["sev"] not in ("CRITICAL", "HIGH"):
            continue
        i = idxs[0]
        # игнорируем 'упоминание без ошибки' (INFO-строки с тем же словом)
        ln = lines[i]
        if level_of(ln) not in ("error", "fatal") and not GENERIC_ERROR_RE.search(ln):
            nxt = [j for j in idxs if GENERIC_ERROR_RE.search(lines[j]) or level_of(lines[j]) in ("error", "fatal")]
            if not nxt:
                continue
            i = nxt[0]
        if first_idx is None or i < first_idx:
            first_idx, first_sig = i, sg
    if first_sig is not None and first_idx is not None:
        ctx = [(j, lines[j].strip()[:200]) for j in range(first_idx, min(len(lines), first_idx + 3)) if lines[j].strip()]
        findings.append(
            Finding(
                severity="CRITICAL",
                code="log.first_severe",
                title=f"Первая серьёзная ошибка в этом логе → {first_sig['title']}",
                detail=(
                    first_sig.get("why", "")
                    + "\n\nСчитай эту строку корнем: всё, что написано ниже (таймауты, 'failed to start', "
                    "'retry') — обычно последствия одной ошибки."
                ),
                evidence=[f"L{j + 1}{'' if j != first_idx else ' ← первое серьёзное'}: {txt}" for j, txt in ctx],
                fixes=list(first_sig.get("fixes", [])),
                hypothesis=first_sig.get("hyp", "unknown"),
                source="log",
            )
        )

    # Неизвестные, но явно ошибочные строки — отдельная находка, чтобы не потерять сигнал.
    uniq: list[tuple[str, int]] = []
    seen: set[str] = set()
    cnt: Counter[str] = Counter()
    for key, idx in unknown_errors:
        cnt[key] += 1
        if key not in seen:
            seen.add(key)
            uniq.append((key, idx))
    if uniq:
        top = ", ".join(f"{k} ×{c}" for k, c in Counter(dict(uniq)).most_common(5))
        findings.append(
            Finding(
                severity="MEDIUM",
                code="log.unknown_errors",
                title="Ошибочные строки, не описанные базой сигнатур",
                detail=(
                    f"Всего ошибкоподобных строк: {err_lines}. Частые шаблоны (цифры свёрнуты в N):\n{top}\n"
                    "Пришли этот лог целиком (или --bundle) — шаблоны разберём и добавим в базу."
                ),
                evidence=[f"L{i + 1}: {k[:200]}" for k, i in uniq[:12]],
                fixes=["Ищи ПЕРВОЕ вхождение 'fail'/'error' сверху лога — обычно корень там, а всё после — каскад."],
                hypothesis="unknown",
                source="log",
            )
        )

    return findings, stats


# --------------------------------------------------------------------------------------
# Windows-специфика: PowerShell-обёртка, реестр, сервисы, процессы, журнал событий
# --------------------------------------------------------------------------------------

# Каждый запрос в своём try: отсутствующий провайдер не должен убивать остальные.
EVENTS_PS = r"""
$start=(Get-Date).AddDays(-@@DAYS@@);
$ev=@();
function Q($h,$w,$n){ try { Get-WinEvent -FilterHashtable $h -ErrorAction Stop | Where-Object $w | Select-Object -First $n | ForEach-Object { $m=('{0}' -f (($_.Message | Out-String) -replace '\s+',' ')).Trim(); [pscustomobject]@{ T=$_.TimeCreated.ToString('s'); Log=$_.LogName; Prov=$_.ProviderName; Id=$_.Id; Lvl=$_.LevelDisplayName; Msg=$m.Substring(0,[Math]::Min(260,$m.Length)) } } } catch { @() } }
$ev += Q @{LogName='System'; StartTime=$start; ProviderName='nvlddmkm'} { $true } 20;
$ev += Q @{LogName='System'; StartTime=$start; Level=1,2} { ($_.ProviderName -match '(?i)nvidia|nvlddm|nvldumdx|Display|DistributedCOM') -or ($_.Message -match '(?i)nvidia') } 25;
$ev += Q @{LogName='Application'; StartTime=$start; ProviderName='Application Error','Application Hang','.NET Runtime','Windows Error Reporting','Microsoft-Windows-AppModel-Runtime'} { $_.Message -match '(?i)nvidia|nvcontainer|nvstream|Overlay|nv-?display' } 20;
$ev += Q @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; StartTime=$start} { ($_.Id -in 3033,3076,3001,3089) -and ($_.Message -match '(?i)nvidia|Overlay|nvcontainer') } 10;
$ev += Q @{LogName='System'; StartTime=$start; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41} { $true } 5;
$ev | Sort-Object T -Descending | Select-Object -First 60
"""

# корень установки NVIDIA-компонентов (вынесен в константу — удобно переопределять в тестах)
NVIDIA_ROOT_WIN = r"C:\Program Files\NVIDIA Corporation"

LOG_ROOTS_WIN = [
    r"C:\ProgramData\NVIDIA Corporation",
    NVIDIA_ROOT_WIN,
    r"C:\Program Files (x86)\NVIDIA Corporation",
    r"%LOCALAPPDATA%\NVIDIA Corporation",
    r"%APPDATA%\NVIDIA Corporation",
    r"%TEMP%",
    r"C:\Windows\Temp",
    r"C:\Windows\Logs",
]

# файлы вне «родовых» папок NVIDIA, которые стоит дочитать (драйвер/установка)
LOG_EXTRA_FILES_WIN = [
    r"C:\Windows\INF\setupapi.dev.log",
    r"C:\Windows\Logs\DPX\*.log",
    r"C:\Windows\Minidump\*.dmp",
]

LOG_NAME_HINTS = re.compile(
    r"(?i)(nvlog|nvidia|nvcontainer|nvstream|overlay|nvnode|gsfl|gameforce|displaydriver|installer|nvldumdx|cef|nvlddmkm|shadowplay|capture|setupapi)"
)
LOG_EXTS = (".log", ".txt", ".json", ".etl", ".csv")

SETTINGS_NAME_RE = re.compile(r"(?i)^(settings?|config|nvidiaapp.*json|.*overlay.*json)\.json$")


def expand(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def find_files(root: Path, name_rx: re.Pattern[str], max_depth: int = 4, limit: int = 4000) -> list[Path]:
    """Поиск файлов по имени на ограниченной глубине — быстрее и безопаснее рекурсивного **."""
    out: list[Path] = []
    if not root.exists():
        return out
    stack: list[tuple[Path, int]] = [(root, 0)]
    visited = 0
    while stack and visited < limit and len(out) < 64:
        d, depth = stack.pop()
        visited += 1
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            visited += 1
            if visited >= limit:
                break
            try:
                if e.is_dir(follow_symlinks=False):
                    if depth < max_depth:
                        stack.append((Path(e.path), depth + 1))
                elif name_rx.search(e.name):
                    out.append(Path(e.path))
            except OSError:
                continue
    return out


class WinCollector:
    """Все обращения к Windows API/PowerShell. Каждый шаг изолирован: ошибка сбора != ошибка системы."""

    def __init__(self, report: Report, timeout: int = 45) -> None:
        self.r = report
        self.timeout = timeout

    # ---------- PowerShell ----------
    def ps(self, script: str, as_json: bool = True) -> Any:
        script = script.strip()
        if as_json and "ConvertTo-Json" not in script:
            script += " | ConvertTo-Json -Compress -Depth 6"
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "$ProgressPreference='SilentlyContinue';" + script
        )
        path = None
        try:
            with tempfile.NamedTemporaryFile("wb", suffix=".ps1", delete=False) as fh:
                path = fh.name
                fh.write(script.encode("ascii", "replace"))
            proc = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    path,
                ],
                capture_output=True,
                timeout=self.timeout,
            )
            out = proc.stdout.decode("utf-8-sig", "replace").strip()
            if not out:
                if proc.returncode:
                    err = proc.stderr.decode("utf-8-sig", "replace").strip()
                    self.r.note(f"PowerShell вернул код {proc.returncode}: {err[:200]}")
                return None
            if not as_json:
                return out
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                return out
            return data
        except FileNotFoundError:
            self.r.note("powershell.exe не найден — живые проверки Windows недоступны")
            return None
        except subprocess.TimeoutExpired:
            self.r.note(f"PowerShell-запрос превысил {self.timeout}s и пропущен")
            return None
        except Exception as exc:  # noqa: BLE001
            self.r.note(f"PowerShell: {type(exc).__name__}: {exc}")
            return None
        finally:
            if path:
                with contextlib.suppress(OSError):
                    os.unlink(path)

    @staticmethod
    def as_list(data: Any) -> list[dict[str, Any]]:
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []

    # ---------- реестр ----------
    def reg_values(self, hive: Any, key_path: str) -> dict[str, tuple[int, Any]]:
        out: dict[str, tuple[int, Any]] = {}
        if not HAS_WINREG:
            return out
        try:
            with winreg.OpenKey(hive, key_path) as k:  # type: ignore[union-attr]
                i = 0
                while True:
                    try:
                        name, value, typ = winreg.EnumValue(k, i)  # type: ignore[union-attr]
                    except OSError:
                        break
                    out[name] = (typ, value)
                    i += 1
        except OSError:
            return out
        return out

    def reg_subkeys(self, hive: Any, key_path: str) -> list[str]:
        names: list[str] = []
        if not HAS_WINREG:
            return names
        try:
            with winreg.OpenKey(hive, key_path) as k:  # type: ignore[union-attr]
                i = 0
                while True:
                    try:
                        names.append(winreg.EnumKey(k, i))  # type: ignore[union-attr]
                    except OSError:
                        break
                    i += 1
        except OSError:
            return names
        return names

    def reg_hunt(
        self,
        keywords: re.Pattern[str],
        roots: Sequence[tuple[Any, str]] | None = None,
        max_depth: int = 3,
        max_keys: int = 400,
    ) -> list[dict[str, Any]]:
        """Обход ключей NVIDIA и поиск значений, чьё имя похоже на оверлей/запись/отключение."""
        found: list[dict[str, Any]] = []
        if not HAS_WINREG or winreg is None:
            return found
        if roots is None:
            roots = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\NVIDIA Corporation"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\NVIDIA Corporation"),
                (winreg.HKEY_CURRENT_USER, r"Software\NVIDIA Corporation"),
            ]
        visited = 0

        def walk(hive: Any, path: str, depth: int) -> None:
            nonlocal visited
            if depth < 0 or visited > max_keys:
                return
            visited += 1
            for name, (typ, value) in self.reg_values(hive, path).items():
                if keywords.search(name):
                    found.append({"key": path, "value": name, "type": typ, "data": str(value)[:120]})
            for sub in self.reg_subkeys(hive, path):
                walk(hive, f"{path}\\{sub}" if path else sub, depth - 1)

        for hive, path in roots:
            if hive is None:
                continue
            walk(hive, path, max_depth)
        return found

    # ==================================================================================
    # Сборщики
    # ==================================================================================

    def collect_all(self) -> None:
        if not IS_WIN:
            self.r.add(
                "INFO",
                "os.not_windows",
                "Живые проверки доступны только в Windows — запущено на другой ОС",
                detail=(
                    f"platform={platform.system()}. Проверки сервисов/реестра/процессов пропущены.\n"
                    "Логи при этом разбираются полностью: скопируй папку логов с Windows и выполни\n"
                    "  python nvidia_overlay_diag.py logs <папка_или_файл>"
                ),
                hypothesis="unknown",
            )
            return
        self.check_os_and_privileges()
        self.check_apps_and_files()
        self.check_driver_and_gpu()
        self.check_services()
        self.check_processes()
        self.check_settings_files()
        self.check_registry_switches()
        self.check_security_software()
        self.check_conflicting_processes()
        self.check_storage()
        # журнал событий добавляет main() (чтобы --no-events и --from работали предсказуемо)

    # ---------- 1. ОС, привилегии, сессия ----------
    def check_os_and_privileges(self) -> None:
        r = self.r
        ver = sys.getwindowsversion()  # type: ignore[attr-defined]
        build = ver.build
        name = ""
        try:
            vals = self.reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            name = str(vals.get("ProductName", ("", ""))[1])
            ubr = vals.get("UBR", ("", 0))[1]
            disp = f"{vals.get('DisplayVersion', ('',''))[1]}"
            r.snapshot["windows"] = {
                "caption": name,
                "version": f"{ver.major}.{ver.minor}.{build}",
                "build": build,
                "ubr": ubr,
                "display_version": disp,
            }
        except Exception:  # noqa: BLE001
            r.snapshot["windows"] = {"version": f"{ver.major}.{ver.minor}.{build}", "build": build}

        admin = False
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        r.snapshot["is_admin"] = admin
        r.snapshot["os_pretty"] = f"{name or 'Windows'} {ver.major}.{ver.minor} build {build}"
        r.snapshot["platform"] = f"Windows {platform.machine()}"

        if build < 19041:
            r.add(
                "HIGH",
                "os.build_old",
                f"Сборка Windows {build} ниже минимальной для NVIDIA App (19041 / 2004)",
                detail="NVIDIA App и его оверлей на более старых сборках не поднимаются: не хватает WinRT/DXGI-API.",
                fixes=["Обнови Windows до 22H2/23H2+ или используй GeForce Experience вместо NVIDIA App."],
                hypothesis="unknown",
            )
        else:
            r.add("OK", "os.build_ok", f"Сборка Windows {build} подходит NVIDIA App")

        if not admin:
            r.add(
                "MEDIUM",
                "priv.not_admin",
                "Скрипт/сессия без повышенных прав",
                detail=(
                    "Часть проверок (сервисы, журнал защиты, папки других профилей) будет беднее. "
                    "Кроме того, если сама игра запущена 'от имени администратора', оверлей без повышения в неё не попадёт."
                ),
                fixes=["Запусти PowerShell от администратора и повтори: python nvidia_overlay_diag.py scan"],
                hypothesis="elevated",
            )

        # Тип сессии: RDP/быстрый запуск ломает захват
        session_name = ""
        for sub in self.reg_subkeys(winreg.HKEY_CURRENT_USER, r"Volatile Environment"):
            vals = self.reg_values(winreg.HKEY_CURRENT_USER, rf"Volatile Environment\{sub}")
            sn = str(vals.get("SessionName", ("", ""))[1])
            if sn:
                session_name = sn
                break
        r.snapshot["session_name"] = session_name
        if session_name and "console" not in session_name.lower():
            r.add(
                "CRITICAL",
                "session.not_console",
                f"Текущая сессия не консольная: {session_name}",
                detail="Из RDP/удалённой сессии Desktop Duplication недоступен → оверлей и запись не стартуют никогда.",
                fixes=[
                    "Проверь оверлей физически у монитора этого ПК (или через Ctrl+Alt+Del-консоль).",
                    "Для удалёнки используй Parsec/Sunshine/Radmin с драйвером-захватом, а не встроенный RDP.",
                ],
                hypothesis="capture_target",
            )
        elif session_name:
            r.add("OK", "session.console", f"Сессия локальная ({session_name})")

    # ---------- 2. Установленные приложения и файлы оверлея ----------
    def check_apps_and_files(self) -> None:
        r = self.r
        base = Path(expand(NVIDIA_ROOT_WIN))
        app_roots = [p for p in (base / "NVIDIA App", base / "NVIDIA GeForce Experience", base) if p.exists()]
        r.snapshot["install_roots"] = [str(p) for p in app_roots]

        if not base.exists():
            r.add(
                "CRITICAL",
                "app.not_installed",
                NVIDIA_ROOT_WIN + " отсутствует",
                detail="Похоже, драйвер/приложение не установлены (или стоят в необычном месте / портативная сборка).",
                fixes=["Установи драйвер + NVIDIA App с nvidia.com; проверь, что установка не в 'Программы x86'."],
                hypothesis="app_ver",
            )
            return

        overlay_candidates = find_files(base, re.compile(r"(?i)^nvidia\s*overlay\.exe$"))
        if not overlay_candidates:
            overlay_candidates = find_files(base, re.compile(r"(?i)overlay.*\.exe$"))
        nvcontainer = find_files(base, re.compile(r"(?i)^nvcontainer\.exe$"))

        if not overlay_candidates:
            r.add(
                "CRITICAL",
                "app.overlay_missing",
                "Не найден NVIDIA Overlay.exe — компонент оверлея не установлен",
                detail=f"Искали рекурсивно в {base}. Обычно он лежит в <...>\\NVIDIA App\\CEF\\NVIDIA Overlay.exe.\n"
                "При 'выборочной' установке без NVIDIA App/оверлея файл отсутствует, а иконка Alt+Z не делает ничего.",
                fixes=[
                    "Перезапусти установщик драйвера → 'Выборочная' → включи NVIDIA App (и Component/Video, если есть) → 'Восстановить'.",
                    "Или: NVIDIA App → Помощь → переустановить приложение; после — перезагрузка.",
                ],
                evidence=[f"корни: {[str(p) for p in app_roots][:3]}"],
                hypothesis="app_ver",
            )
        else:
            paths = [str(p) for p in overlay_candidates]
            r.snapshot["overlay_exe"] = paths
            sizes = []
            for p in overlay_candidates:
                with contextlib.suppress(OSError):
                    sizes.append(f"{p} ({p.stat().st_size // 1024} КБ)")
            r.add(
                "OK",
                "app.overlay_present",
                "Файл оверлея на месте",
                detail="; ".join(sizes or paths),
                fixes=[] if len(overlay_candidates) == 1 else ["Осталось несколько копий оверлея (GFE + App?) — оставь одну, вторую удали через 'Установка и удаление'."],
                evidence=paths,
                hypothesis="app_ver",
            )
            if sizes:
                small = [s for s in sizes if int(re.search(r"\((\d+) КБ\)", s).group(1)) < 200]
                if small:
                    r.add(
                        "HIGH",
                        "app.overlay_truncated",
                        "NVIDIA Overlay.exe подозрительно маленького размера",
                        detail="; ".join(small) + "\nОбрыв установки/лечение антивирусом даёт урезанный файл.",
                        fixes=["Проверь карантин защитника и переустанови приложение."],
                        hypothesis="blocked",
                    )
        r.snapshot["nvcontainer_exe"] = [str(p) for p in nvcontainer]
        if not nvcontainer:
            r.add(
                "HIGH",
                "app.nvcontainer_missing",
                "Не найден nvcontainer.exe",
                detail="Без контейнера NVIDIA App не поднимает ни оверлей, ни запись.",
                fixes=["Восстанови установку драйвера/App; проверь, что папка не в 'Защищённых папках' и не удалена оптимизатором."],
                hypothesis="svc",
            )

        # Одновременные NVIDIA App и GeForce Experience
        both = (base / "NVIDIA App").exists() and (base / "NVIDIA GeForce Experience").exists()
        if both:
            r.add(
                "HIGH",
                "app.both_products",
                "Одновременно стоят NVIDIA App и GeForce Experience",
                detail="Два продукта делят один оверлей-хост и конфликтуют: Alt+Z может не открываться ни там, ни там.",
                fixes=["Удали GeForce Experience (Параметры → Приложения), перезагрузись, оставь NVIDIA App."],
                hypothesis="app_ver",
            )

    # ---------- 3. Драйвер / GPU ----------
    def check_driver_and_gpu(self) -> None:
        r = self.r
        gpus = self.ps(
            "$g=@(); Get-CimInstance Win32_VideoController | ForEach-Object { $g += [pscustomobject]@{ "
            "Name=$_.Name; DriverVersion=$_.DriverVersion; Status=$_.Status; PNP=$_.PNPDeviceID; "
            "Res=(('{0}x{1}' -f $_.CurrentHorizontalResolution, $_.CurrentVerticalResolution)); "
            "DriverDate=$_.DriverDate }; }; $g"
        )
        gpus = self.as_list(gpus)
        r.snapshot["video_controllers"] = gpus
        if not gpus:
            r.add(
                "HIGH",
                "driver.no_query",
                "Не удалось опросить видеоадаптеры (Win32_VideoController)",
                detail="WMI-запрос вернул пусто — иногда это сломанный WMI, иногда реально нет видеодрайвера.",
                fixes=["Проверь 'winmgmt /verifyrepository' и Диспетчер устройств → Видеоадаптеры.", "nvidia-smi в консоли администратора."],
                hypothesis="driver",
            )
            return

        nv = [g for g in gpus if "nvidia" in str(g.get("Name", "")).lower() or "NVIDIA" in str(g.get("AdapterCompatibility", ""))]
        if not nv:
            r.add(
                "CRITICAL",
                "driver.no_nvidia_gpu",
                "Среди активных видеоадаптеров нет NVIDIA",
                detail="Адаптеры: " + ", ".join(str(g.get("Name")) for g in gpus) + "\nБез активного nGPU оверлей/запись невозможны (dGPU отключена в BIOS/Device Manager, или ноутбук в Eco/IGPU-only).",
                fixes=[
                    "Диспетчер устройств → Видеоадаптеры → включить отключённое устройство (Ошибка 22/43).",
                    "В фирменной утилите ноутбука переключи режим графики на 'dGPU only'/Discrete.",
                    "Проверь, что dGPU не 'Unknown device' после сбоя питания.",
                ],
                hypothesis="driver",
            )
            return
        bad = [g for g in nv if str(g.get("Status", "")).lower() not in ("ok", "")]
        if bad:
            r.add(
                "CRITICAL",
                "driver.gpu_status",
                "Видеодаптер NVIDIA в не-RUNNING статусе",
                detail="; ".join(f"{g.get('Name')}: status={g.get('Status')}" for g in bad),
                fixes=["Диспетчер устройств → свойства → 'Устранить'/'Включить'; часто Код 43 = кривый/модифицированный драйвер.", "Полностью переустанови драйвер (чистая установка)."],
                hypothesis="driver",
            )
        else:
            dv = str(nv[0].get("DriverVersion") or "")
            r.add("OK", "driver.present", f"GPU NVIDIA активен: {nv[0].get('Name')} (драйвер {dv or '?'})")
            r.snapshot["driver_version"] = dv
            if dv:
                try:
                    major = int(dv.split(".")[0])
                    if major < 300:  # <5xx ветки = очень старый драйвер (условный порог)
                        r.add(
                            "MEDIUM",
                            "driver.old",
                            f"Версия драйвера {dv} выглядит устаревшей",
                            detail="Старые ветки не знают текущих API NVIDIA App (иногда оверлей просто не стартует).",
                            fixes=["Обнови драйвер до актуальной ветки (Studio или Game Ready), 'Чистая установка'."],
                            hypothesis="driver",
                        )
                except (ValueError, IndexError):
                    pass

        if len(gpus) > 1:
            r.add(
                "MEDIUM",
                "driver.hybrid",
                f"Активно {len(gpus)} видеоадаптеров — гибридная графика (Optimus/Multi-GPU)",
                detail="Имена: " + ", ".join(str(g.get("Name")) for g in gpus)
                + "\nНа гибридных схемах кадр игры часто идёт через iGPU, а NVENC/hook живут на dGPU → оверлей не стартует или пишет чёрный экран.",
                fixes=[
                    "Параметры → Система → Дисплей → Графика → для нужной игры 'Высокая производительность' (NVIDIA).",
                    "Переключи ноутбук в dGPU-only/MUX и перезагрузись.",
                    "Вместо 'Захват игры' попробуй 'Захват рабочего стола' — если работает, это точно гибрид.",
                ],
                hypothesis="capture_target",
            )

        smi = None
        for cand in ("nvidia-smi", r"C:\Windows\System32\nvidia-smi.exe", r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"):
            exe = shutil.which(cand) or (cand if Path(cand).exists() else None)
            if exe:
                try:
                    smi = subprocess.run([exe, "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"], capture_output=True, timeout=20)
                except Exception:  # noqa: BLE001
                    smi = None
                break
        if smi is not None:
            txt = smi.stdout.decode("utf-8", "replace").strip() or smi.stderr.decode("utf-8", "replace").strip()
            r.snapshot["nvidia_smi"] = txt[:400]
            if "not found" in txt.lower() or "no devices" in txt.lower() or smi.returncode not in (0, None):
                r.add(
                    "HIGH",
                    "driver.smi_fail",
                    "nvidia-smi не видит GPU",
                    detail=txt[:300],
                    fixes=["Код 43 / сломанный драйвер: чистая переустановка; проверь питание PCIe и разгон.", "В виртуалке без GPU-проброса оверлей невозможен."],
                    hypothesis="driver",
                )
            else:
                r.add("OK", "driver.smi", "nvidia-smi отвечает: " + txt.replace("\n", " | ")[:160])
        else:
            r.note("nvidia-smi не найден в PATH (обычно лежит в C:\\Windows\\System32)")

    # ---------- 4. Сервисы ----------
    CRITICAL_SVC = re.compile(r"(?i)(NVDisplay\.Container|NVIDIA\s?Display\s?Container|NvidiaApp|NVIDIA\s?App|NvContainerLocalSystem|NvTelemetryContainer|NVIDIA\s?StreamSrv)")

    def check_services(self) -> None:
        r = self.r
        data = self.ps(
            "Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'NVIDIA|^Nv' -or $_.DisplayName -match 'NVIDIA' } | "
            "ForEach-Object { [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; State=$_.State; StartMode=$_.StartMode; "
            "PathName=$_.PathName; ServiceAccount=$_.StartName; ExitCode=$_.ExitCode } }"
        )
        svcs = self.as_list(data)
        if not svcs:
            r.add(
                "HIGH",
                "svc.none",
                "Не найдено ни одного сервиса NVIDIA",
                detail="Ни NVIDIA Display Container, ни App Container не зарегистрированы — приложение установлено криво или сервисы удалены 'оптимизатором'.",
                fixes=[
                    "sc query type= all | findstr -i nvidia  — убедись, что пусто.",
                    "Восстанови установку драйвера+App; после установки перезагрузись.",
                    "Если удалял сервисы руками (sc delete) — только переустановка.",
                ],
                hypothesis="svc",
            )
            return
        r.snapshot["services"] = [{k: v for k, v in s.items() if k != "PathName"} for s in svcs]

        running, stopped_critical, disabled_critical = [], [], []
        for s in svcs:
            state = str(s.get("State", ""))
            start = str(s.get("StartMode", ""))
            crit = bool(self.CRITICAL_SVC.search(str(s.get("Name", "")) + " " + str(s.get("DisplayName", ""))))
            if state.lower() == "running":
                running.append(s)
            elif crit:
                (disabled_critical if start.lower() in ("disabled", "manual") else stopped_critical).append(s)

        r.snapshot["services_running"] = len(running)
        r.add("INFO", "svc.summary", f"Сервисов NVIDIA: {len(svcs)}, запущено: {len(running)}",
              detail="; ".join(f"{s.get('Name')}={s.get('State')}/{s.get('StartMode')}" for s in svcs)[:600])

        if stopped_critical:
            r.add(
                "CRITICAL",
                "svc.stopped",
                "Критичный для оверлея сервис NVIDIA остановлен",
                detail="; ".join(f"{s.get('Name')} (state={s.get('State')}, start={s.get('StartMode')}, exit={s.get('ExitCode')})" for s in stopped_critical),
                fixes=[
                    "PowerShell (админ): Start-Service NVDisplay.ContainerLocalSystem  (и остановленные App/Telemetry контейнеры).",
                    "Если стартует и сразу падает: смотри Applications and Services Logs → Microsoft → Windows → ServiceControlManager, и C:\\ProgramData\\NVIDIA Corporation\\...\\NvContainer*.log",
                    "Проверь зависимость 'Log on as' — у сервиса должен быть LocalSystem, а не отключённая учётка.",
                ],
                hypothesis="svc",
            )
        if disabled_critical:
            r.add(
                "CRITICAL",
                "svc.disabled",
                "Сервис NVIDIA отключён/переведён в Manual",
                detail="; ".join(f"{s.get('Name')}: StartMode={s.get('StartMode')}" for s in disabled_critical)
                + "\nТипично после 'твинов' Windows (WinUtil/Privacy scripts/'отключить телеметрию').",
                fixes=[
                    "Set-Service NVDisplay.ContainerLocalSystem -StartupType Automatic; Start-Service NVDisplay.ContainerLocalSystem",
                    "Откати твики оптимизации (или верни StartMode сервисам NVIDIA вручную).",
                ],
                hypothesis="svc",
            )
        if not stopped_critical and not disabled_critical and running:
            r.add("OK", "svc.ok", "Все нужные сервисы NVIDIA запущены",
                  detail="; ".join(str(s.get("Name")) for s in running)[:300])

    # ---------- 5. Процессы ----------
    def check_processes(self) -> None:
        r = self.r
        data = self.ps(
            "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'NVIDIA|nvtray|nvcontainer|NvTelemetry|nv-?display|nvnode' } | "
            "ForEach-Object { [pscustomobject]@{ Name=$_.Name; PID=$_.ProcessId; Cmd=$_.CommandLine; "
            "Path=$_.ExecutablePath; Sessions=$_.SessionId } }"
        )
        procs = self.as_list(data)
        r.snapshot["nvidia_processes"] = [
            {"name": p.get("Name"), "pid": p.get("PID"), "path": p.get("Path"), "cmd": str(p.get("Cmd"))[:200]} for p in procs
        ]
        names = [str(p.get("Name", "")).lower() for p in procs]
        overlay_up = any("overlay" in n for n in names)
        app_up = any(n in ("nvidia app.exe", "nvidiaapp.exe", "nvtray.exe") for n in names)
        container_up = any("nvcontainer" in n for n in names)
        r.snapshot["overlay_running"] = overlay_up

        if overlay_up:
            up = [p for p in procs if "overlay" in str(p.get("Name", "")).lower()]
            r.add(
                "OK",
                "proc.overlay_running",
                "Процесс оверлея запущен",
                detail="; ".join(f"{p.get('Name')} pid={p.get('PID')} cmd={str(p.get('Cmd'))[:120]}" for p in up),
                fixes=[
                    "Если процесс есть, но окна нет — оно или на другом мониторе/в другой сессии, или не удалось отрисоваться (CEF/GPU).",
                    "Проверь, не 'свёрнут' ли оверлей в неактивный слой: Alt+Z, затем Alt+X (скрыть/показать).",
                ],
                hypothesis="overlay_proc",
            )
        else:
            detail = "Процесс NVIDIA Overlay.exe не найден."
            fixes = []
            if not app_up:
                detail += " Приложение NVIDIA App тоже не запущено → оверлею неоткуда взяться."
                fixes.append("Запусти NVIDIA App (поиск → NVIDIA App) и включи автозапуск: Параметры → App → 'Запускать при входе'.")
            if not container_up:
                detail += " nvcontainer.exe не запущен — оверлей в таком состоянии не поднимется никогда."
                fixes.append("Start-Service NVDisplay.ContainerLocalSystem; если не стартует — переустановка драйвера.")
            fixes.append("После запуска приложения нажми Alt+Z и дождись 15-20 с (первый старт CEF долгий).")
            r.add(
                "HIGH",
                "proc.overlay_absent",
                "Процесс оверлея не запущен",
                detail=detail,
                fixes=fixes,
                evidence=[f"nvidia-процессы: {', '.join(sorted(set(names))[:8]) or 'нет'}"],
                hypothesis="overlay_proc",
            )

    # ---------- 6. Settings.json и пути записи ----------
    def iter_candidate_files(self, patterns: re.Pattern[str], exts: Sequence[str], max_files: int = 400) -> Iterator[Path]:
        seen = 0
        for root in LOG_ROOTS_WIN:
            rp = Path(expand(root))
            if not rp.exists():
                continue
            try:
                for p in rp.rglob("*"):
                    if seen > max_files * 6:
                        return
                    seen += 1
                    try:
                        if not p.is_file():
                            continue
                    except OSError:
                        continue
                    if p.suffix.lower() not in exts:
                        continue
                    if patterns.search(p.name):
                        yield p
                    if seen > 30000:  # не превращаем диагностику в полный обход диска
                        return
            except (PermissionError, OSError):
                continue

    def check_settings_files(self) -> None:
        r = self.r
        settings = sorted(self.iter_candidate_files(SETTINGS_NAME_RE, (".json",), max_files=120), key=lambda p: p.stat().st_mtime, reverse=True)
        r.snapshot["settings_files"] = [str(p) for p in settings[:10]]
        if not settings:
            r.add(
                "MEDIUM",
                "cfg.no_settings",
                "Не найден Settings.json/конфиг NVIDIA App в ожидаемых папках",
                detail=f"Искали в: {', '.join(LOG_ROOTS_WIN[:4])}\nЕсли приложение ещё ни разу не запускалось (или профиль другой) — это объяснимо; иначе конфиг потерян.",
                fixes=["Запусти NVIDIA App хотя бы раз; затем повтори сканирование."],
                hypothesis="config_corrupt",
            )
            return

        keys_of_interest: dict[str, Any] = {}
        paths_found: list[str] = []
        broken: list[str] = []
        for p in settings[:8]:
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
                obj = json.loads(raw)
            except Exception as exc:  # noqa: BLE001
                broken.append(f"{p}: {type(exc).__name__}: {exc}")
                continue

            def walk(node: Any, path: str = "") -> None:
                if isinstance(node, dict):
                    for k, v in node.items():
                        kp = f"{path}/{k}"
                        kl = str(k).lower()
                        if any(t in kl for t in ("overlay", "capture", "record", "replay", "shadow", "inject", "desktop", "enable", "hotkey", "shortcut")):
                            if isinstance(v, (bool, int, str)) and len(str(v)) < 120:
                                keys_of_interest[kp] = v
                        if isinstance(v, str) and re.match(r"^[A-Za-z]:\\", v):
                            paths_found.append(v)
                        walk(v, kp)
                elif isinstance(node, list):
                    for i, v in enumerate(node[:40]):
                        walk(v, f"{path}[{i}]")

            walk(obj)

        r.snapshot["settings_keys"] = keys_of_interest
        if broken:
            r.add(
                "HIGH",
                "cfg.broken",
                "Файл настроек не парсится (битый JSON)",
                detail="\n".join(broken[:6]),
                fixes=["Закрой NVIDIA App, переименуй файл в .bad и запусти приложение — настройки создадутся заново."],
                evidence=broken[:6],
                hypothesis="config_corrupt",
            )

        off = {k: v for k, v in keys_of_interest.items() if str(v).lower() in ("false", "0", "off", "disabled") and any(t in k.lower() for t in ("overlay", "capture", "record", "replay", "shadow"))}
        if off:
            r.add(
                "CRITICAL",
                "cfg.disabled",
                "В настройках оверлея/записи стоит 'выключено'",
                detail="; ".join(f"{k} = {v}" for k, v in off.items()),
                fixes=["NVIDIA App → Настройки → внутриигровой оверлей / Запись → включить; потом полный выход из приложения и запуск.",
                       "Если значения выставлялись политиками — снимай их в HKLM\\SOFTWARE\\Policies\\NVIDIA Corporation."],
                evidence=[f"{k} = {v}" for k, v in off.items()],
                hypothesis="disabled",
            )
        else:
            r.add("OK", "cfg.enabled", "В конфиге флаги overlay/capture не выключены",
                  detail="; ".join(f"{k}={v}" for k, v in list(keys_of_interest.items())[:12]))

        r.snapshot["candidate_paths"] = sorted(set(paths_found))[:20]
        self._check_paths("cfg.path", paths_found, "Путь из настроек")

    def _check_paths(self, code_prefix: str, paths: Iterable[str], label: str) -> None:
        r = self.r
        bad = []
        for raw in sorted(set(paths))[:12]:
            p = Path(expand(raw))
            try:
                drive = p.drive[:2].upper()
                if drive and not Path(drive + "\\").exists():
                    bad.append(f"{raw}: диск {drive} недоступен")
                    continue
                if p.exists():
                    if p.is_dir():
                        free = shutil.disk_usage(str(p)).free / 1024**3
                        if free < 15:
                            bad.append(f"{raw}: свободно {free:.1f} ГБ — мало для записи")
                        if "onedrive" in str(p).lower():
                            bad.append(f"{raw}: папка внутри OneDrive — 'файлы по требованию' ломают запись")
                    else:
                        bad.append(f"{raw}: ожидается папка, а тут файл")
                else:
                    bad.append(f"{raw}: не существует")
            except OSError as exc:
                bad.append(f"{raw}: {exc}")
        if bad:
            r.add(
                "HIGH",
                f"{code_prefix}.bad_path",
                f"{label}: проблемы с путями",
                detail="\n".join(bad[:8]),
                fixes=["Переназначь папку записи на локальный NTFS-диск (D:\\NVCapture), освободи место, уйди из OneDrive.",
                       "Проверь права 'Изменение' для своего пользователя на эту папку."],
                evidence=bad[:8],
                hypothesis="storage",
            )

    # ---------- 7. Реестр: выключатели оверлея/политики ----------
    def check_registry_switches(self) -> None:
        r = self.r
        rx = re.compile(r"(?i)(overlay|capture|record|replay|shadow|inject|privacy|disable|enable|telemetry|policy)")
        hits = self.reg_hunt(rx)
        r.snapshot["registry_hits"] = hits[:40]
        if not hits:
            r.note("реестр: совпадений по overlay/capture/record не найдено (нормально для домашней сборки)")
            return
        suspicious = [h for h in hits if re.search(r"(?i)^(0|false|off)$", str(h["data"]).strip()) and re.search(r"(?i)(overlay|capture|record|replay|shadow|enable)", h["value"])]
        policy = [h for h in hits if "Policies" in h["key"]]
        for h in policy:
            r.add(
                "MEDIUM" if h not in suspicious else "HIGH",
                "reg.policy",
                f"Политика NVIDIA: {h['key']}\\{h['value']} = {h['data']}",
                detail="Значения под HKLM\\SOFTWARE\\Policies переопределяют настройки приложения — в NVIDIA App галки могут быть серыми.",
                fixes=["gpedit.msc → Конфигурация компьютера → Административные шаблоны → NVIDIA Corporation; или удали параметр из реестра (только зная, зачем он)."],
                evidence=[f"{h['key']} :: {h['value']} = {h['data']}"],
                hypothesis="disabled",
            )
        for h in suspicious:
            if "Policies" in h["key"]:
                continue
            r.add(
                "MEDIUM",
                "reg.switch_off",
                f"Похожий на 'выключено' параметр: {h['key']}\\{h['value']} = {h['data']}",
                detail="Совпадение по имени — проверь вручную, что оно значит, прежде чем менять.",
                fixes=["Экспортируй ключ (.reg), потом ставь 1/0 по одному и проверяй Alt+Z."],
                evidence=[f"{h['key']} :: {h['value']} = {h['data']}"],
                hypothesis="disabled",
            )

    # ---------- 8. Защитники / AV / безопасность ----------
    def check_security_software(self) -> None:
        r = self.r
        av = self.ps(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
            "ForEach-Object { [pscustomobject]@{ Name=$_.displayName; State=$_.productState; PathToSignedProductExe=$_.pathToSignedProductExe } }"
        )
        av = self.as_list(av)
        r.snapshot["antivirus"] = [a.get("Name") for a in av]
        if av:
            names = ", ".join(str(a.get("Name")) for a in av)
            r.add(
                "MEDIUM" if len(av) > 1 else "LOW",
                "sec.av",
                "Активные защитники: " + names,
                detail="Поведенческие блокировки 'инъекция в процесс/запись экрана' — частая причина 'оверлей не запускается' при живых сервисах.",
                fixes=[
                    "Добавь ИСКЛЮЧЕНИЕ на папку C:\\Program Files\\NVIDIA Corporation (целиком) и на папку записи.",
                    "На 5 минут отключи защиту и проверь Alt+Z: если заработало — точно блокировка, оформляй исключение постоянно.",
                    "UAC/защита памяти в ESET/Kaspersky/Avast/Dr.Web: 'Мониторинг прямого доступа', 'Anti-STEALTH', 'Блокировка скриншотов' — выключить.",
                ],
                evidence=[f"{a.get('Name')} state={a.get('State')}" for a in av],
                hypothesis="blocked",
            )

        cfa = self.reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access") if HAS_WINREG else {}
        if cfa:
            enabled = str(cfa.get("EnableControlledFolderAccess", ("", 0))[1])
            if enabled.strip() in ("1", "0x1"):
                r.add(
                    "HIGH",
                    "sec.cfa",
                    "Включён 'Контроль папок' (Controlled Folder Access)",
                    detail="Защитник не даст приложению писать в 'Документы/Видео', если оно не в списке разрешённых: запись обрывается или оверлей не стартует.",
                    fixes=[
                        "Безопасность Windows → Защита вируса и угроз → Защита от вымогателей → 'Разрешить взаимодействие с приложением' → добавь NVIDIA App.exe и NVIDIA Overlay.exe (пути из этого отчёта).",
                        "Или переназначь папку записи на защищённую не входящую (D:\\NVCapture).",
                    ],
                    hypothesis="blocked",
                )
            else:
                r.add("OK", "sec.cfa_off", "Контроль папок выключен")

        threat_dets = self.ps(
            "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | "
            "ForEach-Object { [pscustomobject]@{ Time=$_.InitialDetectionTime; Resources=$_.Resources; ID=$_.ThreatID } }"
        )
        threat_dets = self.as_list(threat_dets)
        nv_threats = [t for t in threat_dets if re.search(r"(?i)nvidia", json.dumps(t))]
        if nv_threats:
            r.add(
                "CRITICAL",
                "sec.defender_threat",
                "Defender реагировал на файлы NVIDIA",
                detail="\n".join(f"{t.get('Time')}: {str(t.get('Resources'))[:160]}" for t in nv_threats[:5]),
                fixes=["Восстанови файл из карантина + добавь в исключения, затем переустанови NVIDIA App.", "Проверь, что качал драйвер с nvidia.com (не 'ускоритель драйверов')."],
                hypothesis="blocked",
            )

        smartscreen = self.reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") if HAS_WINREG else {}
        if str(smartscreen.get("SmartScreenEnabled", ("", ""))[1]).lower() in ("block", "off"):
            r.add(
                "LOW",
                "sec.smartscreen",
                "SmartScreen в режиме Block/Off",
                detail="Влияет на запуск подписанных не полностью компонентов при первом старте.",
                fixes=["На тест поставь 'Warn'."],
                hypothesis="blocked",
            )

    # ---------- 9. Конфликтующий софт ----------
    CONFLICT_RES = {
        "RTSS": re.compile(r"(?i)^(rtss|rtsstray|rtsshooks)\.exe$"),
        "MSI Afterburner": re.compile(r"(?i)^msiafterburner\.exe$"),
        "Steam": re.compile(r"(?i)^steam(64)?\.exe$"),
        "Discord": re.compile(r"(?i)^discord\.exe$"),
        "Nahimic/Sonic": re.compile(r"(?i)^(nahimic|nahimic_svc|nahimicmsiservice|ss2svc|sonic|rksvc)\w*\.exe$"),
        "Razer": re.compile(r"(?i)^(razesynapse|rzsvc|rz*\w*synapse)\.exe$"),
        "Corsair iCUE": re.compile(r"(?i)^(icue|corsairsvc32|ccuv4service)\.exe$"),
        "Logitech G Hub": re.compile(r"(?i)^(lghub|lghub_agent)\.exe$"),
        "Xbox Game Bar": re.compile(r"(?i)xboxgamebar"),
        "OBS": re.compile(r"(?i)^obs(64)?\.exe$"),
        "XSplit": re.compile(r"(?i)^xsplit"),
        "Fraps/Bandicam": re.compile(r"(?i)^(fraps|bandicam)\.exe$"),
        "EVGA Precision": re.compile(r"(?i)^(evga|precisionx)\w*\.exe$"),
        "Special K / Lossless Scaling / MangoHUD": re.compile(r"(?i)^(specialk|losslessscaling|mangohud|mvtoh)\w*\.exe$"),
        "AutoHotkey/PowerToys (хуки клавиш)": re.compile(r"(?i)^(ahk|autohotkey|powertoys\.\w+)\.exe$"),
        "HWiNFO": re.compile(r"(?i)^hwinfo\d*\.exe$"),
    }

    def check_conflicting_processes(self) -> None:
        r = self.r
        data = self.ps(
            "Get-CimInstance Win32_Process | ForEach-Object { [pscustomobject]@{ Name=$_.Name; PID=$_.ProcessId; "
            "Path=$_.ExecutablePath; Cmd=$_.CommandLine } }"
        )
        procs = self.as_list(data)
        r.snapshot["process_count"] = len(procs)
        hits: dict[str, list[str]] = {}
        for p in procs:
            nm = str(p.get("Name") or "")
            path = str(p.get("Path") or "")
            for label, rx in self.CONFLICT_RES.items():
                if rx.search(nm) or (path and rx.search(Path(path).name)):
                    hits.setdefault(label, []).append(nm or path)
        r.snapshot["conflicts"] = {k: sorted(set(v)) for k, v in hits.items()}
        if hits:
            lst = ", ".join(f"{k} ({', '.join(sorted(set(v))[:2])})" for k, v in sorted(hits.items()))
            r.add(
                "MEDIUM" if len(hits) < 3 else "HIGH",
                "conflict.software",
                "Обнаружен софт, конкурирующий за оверлей/хуки/захват",
                detail=lst + "\nСовпадение не равно вине: отключай по одному и тестируй Alt+Z, начиная с RTSS/Afterburner и Game Bar.",
                fixes=[
                    "RTSS: закрой полностью (не только Afterburner); в RTSS сними 'On-Screen Display' для всех.",
                    "Steam: свойства игры → снимите 'включать оверлей Steam'.",
                    "Discord: Параметры → Игровой оверлей → выкл.",
                    "Xbox Game Bar: Параметры → Игры → Xbox Game Bar → выкл; 'Записи' → фоновую запись выкл.",
                    "Nahimic/Sonic Studio: останови службы (Остановить 'NahimicSvc') на тест.",
                    "PowerToys/AutoHotkey, 'усилители мыши/клавиатуры' — выйди полностью из трей.",
                ],
                evidence=[f"{k}: {', '.join(sorted(set(v))[:4])}" for k, v in sorted(hits.items())],
                hypothesis="conflict",
            )
        else:
            r.add("OK", "conflict.none", "Типовых конкурентов оверлея в процессах не видно")

    # ---------- 10. Диск/папки ----------
    def check_storage(self) -> None:
        r = self.r
        if HAS_WINREG:
            vals = self.reg_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
            vid = str(vals.get("{F3CE0F7C-C45F-46E6-9D97-82C4F0EB3D6D}", ("", vals.get("My Video", ("", ""))[1]))[1])
        else:
            vid = ""
        vid = expand(vid) if vid else str(Path.home() / "Videos")
        r.snapshot["videos_folder"] = vid
        p = Path(vid)
        free: float | None = None
        if p.exists():
            try:
                free = shutil.disk_usage(str(p)).free / 1024**3
            except OSError as exc:
                r.add(
                    "MEDIUM",
                    "disk.query",
                    f"Не удалось проверить свободное место на '{p}'",
                    detail=f"{type(exc).__name__}: {exc}",
                    fixes=["Если диск сетевой/съёмный — переназначь папку записи на локальный NTFS-диск."],
                    hypothesis="storage",
                )
        if free is not None:
            if free < 15:
                r.add(
                    "HIGH",
                    "disk.low_space",
                    f"На диске папки 'Видео' свободно {free:.1f} ГБ",
                    detail="Instant Replay пишет буфер непрерывно; при 0.5-1 ГБ/мин место кончается быстро, а без места запись не стартует.",
                    fixes=["Освободи 20-30+ ГБ или переназначь папку записи на другой диск в настройках NVIDIA App."],
                    evidence=[f"{p} → {free:.1f} ГБ свободно"],
                    hypothesis="storage",
                )
            else:
                r.add("OK", "disk.space", f"Свободно {free:.0f} ГБ на диске папки '{p}'")
        elif not p.exists():
            r.add(
                "MEDIUM",
                "disk.novideos",
                f"Папка 'Видео' не найдена: {p}",
                detail="Если путь записи в NVIDIA App указывает на неё — запись невозможна физически.",
                fixes=["Создай папку вручную или выбери другую в настройках NVIDIA App → Запись."],
                hypothesis="storage",
            )

        if HAS_WINREG:
            gamebar = self.reg_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\GameBar")
            dvr_pol = self.reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\GameDVR")
            allow = {**{k: v[1] for k, v in gamebar.items()}, **{k: v[1] for k, v in dvr_pol.items()}}
            if any(str(v).strip() in ("1", "0x1") for k, v in allow.items() if "captur" in k.lower() or "AllowAutoGameMode" in k):
                r.add(
                    "LOW",
                    "conflict.gamebar",
                    "Game Bar / GameDVR-захват включён",
                    detail="Два параллельных DXGI-захвата — классический конфликт. Параметры: " + json.dumps({k: str(v) for k, v in list(allow.items())[:8]}),
                    fixes=["Параметры → Игры → Xbox Game Bar → выкл; 'Записи' → фоновую запись выкл."],
                    hypothesis="conflict",
                )

    # ---------- 11. Журнал событий ----------
    def check_event_log(self) -> None:
        r = self.r
        days = int(r.snapshot.get("_days", 3))
        script = EVENTS_PS.replace("@@DAYS@@", str(days))
        events = self.as_list(self.ps(script))
        r.snapshot["events_count"] = len(events)
        if not events:
            r.add("INFO", "ev.clean", f"За последние {days} дн. релевантных событий в журнале нет")
            return
        tdr = [e for e in events if "nvlddmkm" in str(e.get("Prov", "")).lower()]
        crash = [e for e in events if str(e.get("Prov")) in ("Application Error", "Application Hang", "Windows Error Reporting")]
        ci = [e for e in events if "CodeIntegrity" in str(e.get("Prov", ""))]
        r.snapshot["events"] = [
            {"time": e.get("T"), "provider": e.get("Prov"), "id": e.get("Id"), "level": e.get("Lvl"), "msg": str(e.get("Msg"))[:240]}
            for e in events[:40]
        ]
        if tdr:
            r.add(
                "CRITICAL",
                "ev.tdr",
                f"В System-журнале {len(tdr)} событий nvlddmkm (сбой/восстановление видеодрайвера)",
                detail="\n".join(f"{e.get('T')} id={e.get('Id')}: {str(e.get('Msg'))[:160]}" for e in tdr[:6]),
                fixes=[
                    "Это TDR: оверлей падает вместе с драйвером. Сбрось разгон/кривые, проверь температуры и питание.",
                    "Как диагностика: HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers → TdrDelay=8 (после проверки верни).",
                ],
                hypothesis="encoder",
            )
        if crash:
            mods = []
            for e in crash:
                m = re.search(r"(?i)faulting\s+module:?\s*([^\r\n]+)", str(e.get("Msg")))
                app = re.search(r"(?i)faulting\s+application:?\s*([^\r\n]+)", str(e.get("Msg")))
                mods.append(f"{e.get('T')} app={app.group(1).strip() if app else '?'} module={m.group(1).strip() if m else '?'}")
            r.add(
                "HIGH",
                "ev.crash",
                f"Есть аварийные завершения NVIDIA-процессов ({len(crash)})",
                detail="\n".join(mods[:6]),
                fixes=[
                    "Судьбу решает 'Faulting module': nvidia*.dll → переустановка драйвера; чужая dll → отключай соответствующий софт.",
                    "Собери WER-дамп: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps для NVIDIA Overlay.exe, потом пришли .dmp-имена.",
                ],
                evidence=mods[:6],
                hypothesis="overlay_proc",
            )
        if ci:
            r.add(
                "HIGH",
                "ev.codeintegrity",
                "Code Integrity блокировал загрузку модулей NVIDIA",
                detail="\n".join(f"{e.get('T')} id={e.get('Id')}: {str(e.get('Msg'))[:200]}" for e in ci[:5]),
                fixes=["Это WDAC/CI-policy: нужны правила-исключения для C:\\Program Files\\NVIDIA Corporation (обычно вопрос корпоративных политик)."],
                hypothesis="blocked",
            )


# --------------------------------------------------------------------------------------
# Поиск и разбор лог-файлов
# --------------------------------------------------------------------------------------


def find_log_files(roots: Sequence[str], limit: int, hints: re.Pattern[str] | None = None) -> list[Path]:
    """Свежие лог-файлы NVIDIA (по возможности) — сортировка по времени модификации."""
    out: dict[Path, float] = {}
    for root in roots:
        rp = Path(expand(root))
        if not rp.exists():
            continue
        if rp.is_file():
            with contextlib.suppress(OSError):
                out[rp] = rp.stat().st_mtime
            continue
        scanned = 0
        for p in rp.rglob("*"):
            scanned += 1
            if scanned > 40000:
                break
            try:
                if not p.is_file():
                    continue
                if p.suffix.lower() not in LOG_EXTS:
                    continue
                if hints is not None and not hints.search(p.name):
                    continue
                st = p.stat()
            except OSError:
                continue
            if st.st_size == 0:
                continue
            out[p] = st.st_mtime
    ranked = sorted(out.items(), key=lambda kv: kv[1], reverse=True)
    return [p for p, _ in ranked[:limit]]


def analyze_paths(
    report: Report,
    paths: Sequence[str],
    *,
    sigs: Sequence[dict[str, Any]],
    context: int = 0,
    tail_kb: int = 900,
    max_files: int = 25,
    any_files: bool = False,
    per_file_limit: int = 6,
) -> list[Path]:
    """Разбирает файлы/папки, добавляет находки в report. Возвращает список разобранных файлов."""
    files: list[Path] = []
    for raw in paths:
        p = Path(expand(raw))
        if p.exists() and p.is_file():
            files.append(p)
        elif p.exists() and p.is_dir():
            files.extend(
                find_log_files([str(p)], limit=max_files, hints=None if any_files else LOG_NAME_HINTS)
            )
        elif glob.has_magic(raw):
            for g in glob.glob(expand(raw), recursive=True):
                gp = Path(g)
                if gp.is_file():
                    files.append(gp)
        else:
            report.add(
                "LOW",
                "log.not_found",
                f"Путь не найден: {raw}",
                detail="Проверь путь/полномочия (для ProgramData иногда нужен запуск от администратора).",
                hypothesis="unknown",
                source="cli",
            )
    uniq: list[Path] = []
    seen: set[str] = set()
    for f in files:
        k = str(f).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)
    uniq = uniq[:max_files]

    total_bytes = 0
    analyzed = 0
    for f in uniq:
        size = f.stat().st_size if f.exists() else 0
        if total_bytes + size > tail_kb * 1024 * 12 and analyzed >= per_file_limit:
            report.note(f"Остальные {len(uniq) - analyzed} файлов пропущены (лимит объёма) — увеличь --tail-kb / --max-files")
            break
        try:
            lines, enc = sniff_read_text(f, max_bytes=tail_kb * 1024)
        except OSError as exc:
            report.note(f"не прочитан {f}: {exc}")
            continue
        if not lines:
            continue
        total_bytes += size
        analyzed += 1
        findings, stats = scan_lines(lines, sigs, context=context)
        tag = f"{f.name}"
        for fd in findings:
            fd.source = f"log:{tag}"
            if not fd.evidence:
                fd.evidence = [f"{f} ({stats['lines']} строк, прочитан хвост)"]
            else:
                fd.evidence.insert(0, f"файл: {f}")
            report.findings.append(fd)
        # Сводка по файлу — отдельная INFO-находка, чтобы видеть объём шума.
        rel = dt.datetime.fromtimestamp(f.stat().st_mtime).replace(microsecond=0).isoformat(sep=" ")
        report.add(
            "INFO",
            "log.file_summary",
            f"Разобран лог {tag}",
            detail=(
                f"путь: {f}\nизменён: {rel}   размер: {size // 1024} КБ   кодировка: {enc}\n"
                f"строк прочитано: {stats['lines']}   ошибкоподобных: {stats['error_like_lines']}\n"
                f"уровни: {stats['levels'] or 'не размечены'}   метки времени: {stats['first_ts'] or '?'} → {stats['last_ts'] or '?'}\n"
                f"совпадения: {stats['hits'] or 'нет'}"
            ),
            hypothesis="log_nothing" if not stats["hits"] and stats["error_like_lines"] == 0 else "unknown",
            source=f"log:{tag}",
        )
        if stats["error_like_lines"] == 0 and not stats["hits"]:
            report.add(
                "MEDIUM",
                "log.quiet",
                f"В {tag} нет ни одной ошибки/сигнатуры",
                detail=(
                    "Лог выглядит 'чистым' — значит проблема либо до начала логирования оверлея (процесс не запускают), "
                    "либо пишутся другие файлы. Проверь, что время последнего изменения близко к моменту нажатия Alt+Z."
                ),
                fixes=[
                    "Нажми Alt+Z, подожди 20 с, затем сразу снова запусти `scan` — свежие строки появятся.",
                    "Включи расширенное логирование: NVIDIA App → Помощь → 'Собрать файлы отладки'.",
                ],
                hypothesis="log_nothing",
            )
    if analyzed:
        used = report.snapshot.get("log_files_used") or []
        for f in uniq[:analyzed]:
            if str(f) not in used:
                used.append(str(f))
        report.snapshot["log_files_used"] = used
    if not analyzed:
        report.add(
            "MEDIUM",
            "log.no_files",
            "Логи NVIDIA не найдены",
            detail="Папки: " + ", ".join(LOG_ROOTS_WIN[:5]) + "\nВозможно, приложение ни разу не запускалось, либо профиль другой, либо доступ запрещён (нужен админ).",
            fixes=["Запусти `scan` от администратора; или укажи путь явно: logs \"C:\\Путь\\к\\nvlog...log\""],
            hypothesis="log_nothing",
            source="log",
        )
    return uniq


# --------------------------------------------------------------------------------------
# verify: быстрая проверка "починилось ли"
# --------------------------------------------------------------------------------------


def run_verify(wait_s: int, report: Report) -> None:
    r = report
    print("Проверка запуска оверлея.")
    if not IS_WIN:
        r.add("INFO", "verify.not_windows", "verify требует Windows (poll процессов)", hypothesis="unknown")
        return
    col = WinCollector(r, timeout=25)
    print("1) Нажми Alt+Z в NVIDIA App/в игре ПРЯМО СЕЙЧАС, пока я жду (до 40 с)...")

    def snap() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        procs = col.as_list(
            col.ps(
                "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'NVIDIA|nvcontainer|Overlay' } | "
                "ForEach-Object { [pscustomobject]@{ Name=$_.Name; PID=$_.ProcessId; Cmd=$_.CommandLine } }"
            )
        )
        svcs = col.as_list(
            col.ps(
                "Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'NVIDIA|^Nv' } | "
                "ForEach-Object { [pscustomobject]@{ Name=$_.Name; State=$_.State; StartMode=$_.StartMode } }"
            )
        )
        return procs, svcs

    procs, svcs = snap()
    overlay = [p for p in procs if "overlay" in str(p.get("Name", "")).lower()]
    if not overlay and wait_s > 0:
        deadline = time_monotonic() + wait_s
        while time_monotonic() < deadline and not overlay:
            with contextlib.suppress(KeyboardInterrupt):
                dt_ = deadline - time_monotonic()
                time_sleep(min(3, max(0.5, dt_)))
            procs, svcs = snap()
            overlay = [p for p in procs if "overlay" in str(p.get("Name", "")).lower()]

    stopped = [s for s in svcs if str(s.get("State", "")).lower() != "running" and col.CRITICAL_SVC.search(str(s.get("Name", "")))]
    if stopped:
        r.add(
            "CRITICAL",
            "verify.svc_stopped",
            "Во время проверки остановлены критичные сервисы",
            detail="; ".join(f"{s.get('Name')}={s.get('State')}/{s.get('StartMode')}" for s in stopped),
            fixes=HYPOTHESES["svc"]["fixes"],
            hypothesis="svc",
        )
    if overlay:
        r.add(
            "OK",
            "verify.overlay_up",
            "Оверлей запустился: процесс виден",
            detail="; ".join(f"{p.get('Name')} pid={p.get('PID')}" for p in overlay),
            fixes=[
                "Если процесс есть, но окна нет — смотри находки CEF/GPU-процесса и 'Запись' в настройках NVIDIA App.",
                "Проверь само запись: Alt+Z → 'Начать запись' / Alt+F10; затем 'Остановить' и открой папку записи.",
            ],
            hypothesis="overlay_proc",
        )
    else:
        r.add(
            "HIGH",
            "verify.overlay_not_up",
            "За ожидаемое время процесс NVIDIA Overlay.exe так и не появился",
            detail=(
                f"Проверено {wait_s} с. Если NVIDIA App вообще не поднимает оверлей, причины в порядке вероятности: "
                "компонент не установлен → CEF-краш → блокировка AV → оверлей выключен в настройках → конфликт RTSS/Game Bar."
            ),
            fixes=[
                "Запусти NVIDIA App и посмотри в приложении раздел 'Запись' — кнопка активна или серая?",
                "Прогони `scan --bundle diag.zip` сразу после нажатия Alt+Z и пришли архив.",
            ] + HYPOTHESES["overlay_proc"]["fixes"],
            evidence=[f"nvidia-процессы: {', '.join(sorted({str(p.get('Name')) for p in procs})[:10]) or 'нет'}"],
            hypothesis="overlay_proc",
        )
    # Финальная проба записи (только подсказка, ничего не трогаем)
    r.add(
        "INFO",
        "verify.next",
        "Следующий шаг самопроверки",
        detail="Открой любую игру в оконном/полноэкранном режиме → Alt+Z → 'Начать запись' (Alt+F10) → 20 с → стоп → проверь файл (длительность, звук, без чёрных кадров).",
        hypothesis="unknown",
    )


def time_monotonic() -> float:
    import time as _t

    return _t.monotonic()


def time_sleep(s: float) -> None:
    import time as _t

    _t.sleep(s)


# --------------------------------------------------------------------------------------
# Пакет для отправки ("мне лог — я решаю")
# --------------------------------------------------------------------------------------


def write_bundle(zip_path: Path, report: Report, text: str, log_files: Sequence[Path]) -> list[str]:
    included: list[str] = []
    max_total = 18 * 1024 * 1024
    written = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("report.txt", text)
        zf.writestr("report.json", json.dumps(report.to_json(), ensure_ascii=False, indent=1))
        zf.writestr(
            "README.txt",
            "Что это\n"
            "Архив собран nvidia_overlay_diag.py: отчёт + свежие логи NVIDIA в одном месте.\n"
            "Пришли этот файл ассистенту одним сообщением — разберу строки перед первым 'fail' и дам конкретную правку.\n"
            "Если хочешь ускорить: добавь в архив скриншот раздела 'Настройки → Запись' NVIDIA App.\n",
        )
        for f in log_files:
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if written + size > max_total:
                break
            try:
                zf.write(f, arcname=str(Path("logs") / f.name))
            except OSError:
                continue
            written += size
            included.append(f.name)
    return included


# --------------------------------------------------------------------------------------
# Рендер секций (для --from report.json и фильтров)
# --------------------------------------------------------------------------------------


def report_from_json(path: Path) -> Report:
    obj = json.loads(path.read_text(encoding="utf-8-sig"))
    r = Report(mode=obj.get("mode", "from-file") + " (из " + path.name + ")")
    r.snapshot = obj.get("snapshot", {})
    r.notes = obj.get("notes", [])
    r.started = obj.get("started", now_iso())
    keep = {"severity", "code", "title", "detail", "evidence", "fixes", "source", "hypothesis"}
    for f in obj.get("findings", []):
        data = {k: v for k, v in f.items() if k in keep}
        data.setdefault("severity", "INFO")
        r.findings.append(Finding(**data))
    return r


def render_verdict(r: Report, width: int) -> str:
    L = ["=", *["" * 0], "ВЕРОЯТНЫЕ ПРИЧИНЫ И ПОРЯДОК ДЕЙСТВИЙ", "=" * width]
    hyps = r.hypotheses()
    if not hyps:
        L.append("Находок-кандидатов нет — нужен свежий лог (scan --bundle).")
    for i, h in enumerate(hyps, 1):
        tag = "   ← начинай отсюда" if i == 1 else ""
        L.append(f"\n{i}. {h['title']}   [вес {h['weight']}, доля {h['confidence']}%]{tag}")
        L.append(f"   улики: {', '.join(h['finding_codes'][:8])}")
        for j, f in enumerate(h["fixes"], 1):
            L.append(_indent(f"{j}) {f}", "   "))
    return "\n".join(L)


def render_fixes(r: Report, with_commands: bool = True) -> str:
    """Только 'что делать', без дублей (в т.ч. между гипотезами), по приоритету."""
    L = ["ПЛАН ДЕЙСТВИЙ (уникальные шаги, по приоритету)", "=" * 72]
    n = 0
    seen: set[str] = set()
    for h in r.hypotheses():
        body = [f for f in h["fixes"] if f not in seen]
        if not body:
            continue
        L.append(f"\n— {h['title']}")
        for f in body:
            seen.add(f)
            n += 1
            L.append(_indent(f"{n}. {f}", "  "))
    if with_commands:
        L.append("")
        L.append(render_commands())
    return "\n".join(L)


COMMAND_HINTS = [
    'sc query type= all | findstr /i "nvidia"',
    'powershell -c "Get-Service *NVIDIA*,*Nv* | Select Name,Status,StartType"',
    'powershell -c "Restart-Service NVDisplay.ContainerLocalSystem -Force"',
    "powershell -c \"Get-Process | Where-Object { $_.Path -like '*NVIDIA*' } | Select Name,Id,Path\"",
    "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv",
    'powershell -c "Get-MpThreatDetection | Select-Object -First 10 InitialDetectionTime,Resources"',
    'powershell -c "Get-AppxPackage *NVIDIA* | Select Name,Version"',
    'powershell -c "Get-Process RTSS,MSIAfterburner -ErrorAction SilentlyContinue | Select Name,Id"',
]


def render_commands() -> str:
    return "\n".join(
        ["Команды-подсказки (ВЫПОЛНЯЙ САМ — скрипт ничего в системе не меняет):"] + ["  " + c for c in COMMAND_HINTS]
    )


def render_kb(sigs: Sequence[dict[str, Any]]) -> str:
    extra = len(sigs) - len(SIGNATURES)
    L = [f"БАЗА СИГНАТУР: {len(sigs)} правил" + (f", из них {extra} своих" if extra > 0 else "") + " (формат --kb file.json: [{\"re\":...,\"code\":...,\"sev\":\"HIGH\",\"title\":...,\"why\":...,\"fixes\":[...],\"hyp\":\"...\"}])", "=" * 72]
    for s in sigs:
        L.append(f"\n[{s.get('sev','?'):<8}] {s['code']}  → гипотеза: {s.get('hyp','?')}")
        L.append(_indent(f"заголовок: {s['title']}", "  "))
        if s.get("why"):
            L.append(_indent(f"почему: {s['why']}", "  "))
        L.append(_indent(f"регексп: {s['re']}", "  "))
        for f in s.get("fixes", []) or []:
            L.append(_indent(f"• {f}", "    "))
    return "\n".join(L)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


SELFTEST_FIXTURE = """\
2026-11-13 10:00:01:001 INFO  NVIDIA App 11.0.5.253, driver 572.16, session Console
2026-11-13 10:00:01:210 INFO  NvContainerClient: connecting to NVDisplay.ContainerLocalSystem
2026-11-13 10:00:02:010 WARN  Service NVDisplay.Container failed to start: The service has not started after timeout
2026-11-13 10:00:03:010 INFO  TryLaunchOverlay spawn "NVIDIA Overlay.exe"
2026-11-13 10:00:03:500 ERROR CEF GPU process crashed, libcef assert in gpu_main
2026-11-13 10:00:04:000 ERROR NVIDIA Overlay.exe exited with code 0xC0000005
2026-11-13 10:00:04:100 ERROR overlay failed to initialize: unable to create browser window
2026-11-13 10:00:04:200 ERROR DuplicateOutput failed: DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
2026-11-13 10:00:04:300 ERROR desktop duplication acquisition failed on output 0
2026-11-13 10:00:04:400 ERROR OpenProcess(game.exe) failed: Access is denied (5), target elevated
2026-11-13 10:00:04:500 ERROR SetWindowsHookEx injection into game.exe failed, blocked by security software
2026-11-13 10:00:04:600 WARN  module RTSS / RivaTuner Statistics Server hooked D3D11 Present first
2026-11-13 10:00:04:700 ERROR NVENC NvEncodeAPICreateInstance failed: insufficient resources, too many sessions
2026-11-13 10:00:04:800 ERROR DXGI_ERROR_DEVICE_REMOVED after nvlddmkm TDR recovery
2026-11-13 10:00:04:900 ERROR Instant replay failed to start, recording buffer could not write D:\Captures\replay.mp4: not enough space
2026-11-13 10:00:05:000 ERROR failed to parse Settings.json: unexpected end of data
2026-11-13 10:00:05:100 ERROR plugin ShadowPlay not installed (component missing)
2026-11-13 10:00:05:200 WARN  Windows Defender blocked file NVIDIA Overlay.exe in quarantine
2026-11-13 10:00:05:300 ERROR RegisterHotKey(Alt+Z) failed: already registered by another application
2026-11-13 10:00:05:400 WARN  HDR 10-bit color space not supported for capture
2026-11-13 10:00:05:500 ERROR driver not installed, NvAPI_Initialize = -3
2026-11-13 10:00:05:600 ERROR nvldumdx: installer failed with error 1603, rollback
2026-11-13 10:00:05:700 ERROR out of memory: bad_alloc in frame pool allocation
2026-11-13 10:00:05:800 ERROR request to container timed out (30000 ms)
2026-11-13 10:00:05:900 FATAL unhandled exception in capture pipeline, minidump written
2026-11-13 10:00:06:000 INFO  TLS handshake failed with ocsp.spynet, offline mode
2026-11-13 10:00:06:100 WARN  some ordinary line mentioning nothing important at all
2026-11-13 10:00:06:200 ERROR totally unknown failure with a weird code 0xDEADBEEF marker
"""

SELFTEST_EXPECT = {
    "log.cef",
    "log.overlay_fail",
    "log.hook_blocked",
    "log.conflict_software",
    "log.access_denied",
    "log.desktop_duplication",
    "log.nvenc",
    "log.gpu_lost",
    "log.record_fail",
    "log.storage",
    "log.config_corrupt",
    "log.plugin_missing",
    "log.av_block",
    "log.hotkey",
    "log.hdr",
    "log.driver",
    "log.installer",
    "log.oom",
    "log.timeout",
    "log.crash_generic",
    "log.net",
    "log.container",
    "log.first_severe",
    "log.unknown_errors",
}


def run_selftest(sigs: Sequence[dict[str, Any]]) -> int:
    """Проверка, что парсер и база сигнатур работают: прогон встроенного фейкового лога."""
    problems: list[str] = []
    for sg in SIGNATURES:
        for field in ("code", "sev", "title", "hyp"):
            if not sg.get(field):
                problems.append(f"сигнатура {sg.get('code', '?')}: пустое поле {field}")
        if sg.get("sev") not in SEV_WEIGHT:
            problems.append(f"сигнатура {sg['code']}: неизвестный sev {sg.get('sev')}")
        if sg.get("hyp") not in HYPOTHESES:
            problems.append(f"сигнатура {sg['code']}: неизвестная гипотеза {sg.get('hyp')}")
        try:
            re.compile(sg["re"])
        except re.error as exc:
            problems.append(f"сигнатура {sg['code']}: битый регексп ({exc})")

    lines = [ln for ln in SELFTEST_FIXTURE.splitlines() if ln.strip()]
    findings, stats = scan_lines(lines, sigs, context=0)
    got = {f.code for f in findings}
    missed = sorted(SELFTEST_EXPECT - got)
    if missed:
        problems.append("парсер не увидел ожидаемые сигнатуры: " + ", ".join(missed))
    if stats["lines"] != len(lines):
        problems.append("неверный подсчёт строк")
    if not stats["error_like_lines"]:
        problems.append("не засчитаны ошибкоподобные строки")
    if not stats["first_ts"] or not stats["last_ts"]:
        problems.append("не распознаны метки времени")
    r = Report(mode="selftest")
    r.findings.extend(findings)
    hyps = r.hypotheses()
    if not hyps:
        problems.append("не построены гипотезы")
    if hyps and hyps[0]["id"] not in {"overlay_proc", "svc", "capture_target"}:
        problems.append(f"подозрительный топ-гипотез: {hyps[0]['id']}")
    # --from / JSON round-trip
    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / "rep.json"
        fp.write_text(json.dumps(r.to_json(), ensure_ascii=False), encoding="utf-8")
        with contextlib.suppress(Exception):
            fp.write_text(fp.read_text(encoding="utf-8"), encoding="utf-8")
        r2 = report_from_json(fp)
        if len(r2.findings) != len(r.findings):
            problems.append("JSON round-trip потерял находки")
    bundle = Path(tempfile.mkdtemp()) / "b.zip"
    write_bundle(bundle, r, r.render_text(), [])
    if not zipfile.is_zipfile(bundle):
        problems.append("не собирается --bundle архив")

    print(f"проверено сигнатур: {len(SIGNATURES)}, строк фикстуры: {len(lines)}, сработало кодов: {len(got)}")
    print(f"топ-гипотеза по фикстуре: {hyps[0]['id'] if hyps else '-'}")
    if problems:
        print("\nПРОВАЛЫ:")
        for x in problems:
            print("  -", x)
        return 1
    print("OK: парсер логов, база сигнатур, вердикт, JSON и bundle работают.")
    print("Живые проверки Windows этим тестом не покрываются — для них запусти `scan` на самом ПК.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nvidia_overlay_diag.py",
        description="Диагностика оверлея NVIDIA App (запись/Instant Replay) + разбор логов по базе сигнатур.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            типы запуска:
              scan [ПУТЬ ...]     живые проверки Windows + разбор самых свежих логов (пути — дополнительно к типовым)
              logs ФАЙЛ|ПАПКА ...  только разбор логов (работает на Linux/macOS; '-' = stdin)
              verify              проверка 'запустился ли оверлей после правок'
              hypotheses          только вердикт по последнему отчёту (см. --from)
              list-signatures     печать базы сигнатур (для расширения)

            примеры:
              python nvidia_overlay_diag.py scan --bundle diag.zip
              python nvidia_overlay_diag.py scan --json -o report.json
              python nvidia_overlay_diag.py logs "C:\\ProgramData\\NVIDIA Corporation" --only-problems
              python nvidia_overlay_diag.py logs - --context 12 < nvlog.txt
              python nvidia_overlay_diag.py hypotheses --from report.json
              python nvidia_overlay_diag.py scan --no-events --no-logs --width 120
            """
        ),
    )
    sub = p.add_subparsers(dest="cmd")

    def common(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
        sp.add_argument("--json", action="store_true", help="вывести машиночитаемый JSON вместо текста")
        sp.add_argument("-o", "--out", metavar="FILE", help="сохранить отчёт в файл (UTF-8)")
        sp.add_argument("--bundle", metavar="ZIP", help="архив: отчёт + самые свежие логи (пришли его ассистенту)")
        sp.add_argument("--width", type=int, default=100, help="ширина текстового вывода (по умолчанию 100)")
        sp.add_argument("--quiet", "-q", action="store_true", help="только вердикт и план, без деталей")
        sp.add_argument("--only-problems", action="store_true", help="скрыть INFO/OK-находки")
        sp.add_argument("--kb", metavar="FILE", help="дополнительная база сигнатур (JSON)")
        sp.add_argument("--from", dest="src", metavar="report.json", help="восстановить отчёт из JSON вместо живой сборки")
        sp.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
        return sp

    sp = common(argparse.ArgumentParser(add_help=False))
    sp.add_argument("paths", nargs="*", help="дополнительные файлы/папки с логами")
    sp.add_argument("--days", type=int, default=3, help="за сколько дней смотреть журнал событий (по умолчанию 3)")
    sp.add_argument("--no-logs", action="store_true", help="не разбирать логи (только система)")
    sp.add_argument("--no-events", action="store_true", help="не читать журнал событий")
    sp.add_argument("--context", type=int, default=6, help="строк контекста вокруг первого совпадения в логе (0 = выкл)")
    sp.add_argument("--tail-kb", type=int, default=900, help="сколько КБ хвоста читать из каждого лога")
    sp.add_argument("--max-files", type=int, default=25, help="максимум лог-файлов к разбору")
    sp.add_argument("--all-files", action="store_true", help="в папках брать все .log/.txt, а не только nvidia-имена")
    sp.add_argument("--elevate", action="store_true", help="перезапустить себя с правами администратора (Windows)")

    sub.add_parser("scan", parents=[sp], help="полная диагностика (рекомендую)")

    lp = common(argparse.ArgumentParser(add_help=False))
    lp.add_argument("paths", nargs="*", help="лог-файлы или папки ('-' для stdin)")
    lp.add_argument("--context", type=int, default=6)
    lp.add_argument("--tail-kb", type=int, default=1500)
    lp.add_argument("--max-files", type=int, default=25)
    lp.add_argument("--all-files", action="store_true")
    sub.add_parser("logs", parents=[lp], help="разбор логов")

    vp = common(argparse.ArgumentParser(add_help=False))
    vp.add_argument("--wait", type=int, default=25, help="секунд ждать появления процесса оверлея")
    sub.add_parser("verify", parents=[vp], help="быстрая проверка после правок")

    hp = common(argparse.ArgumentParser(add_help=False))
    sub.add_parser("hypotheses", parents=[hp], help="только вероятные причины")

    kp = argparse.ArgumentParser(add_help=False)
    kp.add_argument("--kb", metavar="FILE", help="показать в том числе свою базу")
    kp.add_argument("-o", "--out", metavar="FILE")
    kp.add_argument("--json", action="store_true")
    kp.add_argument("--width", type=int, default=100)
    sub.add_parser("list-signatures", parents=[kp], help="печать базы сигнатур")

    sub.add_parser("selftest", help="проверить, что сам скрипт/база сигнатур исправны")

    p.add_argument("extra", nargs="*", help=argparse.SUPPRESS)
    return p


def _emit(text: str, out: str | None) -> None:
    if out:
        # BOM ставим только для .txt: Notepad корректно покажет кириллицу, а JSON читают парсеры
        enc = "utf-8-sig" if Path(out).suffix.lower() in (".txt", ".md", "") else "utf-8"
        Path(out).write_text(text + "\n", encoding=enc)
        print(f"отчёт сохранён: {out}")
    else:
        print(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    cmd = args.cmd or "scan"

    # самоповышение (только Windows, только scan)
    if getattr(args, "elevate", False) and IS_WIN:
        admin = False
        with contextlib.suppress(Exception):
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        if not admin:
            try:
                cmd_line = " ".join([f'"{sys.executable}"'] + [f'"{a}"' for a in sys.argv[1:] if a != "--elevate"])
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command", f"Start-Process -Verb RunAs -FilePath '{sys.executable}' -ArgumentList {cmd_line!r}"]
                )
                print("Запросил права администратора — продолжай во втором окне UAC.")
                return 0
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] не удалось повыситься: {exc}")

    extra_sigs: list[dict[str, Any]] = []
    if getattr(args, "kb", None):
        extra_sigs = load_extra_kb(Path(args.kb))
    sigs = compile_signatures(SIGNATURES + extra_sigs)

    if cmd == "selftest":
        return run_selftest(sigs)

    if cmd == "list-signatures":
        kb_out = [{k: v for k, v in s.items() if not k.startswith("_")} for s in SIGNATURES + extra_sigs]
        if args.json:
            _emit(json.dumps({"signatures": kb_out}, ensure_ascii=False, indent=1), args.out)
        else:
            _emit(render_kb(kb_out), args.out)
        return 0

    report = Report(mode=cmd)

    if getattr(args, "src", None):
        try:
            report = report_from_json(Path(args.src))
            report.mode = f"{cmd} (из {Path(args.src).name})"
        except Exception as exc:  # noqa: BLE001
            print(f"[error] не удалось прочитать --from {args.src}: {exc}", file=sys.stderr)
            return 2
    elif cmd == "logs":
        paths = list(args.paths or [])
        stdin_mode = "-" in paths
        paths = [p for p in paths if p != "-"]
        if stdin_mode:
            data = sys.stdin.buffer.read().decode("utf-8", "replace").splitlines()
            findings, stats = scan_lines(data, sigs, context=getattr(args, "context", 6))
            for f in findings:
                f.source = "log:<stdin>"
            report.findings.extend(findings)
            report.note(f"stdin: {stats['lines']} строк, ошибкоподобных {stats['error_like_lines']}, совпадения {stats['hits']}")
            if stats["lines"] < 20:
                report.add(
                    "LOW",
                    "log.too_short",
                    "Слишком короткий фрагмент лога",
                    detail="Чтобы вывод был надёжным, дай 200+ строк: от момента запуска NVIDIA App (или от 'Session started') до нажатия Alt+Z.",
                    hypothesis="log_nothing",
                )
        if paths:
            analyze_paths(report, paths, sigs=sigs, context=getattr(args, "context", 6), tail_kb=getattr(args, "tail_kb", 1500), max_files=getattr(args, "max_files", 25), any_files=getattr(args, "all_files", False))
        if not stdin_mode and not paths:
            print("нужно указать файл или папку с логом (или '-' для stdin). Пример: logs \"C:\\ProgramData\\NVIDIA Corporation\"")
            return 2
    elif cmd == "verify":
        run_verify(int(getattr(args, "wait", 25) or 25), report)
    else:  # scan / hypotheses
        if not report.findings:  # не из --from
            col = WinCollector(report)
            report.snapshot["_days"] = int(getattr(args, "days", 3) or 3)
            if cmd == "scan" or not IS_WIN:
                col.collect_all()
            else:
                report.note("hypotheses без --from: собран минимум данных (сервисы + процессы); полный вариант — scan")
                col.check_services()
                col.check_processes()
            extra_paths = list(getattr(args, "paths", []) or [])
            if not getattr(args, "no_logs", False) and IS_WIN:
                roots = [str(x) for x in LOG_ROOTS_WIN] + [expand(x) for x in LOG_EXTRA_FILES_WIN] + extra_paths
                found = find_log_files(roots, limit=int(getattr(args, "max_files", 25)), hints=None if getattr(args, "all_files", False) else LOG_NAME_HINTS)
                report.snapshot["log_files_found"] = [str(p) for p in found]
                analyze_paths(
                    report,
                    [str(p) for p in found],
                    sigs=sigs,
                    context=int(getattr(args, "context", 6)),
                    tail_kb=int(getattr(args, "tail_kb", 900)),
                    max_files=int(getattr(args, "max_files", 25)),
                    any_files=bool(getattr(args, "all_files", False)),
                )
                report.snapshot["log_files_used"] = [str(p) for p in found]
            elif extra_paths:
                analyze_paths(report, extra_paths, sigs=sigs, context=int(getattr(args, "context", 6)))
    # события (для scan)
    if cmd == "scan" and IS_WIN and not getattr(args, "no_events", False) and not getattr(args, "src", None):
        WinCollector(report).check_event_log()

    log_files = [Path(p) for p in (report.snapshot.get("log_files_used") or []) if Path(p).exists()]

    width = max(60, min(160, int(getattr(args, "width", 100) or 100)))
    verbose = not bool(getattr(args, "quiet", False))
    if getattr(args, "json", False):
        payload = report.to_json()
        payload["log_files"] = [str(p) for p in log_files]
        text = json.dumps(payload, ensure_ascii=False, indent=1)
    elif cmd == "hypotheses" or not verbose:
        text = render_verdict(report, width) + "\n\n" + render_fixes(report)
    else:
        text = report.render_text(
            width=width,
            verbose=True,
            only_problems=bool(getattr(args, "only_problems", False)),
        )
        text += "\n" + render_commands()

    _emit(text, getattr(args, "out", None))

    if getattr(args, "bundle", None):
        zp = Path(args.bundle)
        included = write_bundle(zp, report, text, log_files)
        print(f"\nархив готов: {zp}  (файлов логов: {len(included)}) — пришли его ассистенту")
        if not included:
            print("  внимание: логи не найдены — добавь путь вручную: scan \"C:\\Путь\\к\\логу\" --bundle diag.zip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
