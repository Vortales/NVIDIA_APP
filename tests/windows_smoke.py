#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Смоук-тест Windows-веток nvidia_overlay_diag.py на машине без Windows.

Идея: подменить powershell.exe заглушкой (отдаёт заготовленный JSON на любой запрос),
подменить winreg фейковым деревом реестра и включить IS_WIN. Это не проверка «правильности»
выводов, а проверка, что все сборщики данных исполняются без TypeError/AttributeError/NameError
и что находки аккуратно собираются в гипотезы.

Запуск:  python3 tests/windows_smoke.py     (из корня репозитория)
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import nvidia_overlay_diag as diag  # noqa: E402

# -------------------------------------------------------------------------------------
# 1. Заглушка powershell.exe: один и тот же «ответ» на любой запрос
# -------------------------------------------------------------------------------------

CANNED_JSON = json.dumps(
    [
        {
            "Name": "NVIDIA Display Container LS",
            "DisplayName": "NVIDIA Display Container LS",
            "State": "Stopped",
            "StartMode": "Automatic",
            "PathName": '"C:\\Program Files\\NVIDIA Corporation\\Display Container\\nvcontainer.exe" -s "NvidiaDisplayContainer"',
            "ServiceAccount": "LocalSystem",
            "ExitCode": 1053,
        },
        {
            "Name": "NVDisplay.ContainerLocalSystem",
            "State": "Running",
            "StartMode": "Automatic",
            "DisplayName": "NVIDIA Display Container",
            "PathName": "x",
            "ServiceAccount": "LocalSystem",
            "ExitCode": 0,
        },
        {
            "Name": "NVIDIA Overlay.exe",
            "PID": 4242,
            "Cmd": '"C:\\Program Files\\NVIDIA Corporation\\NVIDIA App\\CEF\\NVIDIA Overlay.exe" --disable-gpu',
            "Path": "C:\\Program Files\\NVIDIA Corporation\\NVIDIA App\\CEF\\NVIDIA Overlay.exe",
            "Sessions": 1,
        },
        {"Name": "RTSS.exe", "PID": 700, "Path": "C:\\RivaTuner\\RTSS.exe", "Cmd": "RTSS"},
        {
            "Name": "NVIDIA GeForce RTX 4070",
            "DriverVersion": "572.16",
            "Status": "Error",
            "PNP": "PCI\\VEN_10DE&DEV_2704",
            "Res": "2560x1440",
            "DriverDate": "2025-01-01T00:00:00Z",
        },
        {
            "Name": "Intel UHD Graphics",
            "DriverVersion": "31.0.101",
            "Status": "OK",
            "PNP": "PCI\\VEN_8086",
            "Res": "2560x1440",
            "DriverDate": "2024-11-01T00:00:00Z",
        },
        {
            "T": "2026-11-12T21:11:00",
            "Log": "Application",
            "Prov": "Application Error",
            "Id": 1000,
            "Lvl": "Error",
            "Msg": "Сбой приложения NVIDIA Overlay.exe; ошибка 0xc0000005. Сбойный модуль: nvcuvid.dll",
        },
        {
            "T": "2026-11-12T21:10:02",
            "Log": "System",
            "Prov": "nvlddmkm",
            "Id": 4101,
            "Lvl": "Warning",
            "Msg": "Драйвер nvlddmkm прекратилresponding и был успешно восстановлен.",
        },
        {
            "T": "2026-11-12T21:09:00",
            "Log": "System",
            "Prov": "Microsoft-Windows-CodeIntegrity",
            "Id": 3033,
            "Lvl": "Error",
            "Msg": "Code Integrity determined that a driver \\\\NVIDIA\\nvoverlay.dll is blocked",
        },
    ]
)


def make_fake_powershell(tmp: Path) -> Path:
    bin_dir = tmp / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    shim = bin_dir / "powershell.exe"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        f"sys.stdout.write({json.dumps(CANNED_JSON)})\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return bin_dir


# -------------------------------------------------------------------------------------
# 2. Фейковый winreg
# -------------------------------------------------------------------------------------


def install_fake_winreg() -> types.ModuleType:
    tree = {
        (0x2, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"): {
            "ProductName": (1, "Windows 11 Pro"),
            "DisplayVersion": (1, "23H2"),
            "UBR": (4, 3000),
        },
        (0x2, r"SOFTWARE\NVIDIA Corporation\Global"): {
            "OverlayEnabled": (4, 0),
            "DesktopCapture": (4, 1),
        },
        (0x2, r"SOFTWARE\NVIDIA Corporation\Global\NGS"): {"Version": (1, "11.0.5")},
        (0x2, r"SOFTWARE\Policies\NVIDIA Corporation"): {"DisableOverlay": (4, 1)},
        (0x1, r"Software\NVIDIA Corporation\NVIDIA App"): {"CaptureFolder": (1, "C:\\Users\\user\\OneDrive\\Videos")},
        (0x1, r"Volatile Environment\0"): {"SessionName": (1, "RDP-Tcp#3"), "CLIENTNAME": (1, "LAPTOP")},
        (0x1, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"): {
            "{F3CE0F7C-C45F-46E6-9D97-82C4F0EB3D6D}": (1, "C:\\Users\\user\\OneDrive\\Videos"),
            "My Video": (1, "C:\\Users\\user\\Videos"),
        },
        (0x1, r"Software\Microsoft\GameBar"): {"AllowAutoGameMode": (4, 1), "AutoGameModeEnabled": (4, 1)},
        (0x2, r"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"): {
            "EnableControlledFolderAccess": (4, 1)
        },
        (0x2, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"): {"SmartScreenEnabled": (1, "Block")},
    }

    def children(hive, key):
        pref = key.rstrip("\\")
        out = set()
        for (h, k), _ in tree.items():
            if h != hive or k == key:
                continue
            if pref and not k.startswith(pref + "\\"):
                continue
            rest = k[len(pref) + 1 :] if pref else k
            out.add(rest.split("\\")[0])
        return sorted(out)

    class KeyCtx:
        def __init__(self, hive, key):
            self.hive, self.key = hive, key

        def __enter__(self):
            if (self.hive, self.key) not in tree and not children(self.hive, self.key):
                raise FileNotFoundError(2, "not found")
            return self

        def __exit__(self, *a):
            return False

    mod = types.ModuleType("winreg")
    mod.HKEY_LOCAL_MACHINE = 0x2
    mod.HKEY_CURRENT_USER = 0x1
    mod.KEY_READ = 0

    def OpenKey(hive, key, reserved=0):  # noqa: N802
        return KeyCtx(hive, key)

    def EnumValue(k, i):  # noqa: N802
        vals = list(tree.get((k.hive, k.key), {}).items())
        if i >= len(vals):
            raise OSError(2, "no more data")
        name, (typ, val) = vals[i]
        return name, val, typ

    def EnumKey(k, i):  # noqa: N802
        subs = children(k.hive, k.key)
        if i >= len(subs):
            raise OSError(2, "no more data")
        return subs[i]

    mod.OpenKey, mod.EnumValue, mod.EnumKey = OpenKey, EnumValue, EnumKey
    sys.modules["winreg"] = mod
    return mod


# -------------------------------------------------------------------------------------
# 3. Прогон
# -------------------------------------------------------------------------------------


def main() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bin_dir = make_fake_powershell(tmp)
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

        diag.IS_WIN = True
        diag.HAS_WINREG = True
        diag.winreg = install_fake_winreg()

        # fake windows version
        import collections

        WV = collections.namedtuple("WV", "major minor build platform service_pack")
        diag.sys.getwindowsversion = lambda: WV(10, 0, 19045, 0, "")  # type: ignore[attr-defined]

        # фейковая структура папок Program Files / ProgramData
        base = tmp / "pf"
        (base / "NVIDIA Corporation" / "NVIDIA App" / "CEF").mkdir(parents=True)
        ovl = base / "NVIDIA Corporation" / "NVIDIA App" / "CEF" / "NVIDIA Overlay.exe"
        ovl.write_bytes(b"MZ" + b"\x00" * 5000)
        (base / "NVIDIA Corporation" / "NVIDIA App" / "nvcontainer.exe").write_bytes(b"MZ")
        (base / "NVIDIA Corporation" / "NVIDIA GeForce Experience").mkdir(parents=True)
        logdir = base / "NVIDIA Corporation" / "NVIDIA App" / "Log"
        logdir.mkdir(parents=True)
        (logdir / "nvlog_20261113.log").write_text(
            "\n".join(
                [
                    "2026-11-13 10:00:01 INFO  overlay startup",
                    "2026-11-13 10:00:02 ERROR failed to duplicate output: DXGI_ERROR_NOT_CURRENTLY_AVAILABLE",
                    "2026-11-13 10:00:03 ERROR CEF gpu process crashed, libcef fatal",
                    "2026-11-13 10:00:04 WARN  RTSS present hook installed first",
                ]
            ),
            encoding="utf-8",
        )
        (logdir / "Settings.json").write_text(
            json.dumps(
                {
                    "overlay": {"enabled": False, "desktopCapture": True},
                    "capture": {"record": False, "folder": "C:\\Users\\user\\OneDrive\\Videos", "codec": "h265"},
                }
            ),
            encoding="utf-8",
        )
        # битый конфиг
        (logdir / "Config.json").write_text("{oops", encoding="utf-8")

        diag.NVIDIA_ROOT_WIN = str(base / "NVIDIA Corporation")
        diag.LOG_ROOTS_WIN = [str(base / "NVIDIA Corporation")]
        diag.LOG_EXTRA_FILES_WIN = []

        # папка результатов: проверяем, что main-подобный сценарий пишет всё в одну папку
        out_base = tmp / "out" / "Результат"
        sink = diag.RunSink(base=out_base, keep=3)
        assert sink.active, "RunSink не создал папку прогона"

        rep = diag.Report(mode="scan")
        rep.snapshot["_days"] = 3
        col = diag.WinCollector(rep, timeout=25)
        col.collect_all()
        diag.WinCollector(rep).check_event_log()   # ровно как это делает main() для scan
        found = diag.find_log_files(diag.LOG_ROOTS_WIN, limit=10)
        assert found, "find_log_files не нашёл подготовленный nvlog"
        diag.analyze_paths(rep, [str(f) for f in found], sigs=diag.COMPILED_SIGNATURES, context=2)

        txt = rep.render_text(width=100)
        hyps = rep.hypotheses()
        print(txt[:4000])
        print("\n...\n")
        print("всего находок:", len(rep.findings))
        print("гипотезы:", [(h["id"], h["weight"]) for h in hyps])
        print("notes:", rep.notes)

        assert any(f.code == "svc.stopped" for f in rep.findings), "не найден остановленный сервис"
        assert any(f.code == "cfg.disabled" for f in rep.findings), "не найден выключенный оверлей в Settings.json"
        assert any(f.code == "cfg.broken" for f in rep.findings), "битый JSON не пойман"
        assert any(f.code == "session.not_console" for f in rep.findings), "RDP-сессия не поймана"
        assert any(f.code == "sec.cfa" for f in rep.findings), "Controlled Folder Access не пойман"
        assert any(f.code == "reg.policy" for f in rep.findings), "политика реестра не найдена"
        assert any(f.code == "conflict.software" for f in rep.findings), "RTSS не найден в процессах"
        assert any(f.code == "driver.hybrid" for f in rep.findings), "гибридная графика не найдена"
        assert any(f.code == "ev.crash" for f in rep.findings), "краш из журнала событий не найден"
        assert any(f.code == "ev.tdr" for f in rep.findings), "TDR не найден"
        assert any(f.code == "ev.codeintegrity" for f in rep.findings), "CodeIntegrity-блокировка не найдена"
        assert any(f.code == "app.both_products" for f in rep.findings), "App+GFE одновременно не найдены"
        assert any(f.code.startswith("log.") for f in rep.findings), "логи не разобраны"
        assert any(f.code == "log.first_severe" for f in rep.findings), "не сработала эвристика первой ошибки"
        assert "overlay_proc" in {h["id"] for h in hyps}, "нет гипотезы по CEF-крашу"
        assert json.dumps(rep.to_json(), ensure_ascii=False), "JSON не сериализуется"
        # sink: отчёты + копии логов + манифест + resolve_input из incoming
        used = [Path(x) for x in rep.snapshot.get("log_files_used", []) if Path(x).exists()]
        sink.copy_logs(used)
        sink.write_text("report.txt", txt)
        sink.write_json("report.json", rep.to_json())
        sink.write_text("verdict.txt", diag.render_verdict(rep, 90) + "\n" + diag.render_fixes(rep))
        sink.write_text("manifest.txt", sink.manifest(rep, "scan", ["--out-dir", str(out_base)]))
        for name in ("report.txt", "report.json", "verdict.txt", "manifest.txt"):
            assert (sink.dir / name).exists(), f"нет {name} в папке прогона"
        assert (sink.dir / "logs").exists() and list((sink.dir / "logs").iterdir()), "логи не скопированы в прогон"
        inc = sink.incoming / "hand.log"
        inc.write_text("2026-11-13 09:00:00 ERROR CEF gpu process crashed\n", encoding="utf-8")
        assert sink.grab_incoming(), "incoming не подхватывается"
        assert Path(diag.resolve_input("hand.log", sink)).exists(), "resolve_input не ищет в incoming"
        assert diag.place_output(sink, "x.txt", "report.txt").startswith(str(sink.dir)), "-o должен писать в папку прогона"
        assert "ЧТО В ЭТОЙ ПАПКЕ" in (sink.dir / "manifest.txt").read_text(encoding="utf-8-sig")

        m = diag.render_fixes(rep)
        assert "ПЛАН ДЕЙСТВИЙ" in m and len(m) > 200
        assert "Команды-подсказки" in diag.render_commands()
        print("\nSMOKE OK: все Windows-сборщики отработали, находки и гипотезы собраны.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
