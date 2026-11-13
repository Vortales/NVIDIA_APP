@echo off
chcp 65001 >nul
rem  Двойной клик = «сделай сам»: диагностика + автопочинка стека NVIDIA App + проверка Alt+Z.
rem  Ничего не удаляется: папки только переименовываются в *.diagbak-..., конфиги пишутся с бэкапом.
rem  Откат:  run_fix.bat undo    (то же самое: python nvidia_overlay_diag.py fix --undo)
rem  Весь вывод — в папке «Результат» рядом с этим файлом, её и архивируй.
setlocal enableextensions
cd /d "%~dp0"

rem --- повышаем права (без админа сервисы/Drs/реестр не трогаем) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Запрашиваю права администратора...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
    exit /b
)

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")

if /i "%~1"=="undo" (
    echo Откатываю последний прогон fix по журналу...
    %PY% nvidia_overlay_diag.py fix --undo
    goto :end
)

echo.
echo [1/4] Самопроверка скрипта...
%PY% nvidia_overlay_diag.py selftest

echo.
echo [2/4] Диагностика + план — этим шагом ничего не меняется...
%PY% nvidia_overlay_diag.py fix --dry-run

echo.
echo [3/4] Дальше скрипт сам: выгрузит висящие NVIDIA Overlay.exe, перезапустит
echo       сервисы, сбросит базу профилей Drs, уберёт кэш CEF, включит оверлей в
echo       конфиге, почистит пустые хоткеи, запустит App, отправит Alt+Z и проверит окно.
echo.
set "ARGS=fix --wait 40"
if not "%~1"=="" set "ARGS=%ARGS% %*"
set /p _=Enter — начать починку.   Ctrl+C — отменить...
%PY% nvidia_overlay_diag.py %ARGS%
if errorlevel 2 (
    echo.
    echo Окно оверлея НЕ появилось. Решающий шаг — переустановка полного пакета
    echo драйвера: Graphics Driver + NVIDIA App + захват/ShadowPlay + «Чистая установка».
    echo Запустить найденный установщик:  run_fix.bat --reinstall
)

echo.
echo [4/4] Открываю папку Результат...
if exist "%~dp0Результат" ( explorer "%~dp0Результат" ) else ( echo папка не создалась — смотри вывод выше )
echo.
echo Готово. Заархивируй «Результат» и отправь ассистенту: по fix_journal.json видно каждое действие.
:end
pause
