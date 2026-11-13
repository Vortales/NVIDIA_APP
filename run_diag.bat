@echo off
rem  Двойной клик = полная диагностика оверлея NVIDIA App + архив с логами на Рабочем столе.
rem  Файл рядом: nvidia_overlay_diag.py (тот же каталог).
setlocal enableextensions
cd /d "%~dp0"

rem --- повышаем права, если нас запустили обычным пользователем ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Запрашиваю права администратора ^(для сервисов и журнала событий^)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")

set "OUT=%USERPROFILE%\Desktop\nvidia_overlay_report.txt"
set "ZIP=%USERPROFILE%\Desktop\nvidia_overlay_diag.zip"

echo [1/2] Самодиагностика скрипта...
%PY% nvidia_overlay_diag.py selftest

echo.
echo [2/2] Диагностика системы + разбор логов...
%PY% nvidia_overlay_diag.py scan --bundle "%ZIP%" -o "%OUT%"

echo.
echo Отчёт: %OUT%
echo Архив с логами: %ZIP%   (пришли его ассистенту целиком)
if exist "%OUT%" start notepad "%OUT%"
pause
