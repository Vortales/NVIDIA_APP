@echo off
chcp 65001 >nul
rem  Двойной клик = диагностика оверлея NVIDIA App.
rem  Весь вывод ляжет в папку "Результат" рядом с этим файлом - её и архивируй.
setlocal enableextensions
cd /d "%~dp0"

rem --- повышаем права, если запуск от обычного пользователя (нужны сервисы и журнал событий) ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Запрашиваю права администратора...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")

echo Если есть свежие логи NVIDIA (nvlog*.log, NvContainer*.log, Settings.json) -
echo положи их сейчас в "%~dp0Результат\incoming\" (папка создаётся сама).
echo Можно и ничего не класть: скрипт найдёт логи сам.
set /p _=Enter - начать диагностику...

echo.
echo [1/3] Самопроверка скрипта...
%PY% nvidia_overlay_diag.py selftest

echo.
echo [2/3] Диагностика системы + разбор логов...
%PY% nvidia_overlay_diag.py scan

echo.
echo [3/3] Открываю папку Результат...
if exist "%~dp0Результат" ( explorer "%~dp0Результат" ) else ( echo папка не создалась -смотри вывод выше )
echo.
echo Готово. Заархивируй папку Результат и отправь ассистенту.
pause
