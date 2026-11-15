@echo off
chcp 65001 >nul
rem  Двойной клик = диагностика оверлея NVIDIA App.
rem  Весь вывод ляжет в папку "Результат" рядом с этим файлом; рядом с ней появится
rem  архив попытки "Результат_N.zip" - его и отправляй ассистенту одним файлом.
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
echo [3/3] Ищу архив попытки...
set "ZIP="
for /f "delims=" %%f in ('dir /b /o-n "%~dp0Результат_*.zip" 2^>nul') do if not defined ZIP set "ZIP=%%f"
if defined ZIP (
    echo Готово: попытка в файле %ZIP% - отправь ассистенту именно его.
    explorer /select,"%~dp0%ZIP%"
) else (
    echo Архив не собрался -заархивируй папку Результат и отправь её.
    if exist "%~dp0Результат" explorer "%~dp0Результат"
)
pause
