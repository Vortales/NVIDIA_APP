@echo off
chcp 65001 >nul
rem  Двойной клик = «сделай сам»: диагностика + автопочинка стека NVIDIA App + проверка Alt+Z.
rem  Ничего не удаляется: папки только переименовываются в *.diagbak-..., конфиги пишутся с бэкапом.
rem  Откат:  run_fix.bat undo    (то же самое: python nvidia_overlay_diag.py fix --undo)
rem  Весь вывод — в папке «Результат»; рядом с ней скрипт кладёт архив попытки
rem  «Результат_N.zip» — именно его и отправляй ассистенту одним файлом.
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
echo [4/4] Ищу архив попытки...
set "ZIP="
for /f "delims=" %%f in ('dir /b /o-n "%~dp0Результат_*.zip" 2^>nul') do if not defined ZIP set "ZIP=%%f"
if defined ZIP (
    echo Готово. Архив попытки: %ZIP% - отправь ассистенту этим одним файлом.
    echo По fix_journal.json внутри видно каждое действие; откат - run_fix.bat undo
    explorer /select,"%~dp0%ZIP%"
) else (
    echo Архив не собрался -заархивируй папку «Результат» и отправь её.
    if exist "%~dp0Результат" explorer "%~dp0Результат"
)
:end
pause
