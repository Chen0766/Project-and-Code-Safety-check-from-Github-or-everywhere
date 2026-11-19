@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "PY=python"
where py >nul 2>nul
if not errorlevel 1 set "PY=py"

"%PY%" depaudit.py %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="3" echo [E] target path not found
if "%RC%"=="2" echo [D] do NOT install these dependencies
if "%RC%"=="1" echo [C] verify each item before installing
if "%RC%"=="0" echo [A/B] ok to install
echo.
pause
