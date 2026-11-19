@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "PY=python"
where py >nul 2>nul
if not errorlevel 1 set "PY=py"

"%PY%" audit.py %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="3" echo [E] target path not found
if "%RC%"=="2" echo [D] do NOT run it on this machine
if "%RC%"=="1" echo [C] run it only inside the sandbox
if "%RC%"=="0" echo [A/B] ok to open
echo.
pause
