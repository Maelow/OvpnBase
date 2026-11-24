@echo off
rem OvpnBase launcher: prefers PowerShell 7 (pwsh), falls back to Windows PowerShell 5.1
setlocal
cd /d "%~dp0"
where pwsh.exe >nul 2>&1
if %errorlevel%==0 (
    start "OvpnBase" pwsh.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0OvpnBase.ps1"
) else (
    start "OvpnBase" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0OvpnBase.ps1"
)
endlocal
