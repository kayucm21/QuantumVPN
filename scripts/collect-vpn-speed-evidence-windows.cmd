@echo off
setlocal EnableExtensions
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-vpn-speed-evidence.ps1" %*
set "QUANTUM_RESULT=%ERRORLEVEL%"
echo.
pause
exit /b %QUANTUM_RESULT%
