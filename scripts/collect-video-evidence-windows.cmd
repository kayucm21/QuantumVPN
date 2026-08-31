@echo off
setlocal EnableExtensions

set "ZAPRET_PKG=io.github.zapretkvn.android.debug"
set "ADB=adb.exe"
if exist "%~dp0adb.exe" set "ADB=%~dp0adb.exe"

if exist "%~dp0adb.exe" goto adb_ready
where adb.exe >nul 2>&1
if not errorlevel 1 goto adb_ready

echo ERROR: adb.exe was not found.
echo Copy this script into the Android platform-tools directory and run it there.
pause
exit /b 1

:adb_ready
"%ADB%" get-state >nul 2>&1
if not errorlevel 1 goto device_ready

echo ERROR: no authorized Android device is available through ADB.
"%ADB%" devices -l
pause
exit /b 1

:device_ready
for /f %%T in ('powershell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "ZAPRET_STAMP=%%T"
set "ZAPRET_EVIDENCE=%USERPROFILE%\Desktop\zapret-video-%ZAPRET_STAMP%"
set "ZAPRET_ARCHIVE=%ZAPRET_EVIDENCE%.zip"
mkdir "%ZAPRET_EVIDENCE%" >nul 2>&1

"%ADB%" devices -l > "%ZAPRET_EVIDENCE%\devices.txt" 2>&1
"%ADB%" shell dumpsys package %ZAPRET_PKG% | findstr /i "versionCode versionName" > "%ZAPRET_EVIDENCE%\installed-version.txt"
findstr /c:"versionName=" "%ZAPRET_EVIDENCE%\installed-version.txt" >nul
if not errorlevel 1 goto package_ready

echo ERROR: %ZAPRET_PKG% is not installed.
pause
exit /b 1

:package_ready
"%ADB%" shell getprop ro.build.version.release > "%ZAPRET_EVIDENCE%\android-release.txt"
"%ADB%" shell getprop ro.build.version.sdk > "%ZAPRET_EVIDENCE%\android-api.txt"
"%ADB%" shell getprop ro.product.cpu.abi > "%ZAPRET_EVIDENCE%\android-abi.txt"
"%ADB%" shell settings get global private_dns_mode > "%ZAPRET_EVIDENCE%\private-dns-mode.txt" 2>&1
"%ADB%" shell settings get global private_dns_specifier > "%ZAPRET_EVIDENCE%\private-dns-specifier.txt" 2>&1
"%ADB%" shell run-as %ZAPRET_PKG% rm -f cache/diagnostics/zapret-kvn-diagnostic.json
"%ADB%" logcat -c

echo.
type "%ZAPRET_EVIDENCE%\installed-version.txt"
echo.
echo Connect the VPN and start the video that stutters.
echo Keep the video playing, return to this window, and press any key.
pause >nul

"%ADB%" shell pidof -s %ZAPRET_PKG% > "%ZAPRET_EVIDENCE%\zapret-pid.txt"
set /p "ZAPRET_PID="<"%ZAPRET_EVIDENCE%\zapret-pid.txt"
if defined ZAPRET_PID goto pid_ready

echo ERROR: the Zapret KVN process is not running.
pause
exit /b 1

:pid_ready
echo Capturing 35 seconds of CPU, scheduler, memory, and network evidence...
"%ADB%" shell cat /proc/%ZAPRET_PID%/stat > "%ZAPRET_EVIDENCE%\proc-stat-before.txt" 2>&1
"%ADB%" shell ip -s link > "%ZAPRET_EVIDENCE%\network-before.txt" 2>&1
"%ADB%" shell top -b -d 1 -n 20 -H -p %ZAPRET_PID% > "%ZAPRET_EVIDENCE%\zapret-top.txt" 2>&1
"%ADB%" shell atrace -z -b 32768 -t 15 sched freq idle am wm gfx view binder_driver > "%ZAPRET_EVIDENCE%\zapret-video.atrace" 2>&1
"%ADB%" shell cat /proc/%ZAPRET_PID%/stat > "%ZAPRET_EVIDENCE%\proc-stat-after.txt" 2>&1
"%ADB%" shell cat /proc/%ZAPRET_PID%/status > "%ZAPRET_EVIDENCE%\proc-status.txt" 2>&1
"%ADB%" shell ip -s link > "%ZAPRET_EVIDENCE%\network-after.txt" 2>&1
"%ADB%" shell dumpsys cpuinfo > "%ZAPRET_EVIDENCE%\cpuinfo.txt" 2>&1
"%ADB%" shell dumpsys meminfo %ZAPRET_PKG% > "%ZAPRET_EVIDENCE%\meminfo.txt" 2>&1
"%ADB%" shell dumpsys connectivity > "%ZAPRET_EVIDENCE%\connectivity.txt" 2>&1
"%ADB%" logcat -d -b main -b system -b crash -v threadtime > "%ZAPRET_EVIDENCE%\zapret-logcat.txt" 2>&1

:export_diagnostic
echo.
echo In Zapret KVN, open Settings - Diagnostics - Export diagnostics.
echo Wait until the Android Sharesheet appears, then return here and press any key.
pause >nul

"%ADB%" shell run-as %ZAPRET_PKG% ls -l cache/diagnostics > "%ZAPRET_EVIDENCE%\diagnostic-files.txt" 2>&1
"%ADB%" exec-out run-as %ZAPRET_PKG% cat cache/diagnostics/zapret-kvn-diagnostic.json > "%ZAPRET_EVIDENCE%\zapret-kvn-diagnostic.json" 2>&1
findstr /c:"report_version" "%ZAPRET_EVIDENCE%\zapret-kvn-diagnostic.json" >nul
if not errorlevel 1 goto diagnostic_ready

echo ERROR: the diagnostic JSON has not been created yet. Please export it in the app.
goto export_diagnostic

:diagnostic_ready
powershell.exe -NoProfile -Command "Compress-Archive -Path ($env:ZAPRET_EVIDENCE + '\*') -DestinationPath $env:ZAPRET_ARCHIVE -Force"
if not errorlevel 1 goto archive_ready

echo ERROR: PowerShell could not create the ZIP archive.
pause
exit /b 1

:archive_ready
echo.
echo Evidence archive created:
echo %ZAPRET_ARCHIVE%
pause
exit /b 0
