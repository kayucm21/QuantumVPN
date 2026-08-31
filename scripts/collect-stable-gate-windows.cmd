@echo off
setlocal EnableExtensions

set "ZAPRET_PKG=io.github.zapretkvn.android"
set "ZAPRET_IDLE_SECONDS=180"
set "ZAPRET_VIDEO_SECONDS=120"
set "ADB=adb.exe"
if exist "%~dp0adb.exe" set "ADB=%~dp0adb.exe"

if exist "%~dp0adb.exe" goto adb_ready
where adb.exe >nul 2>&1
if not errorlevel 1 goto adb_ready

echo ERROR: adb.exe was not found.
echo Extract this script into the Android platform-tools directory and run it there.
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
set "ZAPRET_EVIDENCE=%USERPROFILE%\Desktop\zapret-stable-gate-%ZAPRET_STAMP%"
set "ZAPRET_ARCHIVE=%ZAPRET_EVIDENCE%.zip"
mkdir "%ZAPRET_EVIDENCE%" >nul 2>&1

"%ADB%" devices -l > "%ZAPRET_EVIDENCE%\devices.txt" 2>&1
"%ADB%" shell dumpsys package %ZAPRET_PKG% > "%ZAPRET_EVIDENCE%\package.txt" 2>&1
findstr /i "versionCode versionName" "%ZAPRET_EVIDENCE%\package.txt" > "%ZAPRET_EVIDENCE%\installed-version.txt"
findstr /c:"versionName=0.2.1" "%ZAPRET_EVIDENCE%\installed-version.txt" >nul
if not errorlevel 1 goto package_ready

echo ERROR: stable Zapret KVN 0.2.1 is not installed.
type "%ZAPRET_EVIDENCE%\installed-version.txt"
pause
exit /b 1

:package_ready
"%ADB%" shell getprop ro.build.version.release > "%ZAPRET_EVIDENCE%\android-release.txt"
"%ADB%" shell getprop ro.build.version.sdk > "%ZAPRET_EVIDENCE%\android-api.txt"
"%ADB%" shell getprop ro.product.cpu.abi > "%ZAPRET_EVIDENCE%\android-abi.txt"
"%ADB%" shell getprop ro.product.manufacturer > "%ZAPRET_EVIDENCE%\manufacturer.txt"
"%ADB%" shell getprop ro.product.model > "%ZAPRET_EVIDENCE%\model.txt"
"%ADB%" shell settings get global private_dns_mode > "%ZAPRET_EVIDENCE%\private-dns-mode.txt" 2>&1
"%ADB%" shell settings get global private_dns_specifier > "%ZAPRET_EVIDENCE%\private-dns-specifier.txt" 2>&1
"%ADB%" shell dumpsys -l > "%ZAPRET_EVIDENCE%\dumpsys-services.txt" 2>&1
"%ADB%" logcat -c

(
  echo collector_version=1
  echo package=%ZAPRET_PKG%
  echo idle_seconds=%ZAPRET_IDLE_SECONDS%
  echo video_seconds=%ZAPRET_VIDEO_SECONDS%
  echo started=%DATE% %TIME%
) > "%ZAPRET_EVIDENCE%\collector.txt"

echo.
echo Stable Gate collector
echo ---------------------
type "%ZAPRET_EVIDENCE%\installed-version.txt"
echo.
echo Four objective phases will be captured. The script never changes VPN,
echo DNS, Wi-Fi, mobile data, profiles, or application data.
echo.
echo Phase 1/4: disconnect Zapret KVN, open its main screen once, return Home,
echo lock the phone, then press any key here.
pause >nul
call :capture_phase vpn-off-idle %ZAPRET_IDLE_SECONDS% no

echo.
echo Phase 2/4: unlock the phone, connect Zapret KVN with the profile being
echo tested, return Home, lock the phone, then press any key here.
pause >nul
call :capture_phase vpn-on-idle %ZAPRET_IDLE_SECONDS% no

echo.
echo Phase 3/4: unlock the phone and play the problem video in an application
echo selected for VPN. Enable the player's technical statistics if available.
echo Leave the video playing and press any key here.
pause >nul
call :capture_phase proxy-video %ZAPRET_VIDEO_SECONDS% yes

echo.
echo Phase 4/4: leave the same video playing. During the next measurement,
echo switch Wi-Fi to mobile data, wait for recovery, then switch back to Wi-Fi.
echo Keep USB debugging connected and press any key to start.
pause >nul
call :capture_phase network-switch %ZAPRET_VIDEO_SECONDS% yes

"%ADB%" logcat -d -b main -b system -b crash -v threadtime > "%ZAPRET_EVIDENCE%\logcat.txt" 2>&1
"%ADB%" shell dumpsys connectivity > "%ZAPRET_EVIDENCE%\connectivity-final.txt" 2>&1
"%ADB%" shell dumpsys netd > "%ZAPRET_EVIDENCE%\netd-final.txt" 2>&1
"%ADB%" shell dumpsys batterystats --charged > "%ZAPRET_EVIDENCE%\batterystats-final.txt" 2>&1
"%ADB%" shell dumpsys procstats %ZAPRET_PKG% > "%ZAPRET_EVIDENCE%\procstats-final.txt" 2>&1
"%ADB%" shell dumpsys gfxinfo %ZAPRET_PKG% > "%ZAPRET_EVIDENCE%\gfxinfo-final.txt" 2>&1

powershell.exe -NoProfile -Command "Compress-Archive -Path ($env:ZAPRET_EVIDENCE + '\*') -DestinationPath $env:ZAPRET_ARCHIVE -Force"
if not errorlevel 1 goto archive_ready

echo ERROR: PowerShell could not create the ZIP archive.
pause
exit /b 1

:archive_ready
echo.
echo Evidence archive created:
echo %ZAPRET_ARCHIVE%
echo.
echo If VPN or DNS failed, also export the redacted diagnostic from
echo Settings - Diagnostics and send it next to this ZIP.
echo Raw system evidence can contain network and device identifiers.
pause
exit /b 0

:capture_phase
set "PHASE=%~1"
set "PHASE_SECONDS=%~2"
set "PHASE_TRACE=%~3"
set "PHASE_DIR=%ZAPRET_EVIDENCE%\%PHASE%"
mkdir "%PHASE_DIR%" >nul 2>&1

(
  echo phase=%PHASE%
  echo seconds=%PHASE_SECONDS%
  echo started=%DATE% %TIME%
) > "%PHASE_DIR%\phase.txt"

"%ADB%" shell log -t ZapretStableGate "phase_start:%PHASE%" >nul 2>&1
"%ADB%" shell pidof -s %ZAPRET_PKG% > "%PHASE_DIR%\pid.txt" 2>&1
set "ZAPRET_PID="
set /p "ZAPRET_PID="<"%PHASE_DIR%\pid.txt"

call :snapshot before
"%ADB%" exec-out screencap -p > "%PHASE_DIR%\screen-before.png" 2>nul

if /i not "%PHASE_TRACE%"=="yes" goto no_trace
"%ADB%" shell atrace -z -b 32768 -t 15 sched freq idle am wm gfx view binder_driver > "%PHASE_DIR%\trace.atrace" 2>&1

:no_trace
set /a TOP_ITERATIONS=(PHASE_SECONDS+4)/5
if defined ZAPRET_PID (
  "%ADB%" shell top -b -d 5 -n %TOP_ITERATIONS% -H -p %ZAPRET_PID% > "%PHASE_DIR%\top.txt" 2>&1
) else (
  "%ADB%" shell sleep %PHASE_SECONDS%
)

call :snapshot after
"%ADB%" exec-out screencap -p > "%PHASE_DIR%\screen-after.png" 2>nul
"%ADB%" shell log -t ZapretStableGate "phase_end:%PHASE%" >nul 2>&1
echo finished=%DATE% %TIME%>> "%PHASE_DIR%\phase.txt"
exit /b 0

:snapshot
set "SNAPSHOT=%~1"
"%ADB%" shell date > "%PHASE_DIR%\%SNAPSHOT%-device-time.txt" 2>&1
"%ADB%" shell dumpsys meminfo %ZAPRET_PKG% > "%PHASE_DIR%\%SNAPSHOT%-meminfo.txt" 2>&1
"%ADB%" shell dumpsys cpuinfo > "%PHASE_DIR%\%SNAPSHOT%-cpuinfo.txt" 2>&1
"%ADB%" shell dumpsys battery > "%PHASE_DIR%\%SNAPSHOT%-battery.txt" 2>&1
"%ADB%" shell dumpsys batterystats --charged %ZAPRET_PKG% > "%PHASE_DIR%\%SNAPSHOT%-batterystats.txt" 2>&1
"%ADB%" shell ip -s link > "%PHASE_DIR%\%SNAPSHOT%-network-links.txt" 2>&1
"%ADB%" shell dumpsys connectivity > "%PHASE_DIR%\%SNAPSHOT%-connectivity.txt" 2>&1
"%ADB%" shell dumpsys activity activities > "%PHASE_DIR%\%SNAPSHOT%-activities.txt" 2>&1
"%ADB%" shell cat /sys/class/power_supply/battery/charge_counter > "%PHASE_DIR%\%SNAPSHOT%-charge-counter.txt" 2>&1
if not defined ZAPRET_PID exit /b 0
"%ADB%" shell cat /proc/%ZAPRET_PID%/stat > "%PHASE_DIR%\%SNAPSHOT%-proc-stat.txt" 2>&1
"%ADB%" shell cat /proc/%ZAPRET_PID%/status > "%PHASE_DIR%\%SNAPSHOT%-proc-status.txt" 2>&1
exit /b 0
