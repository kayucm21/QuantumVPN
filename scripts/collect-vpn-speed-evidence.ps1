[CmdletBinding()]
param(
    [string]$AdbPath = '',
    [ValidatePattern('^[A-Za-z0-9._:-]+$')][string]$Serial = '',
    [ValidateSet('com.quantumvpn', 'com.quantumvpn.debug')][string]$Package = 'com.quantumvpn',
    [ValidateRange(10, 60)][int]$CaptureSeconds = 30,
    [string]$DiagnosticPath = '',
    [string]$OutputDirectory = ''
)

# Read-only device capture: no install/clear/restart/network-setting mutations.
# Release diagnostics are exported explicitly through the Android Sharesheet.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
if (-not $AdbPath) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'adb.exe'),
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe')
    )
    $AdbPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $AdbPath) {
        $command = Get-Command adb.exe -ErrorAction SilentlyContinue
        if ($command) { $AdbPath = $command.Source }
    }
}
if (-not $AdbPath -or -not (Test-Path -LiteralPath $AdbPath -PathType Leaf)) {
    throw 'ADB is missing. Extract this collector beside adb.exe in Android platform-tools.'
}
$AdbPath = [IO.Path]::GetFullPath($AdbPath)

function Invoke-Adb([string[]]$Arguments) {
    # All device arguments are fixed commands or validated package/serial values.
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $AdbPath
    $start.Arguments = ($Arguments -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(20000)) {
            $process.Kill()
            $process.WaitForExit()
            return [pscustomobject]@{ Text = 'ADB inspection timed out'; ExitCode = 124 }
        }
        return [pscustomobject]@{ Text = $stdout.Result + $stderr.Result; ExitCode = $process.ExitCode }
    } finally { $process.Dispose() }
}

$devices = Invoke-Adb @('devices', '-l')
$online = @($devices.Text -split '\r?\n' | Where-Object { $_ -match '^\S+\s+device(?:\s|$)' })
if (-not $Serial) {
    if ($online.Count -ne 1) { throw "Connect exactly one authorized Android device, or supply -Serial. $($devices.Text)" }
    $Serial = ($online[0] -split '\s+')[0]
    if ($Serial -notmatch '^[A-Za-z0-9._:-]+$') { throw 'Unsupported device serial.' }
}
$deviceArgs = @('-s', $Serial)
$state = Invoke-Adb ($deviceArgs + @('get-state'))
if ($state.ExitCode -ne 0 -or $state.Text.Trim() -ne 'device') { throw 'Selected Android device is not authorized/online.' }
$packageInfo = Invoke-Adb ($deviceArgs + @('shell', 'dumpsys', 'package', $Package))
if ($packageInfo.ExitCode -ne 0 -or $packageInfo.Text -notmatch 'versionName=') {
    throw "$Package is not installed. For a debug APK run with -Package com.quantumvpn.debug."
}
if (-not $OutputDirectory) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not $desktop) { $desktop = $PSScriptRoot }
    $OutputDirectory = Join-Path $desktop ('quantum-vpn-speed-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; use a new directory to preserve older evidence.' }
$null = New-Item -ItemType Directory -Path $OutputDirectory
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'devices.txt'), $devices.Text, $utf8)
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'package.txt'), $packageInfo.Text, $utf8)

function Save-Adb([string]$Name, [string[]]$Arguments) {
    $result = Invoke-Adb ($deviceArgs + $Arguments)
    [IO.File]::WriteAllText((Join-Path $OutputDirectory $Name), $result.Text, $utf8)
    if ($result.ExitCode -ne 0) { Write-Warning "Evidence unavailable: $Name" }
}

Save-Adb 'android-api.txt' @('shell', 'getprop', 'ro.build.version.sdk')
Save-Adb 'android-release.txt' @('shell', 'getprop', 'ro.build.version.release')
Save-Adb 'android-abi.txt' @('shell', 'getprop', 'ro.product.cpu.abi')
Save-Adb 'android-model.txt' @('shell', 'getprop', 'ro.product.model')
Save-Adb 'private-dns-mode.txt' @('shell', 'settings', 'get', 'global', 'private_dns_mode')
Save-Adb 'private-dns-specifier.txt' @('shell', 'settings', 'get', 'global', 'private_dns_specifier')
$services = Invoke-Adb ($deviceArgs + @('shell', 'dumpsys', '-l'))
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'dumpsys-services.txt'), $services.Text, $utf8)
$description = Read-Host 'Profile protocol and visible problem (do not enter credentials)'
$started = [DateTimeOffset]::Now
$logcat = $null
$exported = $false
$sessionNotes = @()

function Capture-Phase([string]$Name) {
    $phaseStart = [DateTimeOffset]::Now
    $pidBefore = (Invoke-Adb ($deviceArgs + @('shell', 'pidof', '-s', $Package))).Text.Trim()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory ($Name + '-pid-before.txt')), $pidBefore, $utf8)
    Save-Adb ($Name + '-interfaces-before.txt') @('shell', 'ip', '-s', 'link')
    Save-Adb ($Name + '-cpu-before.txt') @('shell', 'dumpsys', 'cpuinfo')
    Save-Adb ($Name + '-memory-before.txt') @('shell', 'dumpsys', 'meminfo', $Package)
    $phaseTimer = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "Capturing $Name for $CaptureSeconds seconds; keep the same video playing."
    $top = $null
    try {
        if ($pidBefore -match '^\d+$') {
            $top = Start-Process -FilePath $AdbPath -ArgumentList ($deviceArgs + @('shell', 'top', '-b', '-d', '1', '-n', "$CaptureSeconds", '-H', '-p', $pidBefore)) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $OutputDirectory ($Name + '-threads.txt')) -RedirectStandardError (Join-Path $OutputDirectory ($Name + '-threads-error.txt'))
        }
        while ($phaseTimer.Elapsed.TotalSeconds -lt $CaptureSeconds) { Start-Sleep -Milliseconds 500 }
    } finally {
        if ($top) {
            $top.Refresh()
            if (-not $top.HasExited) { $top.Kill(); $top.WaitForExit() }
            $top.Dispose()
        }
    }
    Save-Adb ($Name + '-interfaces-after.txt') @('shell', 'ip', '-s', 'link')
    Save-Adb ($Name + '-cpu-after.txt') @('shell', 'dumpsys', 'cpuinfo')
    Save-Adb ($Name + '-memory-after.txt') @('shell', 'dumpsys', 'meminfo', $Package)
    foreach ($service in @('connectivity', 'netd', 'thermalservice')) {
        if ($services.Text -match ('(?m)^\s*' + [regex]::Escape($service) + '\s*$')) {
            Save-Adb ($Name + '-' + $service + '.txt') @('shell', 'dumpsys', $service)
        }
    }
    $pidAfter = (Invoke-Adb ($deviceArgs + @('shell', 'pidof', '-s', $Package))).Text.Trim()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory ($Name + '-pid-after.txt')), $pidAfter, $utf8)
    if ($pidBefore -and $pidBefore -ne $pidAfter) { Write-Warning 'App process changed during measurement. Preserve this capture and diagnostic; reproduction may be incomplete.' }
    $observed = Read-Host "Observed result for $Name (quality, buffering, phone speed test if available)"
    [pscustomobject]@{ Phase = $Name; Started = $phaseStart.ToString('o'); Ended = [DateTimeOffset]::Now.ToString('o'); ProcessBefore = $pidBefore; ProcessAfter = $pidAfter; Observation = $observed }
}

try {
    # Continuous, unfiltered system log covers the VPN connection and failure.
    # Do not clear the device log or filter by an application PID.
    $logcat = Start-Process -FilePath $AdbPath -ArgumentList ($deviceArgs + @('logcat', '-T', '1', '-b', 'main', '-b', 'system', '-b', 'crash', '-v', 'threadtime')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $OutputDirectory 'logcat.txt') -RedirectStandardError (Join-Path $OutputDirectory 'logcat-error.txt')
    Read-Host 'Disconnect VPN yourself; play the problem video without VPN; press Enter when ready' | Out-Null
    $sessionNotes += Capture-Phase 'vpn-off'
    Read-Host 'Connect VPN with the problem profile; play the SAME video and quality; press Enter when ready' | Out-Null
    $sessionNotes += Capture-Phase 'vpn-on'
    Write-Host 'Keep the app running in this process. Open Settings -> Diagnostics -> Export diagnostics.'
    Read-Host 'Wait for the Android Sharesheet; press Enter after export (do not restart the app)' | Out-Null
    $source = ''
    if ($Package.EndsWith('.debug')) {
        $report = Invoke-Adb ($deviceArgs + @('exec-out', 'run-as', $Package, 'cat', 'cache/diagnostics/zapret-kvn-diagnostic.json'))
        if ($report.ExitCode -eq 0) { $source = $report.Text }
    }
    if (-not $source) {
        if (-not $DiagnosticPath) {
            $DiagnosticPath = (Read-Host 'Save the exported JSON on this computer; enter its full path (Enter to leave capture incomplete)').Trim().Trim('"')
        }
        if ($DiagnosticPath -and (Test-Path -LiteralPath $DiagnosticPath -PathType Leaf)) {
            $source = [IO.File]::ReadAllText([IO.Path]::GetFullPath($DiagnosticPath))
        }
    }
    if ($source) {
        try {
            $json = $source | ConvertFrom-Json
            if ($json.report_version -lt 2 -or $json.app -isnot [pscustomobject]) {
                throw 'Not a QuantumVPN diagnostic JSON.'
            }
            [IO.File]::WriteAllText((Join-Path $OutputDirectory 'zapret-kvn-diagnostic.json'), $source, $utf8)
            $exported = $true
        } catch { Write-Warning 'Invalid app diagnostic; evidence remains incomplete.' }
    }
    if (-not $exported) { Write-Warning 'App diagnostic is missing. System logs alone cannot identify a VPN/core bottleneck.' }
    Save-Adb 'crash.txt' @('logcat', '-d', '-b', 'crash', '-v', 'threadtime')
} finally {
    if ($logcat) {
        $logcat.Refresh()
        if (-not $logcat.HasExited) { $logcat.Kill(); $logcat.WaitForExit() }
        $logcat.Dispose()
    }
}

$manifest = [pscustomobject]@{
    CollectorVersion = 1; Package = $Package; Started = $started.ToString('o'); Ended = [DateTimeOffset]::Now.ToString('o')
    Description = $description; Phases = $sessionNotes; AppDiagnosticPresent = $exported
    DeviceMutations = $false; PhysicalDevice = -not $Serial.StartsWith('emulator-'); PhysicalDeviceGate = $false
    Note = 'Raw system evidence may contain network/device identifiers. Keep private; do not publish to Releases.'
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'collector.json'), ($manifest | ConvertTo-Json -Depth 8), $utf8)
$archive = $OutputDirectory + '.zip'
Compress-Archive -LiteralPath $OutputDirectory -DestinationPath $archive
Write-Host "Evidence archive: $archive"
Write-Host "App diagnostic present: $exported. Send this archive privately for diagnosis."
