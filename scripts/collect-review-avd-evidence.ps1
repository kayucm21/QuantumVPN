[CmdletBinding()]
param(
    [string]$SdkRoot = 'C:/Users/Admin/AppData/Local/Android/Sdk',
    [ValidateSet('Quantum2Review26', 'Quantum2Review')][string]$AvdName = 'Quantum2Review26',
    [ValidatePattern('^emulator-\d+$')][string]$Serial = 'emulator-5582'
)

# Read-only capture on a verified disposable AVD. No install, clear, restart,
# networking changes or diagnostic generation; absent exports remain absent.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
$state = (& $adb -s $Serial get-state 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne 'device') { throw 'Review emulator is not online.' }
$name = (& $adb -s $Serial emu avd name 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not ($name -split '\r?\n' -contains $AvdName)) { throw 'Refusing evidence capture from a different device.' }
$reviewRoot = Join-Path $projectRoot $(if ($AvdName -eq 'Quantum2Review26') { 'artifacts/quantum2-review-26' } else { 'artifacts/quantum2-review' })
$folder = Join-Path $reviewRoot ('baseline-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
function Save-Adb([string]$File, [string[]]$Arguments) {
    $output = (& $adb -s $Serial @Arguments 2>&1 | Out-String)
    [IO.File]::WriteAllText((Join-Path $folder $File), $output, [Text.UTF8Encoding]::new($false))
    if ($LASTEXITCODE -ne 0) { Write-Warning "Evidence unavailable: $File" }
}
Save-Adb 'device-properties.txt' @('shell', 'getprop')
Save-Adb 'package.txt' @('shell', 'dumpsys', 'package', 'com.quantumvpn.debug')
Save-Adb 'meminfo.txt' @('shell', 'dumpsys', 'meminfo', 'com.quantumvpn.debug')
Save-Adb 'battery.txt' @('shell', 'dumpsys', 'battery')
Save-Adb 'private-dns-mode.txt' @('shell', 'settings', 'get', 'global', 'private_dns_mode')
Save-Adb 'private-dns-specifier.txt' @('shell', 'settings', 'get', 'global', 'private_dns_specifier')
Save-Adb 'logcat.txt' @('logcat', '-d', '-b', 'main', '-b', 'system', '-b', 'crash', '-v', 'threadtime')
$services = (& $adb -s $Serial shell dumpsys -l | Out-String)
[IO.File]::WriteAllText((Join-Path $folder 'dumpsys-services.txt'), $services, [Text.UTF8Encoding]::new($false))
foreach ($service in @('connectivity', 'netd')) {
    if ($services -match ('(?m)^\s*' + [regex]::Escape($service) + '\s*$')) { Save-Adb ($service + '.txt') @('shell', 'dumpsys', $service) }
}
$diagnostic = (& $adb -s $Serial exec-out run-as com.quantumvpn.debug cat cache/diagnostics/zapret-kvn-diagnostic.json 2>$null | Out-String)
$diagnosticPresent = $false
if ($LASTEXITCODE -eq 0) {
    try {
        $report = $diagnostic | ConvertFrom-Json
        if ($report.report_version -ge 2 -and $null -ne $report.app) {
            [IO.File]::WriteAllText((Join-Path $folder 'zapret-kvn-diagnostic.json'), $diagnostic, [Text.UTF8Encoding]::new($false))
            $diagnosticPresent = $true
        }
    } catch { Write-Warning 'Existing diagnostic export is not a valid app report.' }
}
[pscustomobject]@{ EvidencePath=$folder; Serial=$Serial; AvdName=$AvdName; DiagnosticPresent=$diagnosticPresent; DeviceMutations=$false; PhysicalDeviceGate=$false } | ConvertTo-Json
