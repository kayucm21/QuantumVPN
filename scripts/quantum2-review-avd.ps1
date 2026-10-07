[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Prepare', 'Boot', 'Status', 'RunTests', 'Capture', 'Stop')]
    [string]$Mode = 'Inspect',
    [string]$SdkRoot = 'C:/Users/Admin/AppData/Local/Android/Sdk',
    [ValidateSet(26, 35)]
    [int]$AndroidApi = 35,
    [string]$ReviewRoot = '',
    [int]$EmulatorPort = 5582,
    [switch]$HoldProcess,
    [string]$AppApk = '',
    [string]$TestApk = ''
)

# Disposable UI-only verification. No physical-device installation, storage clear,
# profile import, VPN/DNS mutation, or user AVD overwrite is performed here.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($AppApk)) {
    $AppApk = Join-Path $projectRoot 'app/build/outputs/apk/debug/app-debug.apk'
}
if ([string]::IsNullOrWhiteSpace($TestApk)) {
    $TestApk = Join-Path $projectRoot 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'
}
if ([string]::IsNullOrWhiteSpace($ReviewRoot)) {
    $ReviewRoot = Join-Path $projectRoot $(if ($AndroidApi -eq 35) { 'artifacts/quantum2-review' } else { 'artifacts/quantum2-review-26' })
}
$reviewPath = [IO.Path]::GetFullPath($ReviewRoot)
if ($reviewPath -eq [IO.Path]::GetFullPath($projectRoot) -or
    $reviewPath -eq [IO.Path]::GetPathRoot($reviewPath)) {
    throw 'ReviewRoot must be a dedicated directory, not a workspace or drive root.'
}
if ($EmulatorPort -lt 5554 -or $EmulatorPort -gt 5682 -or ($EmulatorPort % 2) -ne 0) {
    throw 'Use an even emulator console port between 5554 and 5682.'
}
$avdName = if ($AndroidApi -eq 35) { 'Quantum2Review' } else { 'Quantum2Review26' }
$serial = "emulator-$EmulatorPort"
$indexPath = Join-Path $reviewPath 'avd-index'
$avdPath = Join-Path $reviewPath "$avdName.avd"
$adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
$emulator = Join-Path $SdkRoot 'emulator/emulator.exe'
$tools = Join-Path $SdkRoot 'cmdline-tools/12.0/bin'
if (-not (Test-Path -LiteralPath $tools)) { $tools = Join-Path $SdkRoot 'cmdline-tools/latest/bin' }
$sdkmanager = Join-Path $tools 'sdkmanager.bat'
$avdmanager = Join-Path $tools 'avdmanager.bat'
$imagePackage = "system-images;android-$AndroidApi;google_apis;x86_64"
$imageManifest = Join-Path $SdkRoot "system-images/android-$AndroidApi/google_apis/x86_64/package.xml"
$imageProperties = Join-Path $SdkRoot "system-images/android-$AndroidApi/google_apis/x86_64/source.properties"

function Assert-ReviewDevice {
    $state = (& $adb -s $serial get-state 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $state -ne 'device') { throw "$serial is not online." }
    $name = (& $adb -s $serial emu avd name 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not ($name -split '\r?\n' -contains $avdName)) {
        throw "Refusing to touch ${serial}: it is not the disposable $avdName AVD."
    }
}

function Show-Status {
    $memory = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        ReviewRoot = $reviewPath
        AvdName = $avdName
        AndroidApi = $AndroidApi
        Serial = $serial
        MemoryFreeMB = [math]::Round($memory.FreePhysicalMemory / 1024)
        MemoryTotalMB = [math]::Round($memory.TotalVisibleMemorySize / 1024)
        ImageInstalled = (Test-Path -LiteralPath $imageManifest) -or (Test-Path -LiteralPath $imageProperties)
        AvdPrepared = Test-Path -LiteralPath (Join-Path $avdPath 'config.ini')
        EmulatorInstalled = Test-Path -LiteralPath $emulator
    } | ConvertTo-Json
}

if ($Mode -eq 'Inspect' -or $Mode -eq 'Status') {
    Show-Status
    if ($Mode -eq 'Status' -and (Test-Path -LiteralPath $adb)) { & $adb devices -l }
    exit 0
}
New-Item -ItemType Directory -Path $reviewPath -Force | Out-Null

if ($Mode -eq 'Prepare') {
    if (-not (Test-Path -LiteralPath $sdkmanager)) { throw 'Android SDK command-line tools are required.' }
    if (-not (Test-Path -LiteralPath $emulator)) {
        & $sdkmanager --install 'emulator' "--sdk_root=$SdkRoot" --channel=0
        if ($LASTEXITCODE -ne 0) { throw 'Official emulator installation did not complete.' }
    }
    & $emulator -accel-check
    if ($LASTEXITCODE -ne 0) { throw 'Hardware acceleration is unavailable; no AVD will be created.' }
    if (-not (Test-Path -LiteralPath $imageManifest) -and -not (Test-Path -LiteralPath $imageProperties)) {
        & $sdkmanager --install $imagePackage "--sdk_root=$SdkRoot" --channel=0
        if ($LASTEXITCODE -ne 0) { throw "Official Android $AndroidApi image installation did not complete." }
    }
    New-Item -ItemType Directory -Path $indexPath -Force | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $avdPath 'config.ini'))) {
        if (Test-Path -LiteralPath $avdPath) { throw 'Existing incomplete AVD directory preserved; inspect it manually.' }
        $previousAvdDirectory = $env:ANDROID_AVD_HOME
        try {
            $env:ANDROID_AVD_HOME = $indexPath
            'no' | & $avdmanager create avd -n $avdName -k $imagePackage -p $avdPath -d 'pixel_2'
            if ($LASTEXITCODE -ne 0) { throw 'AVD creation did not complete.' }
        } finally {
            $env:ANDROID_AVD_HOME = $previousAvdDirectory
        }
    }
    Show-Status
    Write-Output 'Prepared only. Stop Gradle daemons before running -Mode Boot.'
    exit 0
}

if ($Mode -eq 'Boot') {
    if (-not (Test-Path -LiteralPath (Join-Path $avdPath 'config.ini'))) { throw 'Run -Mode Prepare first.' }
    $freeMB = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024
    if ($freeMB -lt 2300) { throw "Only $([math]::Round($freeMB)) MB RAM free. Stop Gradle daemons before boot." }
    if (Get-NetTCPConnection -LocalPort $EmulatorPort -ErrorAction SilentlyContinue) { throw "$EmulatorPort is occupied; existing device preserved." }
    $previousAvdDirectory = $env:ANDROID_AVD_HOME
    try {
        $env:ANDROID_AVD_HOME = $indexPath
        $process = Start-Process -FilePath $emulator -WindowStyle Hidden -PassThru -ArgumentList @(
            '-avd', $avdName, '-port', $EmulatorPort, '-no-window', '-no-audio',
            '-no-snapshot', '-no-boot-anim', '-memory', '1024', '-cores', '2',
            '-skin', '1080x1920', '-gpu', 'swiftshader',
            '-feature', '-Vulkan'
        ) -RedirectStandardOutput (Join-Path $reviewPath 'emulator.stdout.log') `
          -RedirectStandardError (Join-Path $reviewPath 'emulator.stderr.log')
    } finally {
        $env:ANDROID_AVD_HOME = $previousAvdDirectory
    }
    Write-Output "Started disposable $avdName PID $($process.Id), serial $serial."
    Write-Output 'Check -Mode Status and adb -s emulator-5582 shell getprop sys.boot_completed.'
    if ($HoldProcess) {
        # Keep the launch job alive on hosts that suspend detached descendants
        # after their command session exits. Shutdown still uses the exact AVD.
        $process.WaitForExit()
    }
    exit 0
}

Assert-ReviewDevice
if ($Mode -eq 'RunTests') {
    # Install only the checked debug packages on the verified disposable AVD.
    # No Gradle, network download, pm clear, uninstall, profile import or VPN test.
    foreach ($candidatePath in @($AppApk, $TestApk)) {
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "Already-built APK is missing: $candidatePath"
        }
    }
    $appPath = (Resolve-Path -LiteralPath $AppApk).Path
    $testPath = (Resolve-Path -LiteralPath $TestApk).Path
    $buildTools = Get-ChildItem -LiteralPath (Join-Path $SdkRoot 'build-tools') -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'aapt2.exe') } |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if ($null -eq $buildTools) { throw 'aapt2 is required to validate APK package IDs.' }
    $aapt = Join-Path $buildTools.FullName 'aapt2.exe'
    $appBadging = (& $aapt dump badging $appPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $appBadging -notmatch "(?m)^package: name='com\.quantumvpn\.debug'") {
        throw 'Refusing to install an APK other than com.quantumvpn.debug.'
    }
    $testBadging = (& $aapt dump badging $testPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $testBadging -notmatch "(?m)^package: name='com\.quantumvpn\.debug\.test'") {
        throw 'Refusing to install an APK other than com.quantumvpn.debug.test.'
    }
    $deviceAbi = (& $adb -s $serial shell getprop ro.product.cpu.abi | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $deviceAbi -ne 'x86_64') { throw 'The review emulator must use the prepared x86_64 image.' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($appPath)
    try {
        $nativeEntries = @($archive.Entries | Where-Object { $_.FullName -match '^lib/[^/]+/[^/]+\.so$' })
        if ($nativeEntries.Count -gt 0 -and -not ($nativeEntries | Where-Object { $_.FullName -like 'lib/x86_64/*' })) {
            throw 'The debug APK contains native code but no x86_64 libraries. Build the emulator ABI first.'
        }
    } finally { $archive.Dispose() }
    $testRunPath = Join-Path $reviewPath ('tests-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $testRunPath -Force | Out-Null
    [pscustomobject]@{
        Serial = $serial
        AvdName = $avdName
        AppApk = $appPath
        AppSha256 = (Get-FileHash -LiteralPath $appPath -Algorithm SHA256).Hash.ToLowerInvariant()
        TestApk = $testPath
        TestSha256 = (Get-FileHash -LiteralPath $testPath -Algorithm SHA256).Hash.ToLowerInvariant()
        TestClasses = @('com.quantumvpn.ui.Quantum2InstrumentedTest', 'com.quantumvpn.ui.Aurora2026InstrumentedTest', 'com.quantumvpn.ui.AuroraOnboardingInstrumentedTest', 'com.quantumvpn.cards.CardTableSessionInstrumentedTest')
    } | ConvertTo-Json | Out-File -LiteralPath (Join-Path $testRunPath 'inputs.json') -Encoding utf8
    & $adb -s $serial install -r -t $appPath 2>&1 | Tee-Object -FilePath (Join-Path $testRunPath 'install-app.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Debug APK installation failed; existing AVD data is preserved.' }
    & $adb -s $serial install -r -t $testPath 2>&1 | Tee-Object -FilePath (Join-Path $testRunPath 'install-test.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Instrumentation APK installation failed; existing AVD data is preserved.' }
    $classes = 'com.quantumvpn.ui.Quantum2InstrumentedTest,com.quantumvpn.ui.Aurora2026InstrumentedTest,com.quantumvpn.ui.AuroraOnboardingInstrumentedTest,com.quantumvpn.cards.CardTableSessionInstrumentedTest'
    $result = & $adb -s $serial shell am instrument -w -r -e class $classes `
        'com.quantumvpn.debug.test/androidx.test.runner.AndroidJUnitRunner' 2>&1 |
        Tee-Object -FilePath (Join-Path $testRunPath 'instrumentation.txt')
    $exitCode = $LASTEXITCODE
    $result | Write-Output
    $resultText = $result | Out-String
    Write-Output "Saved emulator-only UI results: $testRunPath"
    if ($exitCode -ne 0 -or $resultText -match 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed|shortMsg=' -or
        $resultText -notmatch 'OK \(\d+ tests?\)') {
        throw 'UI instrumentation did not finish successfully. Inspect the saved output; no physical VPN gate is implied.'
    }
} elseif ($Mode -eq 'Capture') {
    $capturePath = Join-Path $reviewPath ('capture-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $capturePath -Force | Out-Null
    & $adb -s $serial shell getprop ro.build.version.sdk | Out-File -LiteralPath (Join-Path $capturePath 'api.txt') -Encoding utf8
    & $adb -s $serial shell getprop ro.product.cpu.abi | Out-File -LiteralPath (Join-Path $capturePath 'abi.txt') -Encoding utf8
    & $adb -s $serial shell dumpsys meminfo com.quantumvpn.debug | Out-File -LiteralPath (Join-Path $capturePath 'app-meminfo.txt') -Encoding utf8
    & $adb -s $serial logcat -d -b crash -v threadtime | Out-File -LiteralPath (Join-Path $capturePath 'crash.txt') -Encoding utf8
    & $adb -s $serial pull '/sdcard/Android/data/com.quantumvpn.debug/files/quantum2-review' $capturePath
    Write-Output "UI-fixture images and emulator evidence: $capturePath"
} elseif ($Mode -eq 'Stop') {
    & $adb -s $serial emu kill
    if ($LASTEXITCODE -ne 0) { throw 'Emulator shutdown request failed; AVD files are preserved.' }
}
