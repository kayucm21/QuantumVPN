#requires -Version 7.2
<# Local Windows verification/build path. No upload, publication or device changes.
An owned temporary ASCII drive avoids Java test-runner classpath encoding failures
when the checkout path contains Cyrillic. Existing mappings are never reused.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$JavaHome,
    [switch]$BuildApks
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-SubstMappings {
    param([AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)
    $mappings = @{}
    foreach ($line in $Lines) {
        if ($line -match '^([A-Za-z]):\\:\s*=>\s*(.+)$') {
            $mappings[$Matches[1].ToUpperInvariant() + ':'] = [IO.Path]::GetFullPath($Matches[2].Trim())
        }
    }
    return $mappings
}

function Get-SubstTarget {
    param([Parameter(Mandatory)][string]$Drive)
    if ($Drive -cnotmatch '^[A-Za-z]:$') { throw 'Invalid temporary drive identity' }
    # subst.exe writes its listing in the Windows OEM code page. Capturing it
    # as UTF-8 corrupts Cyrillic paths, so ownership must use the Unicode API.
    if (-not ('QuantumLocalBuild.NativeDriveMapping' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace QuantumLocalBuild {
    public static class NativeDriveMapping {
        [DllImport("kernel32.dll", EntryPoint = "QueryDosDeviceW", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maxLength);
    }
}
'@
    }
    $targetBuffer = [Text.StringBuilder]::new(32768)
    $result = [QuantumLocalBuild.NativeDriveMapping]::QueryDosDevice($Drive.ToUpperInvariant(), $targetBuffer, $targetBuffer.Capacity)
    if ($result -eq 0) {
        $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($nativeError -eq 2) { return $null }
        throw "Cannot inspect temporary drive mapping (Win32 $nativeError)"
    }
    $target = $targetBuffer.ToString()
    if ($target -notmatch '^\\\?\?\\([A-Za-z]:\\.+)$') { return $null }
    return [IO.Path]::GetFullPath($Matches[1])
}

function Assert-JavaProperties {
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)
    $properties = @{}
    foreach ($line in $Lines) {
        if ($line -match '^\s*(java.version|sun.arch.data.model)\s*=\s*(\S+)\s*$') {
            $properties[$Matches[1]] = $Matches[2]
        }
    }
    if ($properties['java.version'] -notmatch '^21(?:\.|$)' -or $properties['sun.arch.data.model'] -ne '64') {
        throw 'This local build path requires a 64-bit JDK 21'
    }
}

$sourcePaths = @(
    'app/src/', 'app-updater/src/', 'network-bootstrap/src/', 'wireguard-import/src/',
    'app/build.gradle.kts', 'app-updater/build.gradle.kts', 'network-bootstrap/build.gradle.kts',
    'wireguard-import/build.gradle.kts', 'build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
    'core.properties', 'gradle/', 'gradlew', 'gradlew.bat', 'buildSrc/', 'build-logic/',
    'scripts/build-local-arm-tests.ps1'
)

function Get-SourceCommit {
    param([Parameter(Mandatory)][string]$Root)
    $checkout = @(& git.exe -C $Root -c core.fsmonitor=false rev-parse --show-toplevel)
    if ($LASTEXITCODE -ne 0 -or $checkout.Count -ne 1 -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($checkout[0]), [IO.Path]::GetFullPath($Root))) {
        throw 'Unexpected Git checkout identity'
    }
    $branch = @(& git.exe -C $Root -c core.fsmonitor=false branch --show-current)
    if ($LASTEXITCODE -ne 0 -or $branch.Count -ne 1 -or $branch[0] -cne 'main') { throw 'Local builds must use main' }
    $commit = @(& git.exe -C $Root -c core.fsmonitor=false rev-parse --verify HEAD)
    if ($LASTEXITCODE -ne 0 -or $commit.Count -ne 1 -or $commit[0] -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid source commit' }
    $tracked = @(& git.exe -C $Root -c core.fsmonitor=false status --porcelain --untracked-files=no -- @sourcePaths)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -gt 0) { throw 'Commit Android source changes before building a provenance-bound APK bundle' }
    $untracked = @(& git.exe -C $Root -c core.fsmonitor=false ls-files --others --exclude-standard -- @sourcePaths)
    if ($LASTEXITCODE -ne 0 -or $untracked.Count -gt 0) { throw 'Untracked Android build sources cannot be included in a provenance-bound APK bundle' }
    return $commit[0]
}

function Assert-BuildContext {
    param([Parameter(Mandatory)][string]$Drive, [Parameter(Mandatory)][string]$Root,
          [AllowNull()][string]$Commit)
    $target = Get-SubstTarget -Drive $Drive
    if ($null -eq $target -or -not [StringComparer]::OrdinalIgnoreCase.Equals($target, $Root)) {
        throw 'Temporary drive no longer points to this checkout'
    }
    if ($Commit -and (Get-SourceCommit -Root $Root) -cne $Commit) { throw 'Source changed during build; do not publish this bundle' }
}

function Copy-ArtifactCreateNew {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    # Failed copies are retained for inspection, never mistaken for a passed
    # two-ABI bundle. A later invocation cannot silently overwrite them.
    $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $inputApk = [IO.File]::OpenRead($Source)
        try { $inputApk.CopyTo($output) } finally { $inputApk.Dispose() }
    } finally { $output.Dispose() }
}

$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if (-not [IO.Path]::IsPathFullyQualified($JavaHome) -or $JavaHome -notmatch '^[A-Za-z]:[\\/]') {
    throw 'JavaHome must be an absolute local JDK path'
}
$javaRoot = [IO.Path]::GetFullPath($JavaHome)
$javaExecutable = Join-Path $javaRoot 'bin/java.exe'
if (-not (Test-Path -LiteralPath $javaExecutable -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $javaRoot 'bin/javac.exe') -PathType Leaf)) { throw 'JDK runtime/compiler missing' }
$javaProperties = @(& $javaExecutable -XshowSettings:properties -version 2>&1 | ForEach-Object { $_.ToString() })
if ($LASTEXITCODE -ne 0) { throw 'JDK properties check failed' }
Assert-JavaProperties -Lines $javaProperties
$versionProperties = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $projectRoot 'gradle.properties'))) {
    if ($line -match '^(zapretVersionName|zapretVersionCode)=(.+)$') {
        if ($versionProperties.ContainsKey($Matches[1])) { throw 'Duplicate local version property' }
        $versionProperties[$Matches[1]] = $Matches[2]
    }
}
$version = $versionProperties['zapretVersionName']
if ($version -cnotmatch '^\d+\.\d+\.\d+$' -or $versionProperties['zapretVersionCode'] -cnotmatch '^\d+$') { throw 'Invalid local version properties' }
$artifactFolder = Join-Path $projectRoot "artifacts/$version"
$sourceCommit = $null
if ($BuildApks) {
    $sourceCommit = Get-SourceCommit -Root $projectRoot
    foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
        if (Test-Path -LiteralPath (Join-Path $artifactFolder "QuantumVPN-$version-operator-debug-$abi.apk")) { throw 'An APK artifact already exists; inspect it instead of overwriting it' }
    }
}
$ownedDrive = $null
$originalHash = $null
$priorJava = $env:JAVA_HOME
$priorPath = $env:PATH
$priorLocation = Get-Location
try {
    foreach ($letter in @('Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y')) {
        $candidate = $letter + ':'
        if ((Get-PSDrive -Name $letter -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath ($candidate + '\'))) { continue }
        & subst.exe $candidate $projectRoot
        if ($LASTEXITCODE -ne 0) { throw 'Temporary ASCII mapping failed' }
        $ownedDrive = $candidate
        break
    }
    if ($null -eq $ownedDrive) { throw 'No unused drive letter for the temporary build mapping' }
    $mappedRoot = $ownedDrive + '\'
    Assert-BuildContext -Drive $ownedDrive -Root $projectRoot -Commit $sourceCommit
    $originalHash = (Get-FileHash -LiteralPath (Join-Path $projectRoot 'gradlew.bat')).Hash
    if ((Get-FileHash -LiteralPath (Join-Path $mappedRoot 'gradlew.bat')).Hash -cne $originalHash) { throw 'Mapped checkout identity mismatch' }
    $env:JAVA_HOME = $javaRoot
    $env:PATH = (Join-Path $env:JAVA_HOME 'bin') + ';' + $priorPath
    Set-Location -LiteralPath $mappedRoot
    $common = @('--no-daemon', '--max-workers=1', '-Pkotlin.compiler.execution.strategy=in-process',
        '-Dorg.gradle.jvmargs=-Xmx900m -Dfile.encoding=UTF-8 -XX:+UseSerialGC -Xss512k')
    & .\gradlew.bat @common ':app-updater:testDebugUnitTest' ':app:testDebugUnitTest' ':app:compileDebugAndroidTestKotlin'
    if ($LASTEXITCODE -ne 0) { throw 'Local verification failed; APKs were not built' }
    Assert-BuildContext -Drive $ownedDrive -Root $projectRoot -Commit $sourceCommit
    if ($BuildApks) {
        [void][IO.Directory]::CreateDirectory($artifactFolder)
        foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
            Assert-BuildContext -Drive $ownedDrive -Root $projectRoot -Commit $sourceCommit
            & .\gradlew.bat @common ':app:assembleDebug' "-PzapretAbi=$abi"
            if ($LASTEXITCODE -ne 0) { throw "Local $abi assembly failed; do not publish this bundle" }
            Assert-BuildContext -Drive $ownedDrive -Root $projectRoot -Commit $sourceCommit
            $source = Join-Path $projectRoot 'app/build/outputs/apk/debug/app-debug.apk'
            $target = Join-Path $artifactFolder "QuantumVPN-$version-operator-debug-$abi.apk"
            Copy-ArtifactCreateNew -Source $source -Destination $target
            Assert-BuildContext -Drive $ownedDrive -Root $projectRoot -Commit $sourceCommit
        }
    }
    [pscustomobject]@{ Status='Passed'; Version=$version; SourceCommit=$sourceCommit; ArmApksBuilt=[bool]$BuildApks; PhysicalDevice='not-tested'; Publication='not-performed' } | ConvertTo-Json
} finally {
    try { Set-Location -LiteralPath $priorLocation.Path } catch { Write-Warning 'Could not restore the previous working directory' }
    $env:JAVA_HOME = $priorJava
    $env:PATH = $priorPath
    if ($null -ne $ownedDrive) {
        # A matching wrapper hash does not prove mapping ownership. Reinspect
        # the exact drive target; if it disappeared or changed, leave it alone.
        try {
            $currentTarget = Get-SubstTarget -Drive $ownedDrive
            if ($null -ne $currentTarget -and [StringComparer]::OrdinalIgnoreCase.Equals($currentTarget, $projectRoot)) {
                & subst.exe $ownedDrive /D
                if ($LASTEXITCODE -ne 0) { Write-Warning 'Owned temporary mapping could not be removed' }
            } elseif ($null -ne $currentTarget) { Write-Warning 'Temporary mapping changed ownership; it was not removed' }
        } catch { Write-Warning 'Could not verify temporary mapping ownership; it was not removed' }
    }
}
