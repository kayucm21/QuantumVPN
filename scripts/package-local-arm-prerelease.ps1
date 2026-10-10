#requires -Version 7.2
<# Package already-built local ARM test APKs. Never uploads or publishes. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][long]$VersionCode,
    [Parameter(Mandatory)][DateTimeOffset]$PublishAt,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSigner,
    [switch]$Immediate,
    [string]$PhysicalDeviceVerification = 'pending',
    [string]$UiVerification = 'pending'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$folder = Join-Path $projectRoot "artifacts/$Version"
$publication = $PublishAt.ToOffset([TimeSpan]::FromHours(3))
if ($Immediate) {
    if ($Version -ceq '5.11.2' -or $VersionCode -le 501103099) { throw 'Immediate release must exceed the 5.11.3 versionCode' }
} elseif (($publication.TimeOfDay.Ticks % [TimeSpan]::TicksPerHour) -ne 0) { throw 'Release must be at an explicit whole hour in Moscow' }
function Read-Properties([string]$Path) {
    $out = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line -match '^([^#=]+)=(.*)$') {
            $key, $raw = $Matches[1].Trim(), $Matches[2].Trim()
            $out[$key] = [regex]::Replace($raw, '\\u([0-9A-Fa-f]{4})|\\(.)', [Text.RegularExpressions.MatchEvaluator]{
                param($propertyMatch)
                if ($propertyMatch.Groups[1].Success) { return [string][char][Convert]::ToInt32($propertyMatch.Groups[1].Value, 16) }
                switch ($propertyMatch.Groups[2].Value) {
                    'n' { return "`n" }
                    'r' { return "`r" }
                    't' { return "`t" }
                    'f' { return "`f" }
                    default { return $propertyMatch.Groups[2].Value }
                }
            })
        }
    }
    return $out
}
function Invoke-LocalArmPackage {
$local = Read-Properties (Join-Path $projectRoot 'local.properties')
$core = Read-Properties (Join-Path $projectRoot 'core.properties')
if (-not $local.ContainsKey('sdk.dir') -or -not [IO.Path]::IsPathFullyQualified($local['sdk.dir']) -or -not (Test-Path -LiteralPath $local['sdk.dir'] -PathType Container)) { throw 'Missing or invalid absolute Android SDK path' }
$buildTools = Join-Path $local['sdk.dir'] ('build-tools/' + $core['ANDROID_BUILD_TOOLS'])
$aapt = Join-Path $buildTools 'aapt2.exe'
$signer = Join-Path $buildTools 'apksigner.bat'
foreach ($toolPath in @($aapt, $signer)) {
    if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) { throw 'Android build verification tool missing' }
}
$artifacts = @()
foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
    $name = "QuantumVPN-$Version-operator-debug-$abi.apk"
    $apk = Join-Path $folder $name
    if (-not (Test-Path -LiteralPath $apk -PathType Leaf) -or ((Get-Item -LiteralPath $apk).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Missing or linked $abi APK" }
    $badging = @(& $aapt dump badging $apk 2>$null)
    if ($LASTEXITCODE -ne 0 -or $badging.Count -eq 0 -or $badging[0] -notlike "*name='com.quantumvpn.debug'*" -or $badging[0] -notlike "*versionCode='$VersionCode'*" -or $badging[0] -notlike "*versionName='$Version'*") { throw "APK identity mismatch: $abi" }
    $certificate = (& $signer verify --print-certs $apk 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $certificate -notmatch 'Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})' -or $Matches[1].ToLowerInvariant() -cne $ExpectedSigner) { throw "APK signature mismatch: $abi" }
    $archive = [IO.Compression.ZipFile]::OpenRead($apk)
    try {
        $native = @($archive.Entries | Where-Object { $_.FullName -match '^lib/[^/]+/.*\.so$' })
        $abis = @($native | ForEach-Object { $_.FullName.Split('/')[1] } | Sort-Object -Unique)
        if ($abis.Count -ne 1 -or $abis[0] -cne $abi -or -not ($native.FullName -ccontains "lib/$abi/libbox.so")) { throw "APK native ABI mismatch: $abi" }
    } finally { $archive.Dispose() }
    $sha = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($apk + '.sha256', "$sha  $name`n", [Text.Encoding]::ASCII)
    $artifacts += [ordered]@{ abi=$abi; apk_file=$name; apk_sha256=$sha; apk_size=(Get-Item -LiteralPath $apk).Length }
}
$commit = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Build commit missing' }
$dirty = @(& git -C $projectRoot status --porcelain --untracked-files=no).Count -gt 0
$metadata = [ordered]@{ schema=2; version_name=$Version; version_code=$VersionCode; application_id='com.quantumvpn.debug'; core_tag=$core['CORE_TAG']; core_commit=$core['CORE_COMMIT']; core_patch_sha256=$core['CORE_PATCH_SHA256']; signer_sha256=$ExpectedSigner; artifacts=$artifacts }
$build = [ordered]@{ version_name=$Version; version_code=$VersionCode; git_commit=$commit; dirty_at_build=$dirty; core_commit=$core['CORE_COMMIT']; local_build=$true; physical_device_verification=$PhysicalDeviceVerification; ui_verification=$UiVerification; publish_at_epoch=$PublishAt.ToUnixTimeSeconds(); artifacts=$artifacts }
if ($Immediate) { $build['publication_mode'] = 'immediate' }
foreach ($entry in @(@('release-metadata.json',$metadata), @('build-info.json',$build))) {
    [IO.File]::WriteAllText((Join-Path $folder $entry[0]), ($entry[1] | ConvertTo-Json -Depth 10) + "`n", [Text.UTF8Encoding]::new($false))
}
return [pscustomobject]@{ Status='VerifiedLocalBundle'; Version=$Version; VersionCode=$VersionCode; Commit=$commit; Dirty=$dirty; PublishAt=$publication.ToString('o'); Files=@($artifacts.apk_file) }
}
# Dot-sourcing permits isolated properties/packaging tests without writing assets.
if ($MyInvocation.InvocationName -ne '.') { Invoke-LocalArmPackage | ConvertTo-Json }
