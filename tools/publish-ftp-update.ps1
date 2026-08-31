# Upload QuantumVPN release APKs + manifest.json to the FTP update host.
# Usage (from repo root, after building release-apks):
#   powershell -ExecutionPolicy Bypass -File tools/publish-ftp-update.ps1
# Optional:
#   -VersionName 4.5.0 -VersionCode 55 -Kind minor|global|patch -Notes "..."

param(
    [string]$VersionName = "4.5.0",
    [int]$VersionCode = 55,
    [ValidateSet("minor", "global", "patch")]
    [string]$Kind = "minor",
    [string]$Notes = "Автообновление QuantumVPN $VersionName",
    [string]$HostName = $(if ($env:ZAPRET_FTP_HOST) { $env:ZAPRET_FTP_HOST } else { "185.117.119.3" }),
    [string]$UserName = $(if ($env:ZAPRET_FTP_USER) { $env:ZAPRET_FTP_USER } else { "user4469441" }),
    [string]$Password = $(if ($env:ZAPRET_FTP_PASSWORD) { $env:ZAPRET_FTP_PASSWORD } else { "B2TGm3hEOGsn" }),
    [string]$RemoteDir = $(if ($env:ZAPRET_FTP_DIR) { $env:ZAPRET_FTP_DIR } else { "quantumvpn" }),
    [string]$ApkDir = "release-apks"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Ensure-FtpDirectory([string]$Url, [System.Net.NetworkCredential]$Cred) {
    try {
        $req = [System.Net.FtpWebRequest]::Create($Url)
        $req.Method = [System.Net.WebRequestMethods+Ftp]::MakeDirectory
        $req.Credentials = $Cred
        $req.UsePassive = $true
        $req.KeepAlive = $false
        $resp = $req.GetResponse()
        $resp.Close()
    } catch {
        # Directory may already exist.
    }
}

function Upload-FtpFile([string]$LocalPath, [string]$RemoteUrl, [System.Net.NetworkCredential]$Cred) {
    Write-Host "Uploading $LocalPath -> $RemoteUrl"
    $req = [System.Net.FtpWebRequest]::Create($RemoteUrl)
    $req.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
    $req.Credentials = $Cred
    $req.UseBinary = $true
    $req.UsePassive = $true
    $req.KeepAlive = $false
    $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
    $req.ContentLength = $bytes.Length
    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()
    $resp = $req.GetResponse()
    $resp.Close()
}

$abis = @("arm64-v8a", "armeabi-v7a")
$artifacts = @()
foreach ($abi in $abis) {
    $name = "QuantumVPN-v$VersionName-$abi.apk"
    $path = Join-Path $ApkDir $name
    if (-not (Test-Path $path)) {
        throw "Missing APK: $path"
    }
    $sha = Get-Sha256Hex $path
    $size = (Get-Item $path).Length
    $artifacts += [pscustomobject]@{
        abi = $abi
        apk_file = $name
        apk_sha256 = $sha
        apk_size = $size
    }
}

$manifestObj = [ordered]@{
    schema = 1
    version_name = $VersionName
    version_code = $VersionCode
    application_id = "com.quantumvpn"
    kind = $Kind
    notes = $Notes
    published_at = (Get-Date).ToUniversalTime().ToString("o")
    artifacts = $artifacts
}
$manifestPath = Join-Path $ApkDir "manifest.json"
$json = $manifestObj | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText((Join-Path (Get-Location) $manifestPath), $json, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote $manifestPath"

$cred = New-Object System.Net.NetworkCredential($UserName, $Password)
$base = "ftp://$HostName/$RemoteDir"
Ensure-FtpDirectory -Url $base -Cred $cred

foreach ($abi in $abis) {
    $name = "QuantumVPN-v$VersionName-$abi.apk"
    $path = Join-Path $ApkDir $name
    Upload-FtpFile -LocalPath $path -RemoteUrl "$base/$name" -Cred $cred
}
Upload-FtpFile -LocalPath $manifestPath -RemoteUrl "$base/manifest.json" -Cred $cred
Write-Host "FTP publish complete: $VersionName ($VersionCode) kind=$Kind"
