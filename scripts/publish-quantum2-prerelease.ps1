#requires -Version 7.2
<#
Read-only by default. -Publish is the only mutation and is forbidden before
the verified PublishAt midnight. The default preserves v5.11.2; later versions
must carry an identical publish_at_epoch in their local build metadata.
Only the existing verified draft is published after both production ABI APIs agree.
Credentials are read in memory from the existing Git Credential Manager;
no credential file, token argument, release upload/delete, tag or branch change.
GitHub CLI flags: https://cli.github.com/manual/gh_release_edit
#>
[CmdletBinding()]
param(
    [switch]$Publish,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '5.11.2',
    [ValidateRange(1,2147483647)][long]$VersionCode = 501102099,
    [DateTimeOffset]$PublishAt = '2026-10-04T00:00:00+03:00'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Repository = 'kayucm21/QuantumVPN'
$script:QualifiedRepository = 'github.com/kayucm21/QuantumVPN'
$script:Tag = 'v' + $Version
$script:Version = $Version
$script:VersionCode = $VersionCode
$script:Deadline = $PublishAt.ToUnixTimeSeconds()
$script:PublishAt = $PublishAt.ToOffset([TimeSpan]::FromHours(3))
if ($script:PublishAt.TimeOfDay.Ticks -ne 0) { throw 'Release must be at Moscow midnight' }
if ($Version -ceq '5.11.2' -and ($VersionCode -ne 501102099 -or $script:Deadline -ne 1791061200)) { throw 'Legacy release identity and deadline are immutable' }
if ($Version -cne '5.11.2' -and $VersionCode -le 501102099) { throw 'New release versionCode must exceed the published 5.11.2 versionCode' }
$script:Signer = '4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d'
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ArtifactRoot = Join-Path $script:ProjectRoot ('artifacts/' + $Version)
$script:VdsBase = 'https://pecaocek.ignorelist.com:8443'

function Assert-ReleaseCondition([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Release verification failed: $Label" }
}

function Get-UtcEpoch { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Get-OptionalProperty($Value, [string]$Name) {
    $property = $Value.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Invoke-PrivateProcess {
    param([string]$File, [string[]]$Arguments, [string]$InputText = '', [int]$TimeoutSeconds = 90)
    # Windows can expose installed and bundled runtimes under the same name.
    # ProcessStartInfo needs one executable, never an array joined into a path.
    $command = Get-Command $File -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $command.Source
    $start.WorkingDirectory = $script:ProjectRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['GIT_TERMINAL_PROMPT'] = '0'
    $start.Environment['GCM_INTERACTIVE'] = 'Never'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw 'Private subprocess timed out.'
        }
        $output = $stdoutTask.GetAwaiter().GetResult()
        $discardedError = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'Private subprocess failed; output suppressed.' }
        Assert-ReleaseCondition ($output.Length -le 2MB) 'Subprocess response too large'
        return $output
    } finally {
        $discardedError = $null
        $process.Dispose()
    }
}

function Get-TransientGitCredential {
    $helpers = Invoke-PrivateProcess -File 'git.exe' -Arguments @('config', '--get-all', 'credential.helper')
    Assert-ReleaseCondition ($helpers -match '(?im)manager') 'Existing Git Credential Manager required'
    $credential = $null
    try {
        $credential = Invoke-PrivateProcess -File 'git.exe' -Arguments @('credential', 'fill') `
            -InputText "protocol=https`nhost=github.com`n`n"
        $values = @{}
        foreach ($line in ($credential -split "`r?`n")) {
            $parts = $line.Split('=', 2)
            if ($parts.Count -eq 2) { $values[$parts[0]] = $parts[1] }
        }
        Assert-ReleaseCondition ($values['protocol'] -eq 'https' -and $values['host'] -eq 'github.com') 'Credential scope mismatch'
        Assert-ReleaseCondition ($values.ContainsKey('password') -and $values['password'] -match '^\S{20,}$') 'Existing Git credential missing'
        return [string]$values['password']
    } finally {
        $credential = $null
        $values = $null
    }
}

function Convert-PrivateJson([string]$Text, [string]$Label) {
    try { return ConvertFrom-Json -InputObject $Text -Depth 50 }
    catch { throw "Invalid JSON in $Label; response suppressed." }
}

function Get-VerifiedLocalRelease {
    $metadataPath = Join-Path $script:ArtifactRoot 'release-metadata.json'
    $buildPath = Join-Path $script:ArtifactRoot 'build-info.json'
    foreach ($path in @($metadataPath, $buildPath)) {
        Assert-ReleaseCondition (Test-Path -LiteralPath $path -PathType Leaf) 'Local build metadata missing'
        Assert-ReleaseCondition ((Get-Item -LiteralPath $path).Length -le 65536) 'Local metadata too large'
        Assert-ReleaseCondition (((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Local artifact symlink rejected'
    }
    $metadata = Convert-PrivateJson ([IO.File]::ReadAllText($metadataPath)) 'local release metadata'
    $build = Convert-PrivateJson ([IO.File]::ReadAllText($buildPath)) 'local build metadata'
    if ($script:Version -ne '5.11.2') {
        Assert-ReleaseCondition ((Get-OptionalProperty $build 'publish_at_epoch') -eq $script:Deadline) 'Publication time differs from verified build schedule'
    }
    Assert-ReleaseCondition ($metadata.schema -eq 2 -and $metadata.version_name -ceq $script:Version `
        -and $metadata.version_code -eq $script:VersionCode -and $metadata.application_id -ceq 'com.quantumvpn.debug' `
        -and $metadata.signer_sha256 -ceq $script:Signer) 'Local APK release identity mismatch'
    Assert-ReleaseCondition ($build.version_name -ceq $script:Version -and $build.version_code -eq $script:VersionCode `
        -and $build.local_build -eq $true -and $build.git_commit -cmatch '^[0-9a-f]{40}$') 'Local build identity/commit mismatch'
    [void](Invoke-PrivateProcess -File 'git.exe' -Arguments @('cat-file', '-e', "$($build.git_commit)^{commit}"))
    $artifacts = @($metadata.artifacts)
    $buildArtifacts = @($build.artifacts)
    Assert-ReleaseCondition ($artifacts.Count -eq 2 -and $buildArtifacts.Count -eq 2) 'Both ABI artifacts required'
    $files = @{}
    foreach ($path in @($metadataPath, $buildPath)) {
        $item = Get-Item -LiteralPath $path
        $files[$item.Name] = @{ Size = $item.Length; Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
        $rows = @($artifacts | Where-Object { $_.abi -ceq $abi })
        $buildRows = @($buildArtifacts | Where-Object { $_.abi -ceq $abi })
        Assert-ReleaseCondition ($rows.Count -eq 1 -and $buildRows.Count -eq 1) 'Duplicate or missing ABI'
        $artifact = $rows[0]
        $buildArtifact = $buildRows[0]
        $name = "QuantumVPN-$($script:Version)-operator-debug-$abi.apk"
        Assert-ReleaseCondition ($artifact.apk_file -ceq $name -and $artifact.apk_sha256 -cmatch '^[0-9a-f]{64}$' `
            -and [long]$artifact.apk_size -gt 0 -and $buildArtifact.apk_file -ceq $name `
            -and $buildArtifact.apk_sha256 -ceq $artifact.apk_sha256 -and $buildArtifact.apk_size -eq $artifact.apk_size) 'ABI metadata mismatch'
        $apk = Join-Path $script:ArtifactRoot $name
        $checksum = $apk + '.sha256'
        foreach ($path in @($apk, $checksum)) {
            Assert-ReleaseCondition (Test-Path -LiteralPath $path -PathType Leaf) 'Local APK/checksum asset missing'
            $item = Get-Item -LiteralPath $path
            Assert-ReleaseCondition (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Local APK/checksum symlink rejected'
        }
        Assert-ReleaseCondition ((Get-Item -LiteralPath $apk).Length -eq [long]$artifact.apk_size `
            -and (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $artifact.apk_sha256) 'Local APK checksum/size mismatch'
        Assert-ReleaseCondition ((Get-Item -LiteralPath $checksum).Length -le 4096 `
            -and [IO.File]::ReadAllText($checksum).Trim() -ceq "$($artifact.apk_sha256)  $name") 'Local SHA-256 asset mismatch'
        $files[$name] = @{ Size = [long]$artifact.apk_size; Sha256 = $artifact.apk_sha256 }
        $files[$name + '.sha256'] = @{ Size = (Get-Item -LiteralPath $checksum).Length; Sha256 = (Get-FileHash -LiteralPath $checksum -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    return @{ Metadata = $metadata; Build = $build; Files = $files }
}

function Get-GitHubRelease {
    $view = Convert-PrivateJson (Invoke-PrivateProcess -File 'gh.exe' -Arguments @(
        'release', 'view', $script:Tag, '--repo', $script:QualifiedRepository,
        '--json', 'databaseId,tagName,isDraft,isPrerelease,targetCommitish')) 'GitHub release view'
    Assert-ReleaseCondition ($view.tagName -ceq $script:Tag -and [long]$view.databaseId -gt 0) 'GitHub draft tag mismatch'
    # Raw REST assets retain the authoritative SHA-256 digest supplied by GitHub.
    $release = Convert-PrivateJson (Invoke-PrivateProcess -File 'gh.exe' -Arguments @(
        'api', "repos/$($script:Repository)/releases/$($view.databaseId)", '--hostname', 'github.com', '--method', 'GET')) 'GitHub release inventory'
    Assert-ReleaseCondition ($release.tag_name -ceq $script:Tag -and $release.id -eq $view.databaseId `
        -and $release.draft -eq $view.isDraft -and $release.prerelease -eq $view.isPrerelease) 'GitHub release state changed'
    return $release
}

function Get-GitHubTextAsset($Asset) {
    Assert-ReleaseCondition ([long]$Asset.id -gt 0 -and [long]$Asset.size -le 65536) 'Unsafe GitHub text asset'
    return Invoke-PrivateProcess -File 'gh.exe' -Arguments @(
        'api', "repos/$($script:Repository)/releases/assets/$($Asset.id)",
        '--hostname', 'github.com', '--method', 'GET', '--header', 'Accept: application/octet-stream')
}

function Assert-GitHubAssets($Release, $Local) {
    Assert-ReleaseCondition ($Release.prerelease -eq $true -and $Release.tag_name -ceq $script:Tag) 'GitHub release must be this prerelease'
    $assets = @($Release.assets)
    Assert-ReleaseCondition (@($assets | Where-Object { $_.name -ceq 'release-metadata-v2.json' }).Count -eq 0) 'Unexpected higher-priority updater metadata'
    foreach ($name in $Local.Files.Keys) {
        $matches = @($assets | Where-Object { $_.name -ceq $name })
        Assert-ReleaseCondition ($matches.Count -eq 1) 'Missing or duplicate GitHub artifact'
        $asset = $matches[0]
        $expected = $Local.Files[$name]
        Assert-ReleaseCondition ([long]$asset.size -eq [long]$expected.Size -and $asset.state -ceq 'uploaded') 'GitHub asset size/state mismatch'
        $digest = Get-OptionalProperty $asset 'digest'
        if ($name.EndsWith('.apk', [StringComparison]::Ordinal)) {
            Assert-ReleaseCondition ($digest -ceq ('sha256:' + $expected.Sha256)) 'GitHub APK SHA-256 digest missing/mismatched'
        } elseif ($null -ne $digest) {
            Assert-ReleaseCondition ($digest -ceq ('sha256:' + $expected.Sha256)) 'GitHub metadata digest mismatch'
        }
        if (-not $name.EndsWith('.apk', [StringComparison]::Ordinal)) {
            $text = Get-GitHubTextAsset $asset
            $path = Join-Path $script:ArtifactRoot $name
            Assert-ReleaseCondition ($text.Trim() -ceq [IO.File]::ReadAllText($path).Trim()) 'GitHub metadata/checksum content mismatch'
        }
    }
    # Validate build provenance in addition to comparing the build-info asset.
    if ($Release.target_commitish -cmatch '^[0-9a-f]{40}$') {
        Assert-ReleaseCondition ($Release.target_commitish -ceq $Local.Build.git_commit) 'GitHub release commit mismatch'
    } else {
        Assert-ReleaseCondition ($Release.target_commitish -ceq 'main') 'Unexpected GitHub target branch'
        $commit = Convert-PrivateJson (Invoke-PrivateProcess -File 'gh.exe' -Arguments @(
            'api', "repos/$($script:Repository)/commits/main", '--hostname', 'github.com', '--method', 'GET')) 'GitHub target commit'
        Assert-ReleaseCondition ($commit.sha -ceq $Local.Build.git_commit) 'GitHub target branch differs from build commit'
    }
}

function Assert-VdsRelease($Local) {
    foreach ($artifact in $Local.Metadata.artifacts) {
        $abi = [string]$artifact.abi
        Assert-ReleaseCondition ($abi -cin @('arm64-v8a', 'armeabi-v7a')) 'Unexpected VDS ABI'
        $endpoint = "$($script:VdsBase)/api/client/update?abi=$abi&channel=production&current_version_code=0"
        $text = Invoke-PrivateProcess -File 'curl.exe' -Arguments @(
            '--fail', '--silent', '--show-error', '--proto', '=https', '--tlsv1.2',
            '--connect-timeout', '15', '--max-time', '45', '--max-filesize', '65536', $endpoint)
        $info = Convert-PrivateJson $text 'VDS update metadata'
        $expectedUrl = "$($script:VdsBase)/downloads/$($script:Version)/$($artifact.apk_file)"
        Assert-ReleaseCondition ($info.version -ceq $script:Version -and $info.version_code -eq $script:VersionCode `
            -and $info.application_id -ceq 'com.quantumvpn.debug' -and $info.sha256 -ceq $artifact.apk_sha256 `
            -and [long]$info.size -eq [long]$artifact.apk_size -and $info.url -ceq $expectedUrl) 'VDS has not safely promoted this ABI'
    }
}

function Assert-VdsDownloads($Local) {
    foreach ($artifact in $Local.Metadata.artifacts) {
        $url = "$($script:VdsBase)/downloads/$($script:Version)/$($artifact.apk_file)"
        $headers = Invoke-PrivateProcess -File 'curl.exe' -Arguments @(
            '--head', '--fail', '--silent', '--show-error', '--proto', '=https', '--tlsv1.2',
            '--connect-timeout', '15', '--max-time', '45', $url)
        Assert-ReleaseCondition ($headers -match '(?im)^HTTP/\S+ 200' -and
            $headers -match ('(?im)^Content-Length:\s*' + [long]$artifact.apk_size + '\s*$')) 'HTTPS APK download HEAD failed'
    }
}

function Invoke-Quantum2Publication([switch]$Publish) {
    $local = Get-VerifiedLocalRelease
    $previousToken = [Environment]::GetEnvironmentVariable('GH_TOKEN', 'Process')
    $token = $null
    try {
        $token = Get-TransientGitCredential
        [Environment]::SetEnvironmentVariable('GH_TOKEN', $token, 'Process')
        $release = Get-GitHubRelease
        Assert-GitHubAssets $release $local
        $due = (Get-UtcEpoch) -ge $script:Deadline
        if (-not $release.draft) {
            Assert-ReleaseCondition $due 'Release was published before authorized deadline'
            Assert-VdsRelease $local
            Assert-VdsDownloads $local
            return [pscustomobject]@{ Status = $(if ($due) { 'AlreadyPublished' } else { 'AlreadyPublishedBeforeDeadline' }); Changed = $false; Tag = $script:Tag }
        }
        if (-not $due) {
            return [pscustomobject]@{ Status = 'NotDue'; Changed = $false; Tag = $script:Tag; PublishAt = $script:PublishAt.ToString('o') }
        }
        Assert-VdsRelease $local
        if (-not $Publish) {
            return [pscustomobject]@{ Status = 'ReadyToPublish'; Changed = $false; Tag = $script:Tag }
        }
        # Re-read state/inventory and wall time immediately before the sole write.
        $latest = Get-GitHubRelease
        Assert-GitHubAssets $latest $local
        Assert-ReleaseCondition ((Get-UtcEpoch) -ge $script:Deadline) 'Publication is not due'
        if (-not $latest.draft) {
            Assert-VdsRelease $local
            Assert-VdsDownloads $local
            return [pscustomobject]@{ Status = 'AlreadyPublished'; Changed = $false; Tag = $script:Tag }
        }
        Assert-ReleaseCondition ($latest.id -eq $release.id) 'GitHub draft changed during preflight'
        Assert-VdsRelease $local
        Assert-ReleaseCondition ((Get-UtcEpoch) -ge $script:Deadline) 'Publication is no longer due'
        [void](Invoke-PrivateProcess -File 'gh.exe' -Arguments @('release', 'edit', $script:Tag,
            '--repo', $script:QualifiedRepository, '--draft=false', '--prerelease', '--latest=false'))
        $published = Get-GitHubRelease
        Assert-ReleaseCondition (-not $published.draft -and $published.prerelease -and $published.id -eq $release.id) 'Publication confirmation failed'
        Assert-GitHubAssets $published $local
        Assert-VdsRelease $local
        Assert-VdsDownloads $local
        return [pscustomobject]@{ Status = 'Published'; Changed = $true; Tag = $script:Tag; Url = "https://github.com/$($script:Repository)/releases/tag/$($script:Tag)" }
    } finally {
        [Environment]::SetEnvironmentVariable('GH_TOKEN', $previousToken, 'Process')
        $token = $null
    }
}

# Dot-sourcing loads pure checks for isolated tests without credential/API calls.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Quantum2Publication -Publish:$Publish | ConvertTo-Json -Depth 5
}
