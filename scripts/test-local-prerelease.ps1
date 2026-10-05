#requires -Version 7.2
<# Offline assertions. No GitHub, VDS, credentials, subprocesses, or release writes. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$publisher = Join-Path $PSScriptRoot 'publish-quantum2-prerelease.ps1'
$packager = Join-Path $PSScriptRoot 'package-local-arm-prerelease.ps1'
$signerFixture = '4cb9e0871e8f54000da71d6e11ebb4b19c8dec4ea6737c8e266d4d000706851d'
$timeFixture = [DateTimeOffset]'2026-10-06T00:00:00+03:00'
$testCount = 0
function Assert-Test([bool]$Condition, [string]$Label) {
    if (-not $Condition) { throw "Offline test failed: $Label" }
    $script:testCount++
}
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $caught = $null
    try { & $Action } catch { $caught = $_ }
    Assert-Test ($null -ne $caught) "Expected rejection: $Message"
    Assert-Test ($caught.Exception.Message -like "*$Message*") "Unexpected rejection: $Message"
}
$fixtureDirectory = Join-Path ([IO.Path]::GetTempPath()) ('qv-release-fixture-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureDirectory)
$originalToken = [Environment]::GetEnvironmentVariable('GH_TOKEN', 'Process')
try {
    # Dot-source permits testing the actual parser, without packaging/writing a
    # real release or touching the SDK. Paths contain Java-properties escapes.
    . $packager -Version '5.11.3' -VersionCode 501103099 -PublishAt $timeFixture -ExpectedSigner $signerFixture
    $propertiesFixture = Join-Path $fixtureDirectory 'fixture.properties'
    [IO.File]::WriteAllText($propertiesFixture, 'sdk.dir=C\:\\Users\\Admin\\AppData\\Local\\Android\\Sdk' + "`n" + 'name=Quantum\u0020VPN' + "`n")
    $properties = Read-Properties $propertiesFixture
    Assert-Test ($properties['sdk.dir'] -ceq 'C:\Users\Admin\AppData\Local\Android\Sdk') 'Java escaped drive/backslashes decode exactly'
    Assert-Test ($properties['name'] -ceq 'Quantum VPN') 'Java Unicode escapes decode exactly'
    [IO.File]::WriteAllText($propertiesFixture, 'sdk.dir=\\\\server\\Android SDK' + "`n")
    Assert-Test ((Read-Properties $propertiesFixture)['sdk.dir'] -ceq '\\server\Android SDK') 'UNC path decoding preserves leading double slash'
    Assert-Throws { . $packager -Version '5.11.3' -VersionCode 501103099 -PublishAt ([DateTimeOffset]'2026-10-06T00:00:00.500+03:00') -ExpectedSigner $signerFixture } 'Moscow midnight'

    . $publisher
    Assert-Test ($script:Version -ceq '5.11.2' -and $script:VersionCode -eq 501102099 -and $script:Deadline -eq 1791061200) 'Legacy defaults unchanged'
    Assert-Throws { . $publisher -Version '5.11.2' -VersionCode 501102099 -PublishAt ([DateTimeOffset]'2026-10-03T00:00:00+03:00') } 'immutable'
    Assert-Throws { . $publisher -Version '5.11.3' -VersionCode 501103099 -PublishAt ([DateTimeOffset]'2026-10-06T00:00:00.001+03:00') } 'Moscow midnight'
    Assert-Throws { . $publisher -Version '5.11.3' -VersionCode 501102099 -PublishAt $timeFixture } 'must exceed'
    . $publisher -Version '5.11.3' -VersionCode 501103099 -PublishAt $timeFixture
    Assert-Test ($script:VersionCode -eq 501103099 -and $script:VersionCode -gt 501102099) 'Explicit monotonic code, no derived formula'
    Assert-Test ($script:Deadline -eq $timeFixture.ToUnixTimeSeconds() -and $script:Tag -ceq 'v5.11.3') 'New release binds exact deadline and tag'
    $script:ArtifactRoot = $fixtureDirectory
    $script:TestArtifacts = @()
    foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
        $name = "QuantumVPN-5.11.3-operator-debug-$abi.apk"
        $path = Join-Path $fixtureDirectory $name
        [IO.File]::WriteAllText($path, "Synthetic checksum-only APK fixture $abi", [Text.Encoding]::ASCII)
        $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText($path + '.sha256', "$sha  $name`n", [Text.Encoding]::ASCII)
        $script:TestArtifacts += [pscustomobject]@{ abi=$abi; apk_file=$name; apk_sha256=$sha; apk_size=(Get-Item -LiteralPath $path).Length }
    }
    $script:TestMetadata = [ordered]@{ schema=2; version_name='5.11.3'; version_code=501103099; application_id='com.quantumvpn.debug'; signer_sha256=$signerFixture; artifacts=$script:TestArtifacts }
    $script:TestBuild = [ordered]@{ version_name='5.11.3'; version_code=501103099; local_build=$true; git_commit=('a' * 40); publish_at_epoch=$script:Deadline; artifacts=$script:TestArtifacts }
    function Save-FixtureMetadata {
        [IO.File]::WriteAllText((Join-Path $script:ArtifactRoot 'release-metadata.json'), ($script:TestMetadata | ConvertTo-Json -Depth 10) + "`n")
        [IO.File]::WriteAllText((Join-Path $script:ArtifactRoot 'build-info.json'), ($script:TestBuild | ConvertTo-Json -Depth 10) + "`n")
    }
    Save-FixtureMetadata
    $script:EditCalls = 0
    $script:VdsCalls = 0
    $script:HeadCalls = 0
    $script:TestDraft = $true
    $script:TestClock = $script:Deadline
    $script:ClockQueue = [Collections.Generic.Queue[long]]::new()
    $script:VdsMismatch = $false
    $script:DigestMismatch = $false
    $script:PublishRace = $false
    $script:GitHubReads = 0
    function Get-UtcEpoch {
        if ($script:ClockQueue.Count) { return $script:ClockQueue.Dequeue() }
        return $script:TestClock
    }
    function Get-TransientGitCredential { return 'offline-fixture-not-a-real-credential' }
    function Get-GitHubTextAsset($Asset) { return [IO.File]::ReadAllText((Join-Path $script:ArtifactRoot $Asset.name)) }
    function Get-GitHubRelease {
        $script:GitHubReads++
        if ($script:PublishRace -and $script:GitHubReads -ge 2) { $script:TestDraft = $false }
        $assets = @()
        foreach ($file in Get-ChildItem -LiteralPath $script:ArtifactRoot -File | Where-Object { $_.Name -match '\.(apk|sha256|json)$' }) {
            $sha = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($script:DigestMismatch -and $file.Name.EndsWith('.apk')) { $sha = '0' * 64 }
            $assets += [pscustomobject]@{ name=$file.Name; id=($assets.Count+1); size=$file.Length; state='uploaded'; digest=('sha256:' + $sha) }
        }
        return [pscustomobject]@{ id=42; tag_name=$script:Tag; prerelease=$true; draft=$script:TestDraft; target_commitish=('a' * 40); assets=$assets }
    }
    function Invoke-PrivateProcess {
        param([string]$File, [string[]]$Arguments, [string]$InputText = '', [int]$TimeoutSeconds = 90)
        if ($File -ceq 'git.exe' -and $Arguments[0] -ceq 'cat-file') { return '' }
        if ($File -ceq 'gh.exe' -and $Arguments[0] -ceq 'release' -and $Arguments[1] -ceq 'edit') {
            $script:EditCalls++
            $script:TestDraft = $false
            return ''
        }
        if ($File -ceq 'curl.exe') {
            $url = $Arguments[-1]
            if ($Arguments -ccontains '--head') {
                $script:HeadCalls++
                $artifact = @($script:TestArtifacts | Where-Object { $url.EndsWith($_.apk_file) })[0]
                return "HTTP/2 200`r`nContent-Length: $($artifact.apk_size)`r`n"
            }
            $script:VdsCalls++
            Assert-Test ($url -match 'abi=(arm64-v8a|armeabi-v7a)&') 'ABI API URL is bounded'
            $abi = $Matches[1]
            $artifact = @($script:TestArtifacts | Where-Object { $_.abi -ceq $abi })[0]
            return ([pscustomobject]@{ version=$(if ($script:VdsMismatch) { '5.11.2' } else { $script:Version }); version_code=$script:VersionCode; application_id='com.quantumvpn.debug'; sha256=$artifact.apk_sha256; size=$artifact.apk_size; url="$($script:VdsBase)/downloads/$($script:Version)/$($artifact.apk_file)" } | ConvertTo-Json)
        }
        throw 'Unexpected subprocess/network in offline test'
    }

    $local = Get-VerifiedLocalRelease
    Assert-Test ($local.Files.Count -eq 6) 'Both ARM APKs, checksums and metadata match'
    $script:TestBuild.publish_at_epoch = $script:Deadline - 1
    Save-FixtureMetadata
    Assert-Throws { Get-VerifiedLocalRelease } 'Publication time differs'
    $script:TestBuild.publish_at_epoch = $script:Deadline
    $script:TestMetadata.version_code = 501102099
    Save-FixtureMetadata
    Assert-Throws { Get-VerifiedLocalRelease } 'release identity mismatch'
    $script:TestMetadata.version_code = 501103099
    Save-FixtureMetadata
    $apk = Join-Path $script:ArtifactRoot $script:TestArtifacts[0].apk_file
    $originalApk = [IO.File]::ReadAllBytes($apk)
    [IO.File]::WriteAllText($apk, 'tampered synthetic fixture')
    Assert-Throws { Get-VerifiedLocalRelease } 'checksum/size mismatch'
    [IO.File]::WriteAllBytes($apk, $originalApk)
    $checksum = $apk + '.sha256'
    $originalChecksum = [IO.File]::ReadAllText($checksum)
    [IO.File]::WriteAllText($checksum, ('0' * 64) + '  wrong.apk')
    Assert-Throws { Get-VerifiedLocalRelease } 'SHA-256 asset mismatch'
    [IO.File]::WriteAllText($checksum, $originalChecksum)

    [Environment]::SetEnvironmentVariable('GH_TOKEN', 'existing-offline-fixture', 'Process')
    $script:TestClock = $script:Deadline - 1
    $result = Invoke-Quantum2Publication -Publish
    Assert-Test ($result.Status -ceq 'NotDue' -and $script:EditCalls -eq 0 -and $script:VdsCalls -eq 0) 'Never publish before authorized midnight'
    Assert-Test ([Environment]::GetEnvironmentVariable('GH_TOKEN', 'Process') -ceq 'existing-offline-fixture') 'Private token restored after NotDue'
    $script:TestClock = $script:Deadline
    $result = Invoke-Quantum2Publication
    Assert-Test ($result.Status -ceq 'ReadyToPublish' -and $script:EditCalls -eq 0 -and $script:VdsCalls -eq 2) 'Default stays read-only at deadline'
    $script:VdsMismatch = $true
    Assert-Throws { Invoke-Quantum2Publication -Publish } 'VDS has not safely promoted'
    Assert-Test ($script:EditCalls -eq 0) 'Mismatched VDS blocks publication'
    $script:VdsMismatch = $false
    $script:DigestMismatch = $true
    Assert-Throws { Invoke-Quantum2Publication -Publish } 'APK SHA-256 digest'
    Assert-Test ($script:EditCalls -eq 0) 'Mismatched GitHub APK hash blocks publication'
    $script:DigestMismatch = $false
    $script:ClockQueue.Enqueue($script:Deadline)
    $script:ClockQueue.Enqueue($script:Deadline - 1)
    Assert-Throws { Invoke-Quantum2Publication -Publish } 'Publication is not due'
    Assert-Test ($script:EditCalls -eq 0) 'Backward wall-clock change cannot publish early'
    $result = Invoke-Quantum2Publication -Publish
    Assert-Test ($result.Status -ceq 'Published' -and $script:EditCalls -eq 1 -and $script:HeadCalls -eq 2) 'Exact deadline publication verifies both HTTPS downloads'
    $script:HeadCalls = 0
    $result = Invoke-Quantum2Publication -Publish
    Assert-Test ($result.Status -ceq 'AlreadyPublished' -and $script:EditCalls -eq 1 -and $script:HeadCalls -eq 2) 'AlreadyPublished is idempotent and verifies both downloads'
    $script:TestDraft = $true
    $script:PublishRace = $true
    $script:GitHubReads = 0
    $script:HeadCalls = 0
    $result = Invoke-Quantum2Publication -Publish
    Assert-Test ($result.Status -ceq 'AlreadyPublished' -and $script:EditCalls -eq 1 -and $script:HeadCalls -eq 2) 'Concurrent publication also verifies both downloads'
    Assert-Test ([Environment]::GetEnvironmentVariable('GH_TOKEN', 'Process') -ceq 'existing-offline-fixture') 'Private token restored after all paths'
    [pscustomobject]@{ Status='Passed'; Assertions=$script:testCount; NetworkCalls=0; ExternalMutations=0 } | ConvertTo-Json
} finally {
    [Environment]::SetEnvironmentVariable('GH_TOKEN', $originalToken, 'Process')
    $resolvedFixture = [IO.Path]::GetFullPath($fixtureDirectory)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedFixture.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolvedFixture) -cnotmatch '^qv-release-fixture-[0-9a-f]{32}$') { throw 'Unsafe fixture cleanup target' }
    [IO.Directory]::Delete($resolvedFixture, $true)
}
