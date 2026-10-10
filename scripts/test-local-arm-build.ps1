#requires -Version 7.2
<# Offline guard tests. Parses the build helper and invokes only its pure/guard
functions with mocked Git/SUBST. Never runs Gradle, Java, a real mapping or build.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'build-local-arm-tests.ps1'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($helper, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$source = [IO.File]::ReadAllText($helper)
$tested = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:tested++
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception.Message }
    Assert-True ($null -ne $caught -and $caught -match $Pattern) "Expected rejection: $Pattern; observed: $caught"
}
$allowedFunctions = @('ConvertFrom-SubstMappings', 'Get-SubstTarget', 'Assert-JavaProperties',
    'Get-SourceCommit', 'Assert-BuildContext', 'Copy-ArtifactCreateNew')
$mappingDefinition = $null
foreach ($name in $allowedFunctions) {
    $definitions = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false))
    Assert-True ($definitions.Count -eq 1) "Missing/ambiguous guard function: $name"
    if ($name -eq 'Get-SubstTarget') { $mappingDefinition = $definitions[0] }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$sourceAssignment = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$sourcePaths'
}, $false))
Assert-True ($sourceAssignment.Count -eq 1) 'Source allowlist must be defined once'
$sourceLiterals = @($sourceAssignment[0].Right.FindAll({ param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst]
}, $false))
Assert-True ($sourceLiterals.Count -gt 0 -and $sourceAssignment[0].Right.Extent.Text -notmatch '\$') 'Source allowlist must contain literal paths only'
$sourcePaths = @($sourceLiterals | ForEach-Object { $_.Value })
$mockRoot = [IO.Path]::GetFullPath('D:\QuantumBuildFixture')
$mockCommit = 'a' * 40
$mockBranch = 'main'
$mockTracked = @()
$mockUntracked = @()
$mockCheckout = $mockRoot
$mockGitExit = 0
$mockGitCalls = [Collections.Generic.List[object]]::new()
$mockSubstLines = @("q:\: => $mockRoot")
$mockSubstExit = 0
$priorExitCode = if (Test-Path Variable:global:LASTEXITCODE) { $global:LASTEXITCODE } else { $null }
function git.exe {
    $script:mockGitCalls.Add(@($args))
    $global:LASTEXITCODE = $script:mockGitExit
    $command = $args -join ' '
    if ($command -match 'rev-parse --show-toplevel$') { return $script:mockCheckout }
    if ($command -match 'branch --show-current$') { return $script:mockBranch }
    if ($command -match 'rev-parse --verify HEAD$') { return $script:mockCommit }
    if ($command -match 'status --porcelain --untracked-files=no ') { return $script:mockTracked }
    if ($command -match 'ls-files --others --exclude-standard ') { return $script:mockUntracked }
    throw "Unexpected offline Git command: $command"
}
function subst.exe {
    throw 'Offline test must not call native SUBST'
}
function Get-SubstTarget {
    param([string]$Drive)
    if ($script:mockSubstExit -ne 0) { throw 'Cannot inspect mocked temporary drive mapping' }
    $mappings = ConvertFrom-SubstMappings -Lines $script:mockSubstLines
    if ($mappings.ContainsKey($Drive.ToUpperInvariant())) { return $mappings[$Drive.ToUpperInvariant()] }
    return $null
}
$fixtureRoot = $null
try {
    Assert-JavaProperties @('', ' java.version = 21.0.8', ' sun.arch.data.model = 64', '')
    Assert-JavaProperties @('java.version = 21', 'sun.arch.data.model = 64')
    $tested += 2
    Assert-Throws { Assert-JavaProperties @('java.version = 17.0.20', 'sun.arch.data.model = 64') } '64-bit JDK 21'
    Assert-Throws { Assert-JavaProperties @('java.version = 21.0.8', 'sun.arch.data.model = 32') } '64-bit JDK 21'
    Assert-Throws { Assert-JavaProperties @('java.version = 211.0', 'sun.arch.data.model = 64') } '64-bit JDK 21'
    Assert-Throws { Assert-JavaProperties @('java.version = 21.0.8') } '64-bit JDK 21'
    Assert-Throws { Assert-JavaProperties @('sun.arch.data.model = 64') } '64-bit JDK 21'
    Assert-Throws { Assert-JavaProperties -Lines @() } '64-bit JDK 21'
    $mappings = ConvertFrom-SubstMappings @('irrelevant', "q:\: => $mockRoot", 'R:\: => D:\Каталог сборки')
    Assert-True ($mappings.Count -eq 2) 'Only SUBST mapping lines must be parsed'
    Assert-True ($mappings['Q:'] -ceq $mockRoot) 'Drive names must normalize independently of target path'
    Assert-True ($mappings['R:'] -ceq 'D:\Каталог сборки') 'Mapping parser must preserve Unicode targets'
    Assert-True ($mappingDefinition.Extent.Text -match 'QueryDosDeviceW' -and
        $mappingDefinition.Extent.Text -match 'CharSet.Unicode' -and
        $mappingDefinition.Extent.Text -match 'Invalid temporary drive identity') 'Ownership guard must use validated Unicode drive lookup, not OEM output'
    Assert-True (@($mappingDefinition.FindAll({ param($node)
        $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'subst.exe'
    }, $true)).Count -eq 0) 'Ownership guard must not parse native SUBST output for a Unicode checkout'
    Assert-True ((Get-SubstTarget 'q:') -ceq $mockRoot) 'Owned mapping must resolve'
    Assert-True ($null -eq (Get-SubstTarget 'Z:')) 'Absent mapping must resolve to null under StrictMode'
    Assert-BuildContext -Drive 'Q:' -Root $mockRoot -Commit $mockCommit
    $tested++
    $mockSubstLines = @('Q:\: => D:\SomeOtherCheckout')
    Assert-Throws { Assert-BuildContext 'Q:' $mockRoot $mockCommit } 'no longer points'
    $mockSubstLines = @()
    Assert-Throws { Assert-BuildContext 'Q:' $mockRoot $mockCommit } 'no longer points'
    $mockSubstExit = 1
    Assert-Throws { Get-SubstTarget 'Q:' } 'Cannot inspect'
    $mockSubstExit = 0
    $mockSubstLines = @("Q:\: => $mockRoot")
    Assert-True ((Get-SourceCommit $mockRoot) -ceq $mockCommit) 'Clean main must bind the source commit'
    $mockTracked = @(' M app/src/main/java/Fixture.kt')
    Assert-Throws { Get-SourceCommit $mockRoot } 'Commit Android source changes'
    $mockTracked = @()
    $mockUntracked = @('app/src/main/java/NewFixture.kt')
    Assert-Throws { Get-SourceCommit $mockRoot } 'Untracked Android build sources'
    $mockUntracked = @()
    $mockBranch = 'other'
    Assert-Throws { Get-SourceCommit $mockRoot } 'must use main'
    $mockBranch = 'main'
    $mockCheckout = 'D:\OtherCheckout'
    Assert-Throws { Get-SourceCommit $mockRoot } 'checkout identity'
    $mockCheckout = $mockRoot
    $mockGitExit = 1
    Assert-Throws { Get-SourceCommit $mockRoot } 'checkout identity'
    $mockGitExit = 0
    $mockCommit = 'not-a-commit'
    Assert-Throws { Get-SourceCommit $mockRoot } 'Invalid source commit'
    $mockCommit = 'b' * 40
    Assert-Throws { Assert-BuildContext 'Q:' $mockRoot ('a' * 40) } 'Source changed during build'
    $mockCommit = 'a' * 40
    $statusCall = @($mockGitCalls | Where-Object { ($_ -join ' ') -match 'status --porcelain' })[0]
    $untrackedCall = @($mockGitCalls | Where-Object { ($_ -join ' ') -match 'ls-files --others' })[0]
    foreach ($call in @($statusCall, $untrackedCall)) {
        # PowerShell consumes -- when invoking a mocked function; native Git
        # retains it. Check native syntax through AST and mock argument tails.
        Assert-True (($call[($call.Count - $sourcePaths.Count)..($call.Count - 1)] -join '|') -ceq ($sourcePaths -join '|')) 'Source guards must use the complete scoped allowlist'
    }
    Assert-True ($source -match 'status --porcelain --untracked-files=no -- @sourcePaths' -and
        $source -match 'ls-files --others --exclude-standard -- @sourcePaths') 'Native Git pathspecs must follow the -- separator'
    foreach ($required in @('app/src/', 'app-updater/src/', 'network-bootstrap/src/', 'wireguard-import/src/',
        'settings.gradle.kts', 'gradle.properties', 'gradle/', 'gradlew.bat')) {
        Assert-True ($sourcePaths -contains $required) "Missing Android build input: $required"
    }
    Assert-True (@($sourcePaths | Where-Object { $_ -match '^(artifacts|tools)/' }).Count -eq 0) 'Unrelated user artifacts/tools must not block the source gate'
    Assert-True ($source -match 'IsPathFullyQualified\(\$JavaHome\)' -and $source -match 'javac\.exe') 'Require an absolute JDK path and compiler'
    $abiLoop = @($ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Body.Extent.Text -match 'assembleDebug'
    }, $false))
    Assert-True ($abiLoop.Count -eq 1) 'Both ABIs must share a sequential guarded build loop'
    Assert-True ($abiLoop[0].Condition.Extent.Text -match "'arm64-v8a', 'armeabi-v7a'") 'Both required ARM ABIs must be enumerated'
    $steps = @($abiLoop[0].Body.Statements | ForEach-Object { $_.Extent.Text })
    Assert-True ($steps[0] -match '^Assert-BuildContext' -and $steps[3] -match '^Assert-BuildContext' -and $steps[-1] -match '^Assert-BuildContext') 'Source and checkout identity must be rechecked before/after each ABI and copy'
    Assert-True ($source -match '(?s)Get-SubstTarget -Drive \$ownedDrive.*OrdinalIgnoreCase\.Equals\(\$currentTarget, \$projectRoot\).*subst\.exe \$ownedDrive /D') 'Mapping cleanup must verify its exact current target'
    Assert-True ($source -match 'originalHash = \$null' -and $source -notmatch 'Get-FileHash[^\r\n]*ownedDrive') 'StrictMode cleanup must not depend on an absent mapping file'
    $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $fixtureRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ('quantum-arm-guard-' + [guid]::NewGuid().ToString('N'))))
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $inputPath = Join-Path $fixtureRoot 'input.apk'
    $outputPath = Join-Path $fixtureRoot 'output.apk'
    [IO.File]::WriteAllBytes($inputPath, [byte[]](1, 2, 3, 4))
    Copy-ArtifactCreateNew $inputPath $outputPath
    Assert-True (([IO.File]::ReadAllBytes($outputPath) -join ',') -ceq '1,2,3,4') 'CreateNew copy must preserve APK bytes'
    [IO.File]::WriteAllBytes($inputPath, [byte[]](9, 8))
    Assert-Throws { Copy-ArtifactCreateNew $inputPath $outputPath } 'already exists|существует'
    Assert-True (([IO.File]::ReadAllBytes($outputPath) -join ',') -ceq '1,2,3,4') 'Existing APKs must never be overwritten'
    [pscustomobject]@{ Status='Passed'; Assertions=$tested; Gradle='not-run'; Subst='mocked'; Build='not-performed' } | ConvertTo-Json
} finally {
    $global:LASTEXITCODE = $priorExitCode
    if ($null -ne $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        $parent = [IO.Path]::GetDirectoryName($resolved)
        if ([StringComparer]::OrdinalIgnoreCase.Equals($parent.TrimEnd('\'), $tempBase.TrimEnd('\')) -and
            [IO.Path]::GetFileName($resolved) -cmatch '^quantum-arm-guard-[0-9a-f]{32}$') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } else { throw 'Refusing to remove an unexpected fixture path' }
    }
}
