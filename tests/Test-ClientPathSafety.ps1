[CmdletBinding()]
param([string]$TestRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'Json-Validation.ps1')
. (Join-Path $scriptsRoot 'Build-Transaction.ps1')
. (Join-Path $scriptsRoot 'Config-Archive.ps1')
. (Join-Path $scriptsRoot 'Windows-Deployment.ps1')

function Assert-ClientPathSafety {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-PathGuardWithoutCallerRoot {
    param([string]$Path, [string]$LeafType = 'Any', [switch]$Required)
    $callerRoot = Get-Variable -Name root -Scope Local -ErrorAction SilentlyContinue
    if ($null -ne $callerRoot) { Remove-Variable -Name root -Scope Local -Force }
    if ($Required) { return Assert-ClientPlainPathTree -Path $Path -LeafType $LeafType -Required }
    return Assert-ClientPlainPathTree -Path $Path -LeafType $LeafType
}

function Invoke-PathGuardWithCallerRoot {
    param([string]$Path, [string]$CallerRoot, [string]$LeafType = 'Any', [switch]$Required)
    $root = $CallerRoot
    if ($Required) { return Assert-ClientPlainPathTree -Path $Path -LeafType $LeafType -Required }
    return Assert-ClientPlainPathTree -Path $Path -LeafType $LeafType
}

function New-ClientPathSafetyJunction {
    param([string]$Path, [string]$Target, $CreatedLinks)
    $null = Assert-ClientPlainPathTree -Path $Path -LeafType Directory
    $null = Assert-ClientPlainPathTree -Path $Target -LeafType Directory -Required
    New-Item -ItemType Junction -Path $Path -Target $Target -ErrorAction Stop | Out-Null
    $CreatedLinks.Add([IO.Path]::GetFullPath($Path))
}

function Remove-ClientPathSafetyJunction {
    param([string]$Path, [string]$FixtureRoot, $CreatedLinks)
    $root = Get-ClientNormalizedFullPath -Path $FixtureRoot
    $full = Get-ClientNormalizedFullPath -Path $Path
    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Test junction is outside its fixture root: $full"
    }
    if ([IO.Directory]::Exists($full)) {
        $attributes = [IO.File]::GetAttributes($full)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw "Expected test junction is not a reparse point: $full" }
        [IO.Directory]::Delete($full, $false)
    }
    [void]$CreatedLinks.Remove($full)
}

function Write-ClientPathSafetyFile {
    param([string]$Path, [string]$Text)
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

$projectFull = Get-ClientNormalizedFullPath -Path $projectRoot
if ([string]::IsNullOrWhiteSpace($TestRoot)) { $TestRoot = Join-Path $projectRoot 'outputs\tests\client-path-safety' }
$testParent = Get-ClientNormalizedFullPath -Path $TestRoot
$allowedParent = $false
foreach ($allowedName in @('work','outputs')) {
    $allowedRoot = Get-ClientNormalizedFullPath -Path (Join-Path $projectFull $allowedName)
    if ($testParent.StartsWith($allowedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { $allowedParent = $true }
}
if (-not $allowedParent) { throw 'TestRoot must be a child of project work/ or outputs/.' }
$null = Assert-ClientPlainPathTree -Path $testParent -LeafType Directory
[IO.Directory]::CreateDirectory($testParent) | Out-Null
$runRoot = Join-Path $testParent ('client-path-safety-' + [guid]::NewGuid().ToString('N'))
$null = Assert-ClientPlainPathTree -Path $runRoot -LeafType Directory
[IO.Directory]::CreateDirectory($runRoot) | Out-Null
$null = Assert-ClientPlainPathTree -Path $runRoot -LeafType Directory -Required -IncludeDescendants
$createdLinks = [Collections.Generic.List[string]]::new()

try {
    $targetRoot = Join-Path $runRoot 'sentinel-targets'
    [IO.Directory]::CreateDirectory($targetRoot) | Out-Null
    $runtimeSentinel = Join-Path $targetRoot 'runtime-sentinel.txt'
    $runtimeSentinelText = 'runtime-target-must-remain-byte-identical'
    Write-ClientPathSafetyFile -Path $runtimeSentinel -Text $runtimeSentinelText
    $runtimeSentinelHash = (Get-FileHash -LiteralPath $runtimeSentinel -Algorithm SHA256).Hash

    $archiveParent = Join-Path $runRoot 'publisher-fixture'
    [IO.Directory]::CreateDirectory($archiveParent) | Out-Null
    $archivePath = Join-Path $archiveParent 'input.zip'
    [IO.File]::WriteAllBytes($archivePath, [byte[]](80,75,5,6))
    $archivePublisherLock = (Get-BuildPaths $archiveParent).Lock

    $existingNoRoot = Invoke-PathGuardWithoutCallerRoot -Path $archiveParent -LeafType Directory -Required
    $existingForeignRoot = Invoke-PathGuardWithCallerRoot -Path $archiveParent -CallerRoot (Join-Path $runRoot 'unrelated-caller-root') -LeafType Directory -Required
    Assert-ClientPathSafety ($existingNoRoot -ceq $existingForeignRoot) 'Existing path validation changed with caller root scope.'
    $optionalMissing = Join-Path $archiveParent 'optional\missing\deployment-journal.json'
    $missingNoRoot = Invoke-PathGuardWithoutCallerRoot -Path $optionalMissing -LeafType File
    $missingForeignRoot = Invoke-PathGuardWithCallerRoot -Path $optionalMissing -CallerRoot (Join-Path $runRoot 'unrelated-caller-root') -LeafType File
    Assert-ClientPathSafety ($missingNoRoot -ceq $missingForeignRoot) 'Optional multi-level missing path validation changed with caller root scope.'
    Assert-ClientPathSafety (-not [IO.File]::Exists($optionalMissing)) 'Optional missing path validation unexpectedly created a file.'

    $runtimeTarget = Join-Path $targetRoot 'runtime-link-target'
    [IO.Directory]::CreateDirectory($runtimeTarget) | Out-Null
    $runtimeLink = Join-Path $runRoot 'runtime-parent-link'
    New-ClientPathSafetyJunction -Path $runtimeLink -Target $runtimeTarget -CreatedLinks $createdLinks
    $linkedRuntime = Join-Path $runtimeLink 'runtime'
    $callerRootJunctionRejected = $false
    try { $null = Invoke-PathGuardWithCallerRoot -Path $linkedRuntime -CallerRoot $runtimeLink -LeafType Directory }
    catch { $callerRootJunctionRejected = $true }
    Assert-ClientPathSafety $callerRootJunctionRejected 'A caller-scoped root variable bypassed junction detection.'
    $linkedRuntimeRejected = $false
    try { $null = Enter-WindowsDeploymentLocks -RuntimeDirectory $linkedRuntime -ArchivePath $archivePath -TimeoutSeconds 1 }
    catch { $linkedRuntimeRejected = $true }
    Assert-ClientPathSafety $linkedRuntimeRejected 'Deployment lock entry accepted a junction in the runtime ancestor chain.'
    Assert-ClientPathSafety (-not [IO.Directory]::Exists($linkedRuntime)) 'Rejected deployment created a runtime directory through the junction.'
    Assert-ClientPathSafety (-not [IO.File]::Exists((Join-Path $linkedRuntime '.runtime\control.lock'))) 'Rejected deployment created a control lock through the junction.'
    Assert-ClientPathSafety (-not [IO.File]::Exists($archivePublisherLock)) 'Rejected deployment created a publisher lock before runtime path validation.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $runtimeSentinel -Algorithm SHA256).Hash -ceq $runtimeSentinelHash) 'Runtime ancestor rejection changed sentinel bytes.'
    Remove-ClientPathSafetyJunction -Path $runtimeLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $wrongTypeParent = Join-Path $runRoot 'runtime-parent-file'
    Write-ClientPathSafetyFile -Path $wrongTypeParent -Text 'wrong-type-ancestor'
    $wrongTypeHash = (Get-FileHash -LiteralPath $wrongTypeParent -Algorithm SHA256).Hash
    $wrongTypeRuntime = Join-Path $wrongTypeParent 'runtime'
    $wrongTypeRejected = $false
    try { $null = Enter-WindowsDeploymentLocks -RuntimeDirectory $wrongTypeRuntime -ArchivePath $archivePath -TimeoutSeconds 1 }
    catch { $wrongTypeRejected = $true }
    Assert-ClientPathSafety $wrongTypeRejected 'Deployment lock entry accepted a file in the runtime ancestor chain.'
    Assert-ClientPathSafety (-not [IO.Directory]::Exists($wrongTypeRuntime)) 'Rejected deployment created a child below a file ancestor.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $wrongTypeParent -Algorithm SHA256).Hash -ceq $wrongTypeHash) 'Wrong-type ancestor rejection changed source bytes.'
    Assert-ClientPathSafety (-not [IO.File]::Exists($archivePublisherLock)) 'Rejected wrong-type deployment created a publisher lock.'

    $importTargetParent = Join-Path $targetRoot 'import-stage-target'
    $importTargetStage = Join-Path $importTargetParent 'linked-import.build-stage'
    [IO.Directory]::CreateDirectory((Join-Path $importTargetStage 'rule-set')) | Out-Null
    $importTargetSentinel = Join-Path $importTargetStage 'stage-sentinel.txt'
    Write-ClientPathSafetyFile -Path $importTargetSentinel -Text 'stage-target-must-remain-byte-identical'
    $importTargetHash = (Get-FileHash -LiteralPath $importTargetSentinel -Algorithm SHA256).Hash
    $importParentLink = Join-Path $runRoot 'import-stage-parent-link'
    New-ClientPathSafetyJunction -Path $importParentLink -Target $importTargetParent -CreatedLinks $createdLinks
    $linkedImportStage = Join-Path $importParentLink 'linked-import.build-stage'
    $linkedImportRejected = $false
    try { $null = Import-WindowsArchiveToStage -ArchivePath $archivePath -StageDirectory $linkedImportStage }
    catch { $linkedImportRejected = $true }
    Assert-ClientPathSafety $linkedImportRejected 'Archive import accepted a junction in the stage ancestor chain.'
    Assert-ClientPathSafety (-not [IO.File]::Exists((Join-Path $linkedImportStage 'sing-box-windows-tun.json'))) 'Rejected import wrote a staged config through the ancestor junction.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $importTargetSentinel -Algorithm SHA256).Hash -ceq $importTargetHash) 'Rejected import changed stage target bytes.'
    Remove-ClientPathSafetyJunction -Path $importParentLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $rulesTarget = Join-Path $targetRoot 'linked-rules-target'
    [IO.Directory]::CreateDirectory($rulesTarget) | Out-Null
    $rulesSentinel = Join-Path $rulesTarget 'routing-direct-domain.srs'
    Write-ClientPathSafetyFile -Path $rulesSentinel -Text 'linked-rule-set-must-remain-byte-identical'
    $rulesHash = (Get-FileHash -LiteralPath $rulesSentinel -Algorithm SHA256).Hash
    $internalStage = Join-Path $runRoot 'internal-rule-link.build-stage'
    [IO.Directory]::CreateDirectory($internalStage) | Out-Null
    $internalRuleLink = Join-Path $internalStage 'rule-set'
    New-ClientPathSafetyJunction -Path $internalRuleLink -Target $rulesTarget -CreatedLinks $createdLinks
    $internalRuleRejected = $false
    try { $null = Import-WindowsArchiveToStage -ArchivePath $archivePath -StageDirectory $internalStage }
    catch { $internalRuleRejected = $true }
    Assert-ClientPathSafety $internalRuleRejected 'Archive import accepted a linked rule-set directory.'
    Assert-ClientPathSafety (-not [IO.File]::Exists((Join-Path $internalStage 'sing-box-windows-tun.json'))) 'Rejected rule-set stage was written before validation.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $rulesSentinel -Algorithm SHA256).Hash -ceq $rulesHash) 'Rejected rule-set stage changed linked SRS target bytes.'
    Remove-ClientPathSafetyJunction -Path $internalRuleLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $archiveInput = Join-Path $runRoot 'linked-archive-input'
    [IO.Directory]::CreateDirectory($archiveInput) | Out-Null
    Write-ClientPathSafetyFile -Path (Join-Path $archiveInput 'sing-box-windows-tun.json') -Text '{"route":{"rule_set":[{"type":"local","format":"binary","path":"rule-set/routing-direct-domain.srs"}]}}'
    $archiveRuleLink = Join-Path $archiveInput 'rule-set'
    New-ClientPathSafetyJunction -Path $archiveRuleLink -Target $rulesTarget -CreatedLinks $createdLinks
    $archiveReadRejected = $false
    try { $null = Get-ConfigArchiveFiles -Directory $archiveInput -ConfigurationNames @('sing-box-windows-tun.json') }
    catch { $archiveReadRejected = $true }
    Assert-ClientPathSafety $archiveReadRejected 'Archive input accepted a linked rule-set directory.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $rulesSentinel -Algorithm SHA256).Hash -ceq $rulesHash) 'Archive-input rejection changed linked SRS target bytes.'
    Remove-ClientPathSafetyJunction -Path $archiveRuleLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $linkedRuleCleanupStage = Join-Path $runRoot 'linked-rule-cleanup.build-stage'
    [IO.Directory]::CreateDirectory($linkedRuleCleanupStage) | Out-Null
    $linkedRuleCleanupConfig = Join-Path $linkedRuleCleanupStage 'sing-box-windows-tun.json'
    $linkedRuleCleanupZip = Join-Path $linkedRuleCleanupStage 'sing-box-configs.zip'
    Write-ClientPathSafetyFile -Path $linkedRuleCleanupConfig -Text '{"route":{"rule_set":[{"type":"local","format":"binary","path":"rule-set/routing-direct-domain.srs"}]}}'
    Write-ClientPathSafetyFile -Path $linkedRuleCleanupZip -Text 'linked-rule-cleanup-archive'
    $linkedRuleCleanupLink = Join-Path $linkedRuleCleanupStage 'rule-set'
    New-ClientPathSafetyJunction -Path $linkedRuleCleanupLink -Target $rulesTarget -CreatedLinks $createdLinks
    $linkedRuleCleanupHashes = @{
        $linkedRuleCleanupConfig = (Get-FileHash -LiteralPath $linkedRuleCleanupConfig -Algorithm SHA256).Hash
        $linkedRuleCleanupZip = (Get-FileHash -LiteralPath $linkedRuleCleanupZip -Algorithm SHA256).Hash
        $rulesSentinel = (Get-FileHash -LiteralPath $rulesSentinel -Algorithm SHA256).Hash
    }
    $linkedRuleCleanupRejected = $false
    try { Complete-ArchiveOnlyStage -Directory $linkedRuleCleanupStage -ConfigurationNames @('sing-box-windows-tun.json') }
    catch { $linkedRuleCleanupRejected = $true }
    Assert-ClientPathSafety $linkedRuleCleanupRejected 'Archive cleanup accepted a linked rule-set directory.'
    foreach ($path in $linkedRuleCleanupHashes.Keys) {
        Assert-ClientPathSafety ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $linkedRuleCleanupHashes[$path]) "Rejected rule-set cleanup changed bytes: $path"
    }
    Remove-ClientPathSafetyJunction -Path $linkedRuleCleanupLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $cleanupTargetParent = Join-Path $targetRoot 'cleanup-stage-target-parent'
    $cleanupTargetStage = Join-Path $cleanupTargetParent 'linked-cleanup.build-stage'
    [IO.Directory]::CreateDirectory((Join-Path $cleanupTargetStage 'rule-set')) | Out-Null
    $cleanupTargetConfig = Join-Path $cleanupTargetStage 'sing-box-windows-tun.json'
    $cleanupTargetZip = Join-Path $cleanupTargetStage 'sing-box-configs.zip'
    $cleanupTargetSrs = Join-Path $cleanupTargetStage 'rule-set\routing-direct-domain.srs'
    Write-ClientPathSafetyFile -Path $cleanupTargetConfig -Text '{"route":{"rule_set":[{"type":"local","format":"binary","path":"rule-set/routing-direct-domain.srs"}]}}'
    Write-ClientPathSafetyFile -Path $cleanupTargetZip -Text 'archive-sentinel'
    Write-ClientPathSafetyFile -Path $cleanupTargetSrs -Text 'cleanup-SRS-must-remain-byte-identical'
    $cleanupHashes = @{}
    foreach ($path in @($cleanupTargetConfig,$cleanupTargetZip,$cleanupTargetSrs)) { $cleanupHashes[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    $cleanupParentLink = Join-Path $runRoot 'cleanup-stage-parent-link'
    New-ClientPathSafetyJunction -Path $cleanupParentLink -Target $cleanupTargetParent -CreatedLinks $createdLinks
    $linkedCleanupStage = Join-Path $cleanupParentLink 'linked-cleanup.build-stage'
    $cleanupRejected = $false
    try { Complete-ArchiveOnlyStage -Directory $linkedCleanupStage -ConfigurationNames @('sing-box-windows-tun.json') }
    catch { $cleanupRejected = $true }
    Assert-ClientPathSafety $cleanupRejected 'Archive cleanup accepted a stage reached through an ancestor junction.'
    foreach ($path in $cleanupHashes.Keys) {
        Assert-ClientPathSafety ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $cleanupHashes[$path]) "Rejected linked cleanup changed target bytes: $path"
    }
    Remove-ClientPathSafetyJunction -Path $cleanupParentLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $buildTarget = Join-Path $targetRoot 'build-output-target'
    [IO.Directory]::CreateDirectory($buildTarget) | Out-Null
    $buildTargetStage = Join-Path $buildTarget 'release.build-stage'
    [IO.Directory]::CreateDirectory($buildTargetStage) | Out-Null
    $buildSentinel = Join-Path $buildTargetStage 'build-sentinel.txt'
    Write-ClientPathSafetyFile -Path $buildSentinel -Text 'build-stage-target-must-remain-byte-identical'
    $buildSentinelHash = (Get-FileHash -LiteralPath $buildSentinel -Algorithm SHA256).Hash
    $buildLink = Join-Path $runRoot 'build-output-parent-link'
    New-ClientPathSafetyJunction -Path $buildLink -Target $buildTarget -CreatedLinks $createdLinks
    $buildPaths = Get-BuildPaths (Join-Path $buildLink 'release')
    $buildCleanupRejected = $false
    try { Remove-BuildDirectory -Paths $buildPaths -Path $buildPaths.Stage }
    catch { $buildCleanupRejected = $true }
    Assert-ClientPathSafety $buildCleanupRejected 'Build cleanup accepted a stage under an ancestor junction.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $buildSentinel -Algorithm SHA256).Hash -ceq $buildSentinelHash) 'Rejected build cleanup changed linked stage bytes.'
    Remove-ClientPathSafetyJunction -Path $buildLink -FixtureRoot $runRoot -CreatedLinks $createdLinks

    $wrongTypeBuild = Get-BuildPaths (Join-Path $wrongTypeParent 'release')
    $wrongTypeBuildRejected = $false
    try { Remove-BuildDirectory -Paths $wrongTypeBuild -Path $wrongTypeBuild.Stage }
    catch { $wrongTypeBuildRejected = $true }
    Assert-ClientPathSafety $wrongTypeBuildRejected 'Build cleanup accepted a file in its stage ancestor chain.'
    Assert-ClientPathSafety ((Get-FileHash -LiteralPath $wrongTypeParent -Algorithm SHA256).Hash -ceq $wrongTypeHash) 'Rejected build cleanup changed the wrong-type ancestor.'

    Write-Output 'CLIENT_PATH_SAFETY=PASS'
    Write-Output 'Covered runtime and stage ancestor junctions, linked rule-set cleanup/import, wrong-type ancestors, no premature lock creation, and byte-identical sentinels.'
}
finally {
    foreach ($link in @($createdLinks.ToArray())) {
        if ([IO.Directory]::Exists($link)) { Remove-ClientPathSafetyJunction -Path $link -FixtureRoot $runRoot -CreatedLinks $createdLinks }
    }
    if ([IO.Directory]::Exists($runRoot)) {
        $safeRunRoot = Assert-ClientPlainPathTree -Path $runRoot -LeafType Directory -Required -IncludeDescendants
        $normalizedParent = Get-ClientNormalizedFullPath -Path (Split-Path -Parent $safeRunRoot)
        if ($normalizedParent -ine $testParent -or (Split-Path -Leaf $safeRunRoot) -notmatch '^client-path-safety-[a-f0-9]{32}$') { throw 'Unsafe client path-safety fixture cleanup path.' }
        Remove-Item -LiteralPath $safeRunRoot -Recurse -Force -ErrorAction Stop
    }
}
