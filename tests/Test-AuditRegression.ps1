[CmdletBinding()]
param(
    [string]$SingBoxPath,
    [switch]$ClientArtifactOnly
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
$configRoot = Join-Path $projectRoot 'config'
. (Join-Path $scriptsRoot 'SingBox-Checker.ps1')
$SingBoxPath=Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RequestedPath $SingBoxPath
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ar-' + [guid]::NewGuid().ToString('N').Substring(0,24))
New-Item -ItemType Directory -Path $fixtureRoot -ErrorAction Stop | Out-Null
function Assert-Audit { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Put-AuditText { param([string]$Path,[string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
$auditBodyError=$null
$auditCleanupError=$null
try {
    . (Join-Path $scriptsRoot 'Json-Validation.ps1')
    . (Join-Path $scriptsRoot 'Update-RoutingRules.ps1') -DefinitionsOnly
    . (Join-Path $scriptsRoot 'Build-Transaction.ps1')
    if (-not $ClientArtifactOnly) {
        & (Join-Path $PSScriptRoot 'Test-SourceManifest.ps1')
        & (Join-Path $PSScriptRoot 'Test-WindowsDeploymentTransaction.ps1')
        & (Join-Path $PSScriptRoot 'Test-StrictAuditRepairs.ps1')
        foreach ($format in @('dnsmasq','clash-yaml')) {
            $good = if ($format -eq 'dnsmasq') { "# comment`n`nserver=/example.com/114.114.114.114`n" } else { "---`n# comment`npayload: # header`n  - 'DST-PORT,123' # comment`n  - IP-CIDR,1.2.3.4/32,no-resolve`n" }
            $resource = [pscustomobject]@{tag='fixture';format=$format;url='https://example.invalid/rules.txt'}
            $path = Join-Path $fixtureRoot 'source.txt'
            Put-AuditText $path $good
            Assert-RemoteSource -Resource $resource -Path $path
            $badLines = if ($format -eq 'dnsmasq') { @('THIS IS NOT A RULE','server=/broken.example/','server=/') } else { @('  - BROKEN_RULE','  - DST-PORT,','  - DST-PORT,123,unexpected','  - "DST-PORT,123', 'unknown: value') }
            foreach ($badLine in $badLines) {
                Put-AuditText $path ($good + $badLine + "`n")
                $failed = $false
                try { Assert-RemoteSource -Resource $resource -Path $path } catch { $failed = $true }
                Assert-Audit $failed "Malformed $format line was accepted: $badLine"
            }
        }
    }

    $generator = Join-Path $scriptsRoot 'Generate-SingBoxConfig.ps1'
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($generator,[ref]$tokens,[ref]$errors)
    Assert-Audit (@($errors).Count -eq 0) 'Generator parse error.'
    foreach ($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { . ([scriptblock]::Create($node.Extent.Text)) }

    $defaultClientOutput=Join-Path $projectRoot 'generated'
    $expectedDefaultSupport=Get-NormalizedClientPath (Join-Path $projectRoot 'outputs\client-build')
    $actualDefaultSupport=Get-ClientSupportDirectory -ProjectRoot $projectRoot -OutputDirectory $defaultClientOutput -DefaultOutputDirectory $defaultClientOutput
    Assert-Audit ($actualDefaultSupport.Equals($expectedDefaultSupport,[StringComparison]::OrdinalIgnoreCase)) 'Default output must resolve to outputs/client-build.'
    $customOutputA=Join-Path $fixtureRoot 'custom-a\generated'
    $customOutputB=Join-Path $fixtureRoot 'custom-b\generated'
    $customSupportA=Get-ClientSupportDirectory -ProjectRoot $projectRoot -OutputDirectory $customOutputA -DefaultOutputDirectory $defaultClientOutput
    $customSupportB=Get-ClientSupportDirectory -ProjectRoot $projectRoot -OutputDirectory $customOutputB -DefaultOutputDirectory $defaultClientOutput
    Assert-Audit (-not $customSupportA.Equals($customSupportB,[StringComparison]::OrdinalIgnoreCase)) 'Distinct custom output paths must have independent support directories.'
    Assert-Audit ($customSupportA.StartsWith((Join-Path $expectedDefaultSupport 'custom') + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Custom support directories must remain under outputs/client-build/custom.'

    $pathCheckOutput=Join-Path $fixtureRoot 'path-check-output'
    $pathCheckBuildPaths=Get-BuildPaths $pathCheckOutput
    $pathCheckSupport=Join-Path $fixtureRoot 'path-check-support'
    $layoutFixtureId='client-layout-'+[guid]::NewGuid().ToString('N')
    $workSupportFixture=Join-Path $projectRoot (Join-Path 'work' (Join-Path $layoutFixtureId 'support-cache'))
    $outputsSupportFixture=Join-Path $projectRoot (Join-Path 'outputs' (Join-Path $layoutFixtureId 'support-cache'))
    foreach ($allowedSupport in @($pathCheckSupport,$workSupportFixture,$outputsSupportFixture)) {
        Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory $allowedSupport -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath
    }
    $protectedSupportPaths=@(
        (Join-Path $projectRoot 'tests\support-cache')
        (Join-Path $projectRoot 'docs\support-cache')
        (Join-Path $projectRoot 'backups\support-cache')
        (Join-Path $projectRoot 'config\support-cache')
        (Join-Path $projectRoot 'generated\support-cache')
        (Join-Path $projectRoot 'AGENTS.md\support-cache')
        (Join-Path (Split-Path -Parent $SingBoxPath) 'support-cache')
        (Join-Path $pathCheckOutput 'support-cache')
        (Split-Path -Parent $pathCheckOutput)
        ([IO.Path]::GetPathRoot($env:TEMP))
    )
    foreach ($protectedSupport in $protectedSupportPaths) {
        $rejected=$false
        try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory $protectedSupport -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath } catch { $rejected=$true }
        Assert-Audit $rejected "Protected or overlapping support path was accepted: $protectedSupport"
    }
    $reservedTransactionPaths=@(
        $pathCheckBuildPaths.Destination
        $pathCheckBuildPaths.Stage
        $pathCheckBuildPaths.Backup
        $pathCheckBuildPaths.Journal
        $pathCheckBuildPaths.Lock
        ($pathCheckBuildPaths.Journal + '.write')
    )
    foreach ($reservedTransactionPath in $reservedTransactionPaths) {
        $collisionCandidates=@(
            $reservedTransactionPath
            (Split-Path -Parent $reservedTransactionPath)
            (Join-Path $reservedTransactionPath 'support-cache')
            (Join-Path $reservedTransactionPath 'nested\..\normalized-cache')
        )
        foreach ($collisionCandidate in $collisionCandidates) {
            $rejected=$false
            try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory $collisionCandidate -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath } catch { $rejected=$true }
            Assert-Audit $rejected "Support path intersecting a reserved transaction path was accepted: $collisionCandidate"
        }
    }
    $safeTransactionPrefix=Get-NormalizedClientPath ($pathCheckBuildPaths.Stage + '-sidecar')
    Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory $safeTransactionPrefix -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath
    $collisionOutput=Join-Path $fixtureRoot 'transaction-collision-output'
    $collisionBuildPaths=Get-BuildPaths $collisionOutput
    [IO.Directory]::CreateDirectory($collisionOutput) | Out-Null
    [IO.Directory]::CreateDirectory($collisionBuildPaths.Stage) | Out-Null
    $collisionOutputSentinel=Join-Path $collisionOutput 'old-output-sentinel.txt'
    $collisionStageSentinel=Join-Path $collisionBuildPaths.Stage 'old-stage-sentinel.txt'
    Put-AuditText $collisionOutputSentinel 'old output must survive support-path rejection'
    Put-AuditText $collisionStageSentinel 'stage support must survive support-path rejection'
    $collisionError=''
    try { & $generator -Client android -SkipRoutingRules -OutputDirectory $collisionOutput -SupportDirectory $collisionBuildPaths.Stage -SingBoxPath $SingBoxPath -Force | Out-Null } catch { $collisionError=$_.Exception.Message }
    Assert-Audit ($collisionError -match 'reserved build transaction path') 'A support directory colliding with .build-stage was not rejected by path protection.'
    Assert-Audit ([IO.File]::ReadAllText($collisionOutputSentinel) -ceq 'old output must survive support-path rejection') 'Rejected support collision changed the prior output.'
    Assert-Audit ([IO.File]::ReadAllText($collisionStageSentinel) -ceq 'stage support must survive support-path rejection') 'Rejected support collision removed or changed the stage path contents.'
    $linkTargetDirectory=Join-Path $fixtureRoot 'support-link-target'
    $linkTargetSentinel=Join-Path $linkTargetDirectory 'sentinel.txt'
    $supportAncestorLink=Join-Path $fixtureRoot 'support-ancestor-link'
    [IO.Directory]::CreateDirectory($linkTargetDirectory) | Out-Null
    Put-AuditText $linkTargetSentinel 'reparse target must survive'
    $supportAncestorLinkCreated=$false
    try {
        New-Item -ItemType SymbolicLink -Path $supportAncestorLink -Target $linkTargetDirectory -ErrorAction Stop | Out-Null
        $supportAncestorLinkCreated=$true
    }
    catch { Write-Warning "Skipping reparse-ancestor assertion; symbolic-link creation is unavailable: $($_.Exception.Message)" }
    if ($supportAncestorLinkCreated) {
        try {
            $rejected=$false
    try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory (Join-Path $supportAncestorLink 'cache') -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath } catch { $rejected=$true }
            Assert-Audit $rejected 'Support path through a reparse-point ancestor was accepted.'
        }
        finally {
            [IO.Directory]::Delete($supportAncestorLink)
            Assert-Audit ([IO.File]::Exists($linkTargetSentinel)) 'Removing the reparse ancestor changed its target.'
        }
    }
    $externalInput=Join-Path $fixtureRoot 'explicit-input\template.json'
    $rejected=$false
    try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $pathCheckOutput -SupportDirectory (Split-Path -Parent $externalInput) -BuildPaths $pathCheckBuildPaths -RuntimeExecutable $SingBoxPath -AdditionalProtectedPaths @($externalInput) } catch { $rejected=$true }
    Assert-Audit $rejected 'Support directory overlapping an explicit input was accepted.'

    if (-not $ClientArtifactOnly) {
        foreach ($badValue in @($null,$true,'4096',4096.5,-1,4294967296,[double]::NaN,[double]::PositiveInfinity)) {
            Assert-Audit (-not (Test-UnsignedInteger $badValue)) 'Invalid uint32 accepted.'
        }
        foreach ($goodValue in @(0,4096,4294967295)) { Assert-Audit (Test-UnsignedInteger $goodValue) 'Valid uint32 rejected.' }
        Assert-Audit (Test-UnsignedInteger 576 -Minimum 576 -Maximum 65535) 'MTU lower boundary rejected.'
        Assert-Audit (Test-UnsignedInteger 65535 -Minimum 576 -Maximum 65535) 'MTU upper boundary rejected.'
        Assert-Audit (-not (Test-UnsignedInteger 575 -Minimum 576 -Maximum 65535)) 'MTU below range accepted.'
        Assert-Audit (-not (Test-UnsignedInteger 65536 -Minimum 576 -Maximum 65535)) 'MTU above range accepted.'
        Assert-Audit (-not (Test-UnsignedInteger 1023 -Minimum 1024)) 'DNS capacity below range accepted.'
    }

    $output=Join-Path $fixtureRoot 'output'
    $support=Join-Path $fixtureRoot 'generator-support'
    & $generator -Client android -SkipRoutingRules -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath | Out-Null
    $originalHash=(Get-FileHash -LiteralPath (Join-Path $output 'sing-box-configs.zip')).Hash
    foreach ($field in @('mtu','udp_nat_max','cache_capacity','log-level')) {
        $template=Read-JsonFile (Join-Path $configRoot 'sing-box-core-base.json')
        $fixtureProfiles=Read-JsonFile (Join-Path $configRoot 'client-profiles.json')
        if ($field -eq 'cache_capacity') { $template.dns.cache_capacity=8192.5 }
        elseif ($field -eq 'log-level') { $template.log.level='invalid-level-audit-fixture' }
        elseif ($field -eq 'mtu') { $fixtureProfiles.profiles.android.tun_overlay.mtu=4096.5 }
        else { $template.inbounds[0].$field=4096.5 }
        $templatePath=Join-Path $fixtureRoot 'template.json'
        $profilesPath=Join-Path $fixtureRoot 'profiles.json'
        Put-AuditText $templatePath ($template|ConvertTo-Json -Depth 100)
        Put-AuditText $profilesPath ($fixtureProfiles|ConvertTo-Json -Depth 100)
        $failed=$false
        try { & $generator -Client android -SkipRoutingRules -TemplatePath $templatePath -ProfilesPath $profilesPath -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath -Force | Out-Null } catch { $failed=$true }
        Assert-Audit $failed "Invalid $field was published for Android."
        Assert-Audit ((Get-FileHash -LiteralPath (Join-Path $output 'sing-box-configs.zip')).Hash -ceq $originalHash) 'Rejected config changed old ZIP.'
        Assert-Audit (-not (Test-Path -LiteralPath "$output.build-stage")) 'Rejected config left staging data.'
    }

    $old=Join-Path $fixtureRoot 'old-cache'
    $seed=Join-Path $fixtureRoot 'seed'
    $plan=@([pscustomobject]@{Tag='fixture';Rules=@([ordered]@{port=@(123)})})
    Compile-BinaryRuleSets -RuleSetPlan $plan -Executable $SingBoxPath -StagingDirectory $seed
    $validCache=Read-JsonFile (Join-Path $seed 'build-cache.json')
    $brokenCaches=@('{}','null','[]','{"version":99}', '{"version":2,"entries":null}', '{"version":2,"compiler_sha256":42}')
    $missingEntryField=Read-JsonFile (Join-Path $seed 'build-cache.json')
    $missingEntryField.entries[0].PSObject.Properties.Remove('source_sha256')
    $brokenCaches+=($missingEntryField|ConvertTo-Json -Depth 10)
    $duplicateEntry=Read-JsonFile (Join-Path $seed 'build-cache.json')
    $duplicateEntry.entries=@($duplicateEntry.entries[0],$duplicateEntry.entries[0])
    $brokenCaches+=($duplicateEntry|ConvertTo-Json -Depth 10)
    $caseNumber=0
    foreach ($brokenCache in $brokenCaches) {
        $caseNumber++
        Put-AuditText (Join-Path $old 'build-cache.json') $brokenCache
        Assert-Audit ($null -eq (Read-CompileCache (Join-Path $old 'build-cache.json'))) 'Invalid cache schema was trusted.'
        $stage=Join-Path $fixtureRoot ('compile-'+$caseNumber)
        Compile-BinaryRuleSets -RuleSetPlan $plan -Executable $SingBoxPath -StagingDirectory $stage -ExistingCachePath (Join-Path $old 'build-cache.json')
        $rebuilt=Read-CompileCache (Join-Path $stage 'build-cache.json')
        Assert-Audit ($null -ne $rebuilt -and $rebuilt.entries[0].binary_sha256 -ceq $validCache.entries[0].binary_sha256) 'Bad cache did not fall back to recompilation.'
    }

    if (-not $ClientArtifactOnly) {
        $parent=Join-Path $fixtureRoot 'existing-parent'
        $sentinel=Join-Path $parent 'existing-data.txt'
        Put-AuditText $sentinel 'must survive'
        & (Join-Path $PSScriptRoot 'Test-RoutingTransaction.ps1') -TestRoot $parent
        Assert-Audit ([IO.File]::ReadAllText($sentinel) -ceq 'must survive') 'Custom test parent data was deleted.'
        Assert-Audit (@(Get-ChildItem -LiteralPath $parent -Force).Count -eq 1) 'Custom test parent contains residual fixtures.'
    }
    Write-Host 'Audit regression tests passed: integer validation, cross-platform official check, malformed lines, cache schema recovery and safe test parent.'
}
catch { $auditBodyError=$_ }
finally {
    try {
        $resolved=[IO.Path]::GetFullPath($fixtureRoot)
        if ((Split-Path -Parent $resolved) -ine ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $resolved) -notmatch '^ar-[a-f0-9]{24}$') { throw 'Unsafe audit fixture cleanup.' }
        $items=@(Get-Item -LiteralPath $resolved -Force)+@(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
        if (@($items|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count) { throw 'Audit fixture reparse point.' }
        [IO.Directory]::Delete($resolved,$true)
    }
    catch { $auditCleanupError=$_ }
}
if ($null -ne $auditBodyError) {
    if ($null -ne $auditCleanupError) { throw ('Audit regression failed: '+$auditBodyError.Exception.Message+'; fixture cleanup also failed: '+$auditCleanupError.Exception.Message) }
    throw $auditBodyError
}
if ($null -ne $auditCleanupError) { throw $auditCleanupError }
