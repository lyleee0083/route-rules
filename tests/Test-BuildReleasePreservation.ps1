[CmdletBinding()]
param([string]$TaskDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($TaskDirectory)) { $TaskDirectory = [IO.Path]::GetTempPath() }
$fixtureParent = [IO.Path]::GetFullPath($TaskDirectory).TrimEnd([char[]]'\/')
if (-not [IO.Directory]::Exists($fixtureParent)) { throw "Test parent directory is missing: $fixtureParent" }
$cursor = $fixtureParent
while ($cursor) {
    try { $attributes = [IO.File]::GetAttributes($cursor) }
    catch { throw "Cannot inspect test parent path: $cursor`n$($_.Exception.Message)" }
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unsafe test parent path: $cursor" }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
    $cursor = $parent
}
$runRoot = Join-Path $fixtureParent ('release-preservation-' + [guid]::NewGuid().ToString('N'))
function Assert-ReleaseTest { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Write-ReleaseFixtureFile { param([string]$Path,[string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false))) }
function Format-JsonText { param([string]$Text) return $Text }
function New-ReleaseFixture {
    param([string]$Directory,[string]$PackageText)
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $Directory '2026-10-20-baseline\empty')) | Out-Null
    Write-ReleaseFixtureFile (Join-Path $Directory 'sing-box-configs.zip') $PackageText
    Write-ReleaseFixtureFile (Join-Path $Directory '2026-10-20-baseline\nested\notes.txt') 'baseline-note'
    Write-ReleaseFixtureFile (Join-Path $Directory '2026-10-20-baseline\rule-set\baseline.srs') 'baseline-srs'
    Write-ReleaseFixtureFile (Join-Path $Directory '2026-10-25-performance\rule-set\routing-direct-domain.srs') 'domain-srs'
    Write-ReleaseFixtureFile (Join-Path $Directory '2026-10-25-performance\rule-set\routing-direct-port.srs') 'port-srs'
    Write-ReleaseFixtureFile (Join-Path $Directory '2026-10-25-performance\rule-set\routing-direct-ip.srs') 'ip-srs'
}
function New-ReleaseStage {
    param($Paths,$Snapshot,[string]$PackageText)
    [IO.Directory]::CreateDirectory($Paths.Stage) | Out-Null
    Write-ReleaseFixtureFile (Join-Path $Paths.Stage 'sing-box-configs.zip') $PackageText
    Copy-BuildPreservedDirectoriesToStage -Snapshot $Snapshot -StageDirectory $Paths.Stage
}
function Get-ReleaseFixtureHashMap {
    param([string]$Directory)
    $map = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File -Force) {
        $relative = $file.FullName.Substring($Directory.Length).TrimStart([char[]]'\/').Replace('\','/')
        if ($relative -notmatch '^2026-\d{2}-\d{2}[^/]*/') { continue }
        $map[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $map
}
function Compare-ReleaseFixtureMaps {
    param($Expected,$Actual,[string]$Label)
    Assert-ReleaseTest ($Expected.Count -eq $Actual.Count) ($Label + ': preserved file count differs.')
    foreach ($name in $Expected.Keys) { Assert-ReleaseTest ($Actual.ContainsKey($name) -and $Actual[$name] -ceq $Expected[$name]) ($Label + ': preserved file differs: ' + $name) }
}
function Remove-ReleaseFixtureJunction {
    param([string]$Path,[string]$FixtureRoot,[string]$TargetSentinel,[string]$ExpectedSentinel)
    $root = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd([char[]]'\/')
    $full = [IO.Path]::GetFullPath($Path)
    $sentinel = [IO.Path]::GetFullPath($TargetSentinel)
    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        -not $sentinel.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        $sentinel.StartsWith($full + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing junction cleanup outside its fixture or through its target.' }
    $link = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $link) { return }
    if (-not $link.PSIsContainer -or -not ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing to remove a non-reparse fixture object as a junction.' }
    if ([IO.File]::ReadAllText($sentinel) -cne $ExpectedSentinel) { throw 'Junction target sentinel changed; preserving fixture.' }
    [IO.Directory]::Delete($full,$false)
    if (Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue) { throw 'Fixture junction entry remained after non-recursive deletion.' }
    if (-not [IO.File]::Exists($sentinel) -or [IO.File]::ReadAllText($sentinel) -cne $ExpectedSentinel) { throw 'Fixture junction deletion changed its target sentinel.' }
}

. (Join-Path $projectRoot 'scripts\Build-Transaction.ps1')
[IO.Directory]::CreateDirectory($runRoot) | Out-Null
$junctionPath = $null
try {
    $formalOutput = Join-Path $runRoot 'formal-output'
    $nestedOutput = Join-Path $formalOutput '2026-10-25-performance'
    $failed = $false
    try { Assert-BuildOutputNotNested -OutputDirectory $nestedOutput -FormalOutputDirectory $formalOutput | Out-Null } catch { $failed = $true }
    Assert-ReleaseTest $failed 'A custom publisher was allowed to create transaction state inside a formal output tree.'
    Assert-ReleaseTest ((Assert-BuildOutputNotNested -OutputDirectory $formalOutput -FormalOutputDirectory $formalOutput) -ceq [IO.Path]::GetFullPath($formalOutput)) 'The formal output root was incorrectly rejected.'
    $customOutput = Join-Path $runRoot 'custom-output'
    Assert-ReleaseTest ((Assert-BuildOutputNotNested -OutputDirectory $customOutput -FormalOutputDirectory $formalOutput) -ceq [IO.Path]::GetFullPath($customOutput)) 'A custom output outside the formal tree was incorrectly rejected.'

    $ordinary = Join-Path $runRoot 'ordinary'
    New-ReleaseFixture $ordinary 'old-package'
    $oldFiles = Get-ReleaseFixtureHashMap $ordinary
    Assert-ReleaseTest ($oldFiles.Count -eq 5) 'Release fixture does not contain both dated trees and all three family SRS files.'
    $paths = Get-BuildPaths $ordinary
    $snapshot = Get-BuildPreservationSnapshot -Destination $ordinary
    New-ReleaseStage $paths $snapshot 'new-package'
    Publish-BuildTransaction -Paths $paths -PreservationSnapshot $snapshot
    Assert-BuildPreservationSnapshot -Directory $ordinary -Snapshot $snapshot -ExpectedRoot $ordinary -RequirePackage
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $ordinary 'sing-box-configs.zip')) -ceq 'new-package') 'Successful publication did not replace the current ZIP.'
    Compare-ReleaseFixtureMaps $oldFiles (Get-ReleaseFixtureHashMap $ordinary) 'Successful publication'
    Assert-ReleaseTest ([IO.Directory]::Exists((Join-Path $ordinary '2026-10-20-baseline\empty'))) 'Successful publication did not preserve an empty nested directory.'

    $prepared = Join-Path $runRoot 'prepared'
    New-ReleaseFixture $prepared 'prepared-old-package'
    $preparedFiles = Get-ReleaseFixtureHashMap $prepared
    $preparedPaths = Get-BuildPaths $prepared
    $preparedSnapshot = Get-BuildPreservationSnapshot -Destination $prepared
    New-ReleaseStage $preparedPaths $preparedSnapshot 'prepared-new-package'
    $preparedJournal = [ordered]@{ version=1; destination=$preparedPaths.Destination; phase='prepared'; existed=$true; preservation=$preparedSnapshot }
    Write-BuildJournal $preparedPaths $preparedJournal
    [IO.Directory]::Move($preparedPaths.Destination,$preparedPaths.Backup)
    [IO.Directory]::Move($preparedPaths.Stage,$preparedPaths.Destination)
    Restore-BuildTransaction $preparedPaths
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $prepared 'sing-box-configs.zip')) -ceq 'prepared-old-package') 'Prepared recovery did not restore the old ZIP.'
    Compare-ReleaseFixtureMaps $preparedFiles (Get-ReleaseFixtureHashMap $prepared) 'Prepared recovery'
    Assert-ReleaseTest (-not (Test-Path -LiteralPath $preparedPaths.Journal)) 'Prepared recovery left its journal behind.'

    $committed = Join-Path $runRoot 'committed'
    New-ReleaseFixture $committed 'committed-old-package'
    $committedFiles = Get-ReleaseFixtureHashMap $committed
    $committedPaths = Get-BuildPaths $committed
    $committedSnapshot = Get-BuildPreservationSnapshot -Destination $committed
    New-ReleaseStage $committedPaths $committedSnapshot 'committed-new-package'
    $committedJournal = [ordered]@{ version=1; destination=$committedPaths.Destination; phase='prepared'; existed=$true; preservation=$committedSnapshot }
    Write-BuildJournal $committedPaths $committedJournal
    [IO.Directory]::Move($committedPaths.Destination,$committedPaths.Backup)
    [IO.Directory]::Move($committedPaths.Stage,$committedPaths.Destination)
    $committedJournal.phase = 'committed'
    Write-BuildJournal $committedPaths $committedJournal
    Restore-BuildTransaction $committedPaths
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $committed 'sing-box-configs.zip')) -ceq 'committed-new-package') 'Committed recovery lost the new ZIP.'
    Compare-ReleaseFixtureMaps $committedFiles (Get-ReleaseFixtureHashMap $committed) 'Committed recovery'
    Assert-ReleaseTest (-not (Test-Path -LiteralPath $committedPaths.Backup) -and -not (Test-Path -LiteralPath $committedPaths.Journal)) 'Committed recovery retained its backup or journal.'

    $rejected = Join-Path $runRoot 'unknown-file'
    New-ReleaseFixture $rejected 'protected-package'
    $protectedHash = (Get-FileHash -LiteralPath (Join-Path $rejected 'sing-box-configs.zip')).Hash
    Write-ReleaseFixtureFile (Join-Path $rejected 'unmanaged.txt') 'keep-me'
    $failed = $false
    try { Get-BuildPreservationSnapshot -Destination $rejected | Out-Null } catch { $failed = $true }
    Assert-ReleaseTest $failed 'Unknown ordinary files were accepted in a release output.'
    Assert-ReleaseTest ((Get-FileHash -LiteralPath (Join-Path $rejected 'sing-box-configs.zip')).Hash -ceq $protectedHash) 'Unknown-file rejection changed the existing package.'
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $rejected 'unmanaged.txt')) -ceq 'keep-me') 'Unknown-file rejection removed the unrelated file.'

    $linked = Join-Path $runRoot 'reparse'
    New-ReleaseFixture $linked 'reparse-protected-package'
    $target = Join-Path $runRoot 'junction-target'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    Write-ReleaseFixtureFile (Join-Path $target 'outside.txt') 'external-target'
    $junctionPath = Join-Path $linked '2026-10-25-performance\linked'
    New-Item -ItemType Junction -Path $junctionPath -Target $target | Out-Null
    $failed = $false
    try { Get-BuildPreservationSnapshot -Destination $linked | Out-Null } catch { $failed = $true }
    Assert-ReleaseTest $failed 'A nested reparse point was accepted in a release directory.'
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $target 'outside.txt')) -ceq 'external-target') 'Reparse rejection altered the link target.'
    Remove-ReleaseFixtureJunction -Path $junctionPath -FixtureRoot $runRoot -TargetSentinel (Join-Path $target 'outside.txt') -ExpectedSentinel 'external-target'
    $junctionPath = $null

    $failedStage = Join-Path $runRoot 'failed-stage'
    New-ReleaseFixture $failedStage 'failure-protected-package'
    $failedStageFiles = Get-ReleaseFixtureHashMap $failedStage
    $failedPaths = Get-BuildPaths $failedStage
    $failedSnapshot = Get-BuildPreservationSnapshot -Destination $failedStage
    [IO.Directory]::CreateDirectory($failedPaths.Stage) | Out-Null
    Write-ReleaseFixtureFile (Join-Path $failedPaths.Stage 'sing-box-configs.zip') 'staged-new-package'
    Write-ReleaseFixtureFile (Join-Path $failedPaths.Stage 'unexpected.txt') 'reject-stage'
    $failed = $false
    try { Publish-BuildTransaction -Paths $failedPaths -PreservationSnapshot $failedSnapshot } catch { $failed = $true }
    Assert-ReleaseTest $failed 'A stage with unrecognized files was published.'
    Assert-ReleaseTest ([IO.File]::ReadAllText((Join-Path $failedStage 'sing-box-configs.zip')) -ceq 'failure-protected-package') 'Failed publication changed the previous package.'
    Compare-ReleaseFixtureMaps $failedStageFiles (Get-ReleaseFixtureHashMap $failedStage) 'Failed publication'

    Write-Output 'Build release preservation fixtures passed: dated nested trees, three SRS, success, prepared rollback, committed recovery, unknown-file rejection, reparse rejection, and stage-failure preservation.'
}
finally {
    if ($junctionPath) { Remove-ReleaseFixtureJunction -Path $junctionPath -FixtureRoot $runRoot -TargetSentinel (Join-Path $runRoot 'junction-target\outside.txt') -ExpectedSentinel 'external-target' }
    if (Test-Path -LiteralPath $runRoot) {
        $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot).TrimEnd([char[]]'\/')
        if ((Split-Path -Parent $resolvedRunRoot) -ine $fixtureParent -or (Split-Path -Leaf $resolvedRunRoot) -notmatch '^release-preservation-[a-f0-9]{32}$') {
            throw "Unsafe release-preservation cleanup path: $resolvedRunRoot"
        }
        $items = @((Get-Item -LiteralPath $runRoot -Force)) + @(Get-ChildItem -LiteralPath $runRoot -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw "Refusing test cleanup through a reparse point: $runRoot" }
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop
    }
}
