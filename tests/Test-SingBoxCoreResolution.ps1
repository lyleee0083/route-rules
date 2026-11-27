[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $projectRoot 'scripts/Json-Validation.ps1')
. (Join-Path $projectRoot 'scripts/Core-Assets.ps1')
. (Join-Path $projectRoot 'scripts/SingBox-Checker.ps1')

$asset=Get-SingBoxBuildAsset
$expected=Join-Path $projectRoot ('openwrt/build-stage/cores/'+$asset.Name)
if ((Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot) -cne $expected) { throw 'Wrong build checker selected.' }

$fixtureParent=Assert-ClientPlainPathTree -Path $TestRoot -LeafType Directory
$allowedParent=Join-Path $projectRoot 'outputs'
if (-not $fixtureParent.StartsWith($allowedParent+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal)) {
    throw 'Checker fixtures must be under project outputs/.'
}
$fixture=Join-Path $fixtureParent ('checker-'+[Guid]::NewGuid().ToString('N'))
$null=Assert-ClientPlainPathTree -Path $fixture -LeafType Directory
[void][IO.Directory]::CreateDirectory((Join-Path $fixture 'scripts'))
Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts/Core-Assets.ps1') -Destination (Join-Path $fixture 'scripts')
$link=$null
try {
    if ($null -ne (Resolve-PinnedSingBoxChecker -ProjectRoot $fixture)) { throw 'Missing build checker selected a fallback.' }
    $fixtureCore=Join-Path $fixture ('openwrt/build-stage/cores/'+$asset.Name)
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fixtureCore))
    [IO.File]::WriteAllBytes($fixtureCore,[byte[]](1,2,3))
    if ((Resolve-PinnedSingBoxChecker -ProjectRoot $fixture -RequestedPath $expected) -cne $expected) { throw 'Explicit checker path was ignored.' }
    $corruptRejected=$false
    try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $fixture }
    catch { $corruptRejected=$_.Exception.Message -match 'digest or length mismatch' }
    if (-not $corruptRejected) { throw 'Corrupt checker accepted.' }
    [IO.File]::Delete($fixtureCore)
    $link=$fixtureCore
    New-Item -ItemType SymbolicLink -Path $link -Target $expected -ErrorAction Stop | Out-Null
    $linkRejected=$false
    try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $fixture }
    catch { $linkRejected=$_.Exception.Message -match 'reparse point' }
    if (-not $linkRejected) { throw 'Linked checker accepted.' }
    Write-Output 'Pinned ARM64 build checker selection, digest and symlink tests passed.'
} finally {
    if ($link -and (Test-Path -LiteralPath $link)) {
        if (-not ((Get-Item -LiteralPath $link -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Fixture link changed type.' }
        [IO.File]::Delete($link)
    }
    $safe=Assert-ClientPlainPathTree -Path $fixture -LeafType Directory -Required -IncludeDescendants
    if ($safe -cne $fixture) { throw 'Unexpected fixture path.' }
    Remove-Item -LiteralPath $safe -Recurse -Force -ErrorAction Stop
}
