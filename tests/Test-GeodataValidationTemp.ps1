[CmdletBinding()]
param([string]$TestRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
if ([string]::IsNullOrWhiteSpace($TestRoot)) { $TestRoot = [IO.Path]::GetTempPath() }
$fixtureParent = [IO.Path]::GetFullPath($TestRoot).TrimEnd([char[]]'\/')
if (-not [IO.Directory]::Exists($fixtureParent)) { throw "Test parent directory is missing: $fixtureParent" }
$cursor = $fixtureParent
while ($cursor) {
    try { $attributes = [IO.File]::GetAttributes($cursor) }
    catch { throw "Cannot inspect test parent path: $cursor`n$($_.Exception.Message)" }
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Unsafe test parent path: $cursor"
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
    $cursor = $parent
}
$fixtureRoot = Join-Path $fixtureParent ('geo-validation-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$link = $null
try {
    . (Join-Path $scriptsRoot 'Update-RoutingRules.ps1') -DefinitionsOnly

    $cacheRoot = Join-Path $fixtureRoot 'cache'
    [IO.Directory]::CreateDirectory($cacheRoot) | Out-Null
    $sourcePath = Join-Path $cacheRoot 'geosite.dat'
    [IO.File]::WriteAllBytes($sourcePath, [byte[]]@(1, 2, 3, 4))

    $script:capturedValidationRoot = $null
    function Get-GeodataCache {
        param(
            [Parameter(Mandatory)]$Resource,
            [Parameter(Mandatory)][string]$ResourcePath,
            [Parameter(Mandatory)][string[]]$Selectors,
            [Parameter(Mandatory)][string]$CacheRoot
        )
        $script:capturedValidationRoot = [IO.Path]::GetFullPath($CacheRoot)
        $categories = [ordered]@{ fixture = @([pscustomobject]@{ domain = @('fixture.example') }) }
        return [pscustomobject]@{ categories = [pscustomobject]$categories }
    }

    $resource = [pscustomobject]@{ tag='fixture-geosite'; format='geosite-dat' }
    Assert-RemoteSource -Resource $resource -Path $sourcePath -Selectors @('fixture')
    if ([string]::IsNullOrWhiteSpace($script:capturedValidationRoot)) { throw 'GeoData validation did not receive a dedicated cache root.' }
    $capturedParent = [IO.Path]::GetDirectoryName($script:capturedValidationRoot).TrimEnd([char[]]'\/')
    if ($capturedParent -ine [IO.Path]::GetFullPath($cacheRoot).TrimEnd([char[]]'\/') -or
        [IO.Path]::GetFileName($script:capturedValidationRoot) -notmatch '^\.source-validation-[0-9a-f]{32}$') {
        throw "GeoData validation root was not a private child of the source cache: $($script:capturedValidationRoot)"
    }
    if ([IO.Directory]::Exists($script:capturedValidationRoot) -or [IO.File]::Exists($script:capturedValidationRoot)) {
        throw 'GeoData validation directory was not removed after successful validation.'
    }

    $guardRoot = New-RoutingSourceValidationDirectory -CacheRoot $cacheRoot
    $target = Join-Path $fixtureRoot 'reparse-target'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    $sentinel = Join-Path $target 'sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve-target')
    $link = Join-Path $guardRoot 'linked-child'
    New-Item -ItemType Junction -Path $link -Target $target | Out-Null
    $rejected = $false
    try { Remove-RoutingSourceValidationDirectory -Path $guardRoot -CacheRoot $cacheRoot }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'GeoData validation cleanup accepted a reparse point in its owned tree.' }
    if ([IO.File]::ReadAllText($sentinel) -cne 'preserve-target') { throw 'Reparse-point cleanup changed its target.' }
    [IO.Directory]::Delete($link, $false)
    $link = $null
    Remove-RoutingSourceValidationDirectory -Path $guardRoot -CacheRoot $cacheRoot
    if ([IO.Directory]::Exists($guardRoot)) { throw 'Safe GeoData validation cleanup left its owned directory.' }

    Write-Output 'GeoData validation temp fixtures passed: project-local source-cache child, successful cleanup, reparse rejection, and target preservation.'
}
finally {
    if ($link -and [IO.Directory]::Exists($link)) {
        $linkItem = Get-Item -LiteralPath $link -Force
        if (($linkItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw "Refusing to remove a non-reparse test object: $link" }
        [IO.Directory]::Delete($link, $false)
    }
    $items = @((Get-Item -LiteralPath $fixtureRoot -Force)) + @(Get-ChildItem -LiteralPath $fixtureRoot -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
        throw "Test fixture contains a reparse point; preserve it: $fixtureRoot"
    }
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction Stop
}
