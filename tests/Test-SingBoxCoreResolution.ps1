[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$helper=Join-Path $projectRoot 'scripts\Official-SingBoxChecker.ps1'
. (Join-Path $projectRoot 'scripts\Official-Cores.ps1')
. $helper

function Assert-TestCondition {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-TestNoReparse {
    param([string]$Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse point in test path: '+$cursor) }
        }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor=$parent
    }
}

$projectFull=[IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$fixtureParent=[IO.Path]::GetFullPath($TestRoot).TrimEnd('\')
$allowed=$false
foreach ($allowedName in @('work','outputs')) {
    $allowedPath=[IO.Path]::GetFullPath((Join-Path $projectFull $allowedName)).TrimEnd('\')
    if ($fixtureParent.StartsWith($allowedPath+'\',[StringComparison]::OrdinalIgnoreCase)) { $allowed=$true }
}
if (-not $allowed) { throw 'TestRoot must be a child of project work/ or outputs/.' }
Assert-TestNoReparse -Path $fixtureParent
[IO.Directory]::CreateDirectory($fixtureParent) | Out-Null
$runRoot=Join-Path $fixtureParent ([Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($runRoot) | Out-Null

try {
    $coreRoot=Join-Path $projectRoot 'openwrt\build-stage\cores'
    $corePaths=Get-OpenWrtCorePaths -Root $coreRoot
    $checkerAsset=@(Get-OpenWrtOfficialAssets | Where-Object { $_.Platform -ceq 'sing-box-check' })
    Assert-TestCondition ($checkerAsset.Count -eq 1) 'The current checker pin must be unique.'
    $expected=[IO.Path]::GetFullPath([string]$corePaths['sing-box-check'])
    $default=Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot
    Assert-TestCondition ($default -ceq $expected) 'The default checker must resolve to the project-pinned checker.'
    Assert-TestCondition ((Get-FileHash -LiteralPath $default -Algorithm SHA256).Hash -ceq [string]$checkerAsset[0].BinarySHA256) 'The default project checker hash must match its pin.'

    $explicit=Join-Path $runRoot 'explicit-marker.exe'
    $fallback=Join-Path $runRoot 'fallback-marker.exe'
    [IO.File]::WriteAllBytes($explicit,[byte[]](1,2,3,4))
    [IO.File]::WriteAllBytes($fallback,[byte[]](5,6,7,8))
    $selected=Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RequestedPath $explicit -RuntimeFallbackPath $fallback
    Assert-TestCondition ($selected -ceq [IO.Path]::GetFullPath($explicit)) 'An explicit checker path must take priority over the project pin and fallback.'

    $emptyProject=Join-Path $runRoot 'no-project-core'
    [IO.Directory]::CreateDirectory((Join-Path $emptyProject 'scripts')) | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $emptyProject 'scripts\Official-Cores.ps1')
    $fallbackSelected=Resolve-PinnedSingBoxChecker -ProjectRoot $emptyProject -RuntimeFallbackPath $fallback
    Assert-TestCondition ($fallbackSelected -ceq [IO.Path]::GetFullPath($fallback)) 'With no fixed project assets, the compatibility fallback must remain available.'

    $badProject=Join-Path $runRoot 'bad-project-core'
    $badScript=Join-Path $badProject 'scripts'
    $badCores=Join-Path $badProject 'openwrt\build-stage\cores'
    $badPlatform=Join-Path $badCores 'sing-box-check'
    $versionRoot=Join-Path $badPlatform ([IO.Path]::GetFileName((Split-Path -Parent ([string]$corePaths['sing-box-check']))))
    [IO.Directory]::CreateDirectory($badScript) | Out-Null
    [IO.Directory]::CreateDirectory($versionRoot) | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $badScript 'Official-Cores.ps1')
    [IO.File]::WriteAllBytes((Join-Path $badCores ([string]$checkerAsset[0].Name)),[byte[]](9,8,7,6))
    [IO.File]::WriteAllBytes((Join-Path $versionRoot 'sing-box.exe'),[byte[]](1,1,1,1))
    $badPinRejected=$false
    try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $badProject -RuntimeFallbackPath $fallback }
    catch { $badPinRejected=$true }
    Assert-TestCondition $badPinRejected 'A stale or corrupt project pin must fail instead of silently falling back.'

    $missingProject=Join-Path $runRoot 'missing-project-core'
    $missingScripts=Join-Path $missingProject 'scripts'
    $missingVersion=Join-Path (Join-Path $missingProject 'openwrt\build-stage\cores\sing-box-check') 'sing-box-1.14.3-windows-amd64'
    [IO.Directory]::CreateDirectory($missingScripts) | Out-Null
    [IO.Directory]::CreateDirectory($missingVersion) | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $missingScripts 'Official-Cores.ps1')
    $missingPinRejected=$false
    try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $missingProject -RuntimeFallbackPath $fallback }
    catch { $missingPinRejected=$true }
    Assert-TestCondition $missingPinRejected 'A stale version tree missing the current pin must fail instead of falling back.'

    $badBinaryProject=Join-Path $runRoot 'bad-binary-project'
    $badBinaryScripts=Join-Path $badBinaryProject 'scripts'
    $badBinaryCores=Join-Path $badBinaryProject 'openwrt\build-stage\cores'
    $badBinaryPlatform=Join-Path $badBinaryCores ([string]$checkerAsset[0].Platform)
    $badBinaryVersion=Join-Path $badBinaryPlatform ([IO.Path]::GetFileName((Split-Path -Parent $expected)))
    [IO.Directory]::CreateDirectory($badBinaryScripts) | Out-Null
    [IO.Directory]::CreateDirectory($badBinaryVersion) | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $badBinaryScripts 'Official-Cores.ps1')
    $pinnedArchive=Join-Path $coreRoot ([string]$checkerAsset[0].Name)
    Copy-Item -LiteralPath $pinnedArchive -Destination (Join-Path $badBinaryCores ([string]$checkerAsset[0].Name))
    [IO.File]::WriteAllBytes((Join-Path $badBinaryVersion 'sing-box.exe'),[byte[]](2,4,6,8))
    $badBinaryRejected=$false
    try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $badBinaryProject -RuntimeFallbackPath $fallback }
    catch { $badBinaryRejected=$_.Exception.Message -match 'checker binary is corrupt' }
    Assert-TestCondition $badBinaryRejected 'A current archive with an independently corrupted checker binary must fail instead of falling back.'

    $linkedVersionProject=Join-Path $runRoot 'linked-version-project'
    $linkedVersionScripts=Join-Path $linkedVersionProject 'scripts'
    $linkedVersionCores=Join-Path $linkedVersionProject 'openwrt\build-stage\cores'
    $linkedVersionPlatform=Join-Path $linkedVersionCores ([string]$checkerAsset[0].Platform)
    $linkedVersionName=[IO.Path]::GetFileName((Split-Path -Parent $expected))
    $linkedVersionPath=Join-Path $linkedVersionPlatform $linkedVersionName
    $linkedVersionTarget=Split-Path -Parent $expected
    [IO.Directory]::CreateDirectory($linkedVersionScripts) | Out-Null
    [IO.Directory]::CreateDirectory($linkedVersionPlatform) | Out-Null
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $linkedVersionScripts 'Official-Cores.ps1')
    Copy-Item -LiteralPath (Join-Path $coreRoot ([string]$checkerAsset[0].Name)) -Destination (Join-Path $linkedVersionCores ([string]$checkerAsset[0].Name))
    $linkedTargetBinaryHash=(Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash
    New-Item -ItemType Junction -Path $linkedVersionPath -Target $linkedVersionTarget -ErrorAction Stop | Out-Null
    try {
        $linkedVersionRejected=$false
        try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $linkedVersionProject -RuntimeFallbackPath $fallback }
        catch { $linkedVersionRejected=$_.Exception.Message -match 'reparse point' }
        Assert-TestCondition $linkedVersionRejected 'A reparse point at the pinned platform version directory must be rejected.'
        Assert-TestCondition ((Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash -ceq $linkedTargetBinaryHash) 'Rejecting a linked version directory must leave its target binary unchanged.'
    }
    finally {
        if ([IO.Directory]::Exists($linkedVersionPath)) { [IO.Directory]::Delete($linkedVersionPath, $false) }
    }

    foreach ($kind in @('core-root-file','platform-file','archive-directory')) {
        $typeProject=Join-Path $runRoot ('type-'+$kind)
        $typeScripts=Join-Path $typeProject 'scripts'
        $typeCores=Join-Path $typeProject 'openwrt\build-stage\cores'
        [IO.Directory]::CreateDirectory($typeScripts) | Out-Null
        Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination (Join-Path $typeScripts 'Official-Cores.ps1')
        if ($kind -ceq 'core-root-file') {
            [IO.Directory]::CreateDirectory((Split-Path -Parent $typeCores)) | Out-Null
            [IO.File]::WriteAllText($typeCores,'wrong path kind')
        }
        else {
            [IO.Directory]::CreateDirectory($typeCores) | Out-Null
            if ($kind -ceq 'platform-file') { [IO.File]::WriteAllText((Join-Path $typeCores ([string]$checkerAsset[0].Platform)),'wrong path kind') }
            else { [IO.Directory]::CreateDirectory((Join-Path $typeCores ([string]$checkerAsset[0].Name))) | Out-Null }
        }
        $typeRejected=$false
        try { $null=Resolve-PinnedSingBoxChecker -ProjectRoot $typeProject -RuntimeFallbackPath $fallback }
        catch { $typeRejected=$true }
        Assert-TestCondition $typeRejected ('A project path type conflict must not fall back: '+$kind)
    }

    Write-Output ('SING_BOX_CORE_RESOLUTION_TESTS=PASS')
    Write-Output ('PINNED_DEFAULT='+$expected)
    Write-Output ('FIXTURE_ROOT='+$runRoot)
}
finally {
    if ([IO.Directory]::Exists($runRoot)) {
        $items=@(Get-ChildItem -LiteralPath $runRoot -Force -Recurse -ErrorAction Stop)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'Refusing to clean a fixture containing reparse points.' }
        Remove-Item -LiteralPath $runRoot -Recurse -Force
    }
}
