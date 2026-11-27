function Get-ExistingPinnedCheckerPathItem {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidateSet('File','Directory')][string]$ExpectedType)
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse point in pinned checker path: '+$Path) }
        if ($ExpectedType -ceq 'File' -and $item.PSIsContainer) { throw ('Pinned checker file path is a directory: '+$Path) }
        if ($ExpectedType -ceq 'Directory' -and -not $item.PSIsContainer) { throw ('Pinned checker directory path is a file: '+$Path) }
    }
    return $item
}

function Assert-PinnedCheckerParentDirectories {
    param([Parameter(Mandatory)][string]$Path)
    $null = Assert-ClientPlainPathTree -Path $Path
}

function Resolve-PinnedSingBoxChecker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [string]$RequestedPath,
        [string]$RuntimeFallbackPath='D:\Software\sing-box\sing-box.exe'
    )

    if ($RequestedPath) {
        if (-not [IO.File]::Exists($RequestedPath)) { throw "找不到 sing-box 可执行文件：$RequestedPath" }
        return (Resolve-Path -LiteralPath $RequestedPath).Path
    }

    . (Join-Path $PSScriptRoot 'Json-Validation.ps1')
    $projectRootFull=[IO.Path]::GetFullPath($ProjectRoot)
    $officialScript=Join-Path $projectRootFull 'scripts\Official-Cores.ps1'
    if (-not [IO.File]::Exists($officialScript)) { throw ('Missing project official core pins: '+$officialScript) }
    . $officialScript

    $checkerAssets=@(Get-OpenWrtOfficialAssets | Where-Object { $_.Platform -ceq 'sing-box-check' })
    if ($checkerAssets.Count -ne 1) { throw 'The project must have exactly one pinned Windows sing-box checker asset.' }
    $asset=$checkerAssets[0]
    $coreRoot=Join-Path $projectRootFull 'openwrt\build-stage\cores'
    $paths=Get-OpenWrtCorePaths -Root $coreRoot
    $binary=[IO.Path]::GetFullPath([string]$paths['sing-box-check'])
    $archive=[IO.Path]::GetFullPath((Join-Path $coreRoot ([string]$asset.Name)))
    $platformRoot=[IO.Path]::GetFullPath((Join-Path $coreRoot ([string]$asset.Platform)))

    foreach ($path in @($coreRoot,$platformRoot,$archive,$binary)) { Assert-PinnedCheckerParentDirectories -Path $path }
    $coreRootItem=Get-ExistingPinnedCheckerPathItem -Path $coreRoot -ExpectedType 'Directory'
    $platformRootItem=Get-ExistingPinnedCheckerPathItem -Path $platformRoot -ExpectedType 'Directory'
    $archiveItem=Get-ExistingPinnedCheckerPathItem -Path $archive -ExpectedType 'File'
    $binaryItem=Get-ExistingPinnedCheckerPathItem -Path $binary -ExpectedType 'File'

    $hasPinnedProjectCore=($null -ne $platformRootItem) -or ($null -ne $archiveItem)
    if ($null -ne $coreRootItem) {
        $legacyEntries=@(Get-ChildItem -LiteralPath $coreRoot -Force -ErrorAction Stop | Where-Object { $_.Name -match '^sing-box-' })
        if ($legacyEntries.Count -gt 0) { $hasPinnedProjectCore=$true }
    }
    if (-not $hasPinnedProjectCore) {
        if ($RuntimeFallbackPath -and [IO.File]::Exists($RuntimeFallbackPath)) { return [IO.Path]::GetFullPath($RuntimeFallbackPath) }
        $command=Get-Command 'sing-box' -CommandType Application -ErrorAction SilentlyContinue
        if ($command) { return [IO.Path]::GetFullPath($command.Source) }
        return $null
    }

    if ($null -eq $archiveItem -or $null -eq $binaryItem) {
        throw ('The project pinned sing-box 1.14.4 checker installation is incomplete: '+$binary)
    }
    if ($archiveItem.Length -ne [long]$asset.Length -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne [string]$asset.SHA256) {
        throw ('The project pinned sing-box checker archive is corrupt: '+$archive)
    }
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne [string]$asset.BinarySHA256) {
        throw ('The project pinned sing-box checker binary is corrupt: '+$binary)
    }
    return $binary
}