function Resolve-PinnedSingBoxChecker {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[string]$RequestedPath)

    . (Join-Path $PSScriptRoot 'Json-Validation.ps1')
    if ($RequestedPath) {
        return (Assert-ClientPlainPathTree -Path $RequestedPath -LeafType File -Required)
    }

    . (Join-Path $ProjectRoot 'scripts/Core-Assets.ps1')
    $asset = Get-SingBoxBuildAsset
    $path = Join-Path (Join-Path $ProjectRoot 'openwrt/build-stage/cores') $asset.Name
    $path = Assert-ClientPlainPathTree -Path $path -LeafType File
    if (-not [IO.File]::Exists($path)) { return $null }
    Assert-BuildCoreAsset -Asset $asset -Path $path
    return $path
}
