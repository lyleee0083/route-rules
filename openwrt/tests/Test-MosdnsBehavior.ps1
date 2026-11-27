[CmdletBinding()]
param([string]$PackagePath,[string]$MosdnsPath,[string]$GoPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
if (-not $PackagePath) { $PackagePath=Join-Path $openWrtRoot 'generated/openwrt.zip' }
if (-not $MosdnsPath) { $MosdnsPath=(Get-OpenWrtCorePaths)['mosdns-check'] }
if (-not $GoPath) { $GoPath=Join-Path $openWrtRoot 'build-stage/tools/go1.27.1/go/bin/go.exe' }
foreach ($path in @($PackagePath,$MosdnsPath,$GoPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Missing isolated DNS test input: '+$path) }
}
$mosdnsAsset = Get-OpenWrtOfficialAssets | Where-Object Platform -CEQ 'mosdns-check'
if ((Get-FileHash -LiteralPath $MosdnsPath -Algorithm SHA256).Hash -cne $mosdnsAsset.BinarySHA256) { throw 'Untrusted official mosdns test binary.' }
$names=@('MOSDNS_PACKAGE_ZIP','MOSDNS_CHECK_EXE','GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN')
$old=@{}
foreach ($name in $names) { $old[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location -LiteralPath (Join-Path $PSScriptRoot 'mosdns')
try {
    [Environment]::SetEnvironmentVariable('MOSDNS_PACKAGE_ZIP',[IO.Path]::GetFullPath($PackagePath),'Process')
    [Environment]::SetEnvironmentVariable('MOSDNS_CHECK_EXE',[IO.Path]::GetFullPath($MosdnsPath),'Process')
    $hostPlatform=@(& $GoPath env GOHOSTOS GOHOSTARCH)
    if ($LASTEXITCODE -ne 0 -or $hostPlatform.Count -ne 2) { throw 'Cannot determine Go host platform.' }
    [Environment]::SetEnvironmentVariable('GOOS',[string]$hostPlatform[0],'Process')
    [Environment]::SetEnvironmentVariable('GOARCH',[string]$hostPlatform[1],'Process')
    [Environment]::SetEnvironmentVariable('CGO_ENABLED','0','Process')
    [Environment]::SetEnvironmentVariable('GOTOOLCHAIN','local','Process')
    & $GoPath test -count=1 -timeout 45s -v .
    if ($LASTEXITCODE -ne 0) { throw 'Official mosdns loopback policy behavior failed.' }
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$old[$name],'Process') }
}
