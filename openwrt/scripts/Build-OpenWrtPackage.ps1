[CmdletBinding()]
param(
    [string]$LinuxArchivePath,
    [string]$SourceRoot,
    [string]$OutputDirectory,
    [string]$BuildSupportDirectory,
    [string]$BinaryPath,
    [string]$MosdnsBinaryPath,
    [string]$MosdnsCheckPath,
    [string]$GoPath,
    [string]$SingBoxPath,
    [switch]$ConnectionVerdictCache,
    [switch]$DisableAdapterCache,
    [switch]$Force,
    [ValidateRange(1,600)][int]$LockTimeoutSeconds=30
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $openWrtRoot
$sharedScriptsRoot = Join-Path $projectRoot 'scripts'
$sourceTreeRoot = Join-Path $openWrtRoot 'src'
$buildStageRoot = Join-Path $openWrtRoot 'build-stage'
$nativeSource = Join-Path $sourceTreeRoot 'native'
$connectionCacheMode='off-v1'
if ($ConnectionVerdictCache) { $connectionCacheMode='ctmark-v1' }
if (-not $LinuxArchivePath) { $LinuxArchivePath=Join-Path (Join-Path $projectRoot 'generated') 'sing-box-configs.zip' }
if (-not $SourceRoot) { $SourceRoot=Join-Path (Join-Path $openWrtRoot 'inputs') 'linux' }
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $openWrtRoot 'generated' }
. (Join-Path $sharedScriptsRoot 'Official-Cores.ps1')
$officialPaths=Get-OpenWrtCorePaths
if (-not $BinaryPath) { $BinaryPath=$officialPaths['sing-box-arm64'] }
if (-not $MosdnsBinaryPath) { $MosdnsBinaryPath=$officialPaths['mosdns-arm64'] }
if (-not $MosdnsCheckPath) { $MosdnsCheckPath=$officialPaths['mosdns-check'] }
if (-not $SingBoxPath) { $SingBoxPath=$officialPaths['sing-box-check'] }
if (-not $GoPath) { $GoPath=Join-Path $buildStageRoot 'tools/go1.27.1/go/bin/go.exe' }
foreach ($path in @($BinaryPath,$MosdnsBinaryPath,$MosdnsCheckPath,$GoPath,$SingBoxPath)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Missing build executable; prepare official assets with Official-Cores.ps1: '+$path) } }
if ((Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash -cne '709D6670C49019955E498872BC39B954461517AD8009968D1CF5592E9087B563') { throw 'Pinned official ARM64 sing-box mismatch.' }
if ((Get-FileHash -LiteralPath $MosdnsBinaryPath -Algorithm SHA256).Hash -cne '5E651992DBEC784DF43E0E483428319B0F2892F5FADFD4E39A1462A5D62CB495') { throw 'Pinned official ARM64 mosdns mismatch.' }
Assert-OpenWrtOfficialCheckTools -SingBoxPath $SingBoxPath -MosdnsPath $MosdnsCheckPath
. (Join-Path $PSScriptRoot 'Final-LinuxSnapshot.ps1')
. (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1')
. (Join-Path $PSScriptRoot 'OpenWrt-AdapterCache.ps1')
. (Join-Path $PSScriptRoot 'Nft-KernelPolicy.ps1')
. (Join-Path $PSScriptRoot 'Native-NumericPolicy.ps1')
. (Join-Path $PSScriptRoot 'Native-PackageValidation.ps1')
. (Join-Path $PSScriptRoot 'Mosdns-Policy.ps1')
$BuildSupportDirectory=Get-OpenWrtBuildSupportDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory
$BuildCacheDirectory=Get-OpenWrtAdapterCacheDirectory -BuildSupportDirectory $BuildSupportDirectory
$controllerSource=Join-Path $sourceTreeRoot 'controller'
$runtimePaths=@($BinaryPath,$MosdnsBinaryPath,$MosdnsCheckPath,$GoPath)
$protectedSourcePaths=@(
    $PSScriptRoot,$sharedScriptsRoot,$sourceTreeRoot,$buildStageRoot,
    (Join-Path $projectRoot 'scripts'),(Join-Path $projectRoot 'src'),(Join-Path $projectRoot 'config'),
    (Join-Path $projectRoot 'tests'),(Join-Path $projectRoot 'docs'),(Join-Path $projectRoot 'routing'),
    (Join-Path $projectRoot 'generated'),(Join-Path $projectRoot 'backups'),(Join-Path $openWrtRoot 'tests'),(Join-Path $openWrtRoot 'inputs'),
    (Join-Path $openWrtRoot 'docs'),(Join-Path $openWrtRoot 'diagnostics'),(Join-Path $openWrtRoot 'backups'),
    (Join-Path (Join-Path $openWrtRoot 'outputs') 'build-scratch')
)
$formalPackageDirectory=Join-Path $openWrtRoot 'generated'
Assert-OpenWrtBuildTargets -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
Assert-OpenWrtBuildTargets -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $controllerSource -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
$cachePaths=Assert-OpenWrtAdapterCacheTarget -CacheDirectory $BuildCacheDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
$cachePaths=Assert-OpenWrtAdapterCacheTarget -CacheDirectory $BuildCacheDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $controllerSource -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
$paths=Get-BuildPaths $OutputDirectory
$manifestPath=Get-OpenWrtBuildManifestPath -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory
$supportPaths=Get-BuildPaths (Split-Path -Parent $manifestPath)
$coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $paths
$context=$null; $outputLocks=$null; $payload=Join-Path $paths.Stage '.payload'; $packagePreservationSnapshot=$null
$encoding=New-Object Text.UTF8Encoding($false)
try {
    $context=Enter-OpenWrtInputLocks -ArchivePath $LinuxArchivePath -SourceRoot $SourceRoot -TimeoutSeconds $LockTimeoutSeconds
    Assert-FinalLinuxSnapshot -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath
    $outputLocks=Enter-OpenWrtArtifactLocks -PackagePaths $paths -SupportPaths $supportPaths -CachePaths $cachePaths -TimeoutSeconds $LockTimeoutSeconds
    Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
    Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
    $packagePreservationSnapshot=Get-BuildPreservationSnapshot -Destination $paths.Destination -PackageName 'openwrt.zip'
    $cachePaths=Assert-OpenWrtAdapterCacheTarget -CacheDirectory $BuildCacheDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
    $cachePaths=Assert-OpenWrtAdapterCacheTarget -CacheDirectory $BuildCacheDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory -SourceRoot $controllerSource -ArchivePath $LinuxArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $runtimePaths -ProtectedPaths $protectedSourcePaths -FormalPackageDirectory $formalPackageDirectory
    $packageExists=[IO.Directory]::Exists($paths.Destination)
    $supportExists=[IO.Directory]::Exists($supportPaths.Destination)
    if ($packageExists) { Assert-OpenWrtPackageOutputDirectory -Path $paths.Destination }
    if ($supportExists) { Assert-OpenWrtDirectoryContainsOnly -Path $supportPaths.Destination -Name 'build-manifest.json' }
    if (($packageExists -or $supportExists) -and -not $Force) { throw 'OpenWrt package or support output exists; use -Force.' }
    New-Item -ItemType Directory -Path $paths.Stage -Force | Out-Null
    New-Item -ItemType Directory -Path $supportPaths.Stage -Force | Out-Null
    New-Item -ItemType Directory -Path $payload -Force | Out-Null
    $config=ConvertTo-OpenWrtProxyConfiguration (Read-StrictJsonFile -Path (Join-Path $SourceRoot 'sing-box-openwrt.json'))
    [IO.File]::WriteAllText((Join-Path $payload 'config.json'),(Format-JsonText -Text ($config | ConvertTo-Json -Depth 100 -Compress))+"`n",$encoding)
    $adapterBuild=Build-OpenWrtAdapterOutputs -SourceRoot $SourceRoot -OutputDirectory $payload -SingBoxPath $SingBoxPath -CacheDirectory $BuildCacheDirectory -ConnectionCacheMode $connectionCacheMode -DisableCache:$DisableAdapterCache
    $numeric=$adapterBuild.Numeric
    $dnsPolicy=$adapterBuild.DnsPolicy
    Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $payload 'sing-box')
    Copy-Item -LiteralPath $MosdnsBinaryPath -Destination (Join-Path $payload 'mosdns')
    [IO.File]::WriteAllText((Join-Path $payload 'connection-cache.mode'),$connectionCacheMode+"`n",$encoding)
    foreach ($name in @('forwarding.nft','tun-input.nft','sing-box-service.sh','sing-box.init','install.sh','activate.sh','rollback.sh')) {
        $text=[IO.File]::ReadAllText((Join-Path $nativeSource $name)).Replace("`r`n","`n").TrimEnd([char]10)+"`n"
        [IO.File]::WriteAllText((Join-Path $payload $name),$text,$encoding)
    }
    $oldEnv=@{}
    foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN')) { $oldEnv[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
    Push-Location -LiteralPath $controllerSource
    try {
        $hostPlatform=@(& $GoPath env GOHOSTOS GOHOSTARCH)
        if ($LASTEXITCODE -ne 0 -or $hostPlatform.Count -ne 2) { throw 'Cannot locate Go host platform.' }
        [Environment]::SetEnvironmentVariable('GOOS',[string]$hostPlatform[0],'Process'); [Environment]::SetEnvironmentVariable('GOARCH',[string]$hostPlatform[1],'Process')
        [Environment]::SetEnvironmentVariable('CGO_ENABLED','0','Process'); [Environment]::SetEnvironmentVariable('GOTOOLCHAIN','local','Process')
        & $GoPath test .
        if ($LASTEXITCODE -ne 0) { throw 'Controller regression failed; publication refused.' }
        [Environment]::SetEnvironmentVariable('GOOS','linux','Process'); [Environment]::SetEnvironmentVariable('GOARCH','arm64','Process')
        [Environment]::SetEnvironmentVariable('CGO_ENABLED','0','Process'); [Environment]::SetEnvironmentVariable('GOTOOLCHAIN','local','Process')
        & $GoPath build -trimpath -ldflags '-s -w' -o (Join-Path $payload 'sb-controller') .
        if ($LASTEXITCODE -ne 0) { throw 'ARM64 controller build failed.' }
    } finally {
        Pop-Location
        foreach ($name in $oldEnv.Keys) { [Environment]::SetEnvironmentVariable($name,$oldEnv[$name],'Process') }
    }
    $names=[string[]]@(Get-ChildItem -LiteralPath $payload -File | ForEach-Object Name); [Array]::Sort($names,[StringComparer]::Ordinal)
    $sums=@($names | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $payload $_) -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_ })
    [IO.File]::WriteAllText((Join-Path $payload 'SHA256SUMS'),($sums -join "`n")+"`n",$encoding)
    $temporaryZip=Join-Path $payload 'package.tmp'
    $zip=[IO.Compression.ZipFile]::Open($temporaryZip,[IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in @('SHA256SUMS')+$names) { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $payload $name),$name,[IO.Compression.CompressionLevel]::Optimal) }
    } finally { $zip.Dispose() }
    Assert-NativePackageArchive -ZipPath $temporaryZip -PayloadDirectory $payload -SingBoxPath $SingBoxPath -ExpectedConnectionCacheMode $connectionCacheMode
    Assert-MosdnsRuntimeConfiguration -PayloadDirectory $payload -MosdnsPath $MosdnsCheckPath
    Assert-FinalLinuxSnapshot -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath
    # Persist archive-relative paths, not the transaction directory deleted below.
    $dnsPolicy.paths.dns_direct_domains='dns-direct-domains.txt'
    $dnsPolicy.paths.mosdns_yaml='mosdns.yaml'
    $manifest=[ordered]@{
        generated_at_utc=[DateTime]::UtcNow.ToString('o');status='local-package-not-deployed';backend='nftables-mosdns';core_version='1.14.4';mosdns_version='5.3.4'
        core_sha256=(Get-FileHash -LiteralPath $BinaryPath -Algorithm SHA256).Hash
        mosdns_sha256=(Get-FileHash -LiteralPath $MosdnsBinaryPath -Algorithm SHA256).Hash
        official_assets=@(Get-OpenWrtOfficialAssets | Select-Object Name,Repository,Tag,SHA256)
        linux_archive_sha256=(Get-FileHash -LiteralPath $LinuxArchivePath -Algorithm SHA256).Hash
        linux_config_sha256=(Get-FileHash -LiteralPath (Join-Path $SourceRoot 'sing-box-openwrt.json') -Algorithm SHA256).Hash
        controller_sha256=(Get-FileHash -LiteralPath (Join-Path $payload 'sb-controller') -Algorithm SHA256).Hash
        package_sha256=(Get-FileHash -LiteralPath $temporaryZip -Algorithm SHA256).Hash
        package_file='openwrt.zip'
        package_entries=($names.Count+1);numeric_policy=$numeric;dns_policy=$dnsPolicy
         connection_cache=[ordered]@{mode=$connectionCacheMode;fastpath_enabled=($connectionCacheMode -ceq 'ctmark-v1');boot_bound_receipt=$true}
        adapter_cache=[ordered]@{status=$adapterBuild.CacheStatus;reason=$adapterBuild.CacheReason;fingerprint=$adapterBuild.Fingerprint}
        ownership=[ordered]@{nft_table='inet sb_proxy';firewall_include='firewall.sb_proxy_forward';firewall_input_include='firewall.sb_proxy_input';mark_mask='0x60000000';route_tables=@(10073,10074);dns_options=@('server','noresolv')}
        deferred=[ordered]@{multi_queue='requires a released stable core with the field';new_tun_stack='requires a released stable core with the stack';auto_redirect='stable support exists; replacement requires target kernel, port/IP bypass, fw4 mark/order and acceleration validation';native_nft_check='requires separately authorized target-device validation';device_acceptance='not executed; requires separate authorization'}
    }
    [IO.File]::WriteAllText((Join-Path $supportPaths.Stage 'build-manifest.json'),(Format-JsonText -Text ($manifest | ConvertTo-Json -Depth 100 -Compress))+"`n",$encoding)
    Move-Item -LiteralPath $temporaryZip -Destination (Join-Path $paths.Stage 'openwrt.zip')
    Remove-OpenWrtPayload -Path $payload -ExpectedPath (Join-Path $paths.Stage '.payload')
    Copy-BuildPreservedDirectoriesToStage -Snapshot $packagePreservationSnapshot -StageDirectory $paths.Stage
    Assert-OpenWrtPackageOutputDirectory -Path $paths.Stage -RequirePackage
    Assert-BuildPreservationSnapshot -Directory $paths.Stage -Snapshot $packagePreservationSnapshot -ExpectedRoot $paths.Stage
    Publish-OpenWrtBuildArtifacts -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath -PackagePreservationSnapshot $packagePreservationSnapshot
    Write-Output ('OpenWrt + mosdns local package: '+(Join-Path $paths.Destination 'openwrt.zip'))
    Write-Output ('Build manifest: '+$manifestPath)
    Write-Output ('SHA256: '+$manifest.package_sha256)
    Write-Output ('Numeric policy: '+$numeric.numeric_predicates+' predicates, '+$numeric.cidrs+' CIDRs; no deployment or target-kernel acceptance.')
} finally {
    try {
        if ($outputLocks -and -not (Test-Path -LiteralPath $coordinatorPath) -and -not (Test-Path -LiteralPath $paths.Journal) -and -not (Test-Path -LiteralPath $supportPaths.Journal)) {
            Remove-OpenWrtPayload -Path $payload -ExpectedPath (Join-Path $paths.Stage '.payload')
            Remove-BuildDirectory $paths $paths.Stage
            Remove-BuildDirectory $supportPaths $supportPaths.Stage
        }
    } finally { Exit-OpenWrtArtifactLocks $outputLocks; Exit-OpenWrtInputLocks $context }
}
