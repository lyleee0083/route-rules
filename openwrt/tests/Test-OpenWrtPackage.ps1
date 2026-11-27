[CmdletBinding()]
param([string]$ZipPath,[string]$SingBoxPath,[string]$MosdnsCheckPath,[string]$SourceRoot,[string]$LinuxArchivePath,[ValidateSet('off-v1','ctmark-v1')][string]$ExpectedConnectionCacheMode,[switch]$LegacyRejections)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
$canonicalLinuxInputRoot=Join-Path $openWrtRoot 'inputs/linux'
$canonicalLinuxArchive=Join-Path (Split-Path -Parent $openWrtRoot) 'generated/sing-box-configs.zip'
if ([string]::IsNullOrWhiteSpace($SourceRoot) -xor [string]::IsNullOrWhiteSpace($LinuxArchivePath)) { throw 'SourceRoot and LinuxArchivePath must be supplied together for isolated source validation.' }
if ([string]::IsNullOrWhiteSpace($SourceRoot)) { $SourceRoot=$canonicalLinuxInputRoot; $LinuxArchivePath=$canonicalLinuxArchive }
if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container) -or -not (Test-Path -LiteralPath $LinuxArchivePath -PathType Leaf)) { throw 'Test source snapshot and final Linux archive must both exist.' }
$linuxInputRoot=[IO.Path]::GetFullPath($SourceRoot)
$nativeRoot=Join-Path $openWrtRoot 'src/native'
. (Join-Path $scriptsRoot 'Final-LinuxSnapshot.ps1')
. (Join-Path $scriptsRoot 'Native-NumericPolicy.ps1')
. (Join-Path $scriptsRoot 'Native-PackageValidation.ps1')
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
. (Join-Path $scriptsRoot 'Mosdns-Policy.ps1')
. (Join-Path $scriptsRoot 'Nft-KernelPolicy.ps1')
$corePaths=Get-OpenWrtCorePaths
if (-not $SingBoxPath) { $SingBoxPath=$corePaths['sing-box-check'] }
if (-not $MosdnsCheckPath) { $MosdnsCheckPath=$corePaths['mosdns-check'] }
Assert-OpenWrtOfficialCheckTools -SingBoxPath $SingBoxPath -MosdnsPath $MosdnsCheckPath
Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
if (-not $ZipPath) { $ZipPath=Join-Path $openWrtRoot 'generated/openwrt.zip' }
$verifiedLegacyFormalPackage = $false
$formalPackage = Join-Path $openWrtRoot 'generated/openwrt.zip'
if ($LegacyRejections -and [IO.Path]::GetFullPath($ZipPath) -ieq [IO.Path]::GetFullPath($formalPackage)) {
    $null = Read-OpenWrtBuildManifest -OutputDirectory (Split-Path -Parent $formalPackage)
    $verifiedLegacyFormalPackage = $true
}
$taskScratchRoot=Get-OpenWrtTaskScratchRoot
$formalSupportRoot=[IO.Path]::GetFullPath((Join-Path $openWrtRoot 'outputs/build'))
$pathComparison=[StringComparison]::OrdinalIgnoreCase
if (Test-OpenWrtPathOverlap -First $taskScratchRoot -Second $formalSupportRoot -Comparison $pathComparison) {
    throw 'OpenWrt validation scratch must remain outside the package publication support transaction tree.'
}
$source=Read-StrictJsonFile -Path (Join-Path $linuxInputRoot 'sing-box-openwrt.json')
Assert-FinalLinuxSnapshot -SourceRoot $linuxInputRoot -ArchivePath $LinuxArchivePath

function Test-MosdnsValidationCleanupRejectsReparseTree {
    $scratchRoot=Get-OpenWrtTaskScratchRoot
    $fixture=New-OpenWrtTaskScratchDirectory -Prefix 'sb-mosdns-reparse-fixture'
    $target=Join-Path $scratchRoot ('sb-mosdns-reparse-target-'+[guid]::NewGuid().ToString('N'))
    $link=Join-Path $fixture 'linked-target'
    $marker=Join-Path $target 'preserve.txt'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    [IO.File]::WriteAllText($marker,'outside fixture tree',(New-Object Text.UTF8Encoding($false)))
    try {
        $linkType = if ([IO.Path]::DirectorySeparatorChar -eq [char]'/') { 'SymbolicLink' } else { 'Junction' }
        New-Item -ItemType $linkType -Path $link -Target $target -ErrorAction Stop | Out-Null
        $rejected=$false
        try { Remove-OpenWrtTaskScratchDirectory -Path $fixture -Prefix 'sb-mosdns-reparse-fixture' }
        catch { $rejected=$_.Exception.Message -match 'reparse point' }
        if (-not $rejected) { throw 'MosDNS validation cleanup accepted a reparse point inside its scratch tree.' }
        if (-not [IO.File]::Exists($marker) -or [IO.File]::ReadAllText($marker) -cne 'outside fixture tree') {
            throw 'MosDNS validation cleanup followed a reparse point outside its scratch tree.'
        }
    } finally {
        if ([IO.Directory]::Exists($link) -or [IO.File]::Exists($link)) {
            $linkItem=Get-Item -LiteralPath $link -Force -ErrorAction Stop
            if (-not ($linkItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected non-link at MosDNS cleanup guard fixture.' }
            [IO.Directory]::Delete($link)
            if ([IO.Directory]::Exists($link)) { throw 'MosDNS cleanup guard fixture junction remains after non-recursive unlink.' }
            if (-not [IO.File]::Exists($marker) -or [IO.File]::ReadAllText($marker) -cne 'outside fixture tree') {
                throw 'Removing the MosDNS cleanup guard fixture junction changed its target.'
            }
        }
        Remove-OpenWrtTaskScratchDirectory -Path $fixture -Prefix 'sb-mosdns-reparse-fixture'
        if ([IO.File]::Exists($marker)) { Remove-Item -LiteralPath $marker -Force }
        if ([IO.Directory]::Exists($target)) { Remove-Item -LiteralPath $target -Force }
    }
}

Test-MosdnsValidationCleanupRejectsReparseTree
$temporary=New-OpenWrtTaskScratchDirectory -Prefix 'sb-package-test'
try {
    $archive=[IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $legacyExpected=@('config.json','sing-box','mosdns','mosdns.yaml','dns-direct-domains.txt','sb-controller','SHA256SUMS','routing-policy.nft','forwarding.nft','tun-input.nft','sing-box-service.sh','sing-box.init','install.sh','activate.sh','rollback.sh')
        $currentExpected=$legacyExpected+@('connection-cache.mode')
        $names=@($archive.Entries | ForEach-Object FullName)
        $hasMode=($names -ccontains 'connection-cache.mode')
        if ($hasMode) { $expected=$currentExpected } else { $expected=$legacyExpected }
        if ('routing-reject-domain' -cin @($source.route.rule_set | ForEach-Object { $_.tag })) {
            $expected += 'dns-reject-domains.txt'
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedConnectionCacheMode) -and -not $hasMode) { throw 'Requested connection cache mode is missing from the package.' }
        if (@(Compare-Object ($expected | Sort-Object) ($names | Sort-Object) -CaseSensitive).Count -or @($names | Select-Object -Unique).Count -ne $names.Count -or @($names | Where-Object { $_ -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' }).Count) { throw 'Invalid candidate entry layout or legacy payload.' }
        foreach ($entry in $archive.Entries) { [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $temporary $entry.FullName)) }
    } finally { $archive.Dispose() }
    $connectionCacheMode='legacy-off'
    if ($hasMode) {
        $modeText=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $temporary 'connection-cache.mode')))
        if ($modeText -ceq "off-v1`n") { $connectionCacheMode='off-v1' }
        elseif ($modeText -ceq "ctmark-v1`n") { $connectionCacheMode='ctmark-v1' }
        else { throw 'Package connection cache marker is malformed.' }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedConnectionCacheMode) -and $connectionCacheMode -cne $ExpectedConnectionCacheMode) { throw 'Package connection cache mode differs from the requested mode.' }
    $assertedMode=$null
    if ($hasMode) { $assertedMode=$connectionCacheMode }
    Assert-NativePackageArchive -ZipPath $ZipPath -PayloadDirectory $temporary -SingBoxPath $SingBoxPath -ExpectedConnectionCacheMode $assertedMode
    $config=Read-StrictJsonFile -Path (Join-Path $temporary 'config.json')
    Assert-NativeNumericConfiguration $config
    $expectedConfig=ConvertTo-OpenWrtProxyConfiguration $source
    if ($LegacyRejections) {
        $expectedConfig.route.rules[0].PSObject.Properties.Remove('method')
        $expectedConfig.route.rules[0].PSObject.Properties.Remove('no_drop')
    }
    if (($config | ConvertTo-Json -Depth 100 -Compress) -cne ($expectedConfig | ConvertTo-Json -Depth 100 -Compress)) { throw 'Published configuration differs from the approved Linux transformation.' }
    $fixture=Join-Path $temporary 'regenerated'
    [IO.Directory]::CreateDirectory($fixture) | Out-Null
    Write-MosdnsAdapterFromSnapshot -SourceRoot $linuxInputRoot -OutputDirectory $fixture -SingBoxPath $SingBoxPath | Out-Null
    $renderMode='off-v1'
    if ($connectionCacheMode -ceq 'ctmark-v1') { $renderMode='ctmark-v1' }
    Write-NftAdapterFromSnapshot -SourceRoot $linuxInputRoot -OutputDirectory $fixture -SingBoxPath $SingBoxPath -ConnectionCacheMode $renderMode | Out-Null
    foreach ($name in @($expected | Where-Object { $_ -cin @('mosdns.yaml','dns-direct-domains.txt','dns-reject-domains.txt','routing-policy.nft') })) {
        $actualPath = Join-Path $temporary $name
        $expectedPath = Join-Path $fixture $name
        if ($LegacyRejections -and $name -ceq 'routing-policy.nft') {
            $policy = [IO.File]::ReadAllText($expectedPath)
            $selector = '(ip daddr @reject_net|meta l4proto \{ tcp, udp \} th [ds]port @reject_[ds]port)'
            $legacyPolicy = $policy -creplace ('(?m)^        ' + $selector + ' meta mark set \(meta mark & 0x9fffffff\) return$'), '        $1 drop'
            $legacyPolicy = $legacyPolicy -creplace '(?ms)^    chain reject_(?:marked|input) \{\n.*?^    \}\n', ''
            $legacyPolicy = $legacyPolicy -creplace '(?m)^        iifname "br-lan" meta nfproto ipv4 meta mark & 0x60000000 == 0 jump reject_marked\n', ''
            if ([IO.File]::ReadAllText($actualPath) -cne $legacyPolicy) { throw 'Legacy nftables policy differs beyond its known rejection actions.' }
        } elseif ($verifiedLegacyFormalPackage -and $name -ceq 'mosdns.yaml') {
            $currentYaml = [IO.File]::ReadAllText($expectedPath)
            $legacyYaml = $currentYaml.Replace("      size: 65472`n      lazy_cache_ttl: 3600", "      size: 8192`n      lazy_cache_ttl: 3600").Replace(
                "      size: 65472`n      lazy_cache_ttl: 0", "      size: 1024`n      lazy_cache_ttl: 0")
            if ([IO.File]::ReadAllText($actualPath) -cne $legacyYaml) { throw 'Formal mosdns policy differs beyond its historical cache sizes.' }
        } elseif ((Get-FileHash -LiteralPath $actualPath -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $expectedPath -Algorithm SHA256).Hash) {
            throw ('Published rule/config bytes differ from final Linux inputs: '+$name)
        }
    }
    Assert-MosdnsRuntimeConfiguration -PayloadDirectory $temporary -MosdnsPath $MosdnsCheckPath
    if ($hasMode) {
        foreach ($name in @('forwarding.nft','tun-input.nft','sing-box-service.sh','sing-box.init','install.sh','activate.sh','rollback.sh')) {
            # The retained formal ZIP predates the corrected installer and uninstaller.
            if ($verifiedLegacyFormalPackage -and $name -in @('install.sh','rollback.sh')) { continue }
            $sourceText=[IO.File]::ReadAllText((Join-Path $nativeRoot $name)).Replace("`r`n","`n").TrimEnd([char]10)+"`n"
            if ([IO.File]::ReadAllText((Join-Path $temporary $name)) -cne $sourceText) { throw ('Published service payload differs from current source: '+$name) }
        }
    }
    if ($config.inbounds[0].auto_route -or $config.inbounds[0].auto_redirect -or $config.inbounds[0].strict_route -or
        $config.inbounds[0].stack -cne 'mixed' -or $config.inbounds[0].mtu -ne 65535 -or
        $config.inbounds[0].PSObject.Properties['route_exclude_address_set'] -or
        $config.inbounds[0].PSObject.Properties['multi_queue'] -or $config.route.final -ne 'proxy') {
        throw 'OpenWrt proxy output must retain mixed/65535, manual capture, and no Linux route-exclusion reference.'
    }
    foreach ($name in @('sb-controller','sing-box','mosdns')) {
        $elf=[IO.File]::ReadAllBytes((Join-Path $temporary $name))
        if ($elf.Length -lt 64 -or $elf[0] -ne 127 -or $elf[1] -ne 69 -or $elf[2] -ne 76 -or $elf[3] -ne 70 -or $elf[4] -ne 2 -or $elf[5] -ne 1 -or [BitConverter]::ToUInt16($elf,18) -ne 183) { throw ($name+' must be Linux ARM64 ELF, not a Windows test executable.') }
    }
    $policy=[IO.File]::ReadAllText((Join-Path $temporary 'routing-policy.nft'))
    if ($policy -match '__SB_NETWORKS__|__SB_DPORTS__|__SB_SPORTS__|iptables|ipset|multi_queue|dport 53|redirect to :53' -or @([regex]::Matches($policy,'__SB_LAN_PREFIXES__')).Count -ne 1) { throw 'Malformed nft policy or forced DNS interception.' }
    if ($connectionCacheMode -ceq 'ctmark-v1') {
        if (@([regex]::Matches($policy,'(?m)^\s*ip saddr @lan_net ip saddr != \{ __SB_ROUTER_ADDRESSES__ \} ct state \{ new, established \} ct direction original ct status & 0x9 == 0x8 meta l4proto \{ tcp, udp \} ct mark & 0x60000000 == (?:0x60000000|0x20000000) meta mark set \(meta mark & 0x9fffffff\) \| (?:0x60000000|0x20000000) return$')).Count -ne 2 -or @([regex]::Matches($policy,'__SB_ROUTER_ADDRESSES__')).Count -ne 2) { throw 'Cache-enabled nft policy lacks exactly two confirmed-state, expected-flow-safe verdict-reuse branches.' }
    } elseif ($policy -match 'ct state \{ new, established \} ct direction original|__SB_ROUTER_ADDRESSES__') { throw 'Off-mode or legacy nft policy contains the connection verdict fast path.' }
    Write-Output ('OpenWrt package passed: '+$names.Count+' flat entries; mode='+$connectionCacheMode+'; exact checksums; pinned official ARM64 cores; generated DNS/numeric policy; isolated official mosdns load; no device/network acceptance claim.')
} finally {
    Remove-OpenWrtTaskScratchDirectory -Path $temporary -Prefix 'sb-package-test'
}
