$nodeDnsSupportProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$nodeDnsSupportDirectPolicy = Join-Path (Join-Path $nodeDnsSupportProjectRoot 'scripts') 'Direct-RoutingPolicy.ps1'
if (-not (Test-Path -LiteralPath $nodeDnsSupportDirectPolicy -PathType Leaf)) { throw 'Shared direct-routing validator is missing for the node DNS test fixture.' }
. $nodeDnsSupportDirectPolicy

function ConvertTo-OpenWrtNodeDnsFixtureConfiguration {
    param([Parameter(Mandatory)]$Configuration)

    $config = ConvertTo-Json -InputObject $Configuration -Depth 100 -Compress | ConvertFrom-Json
    $ordinaryRuleCount = @($config.dns.rules).Count
    if ($ordinaryRuleCount -eq 8) {
        if (@($config.inbounds).Count -ne 1 -or $config.inbounds[0].type -cne 'tun' -or @($config.dns.servers).Count -ne 5) {
            throw 'Legacy test input does not match the known one-TUN, five-server, eight-rule fixture shape.'
        }
        $spec = Get-NodeDnsPolicySpec -Port 15354
        $servers = @($config.dns.servers)
        $hostsIndex = -1
        for ($index = 0; $index -lt $servers.Count; $index++) {
            if ($servers[$index].tag -ceq 'dns-doh-hosts') { $hostsIndex = $index; break }
        }
        if ($hostsIndex -lt 0) { throw 'Legacy test input has no DNS hosts server before node-path insertion.' }
        $serverList = New-Object 'System.Collections.Generic.List[object]'
        for ($index = 0; $index -lt $servers.Count; $index++) {
            if ($index -eq $hostsIndex) { $serverList.Add($spec.DnsServer) }
            $serverList.Add($servers[$index])
        }
        $config.dns.servers = @($serverList.ToArray())
        $config.inbounds = @($config.inbounds) + @($spec.Inbound)
        $config.dns.rules = @($spec.DnsRules) + @($config.dns.rules)
        $routeRules = @($config.route.rules)
        if (-not $routeRules.Count -or $routeRules[0].action -cne 'reject' -or $routeRules[0].ip_version -ne 6) {
            throw 'Legacy test input does not begin with the required IPv6 rejection.'
        }
        $config.route.rules = @($routeRules[0],$spec.RouteRule) + @($routeRules | Select-Object -Skip 1)
        $vlessFound = $false
        foreach ($outbound in @($config.outbounds)) {
            if ($outbound.type -ceq 'vless') {
                $vlessFound = $true
                $outbound | Add-Member -NotePropertyName domain_resolver -NotePropertyValue $spec.DomainResolver -Force
            }
        }
        if (-not $vlessFound) { throw 'Legacy test input has no VLESS node outbound for resolver insertion.' }
    }

    Assert-EffectiveDirectConfiguration -Configuration $config
    return $config
}

function New-OpenWrtNodeDnsSnapshotFixture {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$FixtureRoot
    )

    $sourceRootPath = [IO.Path]::GetFullPath($SourceRoot)
    $sourceRootItem = Get-Item -LiteralPath $sourceRootPath -Force -ErrorAction Stop
    $sourceConfigPath = Join-Path $sourceRootPath 'sing-box-openwrt.json'
    $sourceRuleRoot = Join-Path $sourceRootPath 'rule-set'
    $configItem = Get-Item -LiteralPath $sourceConfigPath -Force -ErrorAction Stop
    $ruleRootItem = Get-Item -LiteralPath $sourceRuleRoot -Force -ErrorAction Stop
    if (-not $sourceRootItem.PSIsContainer -or ($sourceRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $configItem.PSIsContainer -or ($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        -not $ruleRootItem.PSIsContainer -or ($ruleRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Node DNS test source must be a regular snapshot directory, JSON file, and rule-set directory.'
    }
    $rootItems = @(Get-ChildItem -LiteralPath $sourceRootPath -Force)
    $ruleItems = @(Get-ChildItem -LiteralPath $sourceRuleRoot -Force)
    if ($rootItems.Count -ne 2 -or @($rootItems | Where-Object { $_.Name -notin @('sing-box-openwrt.json','rule-set') }).Count -ne 0 -or
        -not $ruleItems.Count -or @($ruleItems | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $_.Name -cnotmatch '^[A-Za-z0-9_-]+\.srs$' }).Count -ne 0) {
        throw 'Node DNS test source is not the flat final Linux snapshot layout.'
    }
    if (Test-Path -LiteralPath $FixtureRoot) { throw 'Node DNS test fixture destination already exists.' }

    $config = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($sourceConfigPath)) -ErrorAction Stop
    $config = ConvertTo-OpenWrtNodeDnsFixtureConfiguration -Configuration $config
    $destinationRuleRoot = Join-Path $FixtureRoot 'rule-set'
    [IO.Directory]::CreateDirectory($destinationRuleRoot) | Out-Null
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $configText = ConvertTo-Json -InputObject $config -Depth 100 -Compress
    [IO.File]::WriteAllText((Join-Path $FixtureRoot 'sing-box-openwrt.json'),$configText,$encoding)
    foreach ($ruleItem in $ruleItems) {
        Copy-Item -LiteralPath $ruleItem.FullName -Destination (Join-Path $destinationRuleRoot $ruleItem.Name)
    }
    return [IO.Path]::GetFullPath($FixtureRoot)
}
