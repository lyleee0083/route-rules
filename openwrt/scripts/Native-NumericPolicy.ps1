# The core only proxies captured business; mosdns owns DNS policy and caches.
function ConvertTo-OpenWrtProxyConfiguration {
    param([Parameter(Mandatory)]$Configuration)
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
    Assert-EffectiveDirectConfiguration $Configuration
    $config=$Configuration | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    if (@($config.inbounds).Count -ne 2 -or $config.inbounds[0].type -cne 'tun' -or $config.inbounds[1].tag -cne 'dns-in') { throw 'Expected the final Linux TUN followed by the validated loopback dns-in inbound.' }
    $tun=$config.inbounds[0]
    foreach ($name in @('auto_route','auto_redirect','strict_route')) { $tun | Add-Member NoteProperty $name $false -Force }
    $tun | Add-Member NoteProperty interface_name 'sb-tun' -Force
    $tun | Add-Member NoteProperty dns_mode 'disabled' -Force
    foreach ($name in @('dns_address','endpoint_independent_nat','route_exclude_address_set')) { $tun.PSObject.Properties.Remove($name) }
    if ($tun.PSObject.Properties['multi_queue']) { throw 'Unsupported multi_queue cannot enter the pinned stable build.' }
    $config.inbounds=@($tun,[pscustomobject][ordered]@{type='socks';tag='dns-proxy-in';listen='127.0.0.1';listen_port=15355})
    $config.route.rules=@([pscustomobject][ordered]@{ip_version=6;action='reject';method='default';no_drop=$true})
    $config.route.PSObject.Properties.Remove('rule_set')
    $config.route | Add-Member NoteProperty default_domain_resolver ([pscustomobject][ordered]@{server='node-dns';strategy='ipv4_only';timeout='5s'}) -Force
    $config.dns=[pscustomobject][ordered]@{
        servers=@([pscustomobject][ordered]@{type='udp';tag='node-dns';server='127.0.0.1';server_port=15354})
        final='node-dns';strategy='ipv4_only';disable_cache=$true;reverse_mapping=$false
    }
    $config.outbounds=@($config.outbounds | Where-Object { $_.tag -notin @('dns-proxy-out','dns-direct-out') })
    foreach ($outbound in $config.outbounds) {
        foreach ($field in @('outbounds','default','detour')) {
            if ($outbound.PSObject.Properties[$field] -and @($outbound.$field | Where-Object { $_ -in @('dns-proxy-out','dns-direct-out') }).Count) { throw 'Removed DNS outbound still has a non-DNS dependency.' }
        }
        if ($outbound.PSObject.Properties['domain_resolver']) {
            $outbound.domain_resolver=[pscustomobject][ordered]@{server='node-dns';strategy='ipv4_only';timeout='5s'}
        }
    }
    Assert-NativeNumericConfiguration $config
    return $config
}

function Assert-NativeNumericConfiguration {
    param([Parameter(Mandatory)]$Configuration)
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
    $config=$Configuration | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    if ($config.inbounds[0].stack -cne 'mixed' -or @($config.inbounds[0].address).Count -ne 1 -or
        $config.inbounds[0].address[0] -cne '172.28.255.1/30') { throw 'Mixed TCP INPUT integration requires the fixed 172.28.255.1/30 TUN address.' }
    Assert-NoOtherIPv6Fields -Value $config
    if ($config.route.final -ne 'proxy' -or @($config.route.rules).Count -ne 1 -or $config.route.PSObject.Properties['rule_set']) {
        throw 'OpenWrt core must contain only its IPv6 block and default captured traffic to proxy.'
    }
    $ipv6Block = [ordered]@{ip_version=6;action='reject'}
    if ($config.route.rules[0].PSObject.Properties['method']) {
        $ipv6Block['method'] = 'default'
        $ipv6Block['no_drop'] = $true
    }
    Assert-NodeDnsObjectMatches -Actual $config.route.rules[0] -Expected $ipv6Block -Label 'OpenWrt IPv6 block'
    if (@($config.inbounds).Count -ne 2 -or $config.inbounds[0].type -ne 'tun' -or
        $config.inbounds[0].stack -cne 'mixed' -or $config.inbounds[0].mtu -ne 65535 -or
        $config.inbounds[0].dns_mode -ne 'disabled' -or $config.inbounds[0].auto_route -or
        $config.inbounds[0].auto_redirect -or $config.inbounds[0].strict_route -or
        $config.inbounds[0].PSObject.Properties['route_exclude_address_set'] -or
        $config.inbounds[1].type -ne 'socks' -or $config.inbounds[1].listen -ne '127.0.0.1' -or
        $config.inbounds[1].listen_port -ne 15355) { throw 'Competing capture, DNS hijack or exposed SOCKS inbound.' }
    $expected=[pscustomobject][ordered]@{
        servers=@([pscustomobject][ordered]@{type='udp';tag='node-dns';server='127.0.0.1';server_port=15354})
        final='node-dns';strategy='ipv4_only';disable_cache=$true;reverse_mapping=$false
    }
    if (($config.dns | ConvertTo-Json -Depth 10 -Compress) -cne ($expected | ConvertTo-Json -Depth 10 -Compress)) { throw 'Only the uncached node-only mosdns client may remain in core DNS.' }
    $defaultResolver=$config.route.default_domain_resolver
    if ($defaultResolver.server -ne 'node-dns' -or $defaultResolver.strategy -ne 'ipv4_only' -or
        $defaultResolver.timeout -ne '5s' -or @($defaultResolver.PSObject.Properties.Name).Count -ne 3) { throw 'Default domain resolver must use the node-only mosdns client.' }
    foreach ($outbound in $config.outbounds) {
        if ($outbound.tag -in @('dns-proxy-out','dns-direct-out')) { throw 'Obsolete DNS outbound.' }
        if ($outbound.PSObject.Properties['domain_resolver']) {
            $resolver=$outbound.domain_resolver
            if ($resolver.server -ne 'node-dns' -or $resolver.strategy -ne 'ipv4_only' -or $resolver.timeout -ne '5s' -or
                @($resolver.PSObject.Properties.Name).Count -ne 3) { throw 'Node DNS policy must be owned solely by mosdns.' }
        }
    }
}
