function Get-DnsBootstrapField {
    param($Value, [string]$Name)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) { return $Value[$Name] }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

. (Join-Path $PSScriptRoot 'Node-DnsPolicy.ps1')

function Assert-DnsBootstrapConfiguration {
    param([Parameter(Mandatory)]$Configuration)
    Assert-NodeDnsPolicyShape -Configuration $Configuration
    $dns = Get-DnsBootstrapField $Configuration 'dns'
    if ((Get-DnsBootstrapField $dns 'disable_cache') -eq $true) { throw 'Application DNS caching must remain enabled.' }
    $servers = @(Get-DnsBootstrapField $dns 'servers')
    if ($servers.Count -ne 6) { throw 'DNS policy requires four domain DoH servers, one internal node transport and one predefined Hosts server.' }
    $byTag = @{}
    foreach ($server in $servers) {
        $tag = [string](Get-DnsBootstrapField $server 'tag')
        if (-not $tag -or $byTag.ContainsKey($tag)) { throw 'Missing or duplicate DNS tag.' }
        $byTag[$tag] = $server
    }
    if (-not $byTag.ContainsKey('dns-doh-hosts')) { throw 'Missing predefined DoH Hosts server.' }
    $hosts = $byTag['dns-doh-hosts']
    $predefined = Get-DnsBootstrapField $hosts 'predefined'
    if ($null -eq $predefined -or (Get-DnsBootstrapField $hosts 'type') -cne 'hosts' -or
        $null -ne (Get-DnsBootstrapField $hosts 'domain_resolver') -or
        $null -ne (Get-DnsBootstrapField $hosts 'detour') -or
        $null -ne (Get-DnsBootstrapField $hosts 'server')) { throw 'Invalid local-only DoH Hosts definition.' }
    $hostNames = if ($predefined -is [Collections.IDictionary]) { @($predefined.Keys) } else { @($predefined.PSObject.Properties.Name) }
    if ($hostNames.Count -ne 4 -or -not ($hostNames -ccontains 'dns.alidns.com') -or
        -not ($hostNames -ccontains 'doh.pub') -or -not ($hostNames -ccontains 'cloudflare-dns.com') -or
        -not ($hostNames -ccontains 'dns.google')) { throw 'DoH Hosts must contain exactly the four expected domain names.' }
    foreach ($mapping in @(@('dns.alidns.com','223.5.5.5'),@('doh.pub','120.53.53.53'),@('cloudflare-dns.com','1.1.1.1'),@('dns.google','8.8.8.8'))) {
        $addresses = @(Get-DnsBootstrapField $predefined $mapping[0])
        if ($addresses.Count -ne 1 -or $addresses[0] -cne $mapping[1]) { throw 'Invalid fixed DoH address mapping.' }
    }
    $expectedServers = @(
        [pscustomobject]@{ Tag='dns-direct'; Host='dns.alidns.com'; Timeout='5s'; Detour='dns-direct-out' },
        [pscustomobject]@{ Tag='dns-direct-backup'; Host='doh.pub'; Timeout='5s'; Detour='dns-direct-out' },
        [pscustomobject]@{ Tag='dns-proxy'; Host='cloudflare-dns.com'; Timeout='8s'; Detour='dns-proxy-out' },
        [pscustomobject]@{ Tag='dns-proxy-backup'; Host='dns.google'; Timeout='8s'; Detour='dns-proxy-out' }
    )
    foreach ($expected in $expectedServers) {
        $tag = $expected.Tag
        if (-not $byTag.ContainsKey($tag)) { throw ('Missing domain DoH server: ' + $tag) }
        $hostName = $expected.Host
        $timeout = $expected.Timeout
        $detour = $expected.Detour
        $server = $byTag[$tag]
        $tls = Get-DnsBootstrapField $server 'tls'
        $headers = Get-DnsBootstrapField $server 'headers'
        $resolver = Get-DnsBootstrapField $server 'domain_resolver'
        if ((Get-DnsBootstrapField $server 'type') -cne 'https' -or
            (Get-DnsBootstrapField $server 'server') -cne $hostName -or
            (Get-DnsBootstrapField $server 'server_port') -ne 443 -or
            (Get-DnsBootstrapField $server 'path') -cne '/dns-query' -or
            (Get-DnsBootstrapField $server 'detour') -cne $detour -or
            (Get-DnsBootstrapField $headers 'Host') -cne $hostName -or
            (Get-DnsBootstrapField $tls 'enabled') -ne $true -or
            (Get-DnsBootstrapField $tls 'server_name') -cne $hostName -or
            (Get-DnsBootstrapField $tls 'insecure') -eq $true -or
            (Get-DnsBootstrapField $resolver 'server') -cne 'dns-doh-hosts' -or
            (Get-DnsBootstrapField $resolver 'disable_cache') -eq $true -or
            (Get-DnsBootstrapField $resolver 'strategy') -cne 'ipv4_only' -or
            (Get-DnsBootstrapField $resolver 'timeout') -cne $timeout) {
            throw ('Invalid domain DoH or bootstrap dependency: ' + $tag)
        }
    }
    if ((Get-DnsBootstrapField $dns 'final') -cne 'dns-proxy') { throw 'Bootstrap DNS must not be the default resolver.' }
    $dnsRules = @(Get-DnsBootstrapField $dns 'rules')
    $ordinaryStart = 5 + (Get-ClientDnsBlockRuleCount -Rules $dnsRules)
    if (($dnsRules.Count - $ordinaryStart) -notin @(0, 4, 8)) { throw 'DNS policy must contain the five node rules and, when generated, the ordinary direct/proxy fallback groups.' }
    foreach ($rule in @($dnsRules | Select-Object -Skip $ordinaryStart)) {
        if ($null -eq $rule) { continue }
        $action = [string](Get-DnsBootstrapField $rule 'action')
        $targetServer = Get-DnsBootstrapField $rule 'server'
        if ($action -cnotin @('evaluate','route','respond') -or
            ($targetServer -and $targetServer -cnotin @('dns-direct','dns-direct-backup','dns-proxy','dns-proxy-backup')) -or
            (Get-DnsBootstrapField $rule 'disable_cache') -eq $true) {
            throw 'Application DNS rules may only use the approved primary and backup transports with cache enabled.'
        }
    }
    $outbounds = @(Get-DnsBootstrapField $Configuration 'outbounds')
    $proxy = @($outbounds | Where-Object { (Get-DnsBootstrapField $_ 'tag') -eq 'proxy' })
    if ($proxy.Count -ne 1) { throw 'Exactly one proxy outbound is required.' }
    $nodeResolver = Get-DnsBootstrapField $proxy[0] 'domain_resolver'
    if ((Get-DnsBootstrapField $nodeResolver 'server') -cne 'dns-node' -or
        (Get-DnsBootstrapField $nodeResolver 'timeout') -cne '5s' -or
        (Get-DnsBootstrapField $nodeResolver 'disable_cache') -isnot [bool] -or
        (Get-DnsBootstrapField $nodeResolver 'disable_cache') -ne $false -or
        ((Get-DnsBootstrapField $nodeResolver 'rewrite_ttl') -isnot [int] -and
         (Get-DnsBootstrapField $nodeResolver 'rewrite_ttl') -isnot [long]) -or
        (Get-DnsBootstrapField $nodeResolver 'rewrite_ttl') -ne 3600 -or
        (Get-DnsBootstrapField $nodeResolver 'disable_optimistic_cache') -isnot [bool] -or
        (Get-DnsBootstrapField $nodeResolver 'disable_optimistic_cache') -ne $true) { throw 'Proxy node resolution must use direct DoH with a 3600-second TTL and no optimistic cache.' }
    foreach ($side in @('direct','proxy')) {
        $aliasTag = 'dns-' + $side + '-out'
        $alias = @($outbounds | Where-Object { (Get-DnsBootstrapField $_ 'tag') -eq $aliasTag })
        if ($alias.Count -ne 1) { throw 'Missing DNS selector.' }
        $members = @(Get-DnsBootstrapField $alias[0] 'outbounds')
        if ((Get-DnsBootstrapField $alias[0] 'type') -cne 'selector' -or
            (Get-DnsBootstrapField $alias[0] 'default') -cne $side -or
            $members.Count -ne 1 -or $members[0] -cne $side) { throw 'DNS selector must preserve its original single exit.' }
    }
}
