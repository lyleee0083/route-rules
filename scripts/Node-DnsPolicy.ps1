function New-ClientAAAARejectRule {
    return [ordered]@{ query_type=@('AAAA'); action='reject'; no_drop=$true }
}

function Get-ClientDnsBlockRuleCount {
    param([Parameter(Mandatory)][object[]]$Rules)
    $count = 0
    if ($Rules.Count -gt 0 -and (Get-NodeDnsValue $Rules[0] 'rule_set') -ceq 'routing-reject-domain') {
        $domainRule = [ordered]@{ rule_set='routing-reject-domain'; action='reject'; no_drop=$true }
        Assert-NodeDnsObjectMatches -Actual $Rules[0] -Expected $domainRule -Label 'leading DNS domain rejection'
        $count = 1
    }
    if ($Rules.Count -gt $count -and $null -ne (Get-NodeDnsValue $Rules[$count] 'query_type')) {
        Assert-NodeDnsObjectMatches -Actual $Rules[$count] -Expected (New-ClientAAAARejectRule) -Label 'leading DNS AAAA rejection'
        $count++
    }
    return $count
}

function Get-NodeDnsPolicySpec {
    [CmdletBinding()]
    param([ValidateRange(1, 65535)][int]$Port = 15354)

    $dnsRules = @(
        [ordered]@{ inbound = @('dns-in'); action = 'route-options'; disable_cache = $true; disable_optimistic_cache = $true },
        [ordered]@{ inbound = @('dns-in'); action = 'evaluate'; server = 'dns-direct'; tag = 'node-ali-response'; timeout = '2s' },
        [ordered]@{ inbound = @('dns-in'); match_response = 'node-ali-response'; response_rcode = 'NOERROR'; action = 'respond' },
        [ordered]@{ inbound = @('dns-in'); match_response = 'node-ali-response'; response_rcode = 'NXDOMAIN'; action = 'respond' },
        [ordered]@{ inbound = @('dns-in'); action = 'route'; server = 'dns-direct-backup'; timeout = '3s' }
    )

    return [pscustomobject]@{
        DnsServer = [ordered]@{
            type = 'udp'
            tag = 'dns-node'
            server = '127.0.0.1'
            server_port = $Port
            inet4_bind_address = '127.0.0.1'
        }
        Inbound = [ordered]@{
            type = 'direct'
            tag = 'dns-in'
            listen = '127.0.0.1'
            listen_port = $Port
        }
        DnsRules = [object[]]$dnsRules
        RouteRule = [ordered]@{ action = 'hijack-dns'; inbound = @('dns-in') }
        DomainResolver = [ordered]@{
            server = 'dns-node'
            disable_cache = $false
            rewrite_ttl = 3600
            disable_optimistic_cache = $true
            timeout = '5s'
        }
    }
}

function Get-NodeDnsValue {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-NodeDnsPropertyNames {
    param([Parameter(Mandatory)]$Object)
    if ($Object -is [Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object { [string]$_ })
    }
    return @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Get-NodeDnsFieldEnvelope {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return [pscustomobject]@{ Exists = $false; Value = $null } }
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { return [pscustomobject]@{ Exists = $false; Value = $null } }
        return [pscustomobject]@{ Exists = $true; Value = $Object[$Name] }
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return [pscustomobject]@{ Exists = $false; Value = $null } }
    return [pscustomobject]@{ Exists = $true; Value = $property.Value }
}

function Assert-NodeDnsExactFields {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    $actual = @(Get-NodeDnsPropertyNames -Object $Object | Sort-Object -CaseSensitive)
    $expectedSorted = @($Expected | Sort-Object -CaseSensitive)
    if ($actual.Count -ne $expectedSorted.Count -or ($actual -join ',') -cne ($expectedSorted -join ',')) {
        throw ($Label + ' contains missing or unexpected fields. Expected [' + ($expectedSorted -join ',') + ']; actual [' + ($actual -join ',') + '].')
    }
}

function Assert-NodeDnsObjectMatches {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    $expectedNames = @(Get-NodeDnsPropertyNames -Object $Expected)
    Assert-NodeDnsExactFields -Object $Actual -Expected $expectedNames -Label $Label
    foreach ($name in $expectedNames) {
        $actualField = Get-NodeDnsFieldEnvelope -Object $Actual -Name $name
        $expectedField = Get-NodeDnsFieldEnvelope -Object $Expected -Name $name
        if (-not $actualField.Exists) { throw ($Label + ' is missing field: ' + $name) }
        $actualValue = $actualField.Value
        $expectedValue = $expectedField.Value
        if ($expectedValue -is [array]) {
            if ($actualValue -isnot [array] -or $actualValue.Count -ne $expectedValue.Count -or
                (ConvertTo-Json -InputObject $actualValue -Depth 32 -Compress) -cne (ConvertTo-Json -InputObject $expectedValue -Depth 32 -Compress)) {
                throw ($Label + ' changed field: ' + $name)
            }
        }
        elseif ($expectedValue -is [bool]) {
            if ($actualValue -isnot [bool] -or $actualValue -ne $expectedValue) { throw ($Label + ' changed field: ' + $name) }
        }
        elseif ($expectedValue -is [int] -or $expectedValue -is [long]) {
            if (($actualValue -isnot [int] -and $actualValue -isnot [long]) -or $actualValue -ne $expectedValue) {
                throw ($Label + ' changed field: ' + $name)
            }
        }
        elseif ($expectedValue -is [string]) {
            if ($actualValue -isnot [string] -or $actualValue -cne $expectedValue) { throw ($Label + ' changed field: ' + $name) }
        }
        elseif ((ConvertTo-Json -InputObject $actualValue -Depth 32 -Compress) -cne (ConvertTo-Json -InputObject $expectedValue -Depth 32 -Compress)) {
            throw ($Label + ' changed field: ' + $name)
        }
    }
}

function Assert-NodeDnsPolicyShape {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Configuration,
        [ValidateRange(1, 65535)][int]$Port = 15354
    )

    $spec = Get-NodeDnsPolicySpec -Port $Port
    $dns = Get-NodeDnsValue -Object $Configuration -Name 'dns'
    $servers = @(Get-NodeDnsValue -Object $dns -Name 'servers')
    $expectedServerTags = @('dns-direct', 'dns-direct-backup', 'dns-proxy', 'dns-proxy-backup', 'dns-node', 'dns-doh-hosts')
    $actualServerTags = @($servers | ForEach-Object { [string](Get-NodeDnsValue -Object $_ -Name 'tag') })
    if ($servers.Count -ne $expectedServerTags.Count -or
        @($actualServerTags | Select-Object -Unique).Count -ne $actualServerTags.Count -or
        (($actualServerTags | Sort-Object -CaseSensitive) -join ',') -cne (($expectedServerTags | Sort-Object -CaseSensitive) -join ',')) {
        throw 'The DNS server tag set must contain only the four provider, node, and Hosts transports.'
    }
    $nodeServers = @($servers | Where-Object { (Get-NodeDnsValue -Object $_ -Name 'tag') -ceq 'dns-node' })
    if ($nodeServers.Count -ne 1) { throw 'Exactly one dns-node transport is required.' }
    Assert-NodeDnsObjectMatches -Actual $nodeServers[0] -Expected $spec.DnsServer -Label 'dns-node transport'

    $cacheCapacity = Get-NodeDnsValue -Object $dns -Name 'cache_capacity'
    $disableGlobalCache = Get-NodeDnsValue -Object $dns -Name 'disable_cache'
    # The configuration validator also reads the retained 8192-entry releases.
    if (($cacheCapacity -isnot [int] -and $cacheCapacity -isnot [long]) -or $cacheCapacity -notin @(65472,8192) -or
        ($null -ne $disableGlobalCache -and (($disableGlobalCache -isnot [bool]) -or $disableGlobalCache))) {
        throw 'The global DNS cache must be enabled with a 65472-entry capacity or the historical 8192-entry capacity.'
    }
    $optimistic = Get-NodeDnsValue -Object $dns -Name 'optimistic'
    if ((Get-NodeDnsValue -Object $optimistic -Name 'enabled') -isnot [bool] -or
        (Get-NodeDnsValue -Object $optimistic -Name 'enabled') -ne $true -or
        (Get-NodeDnsValue -Object $optimistic -Name 'timeout') -cne '1h') {
        throw 'The existing global optimistic cache settings must be preserved.'
    }

    $inbounds = @(Get-NodeDnsValue -Object $Configuration -Name 'inbounds')
    if ($inbounds.Count -ne 2 -or (Get-NodeDnsValue -Object $inbounds[0] -Name 'type') -cne 'tun' -or
        (Get-NodeDnsValue -Object $inbounds[1] -Name 'tag') -cne 'dns-in') {
        throw 'The original TUN must remain inbound zero and dns-in must remain inbound one.'
    }
    $tunInbounds = @($inbounds | Where-Object { (Get-NodeDnsValue -Object $_ -Name 'type') -ceq 'tun' })
    $nodeInbounds = @($inbounds | Where-Object { (Get-NodeDnsValue -Object $_ -Name 'tag') -ceq 'dns-in' })
    if ($tunInbounds.Count -ne 1 -or $nodeInbounds.Count -ne 1) { throw 'Exactly one TUN and one dns-in inbound are required.' }
    Assert-NodeDnsObjectMatches -Actual $inbounds[1] -Expected $spec.Inbound -Label 'dns-in inbound'

    $route = Get-NodeDnsValue -Object $Configuration -Name 'route'
    $routeRules = @(Get-NodeDnsValue -Object $route -Name 'rules')
    if ($routeRules.Count -lt 2) { throw 'The route policy must contain its IPv6 reject and dns-in hijack prelude.' }
    $expectedIpv6Block = [ordered]@{ action = 'reject'; ip_version = 6 }
    if ($null -ne (Get-NodeDnsValue $routeRules[0] 'method')) {
        $expectedIpv6Block['method'] = 'default'
        $expectedIpv6Block['no_drop'] = $true
    }
    Assert-NodeDnsObjectMatches -Actual $routeRules[0] -Expected $expectedIpv6Block -Label 'leading IPv6 rejection'
    Assert-NodeDnsObjectMatches -Actual $routeRules[1] -Expected $spec.RouteRule -Label 'dns-in hijack route'
    $dnsHijackRules = @($routeRules | Where-Object { (Get-NodeDnsValue -Object $_ -Name 'action') -ceq 'hijack-dns' })
    if ($dnsHijackRules.Count -ne 1) { throw 'Exactly one dns-in hijack route is required.' }

    $dnsRules = @(Get-NodeDnsValue -Object $dns -Name 'rules')
    $nodeStart = Get-ClientDnsBlockRuleCount -Rules $dnsRules
    if ($dnsRules.Count -lt ($nodeStart + $spec.DnsRules.Count)) { throw 'The five node DNS rules must precede the upstream fallback rules.' }
    for ($index = 0; $index -lt $spec.DnsRules.Count; $index++) {
        Assert-NodeDnsObjectMatches -Actual $dnsRules[$nodeStart + $index] -Expected $spec.DnsRules[$index] -Label ('node DNS rule ' + $index)
    }

    $outbounds = @(Get-NodeDnsValue -Object $Configuration -Name 'outbounds')
    $vlessOutbounds = @($outbounds | Where-Object { (Get-NodeDnsValue -Object $_ -Name 'type') -ceq 'vless' })
    if ($vlessOutbounds.Count -lt 1) { throw 'At least one VLESS node outbound is required.' }
    foreach ($outbound in $vlessOutbounds) {
        $resolver = Get-NodeDnsValue -Object $outbound -Name 'domain_resolver'
        Assert-NodeDnsObjectMatches -Actual $resolver -Expected $spec.DomainResolver -Label 'VLESS domain_resolver'
    }
}
