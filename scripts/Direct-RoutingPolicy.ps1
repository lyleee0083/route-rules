# Final DNS-domain / numeric-traffic direct-only contract.
. (Join-Path $PSScriptRoot 'Node-DnsPolicy.ps1')

function Assert-EffectiveDirectConfiguration {
    param([Parameter(Mandatory)][object]$Configuration)
    # Canonicalize both generator dictionaries and deserialized configuration.
    $document = ConvertTo-Json -InputObject $Configuration -Depth 100 -Compress | ConvertFrom-Json
    Assert-NodeDnsPolicyShape -Configuration $document
    if ($document.route.final -ne 'proxy' -or $document.dns.final -ne 'dns-proxy') {
        throw 'Traffic and DNS must default to their proxy outbounds.'
    }
    Assert-NoOtherIPv6Fields -Value $document
    if ($document.dns.reverse_mapping -ne $false -or @($document.dns.servers | Where-Object { $_.PSObject.Properties['type'] -and $_.type -eq 'fakeip' }).Count) {
        throw 'DNS-only domains must not use reverse mapping or FakeIP.'
    }
    $trafficRules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $document.route.rules) {
        if ($rule.PSObject.Properties['outbound']) {
            if ($rule.action -ne 'route' -or $rule.outbound -ne 'direct') { throw 'Final traffic rules may only contain direct routing actions.' }
        } elseif ($rule.action -eq 'hijack-dns') {
            if (-not $rule.PSObject.Properties['inbound'] -or @($rule.inbound).Count -ne 1 -or $rule.inbound[0] -ne 'dns-in') {
                throw 'DNS exception must be scoped to the dedicated inbound.'
            }
            continue
        } elseif ($rule.action -ne 'reject') { throw 'Unexpected final traffic action.' }
        $trafficRules.Add($rule)
    }
    $available = @($document.route.rule_set | ForEach-Object { $_.tag })
    if (@($available | Select-Object -Unique).Count -ne $available.Count -or
        @($available | Where-Object { $_ -cnotmatch '^(?:routing-(?:direct|reject)-(?:domain|ip|port)|routing-direct-[0-9]+-(?:domain|ip|port|source_port))$' }).Count) {
        throw 'Only unique resolved reject and direct rule-sets may be delivered.'
    }
    $used = New-Object 'System.Collections.Generic.List[string]'
    $typeOrder = New-Object 'System.Collections.Generic.List[string]'
    $previousType = ''; $previousSequence=0
    $directStarted = $false
    foreach ($rule in @($trafficRules | Select-Object -Skip 1)) {
        if ($rule.action -ceq 'reject') {
            $fields = @($rule.PSObject.Properties.Name | Sort-Object) -join ','
            $legacyReject = $fields -ceq 'action,rule_set'
            $activeReject = $fields -ceq 'action,method,no_drop,rule_set' -and $rule.method -ceq 'default' -and $rule.no_drop -is [bool] -and $rule.no_drop
            if ($directStarted -or (-not $legacyReject -and -not $activeReject) -or
                -not $rule.PSObject.Properties['rule_set'] -or $rule.rule_set -isnot [string] -or
                $rule.rule_set -cnotmatch '^routing-reject-(ip|port)$' -or $rule.rule_set -cnotin $available) {
                throw 'Only resolved numeric rejects may precede direct traffic rules.'
            }
            $used.Add($rule.rule_set)
            continue
        }
        $directStarted = $true
        if (@($rule.PSObject.Properties.Name).Count -ne 3 -or @($rule.rule_set).Count -ne 1 -or
            -not $rule.PSObject.Properties['rule_set']) { throw 'Final direct rules may not contain logical, inverse or exclusion conditions.' }
        $tag=[string]$rule.rule_set
        if ($tag -notin $available) { throw 'Missing effective-direct rule-set dependency.' }
        if ($tag -match '^routing-direct-([0-9]+)-(domain|ip|port|source_port)$') { $sequence=[int]$Matches[1]; $kind=$Matches[2] }
        elseif ($tag -match '^routing-direct-(domain|ip|port)$') { $sequence=0; $kind=$Matches[1] }
        else { throw 'Unexpected direct identifier.' }
        if ($kind -eq 'domain') { throw 'Domain predicates are DNS-only and forbidden in business traffic rules.' }
        if ($kind -eq 'source_port') { $kind='port' }
        if ($kind -ne $previousType) {
            if ($typeOrder.Contains($kind)) { throw 'Final rule types must form contiguous blocks.' }
            $typeOrder.Add($kind); $previousSequence=0
        }
        if ($sequence -lt $previousSequence) { throw 'Source order changed within a type block.' }
        $previousType=$kind; $previousSequence=$sequence; $used.Add($tag)
    }
    $numericTags=@($available | Where-Object { $_ -notmatch '-domain$' })
    if (($used.ToArray() -join ',') -cne ($numericTags -join ',')) { throw 'Unused, missing or reordered numeric traffic rule-set.' }
    $domainTags=@($available | Where-Object { $_ -match '^routing-direct-.*domain$' })
    $dnsRules=@($document.dns.rules)
    $nodeRuleCount = 5 + (Get-ClientDnsBlockRuleCount -Rules $dnsRules)
    $hasDomainReject = 'routing-reject-domain' -cin $available
    $hasLeadingDnsReject = $dnsRules.Count -gt 0 -and (Get-NodeDnsValue $dnsRules[0] 'rule_set') -ceq 'routing-reject-domain'
    if ($hasDomainReject -ne $hasLeadingDnsReject) { throw 'DNS reject dependency and leading rule must both be present.' }
    $expectedCount = $nodeRuleCount + 4
    if ($domainTags.Count -gt 0) { $expectedCount += 4 }
    if ($dnsRules.Count -ne $expectedCount) {
        throw 'DNS must contain the ordered direct group when present, followed by the proxy fallback group.'
    }

    function Assert-DnsFallbackGroup {
        param(
            [Parameter(Mandatory)][object[]]$Rules,
            [Parameter(Mandatory)][int]$StartIndex,
            [Parameter(Mandatory)][string]$PrimaryServer,
            [Parameter(Mandatory)][string]$BackupServer,
            [Parameter(Mandatory)][string]$PrimaryTag,
            [Parameter(Mandatory)][string]$PrimaryTimeout,
            [Parameter(Mandatory)][string]$BackupTimeout,
            [Parameter(Mandatory)][string]$SelectorField,
            [Parameter(Mandatory)][object]$SelectorValue
        )
        $expectedKeys = @(
            @($SelectorField, 'action', 'server', 'tag', 'timeout'),
            @($SelectorField, 'match_response', 'response_rcode', 'action'),
            @($SelectorField, 'match_response', 'response_rcode', 'action'),
            @($SelectorField, 'action', 'server', 'timeout')
        )
        $expectedActions = @('evaluate', 'respond', 'respond', 'route')
        $expectedRcodes = @($null, 'NOERROR', 'NXDOMAIN', $null)
        for ($offset = 0; $offset -lt 4; $offset++) {
            $rule = $Rules[$StartIndex + $offset]
            $actualKeys = @($rule.PSObject.Properties.Name | Sort-Object)
            $requiredKeys = @($expectedKeys[$offset] | Sort-Object)
            if (($actualKeys -join ',') -cne ($requiredKeys -join ',')) {
                throw 'DNS fallback rules must contain only the selector and action fields required for their stage.'
            }
            $actualSelector = Get-EffectiveDnsSelectorValue -Rule $rule -Field $SelectorField
            $actualSelectorJson = ConvertTo-Json -InputObject @($actualSelector) -Compress -Depth 10
            $expectedSelectorJson = ConvertTo-Json -InputObject @($SelectorValue) -Compress -Depth 10
            if ($null -eq $actualSelector -or $actualSelectorJson -cne $expectedSelectorJson) {
                throw 'DNS fallback selector changed or became incomplete.'
            }
            if ($rule.action -cne $expectedActions[$offset] -or $rule.PSObject.Properties['invert']) {
                throw 'DNS fallback stage order or positive selector semantics changed.'
            }
            if ($offset -eq 0) {
                if ($rule.server -cne $PrimaryServer -or $rule.tag -cne $PrimaryTag -or $rule.timeout -cne $PrimaryTimeout) {
                    throw 'DNS primary evaluate action changed server, response tag or timeout.'
                }
            } elseif ($offset -lt 3) {
                if ($rule.match_response -cne $PrimaryTag -or $rule.response_rcode -cne $expectedRcodes[$offset]) {
                    throw 'DNS valid response preservation rules changed tag or RCODE.'
                }
            } elseif ($rule.server -cne $BackupServer -or $rule.timeout -cne $BackupTimeout) {
                throw 'DNS backup route or per-query timeout changed.'
            }
        }
    }

    if ($domainTags.Count -gt 0) {
        $directStart = $nodeRuleCount
        $firstSelector = Get-EffectiveDnsSelectorValue -Rule $dnsRules[$directStart] -Field 'rule_set'
        if ((@($firstSelector) -join ',') -cne ($domainTags -join ',')) {
            throw 'DNS direct group must retain every direct-domain rule-set in source order.'
        }
        Assert-DnsFallbackGroup -Rules $dnsRules -StartIndex $directStart -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s' -SelectorField 'rule_set' -SelectorValue $domainTags
        $proxyStart = $nodeRuleCount + 4
    } else {
        $proxyStart = $nodeRuleCount
    }
    Assert-DnsFallbackGroup -Rules $dnsRules -StartIndex $proxyStart -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s' -SelectorField 'domain_regex' -SelectorValue @('.*')
    foreach ($tag in @('dns-direct','dns-direct-backup','dns-proxy','dns-proxy-backup')) {
        if (@($document.dns.servers | Where-Object { $_.tag -eq $tag }).Count -ne 1) { throw 'Both DNS primary and backup servers must be retained.' }
    }
}

function Assert-NoOtherIPv6Fields {
    param($Value,[string]$Field='')
    if ($null -eq $Value) { return }
    if ($Field -match '(?i)ipv6|inet6') { throw 'IPv6 fields other than the leading rejection are forbidden.' }
    if ($Value -is [string]) {
        $candidate=([string]$Value).Split('/')[0].Trim('[',']')
        $address=$null
        if ([Net.IPAddress]::TryParse($candidate,[ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
            throw 'IPv6 addresses or ranges are forbidden in final configuration.'
        }
        return
    }
    if ($Value -is [ValueType]) { return }
    if ($Value -is [array]) { foreach ($item in $Value) { Assert-NoOtherIPv6Fields -Value $item -Field $Field }; return }
    foreach ($property in $Value.PSObject.Properties) { Assert-NoOtherIPv6Fields -Value $property.Value -Field $property.Name }
}

function New-EffectiveDirectRule {
    param(
        [Parameter(Mandatory)][string]$Tag,
        [ValidateSet('outbound', 'server')][string]$TargetField = 'outbound',
        [string]$TargetValue = 'direct'
    )
    $rule = [ordered]@{ rule_set = $Tag }
    $rule['action'] = 'route'
    $rule[$TargetField] = $TargetValue
    return $rule
}

function Get-EffectiveDnsSelectorValue {
    param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)][string]$Field)
    $property = $Rule.PSObject.Properties[$Field]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function New-DnsFallbackRuleGroup {
    param(
        [Parameter(Mandatory)][ValidateSet('rule_set','domain_regex')][string]$SelectorField,
        [Parameter(Mandatory)][object[]]$SelectorValues,
        [Parameter(Mandatory)][string]$PrimaryServer,
        [Parameter(Mandatory)][string]$BackupServer,
        [Parameter(Mandatory)][string]$PrimaryTag,
        [Parameter(Mandatory)][ValidateSet('2s','3s')][string]$PrimaryTimeout,
        [Parameter(Mandatory)][ValidateSet('3s','5s')][string]$BackupTimeout
    )
    if ($SelectorValues.Count -eq 0) { throw 'DNS fallback selectors must not be empty.' }
    $selector = [ordered]@{}
    $selector[$SelectorField] = @($SelectorValues)
    $rules = New-Object 'System.Collections.Generic.List[object]'
    $evaluate = [ordered]@{}
    foreach ($key in $selector.Keys) { $evaluate[$key] = $selector[$key] }
    $evaluate['action'] = 'evaluate'
    $evaluate['server'] = $PrimaryServer
    $evaluate['tag'] = $PrimaryTag
    $evaluate['timeout'] = $PrimaryTimeout
    $rules.Add($evaluate)
    foreach ($rcode in @('NOERROR','NXDOMAIN')) {
        $response = [ordered]@{}
        foreach ($key in $selector.Keys) { $response[$key] = $selector[$key] }
        $response['match_response'] = $PrimaryTag
        $response['response_rcode'] = $rcode
        $response['action'] = 'respond'
        $rules.Add($response)
    }
    $backup = [ordered]@{}
    foreach ($key in $selector.Keys) { $backup[$key] = $selector[$key] }
    $backup['action'] = 'route'
    $backup['server'] = $BackupServer
    $backup['timeout'] = $BackupTimeout
    $rules.Add($backup)
    return $rules.ToArray()
}
