# nftables emitter for the already resolved positive numeric Linux policy.
if (-not (Get-Command New-OpenWrtTaskScratchDirectory -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1')
}
. (Join-Path $PSScriptRoot 'Numeric-KernelPolicy.ps1')

function ConvertTo-NftKernelPolicy {
    param([Parameter(Mandatory)]$Policy,[switch]$ConnectionVerdictCache)
    if (-not $Policy.reject_ipv6 -or $Policy.fallback_numeric_predicates -ne 0) { throw 'Unresolved or IPv6-enabled policy is forbidden.' }
    $openWrtRoot = Split-Path -Parent $PSScriptRoot
    $templatePath = Join-Path (Join-Path (Join-Path $openWrtRoot 'src') 'native') 'policy.template.nft'
    $template = [IO.File]::ReadAllText($templatePath).Replace("`r`n","`n")
    if ($ConnectionVerdictCache) {
        $replyRule = '        ct direction reply return'
        $oldComment = '        # Re-evaluate originals against current sets: no stale connection verdict' + "`n" + '        # after a policy change. Replies use only the saved original verdict.'
        if ([regex]::Matches($template,[regex]::Escape($replyRule)).Count -ne 1 -or
            [regex]::Matches($template,[regex]::Escape($oldComment)).Count -ne 1) { throw 'Cache-mode nft insertion anchors are missing or ambiguous.' }
        $fastPath = @(
            '        # Reuse only confirmed original TCP/UDP verdicts after the boot-bound gate.'
            '        ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ } ct state { new, established } ct direction original ct status & 0x9 == 0x8 meta l4proto { tcp, udp } ct mark & 0x60000000 == 0x60000000 meta mark set (meta mark & 0x9fffffff) | 0x60000000 return'
            '        ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ } ct state { new, established } ct direction original ct status & 0x9 == 0x8 meta l4proto { tcp, udp } ct mark & 0x60000000 == 0x20000000 meta mark set (meta mark & 0x9fffffff) | 0x20000000 return'
            '        # Policy changes require a reboot before this verdict cache can be activated.'
        ) -join "`n"
        $template = $template.Replace($replyRule,$replyRule+"`n"+$fastPath)
        $cacheComment = '        # Confirmed, eligible flows may use the boot-bound verdict cache; all others are classified against current sets.' + "`n" + '        # Replies use only the saved original verdict.'
        $template = $template.Replace($oldComment,$cacheComment)
    }
    $rejectMatches = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @(
        @{ Intervals=$Policy.reject_ip_intervals; Type='ipv4_addr'; Set='reject_net'; Match='ip daddr' },
        @{ Intervals=$Policy.reject_destination_intervals; Type='inet_service'; Set='reject_dport'; Match='th dport' },
        @{ Intervals=$Policy.reject_source_intervals; Type='inet_service'; Set='reject_sport'; Match='th sport' }
    )) {
        if (-not $entry.Intervals.Count) { continue }
        $elements = if ($entry.Type -ceq 'ipv4_addr') {
            [SingBoxSameType.Ranges]::CIDRs($entry.Intervals)
        } else {
            foreach ($range in $entry.Intervals) {
                if ($range.Start -eq $range.End) { [string]$range.Start }
                else { [string]$range.Start + '-' + [string]$range.End }
            }
        }
        $set = '    set ' + $entry.Set + ' { type ' + $entry.Type + '; flags interval; auto-merge; elements = { ' + ($elements -join ', ') + ' }; }'
        $template = $template.Replace('    set lan_net {', $set + "`n" + '    set lan_net {')
        $match = $entry.Match + ' @' + $entry.Set
        if ($entry.Type -ceq 'inet_service') { $match = 'meta l4proto { tcp, udp } ' + $match }
        $rejectMatches.Add('        ' + $match + ' meta mark set (meta mark & 0x9fffffff) return')
    }
    if ($rejectMatches.Count) {
        # Zero in the project-owned bits flags rejection before cache reuse.
        # Netfilter may redirect it locally after classification, so both
        # forward and input must consume the mark before delivery.
        $classifyAnchor = '        ct direction reply return'
        $guardAnchor = '    chain guard {'
        $forwardAnchor = '        type filter hook forward priority -1; policy accept;'
        if ([regex]::Matches($template,[regex]::Escape($classifyAnchor)).Count -ne 1 -or
            [regex]::Matches($template,[regex]::Escape($guardAnchor)).Count -ne 1 -or
            [regex]::Matches($template,[regex]::Escape($forwardAnchor)).Count -ne 1) { throw 'Numeric rejection nft insertion anchors are missing or ambiguous.' }
        $rejectGate = '        iifname "br-lan" meta nfproto ipv4 meta mark & 0x60000000 == 0 jump reject_marked'
        $rejectChains = @(
            '    chain reject_marked {'
            '        meta nfproto ipv4 meta l4proto tcp reject with tcp reset'
            '        meta nfproto ipv4 meta l4proto != tcp reject with icmp type port-unreachable'
            '    }'
            '    chain reject_input {'
            '        type filter hook input priority -1; policy accept;'
            $rejectGate
            '    }'
        ) -join "`n"
        $template = $template.Replace($classifyAnchor, $classifyAnchor + "`n" + ($rejectMatches.ToArray() -join "`n"))
        $template = $template.Replace($guardAnchor, $rejectChains + "`n" + $guardAnchor)
        $template = $template.Replace($forwardAnchor, $forwardAnchor + "`n" + $rejectGate)
    }
    $values = @{
        '__SB_NETWORKS__' = @([SingBoxSameType.Ranges]::CIDRs($Policy.ip_intervals))
        '__SB_DPORTS__' = @($Policy.destination_intervals | ForEach-Object { if ($_.Start -eq $_.End) { [string]$_.Start } else { [string]$_.Start + '-' + [string]$_.End } })
        '__SB_SPORTS__' = @($Policy.source_intervals | ForEach-Object { if ($_.Start -eq $_.End) { [string]$_.Start } else { [string]$_.Start + '-' + [string]$_.End } })
    }
    foreach ($key in $values.Keys) {
        $elements = ''
        if (@($values[$key]).Count) { $elements = 'elements = { ' + ($values[$key] -join ', ') + ' };' }
        $template = $template.Replace($key, $elements)
    }
    return $template.Replace("`r`n", "`n").TrimEnd([char]10) + "`n"
}

function Get-OpenWrtNumericTrafficRules {
    param([Parameter(Mandatory)]$Configuration)
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
    Assert-EffectiveDirectConfiguration -Configuration $Configuration

    $sourceRules = @($Configuration.route.rules)
    if ($sourceRules.Count -lt 2) { throw 'Final Linux route policy is missing its validated DNS-in prelude.' }
    $hijackRule = $sourceRules[1]
    $hijackFields = @($hijackRule.PSObject.Properties.Name | Sort-Object)
    if (($hijackFields -join ',') -cne 'action,inbound' -or
        $hijackRule.action -cne 'hijack-dns' -or @($hijackRule.inbound).Count -ne 1 -or
        $hijackRule.inbound[0] -cne 'dns-in') {
        throw 'Only the exact validated dns-in hijack prelude may be removed before numeric policy conversion.'
    }

    $numericRules = New-Object 'System.Collections.Generic.List[object]'
    $numericRules.Add($sourceRules[0])
    for ($routeIndex = 2; $routeIndex -lt $sourceRules.Count; $routeIndex++) {
        $numericRules.Add($sourceRules[$routeIndex])
    }
    return ,$numericRules.ToArray()
}

function Write-NftAdapterFromSnapshot {
    param([string]$SourceRoot,[string]$OutputDirectory,[string]$SingBoxPath,[ValidateSet('off-v1','ctmark-v1')][string]$ConnectionCacheMode='off-v1')
    $config = Read-StrictJsonFile -Path (Join-Path $SourceRoot 'sing-box-openwrt.json')
    $numericRules = Get-OpenWrtNumericTrafficRules -Configuration $config
    if (-not $config.route -or -not $config.route.rule_set -or -not $config.route.rules) { throw 'Final Linux route policy is missing rule-set references.' }
    $setsByTag = @{}
    foreach ($set in $config.route.rule_set) {
        if ($set.tag -cnotmatch '^[A-Za-z0-9_-]+$' -or $set.path -cnotmatch '^rule-set/[A-Za-z0-9_-]+\.srs$' -or $setsByTag.ContainsKey([string]$set.tag)) { throw 'Unsafe or duplicate source SRS identifier.' }
        $setsByTag[[string]$set.tag] = Join-Path $SourceRoot $set.path
    }
    $referencedTags = New-Object 'System.Collections.Generic.List[string]'
    $seenTags = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    for ($routeIndex = 1; $routeIndex -lt $numericRules.Count; $routeIndex++) {
        foreach ($tagValue in @($numericRules[$routeIndex].rule_set)) {
            $tag = [string]$tagValue
            if (-not $setsByTag.ContainsKey($tag)) { throw ('Route references a missing numeric SRS: ' + $tag) }
            if ($seenTags.Add($tag)) { $referencedTags.Add($tag) }
        }
    }
    $temporary = New-OpenWrtTaskScratchDirectory -Prefix 'sb-nft-decompile'
    try {
        $sets = @{}
        foreach ($tag in $referencedTags) {
            $decoded = Join-Path $temporary ($tag + '.json')
            & $SingBoxPath rule-set decompile --output $decoded $setsByTag[$tag] | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Official SRS decompile failed.' }
            $sets[$tag] = Read-StrictJsonFile -Path $decoded
        }
        $policy = Get-NumericKernelPolicy -Rules $numericRules -RuleSets $sets
        $useConnectionCache = $ConnectionCacheMode -ceq 'ctmark-v1'
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'routing-policy.nft'), (ConvertTo-NftKernelPolicy -Policy $policy -ConnectionVerdictCache:$useConnectionCache), (New-Object Text.UTF8Encoding($false)))
        return [pscustomobject]@{ numeric_predicates=$policy.numeric_predicates; cidrs=@([SingBoxSameType.Ranges]::CIDRs($policy.ip_intervals)).Count; ip_intervals=@($policy.ip_intervals).Count; destination_intervals=@($policy.destination_intervals).Count; source_intervals=@($policy.source_intervals).Count; decompiled_srs_count=$referencedTags.Count }
    } finally {
        Remove-OpenWrtTaskScratchDirectory -Path $temporary -Prefix 'sb-nft-decompile'
    }
}
