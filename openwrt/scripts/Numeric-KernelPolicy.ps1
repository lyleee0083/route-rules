# Positive, pre-resolved IPv4 policy. No per-CIDR firewall expansion or AWK code.
Set-StrictMode -Version 2.0
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path (Join-Path $projectRoot 'scripts') 'SameTypeDirectPolicy.ps1')

function Get-NumericKernelPolicy {
    param([Parameter(Mandatory)][object[]]$Rules,[Parameter(Mandatory)][hashtable]$RuleSets)
    if (-not $Rules.Count -or $Rules[0].action -ne 'reject' -or $Rules[0].ip_version -ne 6) { throw 'IPv6 rejection must be first.' }
    $networks=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $ports=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $sources=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $deniedNetworks=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $deniedPorts=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $deniedSources=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    $numeric=0
    foreach ($route in @($Rules | Select-Object -Skip 1)) {
        $fields = @($route.PSObject.Properties.Name | Sort-Object) -join ','
        $reject = $route.action -ceq 'reject' -and ($fields -ceq 'action,rule_set' -or
            ($fields -ceq 'action,method,no_drop,rule_set' -and $route.method -ceq 'default' -and $route.no_drop -is [bool] -and $route.no_drop))
        $direct = $route.action -ceq 'route' -and $fields -ceq 'action,outbound,rule_set' -and $route.outbound -ceq 'direct'
        if ((-not $reject -and -not $direct) -or @($route.rule_set).Count -ne 1) { throw 'Only resolved numeric reject and direct predicates are accepted.' }
        $tag=[string]$route.rule_set
        if (-not $RuleSets.ContainsKey($tag)) { throw 'Missing numeric SRS.' }
        $networkTarget=$networks; $destinationTarget=$ports; $sourceTarget=$sources
        if ($reject) { $networkTarget=$deniedNetworks; $destinationTarget=$deniedPorts; $sourceTarget=$deniedSources }
        foreach ($rule in @($RuleSets[$tag].rules)) {
            $fields=@($rule.PSObject.Properties.Name)
            if (-not $fields.Count) { throw 'Empty predicate is forbidden.' }
            if ($fields.Count -eq 1 -and $fields[0] -eq 'ip_cidr') {
                foreach ($value in @($rule.ip_cidr)) {
                    $range=[SingBoxSameType.Ranges]::IP([string]$value)
                    if ($range.Bits -ne 32) { throw 'IPv6 addresses are forbidden.' }
                    $networkTarget.Add($range)
                }
            } elseif (-not @($fields | Where-Object { $_ -notin @('port','port_range') }).Count) {
                foreach ($range in (Get-SameTypePortRanges @($rule) port)) { $destinationTarget.Add($range) }
            } elseif (-not @($fields | Where-Object { $_ -notin @('source_port','source_port_range') }).Count) {
                foreach ($range in (Get-SameTypePortRanges @($rule) source_port)) { $sourceTarget.Add($range) }
            } else { throw 'Mixed-type or unsupported predicate; refusing a lossy fast-path conversion.' }
            $numeric++
        }
    }
    $merged=[SingBoxSameType.Ranges]::Merge($networks.ToArray())
    $cidrs=@([SingBoxSameType.Ranges]::CIDRs($merged))
    $destinationRanges=[SingBoxSameType.Ranges]::Merge($ports.ToArray())
    $sourceRanges=[SingBoxSameType.Ranges]::Merge($sources.ToArray())
    [pscustomobject][ordered]@{
        version=1; mode='dns-domains-only-numeric-traffic-positive-kernel-sets'
        reject_ipv6=$true; numeric_predicates=$numeric
        ip_cidr=$cidrs
        port_ranges=@($destinationRanges | ForEach-Object { [pscustomobject]@{start=[int]$_.Start;end=[int]$_.End} })
        source_port_ranges=@($sourceRanges | ForEach-Object { [pscustomobject]@{start=[int]$_.Start;end=[int]$_.End} })
        ip_intervals=$merged; destination_intervals=$destinationRanges; source_intervals=$sourceRanges
        reject_ip_intervals=[SingBoxSameType.Ranges]::Merge($deniedNetworks.ToArray())
        reject_destination_intervals=[SingBoxSameType.Ranges]::Merge($deniedPorts.ToArray())
        reject_source_intervals=[SingBoxSameType.Ranges]::Merge($deniedSources.ToArray())
        fallback_numeric_predicates=0
    }
}
