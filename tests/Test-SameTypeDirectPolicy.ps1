Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'SameTypeDirectPolicy.ps1')
function Match-Domain {
    param($Rule,[string]$Name)
    foreach ($value in (Get-SameTypeValues $Rule domain)) { if ($Name -ieq $value) { return $true } }
    foreach ($value in (Get-SameTypeValues $Rule domain_suffix)) { if ($Name -ieq $value -or $Name.EndsWith('.'+$value,[StringComparison]::OrdinalIgnoreCase)) { return $true } }
    foreach ($value in (Get-SameTypeValues $Rule domain_regex)) { if ([regex]::IsMatch($Name,$value)) { return $true } }
    return $false
}
$raw='{"version":2,"groups":[{"sequence":1,"id":"d0","action":"direct","rules":[{"domain":["keep.parent.test"]}]},{"sequence":2,"id":"p0","action":"proxy","rules":[{"domain":["a.parent.test","keep.parent.test"],"domain_suffix":["b.parent.test","blocked.test"]}]},{"sequence":3,"id":"pport","action":"proxy","rules":[{"port_range":["80:100"]}]},{"sequence":4,"id":"dip","action":"direct","rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::/120"]}]},{"sequence":5,"id":"dparent","action":"direct","rules":[{"domain_suffix":["parent.test","blocked.test"]}]},{"sequence":6,"id":"pip","action":"proxy","rules":[{"ip_cidr":["198.51.100.64/26","2001:db9::40/122"]}]},{"sequence":7,"id":"dport","action":"direct","rules":[{"port_range":["0:65535"]},{"source_port":[80]}]},{"sequence":8,"id":"dip2","action":"direct","rules":[{"ip_cidr":["198.51.100.0/24","2001:db9::/120"]}]}]}'
$doc=$raw | ConvertFrom-Json
$plan=Get-SameTypeDirectPlan $doc
$json=ConvertTo-Json -InputObject $plan -Depth 100 -Compress
if ($json -match '"(invert|type|exclude_rule_sets)"|routing.*proxy') { throw 'Final plan contains exclusion/proxy dependencies.' }
if ($json -match '2001:|"ipv6"|"inet6"') { throw 'IPv6 input must not survive into published direct predicates.' }
$order=@($plan | ForEach-Object Kind | Select-Object -Unique)
if (($order -join ',') -ne 'domain,port,ip') { throw 'Type order must come from first occurrence, including proxy source predicates.' }
$domainRules=@($plan | Where-Object HasDomain | ForEach-Object { $_.Rules })
$domainRules=ConvertTo-Json -InputObject $domainRules -Depth 100 -Compress | ConvertFrom-Json
$names=New-Object 'System.Collections.Generic.List[string]'
foreach ($first in @('a','b','x','1','-','_')) {
    $names.Add($first+'.parent.test')
    foreach ($second in @('a','b','x','1','-','_')) {
        $names.Add($first+$second+'.parent.test')
        $names.Add($second+'.'+$first+'.parent.test')
        foreach ($third in @('a','b','x','1','-','_')) {
            $names.Add($first+$second+$third+'.parent.test')
            $names.Add($third+'.'+$second+'.'+$first+'.parent.test')
        }
    }
}
foreach ($name in @('parent.test','keep.parent.test','x.keep.parent.test','blocked.test','x.blocked.test','other.test','A.PARENT.TEST','aa.parent.test','a1.parent.test','1a.parent.test')) { $names.Add($name) }
$cases=0
foreach ($name in $names) {
    $expected=$false; $found=$false
    foreach ($group in $doc.groups) {
        foreach ($rule in $group.rules) {
            if ((Match-Domain $rule $name)) { $expected=$group.action -eq 'direct'; $found=$true; break }
        }
        if ($found) { break }
    }
    $actual=$false
    foreach ($rule in $domainRules) { if (Match-Domain $rule $name) { $actual=$true; break } }
    if ($actual -ne $expected) { throw ('Domain same-type priority changed: '+$name) }
    $cases++
}
$portRules=@($plan | Where-Object { $_.Tag -match '-port$' } | ForEach-Object { $_.Rules })
$portRules=ConvertTo-Json -InputObject $portRules -Depth 100 -Compress | ConvertFrom-Json
$ports=Get-SameTypePortRanges $portRules port
for ($port=0;$port -le 65535;$port++) {
    $actual=[SingBoxSameType.Ranges]::Contains($ports,$port,16)
    if ($actual -ne ($port -lt 80 -or $port -gt 100)) { throw 'Port interval residual changed.' }
    $cases++
}
$ipItems=@($plan | Where-Object { $_.Kind -eq 'ip' })
foreach ($pair in @(@('192.0.2.',32,$false),@('198.51.100.',32,$true),@('2001:db8::',128,$false),@('2001:db9::',128,$true))) {
    $all=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    foreach ($item in $ipItems) { foreach ($cidr in $item.Rules[0].ip_cidr) { $all.Add([SingBoxSameType.Ranges]::IP($cidr)) } }
    if ($pair[1] -eq 128) {
        # Exercise generic interval arithmetic independently of IPv4-only output.
        $all.Clear()
        $candidate=[SingBoxSameType.Ranges]::IP($pair[0]+'/120')
        $blockers=@()
        if ($pair[2]) { $blockers=@([SingBoxSameType.Ranges]::IP($pair[0]+'40/122')) }
        foreach ($range in [SingBoxSameType.Ranges]::Subtract(@($candidate),$blockers)) { $all.Add($range) }
    }
    for ($number=0;$number -lt 256;$number++) {
        $suffix=[string]$number; if ($pair[1] -eq 128) { $suffix=$number.ToString('x') }
        $address=[SingBoxSameType.Ranges]::IP($pair[0]+$suffix)
        $actual=[SingBoxSameType.Ranges]::Contains($all.ToArray(),$address.Start,$pair[1])
        $expected=-not ($pair[2] -and $number -ge 64 -and $number -le 127)
        if ($actual -ne $expected) { throw ('IP parent/child residual changed: '+$pair[0]+$suffix) }
        $cases++
    }
}
foreach ($cidr in @('0.0.0.0/0','255.255.255.255/32','::/0','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128')) {
    $original=[SingBoxSameType.Ranges]::IP($cidr)
    $roundtrip=[SingBoxSameType.Ranges]::IP([SingBoxSameType.Ranges]::CIDRs(@($original))[0])
    if ($original.Start -ne $roundtrip.Start -or $original.End -ne $roundtrip.End) { throw 'CIDR boundary roundtrip failed.' }
}
$invalid='{"version":2,"groups":[{"sequence":1,"id":"x","action":"direct","rules":[{"domain":["x.test"],"port":[443]}]}]}' | ConvertFrom-Json
$rejected=$false
try { Get-SameTypeDirectPlan $invalid | Out-Null } catch { $rejected=$_.Exception.Message -match 'Mixed-type' }
if (-not $rejected) { throw 'Mixed AND input must not be silently changed to OR.' }
$emptyValues = @(Get-SameTypeValues ([ordered]@{domain=@()}) 'domain')
if ($emptyValues.Count -ne 0) { throw 'An empty rule value array must remain empty.' }
foreach ($field in @('domain','domain_suffix','ip_cidr','port','source_port')) {
    $invalidRule = [ordered]@{}
    $invalidRule[$field] = @($null)
    $invalid = [pscustomobject]@{
        version = 2
        conflict_policy = [pscustomobject]@{ earlier_rule='wins'; later_overlap='ordered-first-match' }
        groups = @([pscustomobject]@{ sequence=1; id='null-value'; action='direct'; rules=@($invalidRule) })
    }
    $rejected = $false
    try { Get-SameTypeDirectPlan $invalid | Out-Null } catch { $rejected = $_.Exception.Message -match 'Null rule value' }
    if (-not $rejected) { throw "A null '$field' value must not be dropped or coerced." }
}
$compacted = [SingBoxSameType.PositiveDomainCompactor]::Compact(
    [string[]]@('www.example.test','api.example.test','keep.test','keep.test'),
    [string[]]@('example.test','deep.example.test','foo.test')
)
if (($compacted[0] -join ',') -ne 'keep.test' -or ($compacted[1] -join ',') -ne 'example.test,foo.test') {
    throw 'Positive exact/suffix compaction did not retain the finite-domain union.'
}
$unionDocument = @'
{"version":2,"groups":[
  {"sequence":1,"id":"exact-child","action":"direct","rules":[{"domain":["host.example.test"]}]},
  {"sequence":2,"id":"suffix-parent","action":"direct","rules":[{"domain_suffix":["example.test"]}]},
  {"sequence":3,"id":"suffix-child","action":"direct","rules":[{"domain_suffix":["sub.example.test"]}]},
  {"sequence":4,"id":"exact-other","action":"direct","rules":[{"domain":["other.test"]}]}
]}
'@ | ConvertFrom-Json
$unionPlan = Get-SameTypeDirectPlan -Document $unionDocument
$unionTags = @($unionPlan | ForEach-Object { $_.Tag })
if (($unionTags -join ',') -cne 'routing-direct-domain') {
    throw 'Cross-group DNS-union compaction did not aggregate the effective domain family into its stable tag.'
}
$parentItem = @($unionPlan | Where-Object { $_.Tag -ceq 'routing-direct-domain' })[0]
if ($parentItem.Rules[0].domain_suffix[0] -cne 'example.test' -or $parentItem.SourceGroups -notcontains 'exact-child' -or
    $parentItem.SourceGroups -notcontains 'suffix-child' -or ($parentItem.SourceSequences -join ',') -cne '1,2,3,4') {
    throw 'Cross-group compaction did not preserve source-group provenance on the retained covering predicate.'
}
if ($script:SameTypeDomainCompactionSummary.NativeBefore -ne 4 -or
    $script:SameTypeDomainCompactionSummary.NativeAfter -ne 2 -or
    $script:SameTypeDomainCompactionSummary.Removed -ne 2 -or
    $script:SameTypeDomainCompactionSummary.RegexBefore -ne $script:SameTypeDomainCompactionSummary.RegexAfter -or
    $script:SameTypeDomainCompactionSummary.GroupsAfter -ne 1 -or $script:SameTypeDomainCompactionSummary.FamilyFilesAfter -ne 1) {
    throw 'Cross-group native-domain reduction counts are incorrect or positive regex predicates changed.'
}
$unionRules = @($unionPlan | ForEach-Object { $_.Rules })
$unionRules = ConvertTo-Json -InputObject $unionRules -Depth 100 -Compress | ConvertFrom-Json
foreach ($name in @('example.test','host.example.test','sub.example.test','a.sub.example.test','other.test','unrelated.test')) {
    $expected = $name -ieq 'example.test' -or $name -ieq 'host.example.test' -or
        $name -ieq 'other.test' -or $name.EndsWith('.example.test',[StringComparison]::OrdinalIgnoreCase)
    $actual = $false
    foreach ($rule in $unionRules) { if (Match-Domain $rule $name) { $actual = $true; break } }
    if ($actual -ne $expected) { throw ('Cross-group domain union changed positive matching for ' + $name) }
}
$regexRules = @($domainRules | ForEach-Object { $_.domain_regex } | Where-Object { $null -ne $_ })
if (-not $regexRules.Count -or @($regexRules | Where-Object { $_ -match '\(\?[=!<]|\[\^' }).Count) {
    throw 'Positive complement regexes must remain present and free of negative constructs.'
}
Write-Output ('Same-type policy passed: '+$cases+' domain/port/IP decisions and independent IPv6 arithmetic; IPv6 omitted from final direct predicates; partial suffix positive automata and first-occurrence block order.')
