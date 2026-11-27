Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'Nft-KernelPolicy.ps1')
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$projectRoot=Split-Path -Parent $openWrtRoot
$snapshotRoot=Join-Path (Join-Path $openWrtRoot 'inputs') 'linux'
$snapshotConfigPath=Join-Path $snapshotRoot 'sing-box-openwrt.json'
if (-not (Test-Path -LiteralPath $snapshotConfigPath -PathType Leaf)) { throw 'Canonical final Linux snapshot is missing for route-prelude coverage.' }
$snapshotConfig=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($snapshotConfigPath)) -ErrorAction Stop
$numericSourceRules=Get-OpenWrtNumericTrafficRules -Configuration $snapshotConfig
if ($numericSourceRules.Count -ne (@($snapshotConfig.route.rules).Count - 1) -or
    $numericSourceRules[0].action -cne 'reject' -or $numericSourceRules[0].ip_version -ne 6 -or
    ($numericSourceRules[1] | ConvertTo-Json -Depth 20 -Compress) -cne ($snapshotConfig.route.rules[2] | ConvertTo-Json -Depth 20 -Compress)) {
    throw 'Strict nft route conversion must preserve IPv6 rejection and numeric order while removing exactly one dns-in hijack.'
}
$malformedHijackCases=New-Object 'System.Collections.Generic.List[object]'
$wrongInbound=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $snapshotConfig -Depth 100 -Compress)
$wrongInbound.route.rules[1].inbound=@('tun')
$malformedHijackCases.Add($wrongInbound)
$extraHijackField=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $snapshotConfig -Depth 100 -Compress)
$extraHijackField.route.rules[1] | Add-Member -NotePropertyName tag -NotePropertyValue 'unexpected-dns-route'
$malformedHijackCases.Add($extraHijackField)
foreach ($malformedHijack in $malformedHijackCases) {
    $malformedRejected=$false
    try { Get-OpenWrtNumericTrafficRules -Configuration $malformedHijack | Out-Null } catch { $malformedRejected=$true }
    if (-not $malformedRejected) { throw 'Nft adapter accepted a malformed or expanded DNS hijack prelude.' }
}
function Read-NftSetRanges {
    param([string]$Text,[string]$Name,[switch]$IP)
    $block=[regex]::Match($Text,'(?s)set '+[regex]::Escape($Name)+' \{(.*?)\n    \}')
    if (-not $block.Success) { throw 'Missing named nft set.' }
    $elements=[regex]::Match($block.Groups[1].Value,'elements = \{ (.*?) \};')
    $ranges=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    if ($elements.Success) {
        foreach ($item in $elements.Groups[1].Value.Split(',')) {
            $value=$item.Trim()
            if ($IP) { $ranges.Add([SingBoxSameType.Ranges]::IP($value)) }
            elseif ($value -cmatch '^(\d+)(?:-(\d+))?$') {
                $start=[int]$Matches[1]; $end=$start
                if ($Matches[2]) { $end=[int]$Matches[2] }
                $ranges.Add([SingBoxSameType.Ranges]::Port($start,$end))
            } else { throw 'Non-numeric nft port element.' }
        }
    }
    return ,$ranges.ToArray()
}
$rules=@([pscustomobject]@{ip_version=6;action='reject'})
$sets=@{}
foreach ($item in @(
    @('net',[pscustomobject]@{ip_cidr=@('0.0.0.0/32','10.0.0.0/8','128.0.0.0/1')}),
    @('dst',[pscustomobject]@{port=@(0,123,65535);port_range=@('80:100','443:445')}),
    @('src',[pscustomobject]@{source_port=@(123);source_port_range=@('5000:5002')})
)) { $sets[$item[0]]=[pscustomobject]@{rules=@($item[1])}; $rules += [pscustomobject]@{rule_set=$item[0];action='route';outbound='direct'} }
$policy=Get-NumericKernelPolicy -Rules $rules -RuleSets $sets
$text=ConvertTo-NftKernelPolicy $policy
$proxyMark=[Convert]::ToInt64('20000000',16)
$directMark=[Convert]::ToInt64('60000000',16)
if ($text -match 'ct state \{ new, established \} ct direction original|__SB_ROUTER_ADDRESSES__') { throw 'The default nft policy must not enable or contain the optional verdict cache.' }
$cacheText=ConvertTo-NftKernelPolicy -Policy $policy -ConnectionVerdictCache
$cacheFastRules=@($cacheText -split "`n" | Where-Object { $_ -match '^\s*ip saddr @lan_net ip saddr != \{ __SB_ROUTER_ADDRESSES__ \} ct state \{ new, established \} ct direction original ct status & 0x9 == 0x8 meta l4proto \{ tcp, udp \} ct mark & 0x60000000 == (?:0x60000000|0x20000000) meta mark set \(meta mark & 0x9fffffff\) \| (?:0x60000000|0x20000000) return$' })
if ($cacheFastRules.Count -ne 2 -or @([regex]::Matches($cacheText,'__SB_ROUTER_ADDRESSES__')).Count -ne 2) { throw 'Cache mode must contain exactly two LAN-source/router-source-safe direct and proxy restore branches.' }
$replyPosition=$cacheText.IndexOf('ct direction reply return',[System.StringComparison]::Ordinal)
$firstFastPosition=$cacheText.IndexOf('ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ }',[System.StringComparison]::Ordinal)
$secondFastPosition=$cacheText.IndexOf('ip saddr @lan_net ip saddr != { __SB_ROUTER_ADDRESSES__ }',$firstFastPosition+1,[System.StringComparison]::Ordinal)
$fullClassifierPosition=$cacheText.IndexOf("`n        meta mark set (meta mark & 0x9fffffff) | 0x20000000",$secondFastPosition,[System.StringComparison]::Ordinal)+1
if ($replyPosition -lt 0 -or $firstFastPosition -le $replyPosition -or $secondFastPosition -le $firstFastPosition -or $fullClassifierPosition -le $secondFastPosition) { throw 'Verdict cache must follow ingress, IPv4, local/LAN destination and reply exclusions, then precede the original full classifier.' }
$rejectRules = @($rules[0])
foreach ($tag in @('net','dst','src')) {
    $rejectRules += [pscustomobject]@{rule_set=$tag;action='reject';method='default';no_drop=$true}
}
$rejectPolicy = Get-NumericKernelPolicy -Rules $rejectRules -RuleSets $sets
foreach ($useCache in @($false,$true)) {
    $rejectText = ConvertTo-NftKernelPolicy -Policy $rejectPolicy -ConnectionVerdictCache:$useCache
    $replyReturn = $rejectText.IndexOf('ct direction reply return')
    $nextVerdict = if ($useCache) { $rejectText.IndexOf('ct state { new, established }') } else { $rejectText.IndexOf('jump direct') }
    $classify = [regex]::Match($rejectText,'(?ms)^    chain classify \{\n(?<rules>.*?)^    \}')
    $forward = [regex]::Match($rejectText,'(?ms)^    chain guard \{\n(?<rules>.*?)^    \}')
    if (-not $classify.Success -or $classify.Groups['rules'].Value -match '\breject with\b' -or -not $forward.Success) {
        throw 'Numeric rejection must keep the prerouting classifier compatible with Linux 5.4.'
    }
    foreach ($selector in @('ip daddr @reject_net','meta l4proto { tcp, udp } th dport @reject_dport','meta l4proto { tcp, udp } th sport @reject_sport')) {
        $rule = $selector + ' meta mark set (meta mark & 0x9fffffff) return'
        $position = $rejectText.IndexOf($rule)
        if ($replyReturn -lt 0 -or $position -le $replyReturn -or $position -ge $nextVerdict) {
            throw 'Reject matches must preserve unrelated bits and return before cache reuse or normal classification.'
        }
    }
    $guardRules = $forward.Groups['rules'].Value -split "`n"
    $rejectGate = 'iifname "br-lan" meta nfproto ipv4 meta mark & 0x60000000 == 0 jump reject_marked'
    $inputRules = [regex]::Match($rejectText,'(?ms)^    chain reject_input \{\n(?<rules>.*?)^    \}').Groups['rules'].Value -split "`n"
    $actions = [regex]::Match($rejectText,'(?ms)^    chain reject_marked \{\n(?<rules>.*?)^    \}').Groups['rules'].Value.TrimEnd("`n")
    $expectedActions = "        meta nfproto ipv4 meta l4proto tcp reject with tcp reset`n        meta nfproto ipv4 meta l4proto != tcp reject with icmp type port-unreachable"
    if ($guardRules[0].Trim() -cne 'type filter hook forward priority -1; policy accept;' -or $guardRules[1].Trim() -cne $rejectGate -or
        $inputRules.Count -ne 3 -or $inputRules[0].Trim() -cne 'type filter hook input priority -1; policy accept;' -or
        $inputRules[1].Trim() -cne $rejectGate -or $actions -cne $expectedActions) {
        throw 'The forward and local-input hooks must consume the rejection mark before delivery and emit the matching protocol error.'
    }
}
$fastRegion=$cacheText.Substring($firstFastPosition,$fullClassifierPosition-$firstFastPosition)
if ($fastRegion -match '\bct mark set\b' -or $fastRegion -notmatch 'ct state \{ new, established \}' -or $fastRegion -notmatch 'ct direction original' -or $fastRegion -notmatch 'ct status & 0x9 == 0x8' -or $fastRegion -notmatch 'meta l4proto \{ tcp, udp \}' -or
    $fastRegion -notmatch 'ct mark & 0x60000000 == 0x60000000 meta mark set \(meta mark & 0x9fffffff\) \| 0x60000000 return' -or
    $fastRegion -notmatch 'ct mark & 0x60000000 == 0x20000000 meta mark set \(meta mark & 0x9fffffff\) \| 0x20000000 return') { throw 'Verdict cache must restore only the two existing owned verdicts, preserve unrelated packet mark bits, and avoid connmark mutation.' }
$eligibilityCases=@(
    [pscustomobject]@{Name='first-unconfirmed-new';State='new';Status=0;Direction='original';Protocol='udp';Source='lan';Mark=$directMark;Expected=$false},
    [pscustomobject]@{Name='confirmed-one-way-udp-new';State='new';Status=8;Direction='original';Protocol='udp';Source='lan';Mark=$directMark;Expected=$true},
    [pscustomobject]@{Name='confirmed-established-tcp';State='established';Status=8;Direction='original';Protocol='tcp';Source='lan';Mark=$proxyMark;Expected=$true},
    [pscustomobject]@{Name='expected-confirmed-new';State='new';Status=9;Direction='original';Protocol='udp';Source='lan';Mark=$directMark;Expected=$false},
    [pscustomobject]@{Name='expected-confirmed-established';State='established';Status=9;Direction='original';Protocol='tcp';Source='lan';Mark=$proxyMark;Expected=$false},
    [pscustomobject]@{Name='invalid';State='invalid';Status=8;Direction='original';Protocol='udp';Source='lan';Mark=$directMark;Expected=$false},
    [pscustomobject]@{Name='untracked';State='untracked';Status=8;Direction='original';Protocol='tcp';Source='lan';Mark=$proxyMark;Expected=$false},
    [pscustomobject]@{Name='reply';State='established';Status=8;Direction='reply';Protocol='tcp';Source='lan';Mark=$proxyMark;Expected=$false},
    [pscustomobject]@{Name='unsupported-l4';State='established';Status=8;Direction='original';Protocol='sctp';Source='lan';Mark=$directMark;Expected=$false},
    [pscustomobject]@{Name='router-originated';State='established';Status=8;Direction='original';Protocol='tcp';Source='router';Mark=$directMark;Expected=$false},
    [pscustomobject]@{Name='foreign-verdict';State='established';Status=8;Direction='original';Protocol='tcp';Source='lan';Mark=0x10000000;Expected=$false}
)
foreach ($case in $eligibilityCases) {
    $eligible=(@('new','established') -contains $case.State) -and
        ($case.Direction -ceq 'original') -and
        (([long]$case.Status -band [long]9) -eq [long]8) -and
        (@('tcp','udp') -contains $case.Protocol) -and
        ($case.Source -ceq 'lan') -and
        (([long]$case.Mark -band [long]0x60000000) -in @([long]$directMark,[long]$proxyMark))
    if ($eligible -ne $case.Expected) { throw ('Connection verdict eligibility model failed: '+$case.Name) }
}
$ownedMarkMask=[Convert]::ToInt64('60000000',16)
$retainedMarkMask=[Convert]::ToInt64('9fffffff',16)
$ctMarkPattern='(?m)^\s*meta mark\s*&\s*(?<matchMask>0x[0-9a-fA-F]+)\s*==\s*(?<matchValue>0x[0-9a-fA-F]+)\s+ct mark set\s+\(\s*ct mark\s*&\s*(?<keepMask>0x[0-9a-fA-F]+)\s*\)\s*\|\s*(?<setValue>0x[0-9a-fA-F]+)\s*$'
$ctMarkMatches=[regex]::Matches($text,$ctMarkPattern)
$ctMarkAssignmentCount=[regex]::Matches($text,'(?m)^\s*.*\bct mark set\b').Count
if ($ctMarkAssignmentCount -ne 2 -or $ctMarkMatches.Count -ne 2 -or $text -match '(?m)^\s*.*\bct mark set\s+.*\bmeta mark\b') { throw 'Generated nft policy must use only two constant connmark branches.' }
$ctMarkBranches=@{}
$parsedBranchOrder=New-Object 'System.Collections.Generic.List[long]'
foreach ($ruleMatch in $ctMarkMatches) {
    $matchMask=[Convert]::ToInt64($ruleMatch.Groups['matchMask'].Value.Substring(2),16)
    $matchValue=[Convert]::ToInt64($ruleMatch.Groups['matchValue'].Value.Substring(2),16)
    $keepMask=[Convert]::ToInt64($ruleMatch.Groups['keepMask'].Value.Substring(2),16)
    $setValue=[Convert]::ToInt64($ruleMatch.Groups['setValue'].Value.Substring(2),16)
    if ($matchMask -ne $ownedMarkMask -or $keepMask -ne $retainedMarkMask -or $setValue -ne $matchValue) { throw 'Generated connmark branch changed its owned bits, retained mask or constant assignment.' }
    $branchKey=$matchValue.ToString('X8')
    if ($ctMarkBranches.ContainsKey($branchKey)) { throw 'Duplicate generated connmark branch.' }
    $ctMarkBranches[$branchKey]=[pscustomobject]@{MatchMask=$matchMask;MatchValue=$matchValue;KeepMask=$keepMask;SetValue=$setValue}
    $parsedBranchOrder.Add($matchValue)
}
if ($ctMarkBranches.Count -ne 2 -or -not $ctMarkBranches.ContainsKey($directMark.ToString('X8')) -or -not $ctMarkBranches.ContainsKey($proxyMark.ToString('X8')) -or $parsedBranchOrder[0] -ne $directMark -or $parsedBranchOrder[1] -ne $proxyMark) { throw 'Generated nft policy is missing the ordered direct and proxy connmark branches.' }
$replyReturnIndex=$text.IndexOf('ct direction reply return',[System.StringComparison]::Ordinal)
$proxyClassificationIndex=$text.IndexOf('meta mark set (meta mark & 0x9fffffff) | 0x20000000',[System.StringComparison]::Ordinal)
$directJumpIndex=$text.IndexOf('        jump direct',[System.StringComparison]::Ordinal)
$firstConnmarkBranchIndex=$text.IndexOf('meta mark & 0x60000000 == 0x60000000 ct mark set',[System.StringComparison]::Ordinal)
if ($replyReturnIndex -lt 0 -or $proxyClassificationIndex -le $replyReturnIndex -or $directJumpIndex -le $proxyClassificationIndex -or $firstConnmarkBranchIndex -le $directJumpIndex) { throw 'Original-direction classification and reply bypass ordering changed.' }
$connmarkCases=0
$otherCtBitPatterns=@('00000000','00001234','10000000','80000000','90001234','9fffffff')
$priorOwnedMarkPatterns=@('00000000','20000000','40000000','60000000')
foreach ($metaMark in @($proxyMark,$directMark)) {
    $selectedBranches=@()
    foreach ($candidate in $ctMarkBranches.Values) {
        if (($metaMark -band $candidate.MatchMask) -eq $candidate.MatchValue) { $selectedBranches+= $candidate }
    }
    if ($selectedBranches.Count -ne 1) { throw 'Generated connmark predicates do not select exactly one branch for the original packet mark.' }
    $selectedBranch=$selectedBranches[0]
    foreach ($otherCtBitsText in $otherCtBitPatterns) {
        $otherCtBits=[Convert]::ToInt64($otherCtBitsText,16)
        foreach ($priorOwnedBitsText in $priorOwnedMarkPatterns) {
            $priorOwnedBits=[Convert]::ToInt64($priorOwnedBitsText,16)
            $originalCtMark=$otherCtBits -bor $priorOwnedBits
            $generatedCtMark=($originalCtMark -band $selectedBranch.KeepMask) -bor $selectedBranch.SetValue
            $expectedCtMark=($originalCtMark -band $retainedMarkMask) -bor $metaMark
            if (($generatedCtMark -band $retainedMarkMask) -ne ($originalCtMark -band $retainedMarkMask) -or ($generatedCtMark -band $ownedMarkMask) -ne $metaMark -or $generatedCtMark -ne $expectedCtMark) { throw 'Generated connmark expression failed to preserve other ct bits or replace the proxy/direct verdict.' }
            $connmarkCases++
        }
    }
}
$dst=Read-NftSetRanges $text direct_dport
$src=Read-NftSetRanges $text direct_sport
$net=Read-NftSetRanges $text direct_net -IP
$cases=0
for ($value=0;$value -le 65535;$value++) {
    $expected=($value -eq 0 -or $value -eq 123 -or $value -eq 65535 -or ($value -ge 80 -and $value -le 100) -or ($value -ge 443 -and $value -le 445))
    if ([SingBoxSameType.Ranges]::Contains($dst,$value,16) -ne $expected) { throw 'nft destination port serialization changed policy.' }
    $expected=($value -eq 123 -or ($value -ge 5000 -and $value -le 5002))
    if ([SingBoxSameType.Ranges]::Contains($src,$value,16) -ne $expected) { throw 'nft source port serialization changed policy.' }
    $cases+=2
}
foreach ($sample in @(@('0.0.0.0',$true),@('0.0.0.1',$false),@('9.255.255.255',$false),@('10.0.0.0',$true),@('10.255.255.255',$true),@('11.0.0.0',$false),@('127.255.255.255',$false),@('128.0.0.0',$true),@('255.255.255.255',$true))) {
    $ip=[SingBoxSameType.Ranges]::IP($sample[0])
    if ([SingBoxSameType.Ranges]::Contains($net,$ip.Start,32) -ne $sample[1]) { throw 'nft IPv4 boundary changed policy.' }
    $cases++
}
$sets.net.rules=@([pscustomobject]@{ip_cidr=@('0.0.0.0/0')})
$all=ConvertTo-NftKernelPolicy (Get-NumericKernelPolicy -Rules $rules -RuleSets $sets)
if ($all -notmatch 'elements = \{ 0\.0\.0\.0/0 \};' -or $all -match '0\.0\.0\.0/1, 128\.0\.0\.0/1') { throw 'nft /0 must not inherit the ipset representation workaround.' }
$empty=Get-NumericKernelPolicy -Rules @($rules[0]) -RuleSets @{}
$emptyText=ConvertTo-NftKernelPolicy $empty
foreach ($name in @('direct_net','direct_dport','direct_sport')) { $emptyRanges=Read-NftSetRanges $emptyText $name; if (@($emptyRanges).Count -ne 0) { throw 'Empty positive set became a match-all.' } }
foreach ($invalid in @([pscustomobject]@{domain_suffix=@('example.test')},[pscustomobject]@{ip_cidr=@('2001:db8::/32')},[pscustomobject]@{ip_cidr=@('10.0.0.0/8');port=@(443)})) {
    $sets.net.rules=@($invalid);$failed=$false
    try { Get-NumericKernelPolicy -Rules $rules -RuleSets $sets | Out-Null } catch { $failed=$true }
    if (-not $failed) { throw 'Unresolved, mixed, domain or IPv6 traffic predicate accepted.' }
}
if (@([regex]::Matches($text,'(?m)^    set ')).Count -ne 4 -or $text -match '__SB_NETWORKS__|__SB_DPORTS__|__SB_SPORTS__|iptables|ipset|nfqueue|multi_queue' -or
    @([regex]::Matches($text,'__SB_LAN_PREFIXES__')).Count -ne 1) { throw 'Invalid static nft program or leaked legacy/unreleased feature.' }
Write-Output ('nft compiler passed: '+$cases+' independent serialized IPv4/port decisions; '+$connmarkCases+' generated connmark evaluations across both branches, all four prior owned-bit values and six retained-bit patterns; '+$eligibilityCases.Count+' connection-state eligibility cases; validated DNS source shape while removing one dns-in hijack, '+$malformedHijackCases.Count+' malformed hijack fixtures rejected; optional boot-gated cache shape, /0, empty sets and rejected lossy inputs. Target nft grammar/kernel validation remains deferred.')
