if (-not (Get-Command New-OpenWrtTaskScratchDirectory -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1')
}

function ConvertTo-MosdnsDomainLine {
    param(
        [Parameter(Mandatory)][ValidateSet('domain','domain_suffix','domain_regex')][string]$Kind,
        [Parameter(Mandatory)][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\r\n\x00-\x1f]') {
        throw 'Empty or control-containing domain predicate is not publishable.'
    }
    switch ($Kind) {
        'domain' {
            $normalized = $Value.ToLowerInvariant()
            if ($normalized.Length -gt 253 -or $normalized -cnotmatch '^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$') {
                throw ('Unsupported exact domain predicate: ' + $Value)
            }
            foreach ($label in $normalized.Split('.')) {
                if ($label.Length -gt 63) { throw ('Domain label exceeds DNS limits: ' + $Value) }
            }
            return 'full:' + $normalized
        }
        'domain_suffix' {
            $normalized = $Value.ToLowerInvariant()
            if ($normalized.Length -gt 253 -or $normalized -cnotmatch '^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$') {
                throw ('Unsupported suffix domain predicate: ' + $Value)
            }
            foreach ($label in $normalized.Split('.')) {
                if ($label.Length -gt 63) { throw ('Domain label exceeds DNS limits: ' + $Value) }
            }
            return 'domain:' + $normalized
        }
        'domain_regex' {
            if ($Value.Length -gt 1000000 -or $Value -match '\(\?[=!<]|\\[1-9]|\\k<|\(\?P<') {
                throw 'Regex is outside the positive Go RE2 subset or exceeds the compiler budget.'
            }
            return 'regexp:' + $Value
        }
    }
}

function Test-OpenWrtDirectDomainRuleSetTag {
    param([Parameter(Mandatory)][string]$Tag)
    return ($Tag -ceq 'routing-direct-domain' -or $Tag -cmatch '^routing-direct-[0-9]+-domain$')
}

function Get-MosdnsDnsProviderPolicyMetadata {
    return [ordered]@{
        direct_primary='Ali DoH direct egress'
        direct_backup='Tencent DoH direct egress; 300ms hedged fallback with always_standby=false'
        proxy_primary='Cloudflare DoH through sing-box SOCKS'
        proxy_backup='Google DoH through sing-box SOCKS; 2000ms hedged fallback with always_standby=false'
        retryable_rcodes='Drop every response code except NOERROR and NXDOMAIN in both branches; these two valid negative/positive response classes do not trigger fallback.'
        forward_query_timeout_seconds=5
        maximum_no_answer_wait_seconds=[ordered]@{direct=5.3;proxy=7.0}
        fallback_semantics='A backup starts after its threshold or immediately after primary transport failure; the first usable response wins, so a slow but healthy primary can race with the backup.'
        node='Node sequence inherits the ordinary direct provider policy; no separate node provider definition.'
        node_cache='Independent node_cache only, size 65472 and lazy_cache_ttl 0; positive A responses receive TTL 3600 and expired entries are not reused.'
        node_forward_query_timeout_seconds=5
        node_maximum_no_answer_wait_seconds=5.3
        node_parent_resolver_timeout_seconds=5
        node_deadline_note='Node requests reuse the ordinary direct fallback, whose 300ms hedge and 5 second forward exchange limit give a 5.3 second no-answer bound. The existing 5 second parent resolver timeout can stop waiting sooner.'
        metrics_api='127.0.0.1:15357/metrics'
    }
}

function Get-MosdnsAdapterPlanFromSnapshot {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$SingBoxPath
    )
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $root = [IO.Path]::GetFullPath($SourceRoot)
    $configPath = Join-Path $root 'sing-box-openwrt.json'
    $ruleRoot = Join-Path $root 'rule-set'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ruleRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $SingBoxPath -PathType Leaf)) {
        throw 'Final Linux snapshot or official sing-box decompiler is missing.'
    }
    $rootItems = @(Get-ChildItem -LiteralPath $root -Force)
    $ruleItems = @(Get-ChildItem -LiteralPath $ruleRoot -Force)
    if ($rootItems.Count -ne 2 -or @($rootItems | Where-Object { $_.Name -notin @('sing-box-openwrt.json','rule-set') }).Count -ne 0 -or
        @($rootItems + $ruleItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -ne 0 -or
        @($ruleItems | Where-Object { $_.PSIsContainer -or $_.Name -cnotmatch '^[A-Za-z0-9_-]+\.srs$' }).Count -ne 0) {
        throw 'SourceRoot is not the flat final Linux snapshot layout.'
    }

    $configText = [IO.File]::ReadAllText($configPath)
    try { $config = ConvertFrom-Json -InputObject $configText -ErrorAction Stop }
    catch { throw ('Cannot parse final Linux JSON snapshot: ' + $_.Exception.Message) }
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
    Assert-EffectiveDirectConfiguration -Configuration $config
    if (-not $config.dns -or -not $config.route -or -not $config.route.rule_set) { throw 'Final Linux snapshot is missing DNS or rule-set data.' }
    if ($config.dns.final -ne 'dns-proxy') { throw 'Only the approved default-proxy DNS policy is supported.' }
    $dnsServersByTag = @{}
    foreach ($server in @($config.dns.servers)) {
        $tag = [string]$server.tag
        if ([string]::IsNullOrWhiteSpace($tag) -or $dnsServersByTag.ContainsKey($tag)) { throw 'DNS server tags must be present and unique.' }
        $dnsServersByTag[$tag] = $server
    }
    $expectedDnsServerTags = @('dns-direct','dns-direct-backup','dns-proxy','dns-proxy-backup','dns-node','dns-doh-hosts')
    if ($dnsServersByTag.Count -ne $expectedDnsServerTags.Count) { throw 'DNS policy must contain exactly the four providers, dns-node, and the hosts server.' }
    foreach ($tag in $expectedDnsServerTags) {
        if (-not $dnsServersByTag.ContainsKey($tag)) { throw ('Approved DNS server is missing: ' + $tag) }
    }

    $ruleSetsByTag = @{}
    foreach ($set in $config.route.rule_set) {
        if ($set.type -ne 'local' -or $set.format -ne 'binary' -or
            $set.path -cnotmatch '^rule-set/[A-Za-z0-9_-]+\.srs$' -or $ruleSetsByTag.ContainsKey([string]$set.tag)) {
            throw 'Unsupported or duplicate rule-set reference in the final Linux snapshot.'
        }
        $setPath = Join-Path $root $set.path
        if (-not (Test-Path -LiteralPath $setPath -PathType Leaf)) { throw ('Missing final SRS: ' + $set.path) }
        $ruleSetsByTag[[string]$set.tag] = [pscustomobject]@{ Tag=[string]$set.tag; Path=$setPath }
    }
    if ($ruleItems.Count -ne $ruleSetsByTag.Count) { throw 'Snapshot contains missing or unreferenced SRS files.' }
    foreach ($item in $ruleItems) {
        if (-not $ruleSetsByTag.ContainsKey([IO.Path]::GetFileNameWithoutExtension($item.Name))) {
            throw ('Unreferenced final SRS is not accepted: ' + $item.Name)
        }
    }

    $allDnsRules = @($config.dns.rules)
    $nodePolicySpec = Get-NodeDnsPolicySpec -Port 15354
    $nodeRuleCount = @($nodePolicySpec.DnsRules).Count
    $rejectTags = @($ruleSetsByTag.Keys | Where-Object { $_ -ceq 'routing-reject-domain' })
    $nodeRuleCount += Get-ClientDnsBlockRuleCount -Rules $allDnsRules
    if ($allDnsRules.Count -ne ($nodeRuleCount + 8)) { throw 'DNS policy must contain the five validated node rules and exactly eight ordinary fallback rules.' }
    $ordinaryDnsRules = New-Object 'System.Collections.Generic.List[object]'
    for ($ruleIndex = $nodeRuleCount; $ruleIndex -lt $allDnsRules.Count; $ruleIndex++) { $ordinaryDnsRules.Add($allDnsRules[$ruleIndex]) }
    $dnsRules = @($ordinaryDnsRules.ToArray())
    if ($dnsRules.Count -ne 8) { throw 'DNS policy must contain exactly one four-rule direct fallback group and one four-rule proxy fallback group after node rules.' }
    $directSelectorTags = @($dnsRules[0].rule_set | ForEach-Object { [string]$_ })
    if ($directSelectorTags.Count -eq 0) { throw 'Direct DNS primary must select positive domain rule sets.' }
    $directSetTags = New-Object 'System.Collections.Generic.List[string]'
    foreach ($tag in $directSelectorTags) {
        if (-not $ruleSetsByTag.ContainsKey([string]$tag) -or -not (Test-OpenWrtDirectDomainRuleSetTag -Tag ([string]$tag))) {
            throw ('DNS references a non-domain or unknown direct rule set: ' + [string]$tag)
        }
        if (-not $directSetTags.Contains([string]$tag)) { $directSetTags.Add([string]$tag) }
    }
    $directSelectorKey = $directSelectorTags -join "`n"
    $directExpectedFields = @{}
    $directExpectedFields[0] = @('rule_set','action','server','tag','timeout')
    $directExpectedFields[1] = @('rule_set','match_response','response_rcode','action')
    $directExpectedFields[2] = @('rule_set','match_response','response_rcode','action')
    $directExpectedFields[3] = @('rule_set','action','server','timeout')
    $directExpectedActions = @('evaluate','respond','respond','route')
    $directExpectedResponseCodes = @('','NOERROR','NXDOMAIN','')
    for ($i = 0; $i -lt 4; $i++) {
        $rule = $dnsRules[$i]
        $propertyNames = @($rule.PSObject.Properties | ForEach-Object Name)
        $unknown = @($propertyNames | Where-Object { $_ -notin $directExpectedFields[$i] })
        $selector = @($rule.rule_set | ForEach-Object { [string]$_ })
        if ($propertyNames.Count -ne $directExpectedFields[$i].Count -or $unknown.Count -ne 0 -or
            ($selector -join "`n") -cne $directSelectorKey -or $rule.action -cne $directExpectedActions[$i]) {
            throw ('Direct DNS fallback rule ' + $i + ' has an unsupported selector, field, or action.')
        }
        if ($i -eq 0 -and ($rule.server -cne 'dns-direct' -or $rule.tag -cne 'dns-direct-primary-response' -or $rule.timeout -cne '2s')) {
            throw 'Direct DNS evaluate must use Ali primary dns-direct with the two-second action timeout.'
        }
        if ($i -eq 1 -or $i -eq 2) {
            if ($rule.match_response -cne 'dns-direct-primary-response' -or $rule.response_rcode -cne $directExpectedResponseCodes[$i]) {
                throw 'Direct DNS must respond to a successful or name-error primary response before routing to its backup.'
            }
        }
        if ($i -eq 3 -and ($rule.server -cne 'dns-direct-backup' -or $rule.timeout -cne '3s')) {
            throw 'Direct DNS terminal fallback must route to the Tencent backup with the three-second action timeout.'
        }
    }
    $proxyExpectedFields = @{}
    $proxyExpectedFields[0] = @('domain_regex','action','server','tag','timeout')
    $proxyExpectedFields[1] = @('domain_regex','match_response','response_rcode','action')
    $proxyExpectedFields[2] = @('domain_regex','match_response','response_rcode','action')
    $proxyExpectedFields[3] = @('domain_regex','action','server','timeout')
    $proxyExpectedActions = @('evaluate','respond','respond','route')
    $proxyExpectedResponseCodes = @('','NOERROR','NXDOMAIN','')
    for ($i = 0; $i -lt 4; $i++) {
        $rule = $dnsRules[$i + 4]
        $propertyNames = @($rule.PSObject.Properties | ForEach-Object Name)
        $unknown = @($propertyNames | Where-Object { $_ -notin $proxyExpectedFields[$i] })
        $selector = @($rule.domain_regex | ForEach-Object { [string]$_ })
        if ($propertyNames.Count -ne $proxyExpectedFields[$i].Count -or $unknown.Count -ne 0 -or
            $selector.Count -ne 1 -or $selector[0] -cne '.*' -or $rule.action -cne $proxyExpectedActions[$i]) {
            throw ('Proxy DNS fallback rule ' + $i + ' must use only the positive catch-all selector and approved fields.')
        }
        if ($i -eq 0 -and ($rule.server -cne 'dns-proxy' -or $rule.tag -cne 'dns-proxy-primary-response' -or $rule.timeout -cne '3s')) {
            throw 'Proxy DNS evaluate must use Cloudflare primary dns-proxy with the three-second action timeout.'
        }
        if ($i -eq 1 -or $i -eq 2) {
            if ($rule.match_response -cne 'dns-proxy-primary-response' -or $rule.response_rcode -cne $proxyExpectedResponseCodes[$i]) {
                throw 'Proxy DNS must respond to a successful or name-error primary response before routing to its backup.'
            }
        }
        if ($i -eq 3 -and ($rule.server -cne 'dns-proxy-backup' -or $rule.timeout -cne '5s')) {
            throw 'Proxy DNS terminal fallback must route to the Google backup with the five-second action timeout.'
        }
    }
    if ($directSetTags.Count -eq 0) { throw 'No effective direct DNS domain sets were referenced by the final Linux snapshot.' }

    $temporary = New-OpenWrtTaskScratchDirectory -Prefix 'sb-mosdns-decompile'
    $entries = New-Object 'System.Collections.Generic.List[string]'
    $rejectEntries = New-Object 'System.Collections.Generic.List[string]'
    $sourceSetHashes = New-Object 'System.Collections.Generic.List[object]'
    try {
        $seenDirect = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        $seenReject = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($tag in @($directSetTags.ToArray()) + $rejectTags) {
            $target = $entries; $seen = $seenDirect
            if ($tag -ceq 'routing-reject-domain') { $target = $rejectEntries; $seen = $seenReject }
            $sourceSet = $ruleSetsByTag[$tag]
            $decodedPath = Join-Path $temporary ($tag + '.json')
            & $SingBoxPath rule-set decompile --output $decodedPath $sourceSet.Path | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $decodedPath -PathType Leaf)) {
                throw ('Official sing-box failed to decompile direct DNS SRS: ' + $tag)
            }
            try { $decoded = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($decodedPath)) -ErrorAction Stop }
            catch { throw ('Cannot parse decompiled direct DNS SRS ' + $tag + ': ' + $_.Exception.Message) }
            if (-not $decoded.rules -or $decoded.rules.Count -eq 0) { throw ('Empty direct DNS SRS: ' + $tag) }
            foreach ($headless in $decoded.rules) {
                $fields = @($headless.PSObject.Properties | ForEach-Object Name)
                if ($fields.Count -eq 0 -or @($fields | Where-Object { $_ -notin @('domain','domain_suffix','domain_regex') }).Count -ne 0) {
                    throw ('Direct DNS SRS is not a positive domain-only set: ' + $tag)
                }
                foreach ($kind in @('domain','domain_suffix','domain_regex')) {
                    $field = $headless.PSObject.Properties[$kind]
                    if ($null -eq $field) { continue }
                    foreach ($value in @($field.Value)) {
                        if ($null -eq $value) { continue }
                        $line = ConvertTo-MosdnsDomainLine -Kind $kind -Value ([string]$value)
                        if ($seen.Add($line)) { $target.Add($line) }
                    }
                }
            }
            $sourceSetHashes.Add([pscustomobject]@{
                tag=$tag
                sha256=(Get-FileHash -LiteralPath $sourceSet.Path -Algorithm SHA256).Hash.ToLowerInvariant()
                predicates=@($decoded.rules).Count
            })
        }
    }
    finally {
        Remove-OpenWrtTaskScratchDirectory -Path $temporary -Prefix 'sb-mosdns-decompile'
    }
    if ($entries.Count -eq 0) { throw 'Final Linux DNS direct SRS yielded no positive domain predicates.' }

    $fullCount = @($entries | Where-Object { $_.StartsWith('full:', [StringComparison]::Ordinal) }).Count
    $domainCount = @($entries | Where-Object { $_.StartsWith('domain:', [StringComparison]::Ordinal) }).Count
    $regexCount = @($entries | Where-Object { $_.StartsWith('regexp:', [StringComparison]::Ordinal) }).Count
    $directLines = $entries.ToArray()
    $yaml = New-MosdnsCandidateYaml -RejectDomains:($rejectEntries.Count -gt 0)
    $sourceHashes = @(
        [pscustomobject]@{ path='sing-box-openwrt.json'; sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    ) + @($sourceSetHashes.ToArray())
    return [pscustomobject]@{
        status='ready'
        publication_ready=$true
        direct_rule_set_count=$directSetTags.Count
        direct_domain_rule_count=$directLines.Count
        full_count=$fullCount
        domain_count=$domainCount
        regexp_count=$regexCount
        source_hashes=$sourceHashes
        domain_lines=$directLines
        reject_domain_lines=$rejectEntries.ToArray()
        candidate_yaml=$yaml
        node_ttl_policy='For node A queries only, apply ttl 3600 when the response is NOERROR and contains an IPv4 address. MosDNS ttl operates on the whole positive DNS message, so it also changes CNAME and TTL=0 records in that response; OPT is not rewritten.'
        dns_provider_policy=(Get-MosdnsDnsProviderPolicyMetadata)
    }
}

function New-MosdnsCandidateYaml {
    param([switch]$RejectDomains)
    $yaml = @'
log:
  level: warn
plugins:
  - tag: ordinary_cache
    type: cache
    args:
      size: 65472
      lazy_cache_ttl: 3600
  - tag: node_cache
    type: cache
    args:
      size: 65472
      lazy_cache_ttl: 0
  - tag: direct_domains
    type: domain_set
    args:
      files:
        - ./dns-direct-domains.txt
  - tag: direct_ali_forward
    type: forward
    args:
      concurrent: 1
      upstreams:
        - tag: ali_direct
          addr: https://dns.alidns.com/dns-query
          dial_addr: 223.5.5.5
          idle_timeout: 120
          insecure_skip_verify: false
  - tag: direct_tencent_forward
    type: forward
    args:
      concurrent: 1
      upstreams:
        - tag: tencent_direct
          addr: https://doh.pub/dns-query
          dial_addr: 120.53.53.53
          idle_timeout: 120
          insecure_skip_verify: false
  - tag: proxy_cloudflare_forward
    type: forward
    args:
      concurrent: 1
      upstreams:
        - tag: cloudflare_proxy
          addr: https://cloudflare-dns.com/dns-query
          dial_addr: 1.1.1.1
          idle_timeout: 120
          socks5: 127.0.0.1:15355
          insecure_skip_verify: false
  - tag: proxy_google_forward
    type: forward
    args:
      concurrent: 1
      upstreams:
        - tag: google_proxy
          addr: https://dns.google/dns-query
          dial_addr: 8.8.8.8
          idle_timeout: 120
          socks5: 127.0.0.1:15355
          insecure_skip_verify: false
  - tag: direct_ordinary_primary
    type: sequence
    args:
      - exec: metrics_collector direct_ali_primary
      - exec: $direct_ali_forward
      - matches:
          - '!rcode 0'
          - '!rcode 3'
        exec: drop_resp
  - tag: direct_ordinary_backup
    type: sequence
    args:
      - exec: metrics_collector direct_tencent_backup
      - exec: $direct_tencent_forward
      - matches:
          - '!rcode 0'
          - '!rcode 3'
        exec: drop_resp
  - tag: direct_ordinary_fallback
    type: fallback
    args:
      primary: direct_ordinary_primary
      secondary: direct_ordinary_backup
      threshold: 300
      always_standby: false
  - tag: proxy_ordinary_primary
    type: sequence
    args:
      - exec: metrics_collector proxy_cloudflare_primary
      - exec: $proxy_cloudflare_forward
      - matches:
          - '!rcode 0'
          - '!rcode 3'
        exec: drop_resp
  - tag: proxy_ordinary_backup
    type: sequence
    args:
      - exec: metrics_collector proxy_google_backup
      - exec: $proxy_google_forward
      - matches:
          - '!rcode 0'
          - '!rcode 3'
        exec: drop_resp
  - tag: proxy_ordinary_fallback
    type: fallback
    args:
      primary: proxy_ordinary_primary
      secondary: proxy_ordinary_backup
      threshold: 2000
      always_standby: false
  - tag: ordinary_sequence
    type: sequence
    args:
      - exec: metrics_collector ordinary_dns
      - matches:
          - qtype 28
        exec: reject 5
      - exec: $ordinary_cache
      - matches: has_resp
        exec: accept
      - matches:
          - qname $direct_domains
        exec: $direct_ordinary_fallback
      - matches: has_resp
        exec: accept
      - exec: $proxy_ordinary_fallback
  - tag: node_sequence
    type: sequence
    args:
      - exec: metrics_collector node_dns
      - matches:
          - qtype 28
        exec: reject 5
      - matches:
          - qtype 1
        exec: $node_cache
      - matches: has_resp
        exec: accept
      - exec: $direct_ordinary_fallback
      # ttl is whole-message: positive A responses also get TTL=3600 on CNAME and TTL=0 RRs; OPT is excluded.
      - matches:
          - qtype 1
          - rcode 0
          - resp_ip 0.0.0.0/0
        exec: ttl 3600
      - matches: has_resp
        exec: accept
  - tag: ordinary_udp
    type: udp_server
    args:
      entry: ordinary_sequence
      listen: 127.0.0.1:15353
  - tag: ordinary_tcp
    type: tcp_server
    args:
      entry: ordinary_sequence
      listen: 127.0.0.1:15353
  - tag: node_udp
    type: udp_server
    args:
      entry: node_sequence
      listen: 127.0.0.1:15354
  - tag: node_tcp
    type: tcp_server
    args:
      entry: node_sequence
      listen: 127.0.0.1:15354
api:
  http: 127.0.0.1:15357
'@
    if ($RejectDomains) {
        $plugin = @'
  - tag: reject_domains
    type: domain_set
    args:
      files:
        - ./dns-reject-domains.txt
'@
        $reject = @'
      - matches:
          - qname $reject_domains
        exec: reject 5
'@
        $yaml = $yaml.Replace('  - tag: direct_domains', $plugin + "`n" + '  - tag: direct_domains')
        $anchor = "          - qtype 28`n        exec: reject 5"
        $yaml = $yaml.Replace($anchor, $anchor + "`n" + $reject)
    }
    return $yaml
}

function Get-MosdnsPathComparison {
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { return [StringComparison]::OrdinalIgnoreCase }
    return [StringComparison]::Ordinal
}

function Assert-MosdnsOutputDirectorySafe {
    param([Parameter(Mandatory)][string]$Path)
    $normalized=ConvertTo-OpenWrtComparisonPath -Path $Path
    Assert-OpenWrtPathAncestors -Path $normalized
    if (Test-Path -LiteralPath $normalized) {
        $item=Get-Item -LiteralPath $normalized -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw ('MosDNS output path is not a plain directory: '+$normalized)
        }
        Assert-OpenWrtTreeHasNoReparsePoints -Path $normalized
    }
}

function Assert-MosdnsAdapterStageSafe {
    param([Parameter(Mandatory)][string]$Stage,[Parameter(Mandatory)][string]$Destination)
    $comparison=Get-MosdnsPathComparison
    $stagePath=ConvertTo-OpenWrtComparisonPath -Path $Stage
    $destinationPath=ConvertTo-OpenWrtComparisonPath -Path $Destination
    if ((Split-Path -Parent $stagePath) -cne $destinationPath -or
        (Split-Path -Leaf $stagePath) -cnotmatch '^\.mosdns-stage-[0-9a-f]{32}$' -or
        -not (Test-OpenWrtPathContains -Parent $destinationPath -Child $stagePath -Comparison $comparison)) {
        throw ('Unsafe MosDNS publication staging path: '+$stagePath)
    }
    Assert-MosdnsOutputDirectorySafe -Path $destinationPath
    Assert-OpenWrtPathAncestors -Path $stagePath
    if (Test-Path -LiteralPath $stagePath) {
        $item=Get-Item -LiteralPath $stagePath -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw ('MosDNS staging path is not a plain directory: '+$stagePath)
        }
        Assert-OpenWrtTreeHasNoReparsePoints -Path $stagePath
    }
}

function Write-MosdnsAdapterStageFile {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Text,[Parameter(Mandatory)][Text.Encoding]$Encoding)
    [IO.File]::WriteAllText($Path,$Text,$Encoding)
}

function Move-MosdnsAdapterStageFile {
    param([Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$Destination)
    # File.Move fails if the destination appeared after the absence check.
    [IO.File]::Move($Source,$Destination)
}

function Write-MosdnsAdapterFromSnapshot {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$SingBoxPath
    )
    $comparison=Get-MosdnsPathComparison
    $destination=ConvertTo-OpenWrtComparisonPath -Path $OutputDirectory
    $source=ConvertTo-OpenWrtComparisonPath -Path $SourceRoot
    Assert-OpenWrtPathAncestors -Path $source
    Assert-MosdnsOutputDirectorySafe -Path $destination
    if (Test-OpenWrtPathOverlap -First $destination -Second $source -Comparison $comparison) {
        throw 'MosDNS output must be outside the immutable final Linux source snapshot.'
    }
    $plan = Get-MosdnsAdapterPlanFromSnapshot -SourceRoot $SourceRoot -SingBoxPath $SingBoxPath
    if (-not $plan.publication_ready) { throw 'MosDNS policy plan is not approved for publication.' }

    Assert-MosdnsOutputDirectorySafe -Path $destination
    if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
        [IO.Directory]::CreateDirectory($destination) | Out-Null
    }
    Assert-MosdnsOutputDirectorySafe -Path $destination
    $names = @('dns-direct-domains.txt','mosdns.yaml')
    if ($plan.reject_domain_lines.Count) { $names += 'dns-reject-domains.txt' }
    foreach ($name in $names) {
        $destinationFile=Join-Path $destination $name
        Assert-OpenWrtPathAncestors -Path $destinationFile
        if (Test-Path -LiteralPath $destinationFile) { throw ('Refusing to overwrite existing MosDNS output: ' + $name) }
    }

    $stage = Join-Path $destination ('.mosdns-stage-' + [guid]::NewGuid().ToString('N'))
    Assert-MosdnsOutputDirectorySafe -Path $destination
    Assert-OpenWrtPathAncestors -Path $stage
    if (Test-Path -LiteralPath $stage) { throw 'MosDNS staging path unexpectedly already exists.' }
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $published = New-Object 'System.Collections.Generic.List[object]'
    $encoding = New-Object Text.UTF8Encoding($false)
    $failure=$null
    $secondaryErrors=New-Object 'System.Collections.Generic.List[string]'
    try {
        Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
        $yamlText = $plan.candidate_yaml.Replace("`r`n","`n").Replace("`r","`n").TrimEnd([char]10)+"`n"
        Write-MosdnsAdapterStageFile -Path (Join-Path $stage $names[0]) -Text (($plan.domain_lines -join "`n")+"`n") -Encoding $encoding
        Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
        Write-MosdnsAdapterStageFile -Path (Join-Path $stage $names[1]) -Text $yamlText -Encoding $encoding
        if ($plan.reject_domain_lines.Count) {
            Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
            Write-MosdnsAdapterStageFile -Path (Join-Path $stage 'dns-reject-domains.txt') -Text (($plan.reject_domain_lines -join "`n")+"`n") -Encoding $encoding
        }
        Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
        foreach ($name in $names) {
            $sourceFile = Join-Path $stage $name
            $destinationFile = Join-Path $destination $name
            Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
            Assert-OpenWrtPathAncestors -Path $destinationFile
            if (Test-Path -LiteralPath $destinationFile) { throw ('MosDNS output appeared during publication: ' + $name) }
            $expectedHash=(Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
            Move-MosdnsAdapterStageFile -Source $sourceFile -Destination $destinationFile
            $published.Add([pscustomobject]@{Path=$destinationFile;Sha256=$expectedHash})
            Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
        }
        Assert-MosdnsOutputDirectorySafe -Path $destination
        foreach ($entry in $published) {
            $path=[string]$entry.Path
            Assert-OpenWrtPathAncestors -Path $path
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$entry.Sha256) {
                throw ('MosDNS output changed during publication: '+$path)
            }
        }
    }
    catch {
        $failure=$_.Exception
        try {
            Assert-MosdnsOutputDirectorySafe -Path $destination
            foreach ($entry in $published) {
                try {
                    $path=[string]$entry.Path
                    Assert-OpenWrtPathAncestors -Path $path
                    if (-not (Test-Path -LiteralPath $path)) { continue }
                    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        throw ('Refusing to roll back a non-regular published path: '+$path)
                    }
                    $currentHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                    if ($currentHash -cne [string]$entry.Sha256) {
                        throw ('Preserving concurrently changed MosDNS output during rollback: '+$path)
                    }
                    [IO.File]::Delete($path)
                }
                catch { [void]$secondaryErrors.Add($_.Exception.Message) }
            }
        }
        catch { [void]$secondaryErrors.Add($_.Exception.Message) }
    }
    finally {
        try {
            Assert-MosdnsAdapterStageSafe -Stage $stage -Destination $destination
            if (Test-Path -LiteralPath $stage) { [IO.Directory]::Delete($stage,$true) }
        }
        catch { [void]$secondaryErrors.Add(('Preserved MosDNS staging data because safe cleanup failed: '+$_.Exception.Message)) }
    }
    if ($failure) {
        $message='MosDNS adapter publication failed: '+$failure.Message
        if ($secondaryErrors.Count -gt 0) { $message+='; '+($secondaryErrors.ToArray() -join '; ') }
        throw $message
    }
    if ($secondaryErrors.Count -gt 0) {
        throw ('MosDNS adapter publication cleanup failed: '+($secondaryErrors.ToArray() -join '; '))
    }

    return [pscustomobject]@{
        status='written'
        publication_ready=$plan.publication_ready
        paths=[pscustomobject]@{
            dns_direct_domains=Join-Path $destination $names[0]
            mosdns_yaml=Join-Path $destination $names[1]
        }
        direct_rule_set_count=$plan.direct_rule_set_count
        direct_domain_rule_count=$plan.direct_domain_rule_count
        full_count=$plan.full_count
        domain_count=$plan.domain_count
        regexp_count=$plan.regexp_count
        node_ttl_policy=$plan.node_ttl_policy
        dns_provider_policy=$plan.dns_provider_policy
        source_hashes=$plan.source_hashes
    }
}
