Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'Direct-RoutingPolicy.ps1')

function New-RuleSetDescriptor {
    param([Parameter(Mandatory)][string]$Tag)
    [ordered]@{
        type = 'local'
        tag = $Tag
        format = 'binary'
        path = ('rule-set/{0}.srs' -f $Tag)
    }
}

function New-ValidConfiguration {
    $nodePolicy = Get-NodeDnsPolicySpec
    $domainTag = 'routing-direct-1-domain'
    $secondDomainTag = 'routing-direct-2-domain'
    $ipTag = 'routing-direct-1-ip'
    $portTag = 'routing-direct-2-port'
    $sourcePortTag = 'routing-direct-3-source_port'

    $routeRules = New-Object 'System.Collections.Generic.List[object]'
    $routeRules.Add([ordered]@{ action = 'reject'; ip_version = 6 })
    $routeRules.Add($nodePolicy.RouteRule)
    $routeRules.Add((New-EffectiveDirectRule -Tag $ipTag))
    $routeRules.Add((New-EffectiveDirectRule -Tag $portTag))
    $routeRules.Add((New-EffectiveDirectRule -Tag $sourcePortTag))

    $dnsRules = New-Object 'System.Collections.Generic.List[object]'
    $dnsRules.AddRange([object[]]$nodePolicy.DnsRules)
    $dnsRules.AddRange([object[]]@(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues @($domainTag, $secondDomainTag) -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s'))
    $dnsRules.AddRange([object[]]@(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s'))

    $configuration = @{
        route = @{
            final = 'proxy'
            rules = $routeRules.ToArray()
            rule_set = @(
                (New-RuleSetDescriptor -Tag $domainTag),
                (New-RuleSetDescriptor -Tag $secondDomainTag),
                (New-RuleSetDescriptor -Tag $ipTag),
                (New-RuleSetDescriptor -Tag $portTag),
                (New-RuleSetDescriptor -Tag $sourcePortTag)
            )
        }
        dns = @{
            final = 'dns-proxy'
            reverse_mapping = $false
            disable_cache = $false
            cache_capacity = 8192
            optimistic = @{ enabled = $true; timeout = '1h' }
            rules = $dnsRules.ToArray()
            servers = @(
                @{ type = 'udp'; tag = 'dns-direct'; server = '127.0.0.1'; server_port = 15353 },
                @{ type = 'udp'; tag = 'dns-direct-backup'; server = '127.0.0.1'; server_port = 15354 },
                @{ type = 'udp'; tag = 'dns-proxy'; server = '127.0.0.1'; server_port = 15355 },
                @{ type = 'udp'; tag = 'dns-proxy-backup'; server = '127.0.0.1'; server_port = 15356 },
                $nodePolicy.DnsServer,
                @{ type = 'hosts'; tag = 'dns-doh-hosts'; predefined = @{
                    'dns.alidns.com' = @('223.5.5.5')
                    'doh.pub' = @('120.53.53.53')
                    'cloudflare-dns.com' = @('1.1.1.1')
                    'dns.google' = @('8.8.8.8')
                } }
            )
        }
        inbounds = @(
            @{ type = 'tun'; tag = 'tun-in' },
            $nodePolicy.Inbound
        )
        outbounds = @(
            @{ type = 'vless'; tag = 'proxy'; domain_resolver = $nodePolicy.DomainResolver }
        )
    }
    ConvertTo-Json -InputObject $configuration -Depth 100 -Compress | ConvertFrom-Json
}

function Assert-InvalidConfiguration {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Mutate
    )
    $configuration = New-ValidConfiguration
    & $Mutate $configuration
    $rejected = $false
    try {
        Assert-EffectiveDirectConfiguration -Configuration $configuration
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) { throw "Invalid configuration was accepted: $Label" }
    $script:invalidCaseCount++
}

$valid = New-ValidConfiguration
Assert-EffectiveDirectConfiguration -Configuration $valid
$stableValid = New-ValidConfiguration
$stableValid.route.rules = @(
    [pscustomobject]@{ action = 'reject'; ip_version = 6 },
    (Get-NodeDnsPolicySpec).RouteRule,
    (New-EffectiveDirectRule -Tag 'routing-direct-ip'),
    (New-EffectiveDirectRule -Tag 'routing-direct-port')
)
$stableValid.route.rule_set = @(
    (New-RuleSetDescriptor -Tag 'routing-direct-domain'),
    (New-RuleSetDescriptor -Tag 'routing-direct-ip'),
    (New-RuleSetDescriptor -Tag 'routing-direct-port')
)
$stableDnsRules = New-Object 'System.Collections.Generic.List[object]'
$stableDnsRules.AddRange([object[]](Get-NodeDnsPolicySpec).DnsRules)
$stableDnsRules.AddRange([object[]]@(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues @('routing-direct-domain') -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s'))
$stableDnsRules.AddRange([object[]]@(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s'))
$stableValid.dns.rules = $stableDnsRules.ToArray()
Assert-EffectiveDirectConfiguration -Configuration $stableValid
$proxyOnlyValid = New-ValidConfiguration
$proxyOnlyValid.route.rule_set = @((New-RuleSetDescriptor -Tag 'routing-direct-1-ip'))
$proxyOnlyValid.route.rules = @(
    [pscustomobject]@{ action = 'reject'; ip_version = 6 },
    (Get-NodeDnsPolicySpec).RouteRule,
    (New-EffectiveDirectRule -Tag 'routing-direct-1-ip')
)
$proxyOnlyDnsRules = New-Object 'System.Collections.Generic.List[object]'
$proxyOnlyDnsRules.AddRange([object[]](Get-NodeDnsPolicySpec).DnsRules)
$proxyOnlyDnsRules.AddRange([object[]]@(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s'))
$proxyOnlyValid.dns.rules = $proxyOnlyDnsRules.ToArray()
Assert-EffectiveDirectConfiguration -Configuration $proxyOnlyValid

$numericRule = New-EffectiveDirectRule -Tag 'routing-direct-4-ip'
if (($numericRule.Keys -join ',') -cne 'rule_set,action,outbound' -or
    $numericRule.rule_set -cne 'routing-direct-4-ip' -or $numericRule.action -cne 'route' -or
    $numericRule.outbound -cne 'direct') {
    throw 'The traffic rule factory must return one positive direct rule-set matcher.'
}
$dnsFallbackGroup = @(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues @('routing-direct-4-domain') -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s')
if ($dnsFallbackGroup.Count -ne 4 -or $dnsFallbackGroup[0].action -cne 'evaluate' -or
    $dnsFallbackGroup[1].response_rcode -cne 'NOERROR' -or $dnsFallbackGroup[2].response_rcode -cne 'NXDOMAIN' -or
    $dnsFallbackGroup[3].server -cne 'dns-direct-backup' -or $dnsFallbackGroup[3].Contains('invert')) {
    throw 'The DNS fallback rule factory must preserve valid responses and use a positive selector-only backup route.'
}

$factory = Get-Command -Name New-EffectiveDirectRule -CommandType Function
if ($factory.Parameters.ContainsKey('EarlierProxyTags')) {
    throw 'The direct rule factory must not expose the retired proxy-exclusion parameter.'
}
if (Get-Command -Name Expand-EffectiveDirectRouteRules -CommandType Function -ErrorAction SilentlyContinue) {
    throw 'The retired logical-rule expander must not be defined.'
}
$legacyParameterRejected = $false
try {
    New-EffectiveDirectRule -Tag 'routing-direct-4-ip' -EarlierProxyTags @('routing-proxy-1-ip') | Out-Null
}
catch {
    $legacyParameterRejected = $true
}
if (-not $legacyParameterRejected) { throw 'The retired proxy-exclusion parameter was accepted.' }

$script:invalidCaseCount = 0
Assert-InvalidConfiguration -Label 'traffic default is not proxy' -Mutate {
    param($Configuration)
    $Configuration.route.final = 'direct'
}
Assert-InvalidConfiguration -Label 'DNS default is not dns-proxy' -Mutate {
    param($Configuration)
    $Configuration.dns.final = 'dns-direct'
}
Assert-InvalidConfiguration -Label 'IPv6 rejection is not first' -Mutate {
    param($Configuration)
    $first = $Configuration.route.rules[0]
    $Configuration.route.rules[0] = $Configuration.route.rules[1]
    $Configuration.route.rules[1] = $first
}
Assert-InvalidConfiguration -Label 'duplicate IPv6 rejection' -Mutate {
    param($Configuration)
    $Configuration.route.rules = @($Configuration.route.rules) + @([pscustomobject]@{ action = 'reject'; ip_version = 6 })
}
Assert-InvalidConfiguration -Label 'IPv6 predicate outside the leading rejection' -Mutate {
    param($Configuration)
    $Configuration.route.rules[2] | Add-Member -NotePropertyName ipv6 -NotePropertyValue $true
}
Assert-InvalidConfiguration -Label 'domain rule used for business traffic' -Mutate {
    param($Configuration)
    $Configuration.route.rules[2].rule_set = 'routing-direct-1-domain'
}
Assert-InvalidConfiguration -Label 'numeric direct rule has an inverse matcher' -Mutate {
    param($Configuration)
    $Configuration.route.rules[2] | Add-Member -NotePropertyName invert -NotePropertyValue $true
}
Assert-InvalidConfiguration -Label 'legacy logical proxy exclusion' -Mutate {
    param($Configuration)
    $Configuration.route.rules[2] = [pscustomobject]@{
        type = 'logical'
        mode = 'and'
        rules = @(
            [pscustomobject]@{ rule_set = 'routing-direct-1-ip' },
            [pscustomobject]@{ rule_set = @('routing-proxy-1-ip'); invert = $true }
        )
        action = 'route'
        outbound = 'direct'
    }
}
Assert-InvalidConfiguration -Label 'proxy rule-set dependency' -Mutate {
    param($Configuration)
    $proxySet = [pscustomobject]@{ type = 'local'; tag = 'routing-proxy-1-ip'; format = 'binary'; path = 'rule-set/proxy.srs' }
    $Configuration.route.rule_set = @($Configuration.route.rule_set) + @($proxySet)
}
Assert-InvalidConfiguration -Label 'DNS references a numeric rule-set' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].rule_set = 'routing-direct-1-ip'
}
Assert-InvalidConfiguration -Label 'DNS omits a direct domain rule-set' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].rule_set = @('routing-direct-1-domain')
}
Assert-InvalidConfiguration -Label 'DNS grouped domain tags are reordered' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].rule_set = @('routing-direct-2-domain','routing-direct-1-domain')
}
Assert-InvalidConfiguration -Label 'DNS grouped domain tag is duplicated' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].rule_set = @('routing-direct-1-domain','routing-direct-1-domain')
}
Assert-InvalidConfiguration -Label 'DNS grouped rules include an unknown domain tag' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].rule_set = @('routing-direct-1-domain','routing-direct-99-domain')
}
Assert-InvalidConfiguration -Label 'DNS timeout is invalid' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].timeout = '0s'
}
Assert-InvalidConfiguration -Label 'DNS direct primary selects the proxy server' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[5].server = 'dns-proxy'
}
Assert-InvalidConfiguration -Label 'DNS fallback uses inversion instead of a positive selector' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[8] | Add-Member -NotePropertyName invert -NotePropertyValue $true
}
Assert-InvalidConfiguration -Label 'DNS valid response loses its positive direct selector' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[6].PSObject.Properties.Remove('rule_set')
}
Assert-InvalidConfiguration -Label 'DNS proxy catch-all selector changes' -Mutate {
    param($Configuration)
    $Configuration.dns.rules[9].domain_regex = @('^unrelated$')
}
Assert-InvalidConfiguration -Label 'fake-IP DNS server is present' -Mutate {
    param($Configuration)
    $fakeIpServer = [pscustomobject]@{ type = 'fakeip'; tag = 'fakeip' }
    $Configuration.dns.servers = @($Configuration.dns.servers) + @($fakeIpServer)
}

Write-Output "Direct routing contract: 3 valid configurations and $script:invalidCaseCount invalid configurations passed; positive factories and retired logical dependencies checked."
