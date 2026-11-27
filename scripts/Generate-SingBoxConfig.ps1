[CmdletBinding(DefaultParameterSetName = 'Generate')]
param(
    [Parameter(ParameterSetName = 'Generate', Position = 0)]
    [string]$Client,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$All,

    [Parameter(ParameterSetName = 'List', Mandatory)]
    [switch]$ListClients,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$TemplatePath,

    [Parameter(ParameterSetName = 'Generate')]
    [Parameter(ParameterSetName = 'List')]
    [string]$ProfilesPath,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$OutputDirectory,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$SupportDirectory,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$TunAddress,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$RoutingRulesPath,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$Offline,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$AllowSourceShrink,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$ZstdLibraryPath,

    [Parameter(ParameterSetName = 'Generate', DontShow = $true)]
    [switch]$RoutingRulesAlreadyUpdated,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$SkipRoutingRules,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$LinuxRouteExcludeAddressSets,

    [Parameter(ParameterSetName = 'Generate')]
    [string]$SingBoxPath,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$RequireSingBox,

    [Parameter(ParameterSetName = 'Generate')]
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Json-Validation.ps1')
. (Join-Path $PSScriptRoot 'Build-Transaction.ps1')
. (Join-Path $PSScriptRoot 'Direct-RoutingPolicy.ps1')
. (Join-Path $PSScriptRoot 'SameTypeDirectPolicy.ps1')
. (Join-Path $PSScriptRoot 'DNS-BootstrapPolicy.ps1')
. (Join-Path $PSScriptRoot 'SingBox-Checker.ps1')

if (-not $TemplatePath) {
    $TemplatePath = Join-Path (Join-Path $projectRoot 'config') 'sing-box-core-base.json'
}
if (-not $ProfilesPath) {
    $ProfilesPath = Join-Path (Join-Path $projectRoot 'config') 'client-profiles.json'
}
$defaultOutputDirectory = Join-Path $projectRoot 'generated'
if (-not $OutputDirectory) { $OutputDirectory = $defaultOutputDirectory }
if (-not $RoutingRulesPath) {
    $RoutingRulesPath = Join-Path $projectRoot 'routing\merged\merged-rules.json'
}

function Test-UnsignedInteger {
    param($Value, [uint64]$Minimum = 0, [uint64]$Maximum = 4294967295)
    # Reject coercible strings, booleans and floating-point JSON numbers.
    if ($null -eq $Value -or [Type]::GetTypeCode($Value.GetType()) -notin @(
        [TypeCode]::Byte, [TypeCode]::SByte, [TypeCode]::Int16, [TypeCode]::UInt16,
        [TypeCode]::Int32, [TypeCode]::UInt32, [TypeCode]::Int64, [TypeCode]::UInt64
    )) { return $false }
    return $Value -ge $Minimum -and $Value -le $Maximum
}

function Test-PositiveDuration {
    param($Value)
    return [string]$Value -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$'
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "找不到文件：$Path"
    }

    try {
        return Read-StrictJsonFile -Path $Path
    }
    catch {
        throw "JSON 文件无效：$Path`n$($_.Exception.Message)"
    }
}

function Format-JsonText {
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [int]$IndentSize = 2
    )

    $builder = [System.Text.StringBuilder]::new()
    $indent = 0
    $inString = $false
    $escaping = $false

    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($inString) {
            [void]$builder.Append($character)
            if ($escaping) {
                $escaping = $false
            }
            elseif ($character -eq '\') {
                $escaping = $true
            }
            elseif ($character -eq '"') {
                $inString = $false
            }
            continue
        }

        if ([char]::IsWhiteSpace($character)) { continue }
        if ($character -eq '"') {
            $inString = $true
            [void]$builder.Append($character)
            continue
        }
        if ($character -eq '{' -or $character -eq '[') {
            [void]$builder.Append($character)
            $next = $index + 1
            while ($next -lt $Text.Length -and [char]::IsWhiteSpace($Text[$next])) { $next++ }
            $closing = if ($character -eq '{') { '}' } else { ']' }
            if ($next -lt $Text.Length -and $Text[$next] -eq $closing) { continue }
            $indent++
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            continue
        }
        if ($character -eq '}' -or $character -eq ']') {
            $previous = $index - 1
            while ($previous -ge 0 -and [char]::IsWhiteSpace($Text[$previous])) { $previous-- }
            $opening = if ($character -eq '}') { '{' } else { '[' }
            if ($previous -ge 0 -and $Text[$previous] -eq $opening) {
                [void]$builder.Append($character)
                continue
            }
            $indent--
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            [void]$builder.Append($character)
            continue
        }
        if ($character -eq ',') {
            [void]$builder.Append($character)
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            continue
        }
        if ($character -eq ':') {
            [void]$builder.Append(': ')
            continue
        }
        [void]$builder.Append($character)
    }

    return $builder.ToString()
}

function Copy-JsonValue {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $copy = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $copy[$property.Name] = Copy-JsonValue $property.Value
        }
        return $copy
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $copy[[string]$key] = Copy-JsonValue $Value[$key]
        }
        return $copy
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((Copy-JsonValue $item))
        }
        # PowerShell normally unwraps a one-item array when returning it from a
        # function. The unary comma preserves JSON arrays regardless of length.
        return ,$items.ToArray()
    }

    return $Value
}

function Merge-JsonObject {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Base,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Overlay
    )

    $result = Copy-JsonValue $Base
    foreach ($key in $Overlay.Keys) {
        $overlayValue = $Overlay[$key]
        if (
            $result.Contains($key) -and
            $result[$key] -is [System.Collections.IDictionary] -and
            $overlayValue -is [System.Collections.IDictionary]
        ) {
            $result[$key] = Merge-JsonObject -Base $result[$key] -Overlay $overlayValue
        }
        else {
            $result[$key] = Copy-JsonValue $overlayValue
        }
    }
    return $result
}

function Get-MapValue {
    param(
        [System.Collections.IDictionary]$Map,
        [string]$Key
    )

    if ($null -ne $Map -and $Map.Contains($Key)) {
        $value = $Map[$Key]
        if ($value -is [System.Array]) {
            return ,$value
        }
        return $value
    }
    return $null
}

function Assert-Configuration {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration,

        [Parameter(Mandatory)]
        [string]$Name,

        [bool]$LinuxRouteExcludeAddressSets = $false,

        [object[]]$RuleSetPlan = @()
    )

    foreach ($requiredKey in @('log', 'dns', 'outbounds', 'route')) {
        if (-not $Configuration.Contains($requiredKey)) {
            throw "配置 '$Name' 缺少顶层字段 '$requiredKey'。"
        }
    }

    $logConfiguration = Get-MapValue $Configuration 'log'
    if ($null -ne (Get-MapValue $logConfiguration 'output')) {
        throw "配置 '$Name' 不得持续写入 Core 日志文件；运行日志应通过实时接口按需查看。"
    }

    $experimental = Get-MapValue $Configuration 'experimental'
    $clashApi = Get-MapValue $experimental 'clash_api'
    $externalController = Get-MapValue $clashApi 'external_controller'
    if ($Name -eq 'windows') {
        if ($externalController -ne '127.0.0.1:19090') {
            throw "Windows 配置必须在 127.0.0.1:19090 启用仅限本机的实时日志接口。"
        }
        if ($null -ne (Get-MapValue $clashApi 'external_ui')) {
            throw "Windows 实时日志接口不得启用或下载 Clash 网页面板。"
        }
    }
    elseif ($externalController) {
        throw "配置 '$Name' 不得继承 Windows 专用的实时日志接口。"
    }

    $rawOutbounds = Get-MapValue $Configuration 'outbounds'
    if (-not ($rawOutbounds -is [System.Array])) {
        throw "配置 '$Name' 的 outbounds 必须是数组。"
    }
    $outbounds = @($rawOutbounds)
    if ($outbounds.Count -eq 0) {
        throw "配置 '$Name' 至少需要一个出站。"
    }

    $outboundTags = @($outbounds | ForEach-Object { Get-MapValue $_ 'tag' } | Where-Object { $_ })
    if (@($outboundTags | Select-Object -Unique).Count -ne $outboundTags.Count) {
        throw "配置 '$Name' 包含重复的出站 tag。"
    }

    $route = Get-MapValue $Configuration 'route'
    $routeFinal = Get-MapValue $route 'final'
    if ($routeFinal -ne 'proxy') { throw "Configuration '$Name' requires route.final=proxy." }
    if ($routeFinal -and $routeFinal -notin $outboundTags) {
        throw "配置 '$Name' 的 route.final 引用了不存在的出站 '$routeFinal'。"
    }

    $defaultDomainResolver = Get-MapValue $route 'default_domain_resolver'
    if (-not ($defaultDomainResolver -is [System.Collections.IDictionary])) {
        throw "配置 '$Name' 的 route.default_domain_resolver 必须使用对象格式。"
    }
    if (
        (Get-MapValue $defaultDomainResolver 'server') -ne 'dns-proxy' -or
        (Get-MapValue $defaultDomainResolver 'strategy') -ne 'ipv4_only' -or
        (Get-MapValue $defaultDomainResolver 'timeout') -ne '8s'
    ) {
        throw "配置 '$Name' 的默认域名解析器必须使用 dns-proxy、ipv4_only 和 8 秒超时。"
    }

    $rawRuleSets = Get-MapValue $route 'rule_set'
    if ($null -ne $rawRuleSets) {
        if (-not ($rawRuleSets -is [System.Array])) {
            throw "配置 '$Name' 的 route.rule_set 必须是数组。"
        }
        $ruleSetTags = [System.Collections.Generic.List[string]]::new()
        foreach ($ruleSet in @($rawRuleSets)) {
            $ruleSetType = Get-MapValue $ruleSet 'type'
            $ruleSetFormat = Get-MapValue $ruleSet 'format'
            $ruleSetPath = Get-MapValue $ruleSet 'path'
            $ruleSetTag = Get-MapValue $ruleSet 'tag'
            if ($ruleSetType -ne 'local' -or $ruleSetFormat -ne 'binary') {
                throw "配置 '$Name' 的规则集 '$ruleSetTag' 必须使用 local binary SRS。"
            }
            if (-not ([string]$ruleSetPath).StartsWith('rule-set/') -or -not ([string]$ruleSetPath).EndsWith('.srs')) {
                throw "配置 '$Name' 的规则集 '$ruleSetTag' 必须引用 rule-set/*.srs。"
            }
            if (-not $ruleSetTag) {
                throw "配置 '$Name' 包含没有 tag 的规则集。"
            }
            $ruleSetTags.Add([string]$ruleSetTag)
        }
        if (@($ruleSetTags | Select-Object -Unique).Count -ne $ruleSetTags.Count) {
            throw "配置 '$Name' 包含重复的规则集 tag。"
        }
    }

    $dns = Get-MapValue $Configuration 'dns'
    if ((Get-MapValue $dns 'reverse_mapping') -ne $false) {
        throw "配置 '$Name' 必须关闭不再使用的 DNS reverse_mapping。"
    }
    if ($null -ne (Get-MapValue $dns 'disable_cache') -or $null -ne (Get-MapValue $dns 'disable_expire')) {
        throw "配置 '$Name' 启用 optimistic DNS 缓存时不得设置 disable_cache 或 disable_expire。"
    }
    if (-not (Test-UnsignedInteger (Get-MapValue $dns 'cache_capacity') -Minimum 1024)) {
        throw "配置 '$Name' 的 DNS 缓存容量必须为 1024 到 4294967295 的整数。"
    }
    if (-not (Test-PositiveDuration (Get-MapValue $dns 'timeout'))) {
        throw "配置 '$Name' 的全局 DNS 查询超时必须为正时长。"
    }
    $optimistic = Get-MapValue $dns 'optimistic'
    if ((Get-MapValue $optimistic 'enabled') -ne $true -or -not (Test-PositiveDuration (Get-MapValue $optimistic 'timeout'))) {
        throw "配置 '$Name' 必须启用 optimistic DNS 缓存，并使用正时长。"
    }
    $rawDnsServers = Get-MapValue $dns 'servers'
    if (-not ($rawDnsServers -is [System.Array])) {
        throw "配置 '$Name' 的 dns.servers 必须是数组。"
    }
    $dnsServers = @($rawDnsServers)
    $dnsTags = @($dnsServers | ForEach-Object { Get-MapValue $_ 'tag' } | Where-Object { $_ })
    if (@($dnsTags | Select-Object -Unique).Count -ne $dnsTags.Count) {
        throw "配置 '$Name' 包含重复的 DNS tag。"
    }

    $rawDnsRules = Get-MapValue $dns 'rules'
    if ($null -ne $rawDnsRules) {
        foreach ($dnsRule in @($rawDnsRules)) {
            $targetServer = Get-MapValue $dnsRule 'server'
            if ($targetServer -and $targetServer -notin @('dns-direct','dns-direct-backup','dns-proxy','dns-proxy-backup')) {
                throw "Configuration '$Name' DNS rules may only use the approved direct and proxy primary/backup servers."
            }
            $queryTimeout = Get-MapValue $dnsRule 'timeout'
            if ($targetServer -and -not (Test-PositiveDuration $queryTimeout)) {
                throw "配置 '$Name' 的 DNS 规则必须使用正时长。"
            }
        }
    }

    foreach ($dnsServer in $dnsServers) {
        $detour = Get-MapValue $dnsServer 'detour'
        if (-not $detour) { continue }
        if ($detour -notin $outboundTags) {
            throw "配置 '$Name' 的 DNS 服务器引用了不存在的出站 '$detour'。"
        }
        $targetOutbound = @($outbounds | Where-Object { (Get-MapValue $_ 'tag') -eq $detour })[0]
        $targetType = Get-MapValue $targetOutbound 'type'
        $targetOptions = @($targetOutbound.Keys | Where-Object { $_ -notin @('type','tag') })
        if ($targetType -eq 'direct' -and $targetOptions.Count -eq 0) {
            throw "配置 '$Name' 的 DNS detour 不能指向空 direct 出站 '$detour'；省略 detour 即为直连。"
        }
    }

    $proxyOutbound = @($outbounds | Where-Object { (Get-MapValue $_ 'tag') -eq 'proxy' })
    $dnsProxyOutbound = @($outbounds | Where-Object { (Get-MapValue $_ 'tag') -eq 'dns-proxy-out' })
    if ($dnsProxyOutbound.Count -gt 0) {
        if ($proxyOutbound.Count -ne 1 -or $dnsProxyOutbound.Count -ne 1) {
            throw "配置 '$Name' 必须各自包含唯一的 proxy 和 dns-proxy-out 出站。"
        }
        if (-not (Test-PositiveDuration (Get-MapValue $proxyOutbound[0] 'connect_timeout'))) {
            throw "配置 '$Name' 的 proxy 必须使用正时长连接超时。"
        }
        $proxyDomainResolver = Get-MapValue $proxyOutbound[0] 'domain_resolver'
        if (
            -not ($proxyDomainResolver -is [System.Collections.IDictionary]) -or
            (Get-MapValue $proxyDomainResolver 'server') -ne 'dns-node' -or
            -not (Test-PositiveDuration (Get-MapValue $proxyDomainResolver 'timeout'))
        ) {
            throw "配置 '$Name' 的 proxy 域名解析必须使用独立 dns-node transport 和正时长超时。"
        }
        if ((Get-MapValue $dnsProxyOutbound[0] 'type') -ne 'selector') {
            throw "配置 '$Name' 的 dns-proxy-out 必须是 selector 出站。"
        }
        $selectorMembers = @(Get-MapValue $dnsProxyOutbound[0] 'outbounds')
        if ($selectorMembers.Count -ne 1 -or $selectorMembers[0] -ne 'proxy' -or (Get-MapValue $dnsProxyOutbound[0] 'default') -ne 'proxy') {
            throw "配置 '$Name' 的 dns-proxy-out 必须只选择并默认使用 proxy。"
        }
    }

    $directOutbound = @($outbounds | Where-Object { (Get-MapValue $_ 'tag') -eq 'direct' })
    $dnsDirectOutbound = @($outbounds | Where-Object { (Get-MapValue $_ 'tag') -eq 'dns-direct-out' })
    if ($dnsDirectOutbound.Count -gt 0) {
        if ($directOutbound.Count -ne 1 -or $dnsDirectOutbound.Count -ne 1) {
            throw "配置 '$Name' 必须各自包含唯一的 direct 和 dns-direct-out 出站。"
        }
        if (-not (Test-PositiveDuration (Get-MapValue $directOutbound[0] 'connect_timeout'))) {
            throw "配置 '$Name' 的 direct 必须使用正时长连接超时。"
        }
        if ((Get-MapValue $dnsDirectOutbound[0] 'type') -ne 'selector') {
            throw "配置 '$Name' 的 dns-direct-out 必须是 selector 出站。"
        }
        $directSelectorMembers = @(Get-MapValue $dnsDirectOutbound[0] 'outbounds')
        if ($directSelectorMembers.Count -ne 1 -or $directSelectorMembers[0] -ne 'direct' -or (Get-MapValue $dnsDirectOutbound[0] 'default') -ne 'direct') {
            throw "配置 '$Name' 的 dns-direct-out 必须只选择并默认使用 direct。"
        }
    }

    Assert-DnsBootstrapConfiguration -Configuration $Configuration
    $dnsFinal = Get-MapValue $dns 'final'
    if ($dnsFinal -ne 'dns-proxy') { throw "Configuration '$Name' requires dns.final=dns-proxy." }
    if ($dnsFinal -and $dnsFinal -notin $dnsTags) {
        throw "配置 '$Name' 的 dns.final 引用了不存在的 DNS 服务器 '$dnsFinal'。"
    }

    foreach ($outbound in $outbounds) {
        $resolver = Get-MapValue $outbound 'domain_resolver'
        if ($resolver -is [string] -and $resolver -notin $dnsTags) {
            throw "配置 '$Name' 的出站引用了不存在的 DNS 服务器 '$resolver'。"
        }
        if ($resolver -is [System.Collections.IDictionary]) {
            $resolverServer = Get-MapValue $resolver 'server'
            if ($resolverServer -and $resolverServer -notin $dnsTags) {
                throw "配置 '$Name' 的出站引用了不存在的 DNS 服务器 '$resolverServer'。"
            }
        }
    }

    if ($Configuration.Contains('inbounds')) {
        $rawInbounds = Get-MapValue $Configuration 'inbounds'
        if (-not ($rawInbounds -is [System.Array])) {
            throw "配置 '$Name' 的 inbounds 必须是数组。"
        }
        $inboundTags = @(@($rawInbounds) | ForEach-Object { Get-MapValue $_ 'tag' } | Where-Object { $_ })
        if (@($inboundTags | Select-Object -Unique).Count -ne $inboundTags.Count) {
            throw "配置 '$Name' 包含重复的入站 tag。"
        }
        foreach ($inbound in @($rawInbounds | Where-Object { (Get-MapValue $_ 'type') -eq 'tun' })) {
            if (-not (Test-UnsignedInteger (Get-MapValue $inbound 'mtu') -Minimum 576 -Maximum 65535)) {
                throw "配置 '$Name' 的 TUN MTU 必须为 576 到 65535 的整数。"
            }
            if ((Get-MapValue $inbound 'dns_mode') -ne 'hijack') {
                throw "配置 '$Name' 的 TUN 入站必须使用 dns_mode=hijack。"
            }
            if ($null -ne (Get-MapValue $inbound 'dns_address')) {
                throw "配置 '$Name' 的 TUN 入站不得设置 dns_address；应由 sing-box 自动派生并接入内部 DNS。"
            }
            $stack = Get-MapValue $inbound 'stack'
            if (-not ($stack -is [string]) -or $stack -notin @('system','gvisor','mixed')) {
                throw "配置 '$Name' 的 TUN stack 必须是 sing-box 1.14.4 支持的 system、gvisor 或 mixed。"
            }
            if ($inbound.Contains('endpoint_independent_nat') -and
                -not ((Get-MapValue $inbound 'endpoint_independent_nat') -is [bool])) {
                throw "配置 '$Name' 的旧 endpoint_independent_nat 字段若存在必须是布尔值；该字段不控制实际 NAT 行为。"
            }
            if (-not (Test-PositiveDuration (Get-MapValue $inbound 'udp_timeout'))) {
                throw "配置 '$Name' 的 TUN UDP NAT 超时必须为正时长。"
            }
            if ((Get-MapValue $inbound 'udp_mapping') -ne 'endpoint_independent') {
                throw "配置 '$Name' 的 TUN UDP 映射必须使用 endpoint_independent。"
            }
            if ((Get-MapValue $inbound 'udp_filtering') -ne 'endpoint_independent') {
                throw "配置 '$Name' 的 TUN UDP 过滤必须使用 endpoint_independent。"
            }
            if (-not (Test-UnsignedInteger (Get-MapValue $inbound 'udp_nat_max'))) {
                throw "配置 '$Name' 的 TUN UDP NAT 会话上限必须为 0 到 4294967295 的整数。"
            }

            $hasRouteExcludeAddressSet = $inbound.Contains('route_exclude_address_set')
            if ($hasRouteExcludeAddressSet) {
                if (-not $LinuxRouteExcludeAddressSets -or $Name -ne 'linux') {
                    throw "配置 '$Name' 不得继承或生成未经授权的 route_exclude_address_set。"
                }
                $excludeTags = Get-MapValue $inbound 'route_exclude_address_set'
                if (-not ($excludeTags -is [System.Array]) -or $excludeTags.Count -eq 0 -or
                    (Get-MapValue $inbound 'auto_route') -ne $true -or (Get-MapValue $inbound 'auto_redirect') -ne $true) {
                    throw 'Linux route_exclude_address_set requires a non-empty tag array and auto_route/auto_redirect.'
                }
                $expectedIpTags = @($RuleSetPlan | Where-Object { $_.Action -ceq 'direct' -and $_.Kind -eq 'ip' } | ForEach-Object { [string]$_.Tag })
                if ($excludeTags.Count -ne $expectedIpTags.Count -or
                    @($excludeTags | Where-Object { -not ($_ -is [string]) }).Count -gt 0 -or
                    @($excludeTags | Select-Object -Unique).Count -ne $excludeTags.Count -or
                    (($excludeTags -join ',') -cne ($expectedIpTags -join ','))) {
                    throw 'Linux route_exclude_address_set must reference exactly the effective IPv4 direct rule-sets in order.'
                }
            }
            elseif ($LinuxRouteExcludeAddressSets) {
                throw 'Linux route exclusion was selected but no effective IPv4 rule-set reference was generated.'
            }
        }
    }

    $routeRules = Get-MapValue $route 'rules'
    $legacyDnsHijackRules = @()
    foreach ($routeRule in $routeRules) {
        if ((Get-MapValue $routeRule 'outbound') -eq 'proxy') {
            throw "Configuration '$Name' must use effective direct rules with default proxy, not explicit proxy actions."
        }
        $action = Get-MapValue $routeRule 'action'
        $rulePort = Get-MapValue $routeRule 'port'
        if ($action -eq 'hijack-dns') {
            $inboundTags = @(Get-MapValue $routeRule 'inbound')
            if ($inboundTags.Count -eq 1 -and $inboundTags[0] -ceq 'dns-in' -and $null -eq $rulePort) { continue }
            $legacyDnsHijackRules += ,$routeRule
        }
        elseif (($null -ne $rulePort) -and ($rulePort -contains 53)) { $legacyDnsHijackRules += ,$routeRule }
    }
    if ($legacyDnsHijackRules.Count -gt 0) {
        throw "配置 '$Name' 只允许 dns-in 专用 hijack-dns 规则；不得保留旧端口 53 hijack 规则。"
    }
}

function Assert-IPv4Prefix {
    param(
        [Parameter(Mandatory)]
        [string]$Prefix
    )

    if ($Prefix -notmatch '^([^/]+)/([0-9]{1,2})$') {
        throw "TUN 地址必须使用 IPv4 CIDR 格式，例如 172.28.255.1/30：$Prefix"
    }

    $address = $null
    $prefixLength = [int]$Matches[2]
    if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "TUN 地址不是有效的 IPv4 地址：$Prefix"
    }
    if ($prefixLength -lt 1 -or $prefixLength -gt 32) {
        throw "TUN IPv4 前缀长度必须在 1 到 32 之间：$Prefix"
    }
}

function Set-TunAddress {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration,

        [Parameter(Mandatory)]
        [string]$Address
    )

    if (-not $Configuration.Contains('inbounds')) {
        throw '无法覆盖 TUN 地址：配置中没有 inbounds。'
    }

    $tunFound = $false
    $inbounds = Get-MapValue $Configuration 'inbounds'
    foreach ($inbound in $inbounds) {
        if ((Get-MapValue $inbound 'type') -eq 'tun') {
            $inbound['address'] = @($Address)
            $tunFound = $true
        }
    }
    if (-not $tunFound) {
        throw '无法覆盖 TUN 地址：配置中没有 TUN 入站。'
    }
}

function Merge-TunOverlay {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Overlay
    )

    if (-not $Configuration.Contains('inbounds')) {
        throw '无法应用平台 TUN 适配：母版中没有 inbounds。'
    }

    $inbounds = Get-MapValue $Configuration 'inbounds'
    $tunFound = $false
    for ($index = 0; $index -lt $inbounds.Count; $index++) {
        if ((Get-MapValue $inbounds[$index] 'type') -eq 'tun') {
            $inbounds[$index] = Merge-JsonObject -Base $inbounds[$index] -Overlay $Overlay
            $tunFound = $true
        }
    }
    if (-not $tunFound) {
        throw '无法应用平台 TUN 适配：母版中没有 TUN 入站。'
    }
    $Configuration['inbounds'] = $inbounds
}

function Test-RuleContainsDomain {
    param(
        [Parameter(Mandatory)]
        $Rule
    )

    foreach ($field in @('domain', 'domain_suffix')) {
        if ($null -ne $Rule.PSObject.Properties[$field]) {
            return $true
        }
    }
    return $false
}

function Get-BinaryRuleSetPlan {
    param(
        [Parameter(Mandatory)][string]$RulesPath,
        [Parameter(Mandatory)][string]$CachePath,
        $RoutingDocument
    )
    if ($null -eq $RoutingDocument) { $RoutingDocument = Read-JsonFile $RulesPath }
    $routingDocument = $RoutingDocument
    $planFingerprint = Get-BinaryRuleSetPlanFingerprint -RulesPath $RulesPath -RoutingDocument $routingDocument
    if (Test-Path -LiteralPath $CachePath -PathType Leaf) {
        try {
            $cached = Read-JsonFile $CachePath
            $cachedPlan = @($cached.plan)
            $cachedPlanJson = ConvertTo-Json -InputObject $cachedPlan -Depth 100 -Compress
            if ($cached -is [System.Management.Automation.PSCustomObject] -and
                (Test-UnsignedInteger $cached.version -Minimum 2 -Maximum 2) -and
                $cached.fingerprint -is [string] -and $cached.fingerprint -ceq $planFingerprint -and
                $cached.plan_sha256 -is [string] -and $cached.plan_sha256 -match '^[0-9A-Fa-f]{64}$' -and
                $cached.plan -is [array] -and
                (Get-TextSha256 $cachedPlanJson) -ceq [string]$cached.plan_sha256 -and
                (Test-BinaryRuleSetPlanShape -Plan $cachedPlan)) {
                Write-Host 'Effective-direct plan cache reused.'
                return $cachedPlan
            }
        }
        catch {
            # A malformed or incomplete cache is a miss; source data remains authoritative.
        }
    }
    $resolvedPlan = Get-SameTypeDirectPlan -Document $routingDocument
    if (-not (Test-BinaryRuleSetPlanShape -Plan @($resolvedPlan))) { throw 'Same-type routing compiler produced an invalid plan.' }
    $resolvedPlan = @($resolvedPlan)
    Write-Host 'Effective-direct plan cache rebuilt.'
    $planJson = ConvertTo-Json -InputObject $resolvedPlan -Depth 100 -Compress
    $cacheValue = [ordered]@{
        version = 2
        fingerprint = $planFingerprint
        plan_sha256 = Get-TextSha256 $planJson
        plan = $resolvedPlan
    }
    Write-JsonAtomically -Configuration $cacheValue -Destination $CachePath -Overwrite
    return $resolvedPlan
}

function Get-TextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '')
    }
    finally { $sha.Dispose() }
}

function Get-BinaryRuleSetPlanFingerprint {
    param([Parameter(Mandatory)][string]$RulesPath, [Parameter(Mandatory)]$RoutingDocument)
    $parts = [System.Collections.Generic.List[string]]::new()
    $semanticInput = [ordered]@{
        version = $RoutingDocument.version
        conflict_policy = $RoutingDocument.conflict_policy
        groups = @($RoutingDocument.groups)
    }
    $parts.Add('same-type-plan-v2')
    $parts.Add((Get-TextSha256 (ConvertTo-Json -InputObject $semanticInput -Depth 100 -Compress)))
    $manifestPath = Join-Path $projectRoot 'routing\routing-sources.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $parts.Add((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash)
        $manifest = Read-JsonFile $manifestPath
        $manifestDirectory = Split-Path -Parent $manifestPath
        foreach ($rule in @($manifest.rules)) {
            foreach ($input in @($rule.inputs)) {
                if (-not $input.PSObject.Properties['type'] -or [string]$input.type -cne 'local') { continue }
                $sourcePath = Join-Path $manifestDirectory ([string]$input.path)
                $sourceHash = if (Test-Path -LiteralPath $sourcePath -PathType Leaf) { (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash } else { 'missing' }
                $parts.Add('local:' + [string]$rule.id + ':' + [string]$input.path + ':' + $sourceHash)
            }
        }
        foreach ($resource in @($manifest.resources)) {
            if ([string]$resource.type -eq 'remote') {
                $uri = [Uri][string]$resource.url
                $extension = [IO.Path]::GetExtension($uri.AbsolutePath)
                if (-not $extension) { $extension = '.bin' }
                $sourcePath = Join-Path (Join-Path $projectRoot 'routing\cache') ([string]$resource.tag + $extension.ToLowerInvariant())
                $sourceHash = if (Test-Path -LiteralPath $sourcePath -PathType Leaf) { (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash } else { 'missing' }
                $parts.Add('remote:' + [string]$resource.tag + ':' + [string]$resource.format + ':' + [string]$resource.url + ':' + $sourceHash)
            }
        }
    }
    else { $parts.Add('manifest:missing') }
    $generatorImplementationPath = [string]$PSCommandPath
    if ([string]::IsNullOrWhiteSpace($generatorImplementationPath)) {
        $generatorImplementationPath = Join-Path $projectRoot 'scripts\Generate-SingBoxConfig.ps1'
    }
    $generatorDirectory = Split-Path -Parent $generatorImplementationPath
    foreach ($path in @(
        $generatorImplementationPath,
        (Join-Path $generatorDirectory 'SameTypeDirectPolicy.ps1'),
        (Join-Path $generatorDirectory 'Direct-RoutingPolicy.ps1'),
        (Join-Path (Join-Path $projectRoot 'src') 'SameTypeDirectCompiler.cs'),
        (Join-Path $generatorDirectory 'Update-RoutingRules.ps1'),
        (Join-Path $generatorDirectory 'Json-Validation.ps1'),
        (Join-Path (Join-Path $projectRoot 'src') 'RoutingRuleCompiler.cs')
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $parts.Add((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash) }
        else { $parts.Add('missing:' + $path) }
    }
    $parts.Add([string]$PSVersionTable.PSVersion)
    $parts.Add([string][Globalization.CultureInfo]::CurrentCulture.Name)
    return Get-TextSha256 ($parts -join ':')
}

function Test-BinaryRuleSetPlanShape {
    param([Parameter(Mandatory)][object[]]$Plan)
    if ($Plan.Count -lt 1 -or $Plan.Count -gt 10000) { return $false }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $seenTypes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $closedTypes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $lastType = ''
    $lastSequence = 0
    $directStarted = $false
    foreach ($item in $Plan) {
        if ($null -eq $item -or $null -eq $item.PSObject.Properties['Action'] -or
            $null -eq $item.PSObject.Properties['Kind'] -or $null -eq $item.PSObject.Properties['HasDomain'] -or
            $null -eq $item.PSObject.Properties['Sequence'] -or $null -eq $item.PSObject.Properties['Tag'] -or
            $null -eq $item.PSObject.Properties['Rules'] -or $null -eq $item.PSObject.Properties['SourceGroups'] -or
            $null -eq $item.PSObject.Properties['SourceSequences']) { return $false }
        if (-not ($item.Action -is [string]) -or -not ($item.Kind -is [string]) -or
            -not ($item.HasDomain -is [bool]) -or -not ($item.Tag -is [string]) -or
            -not ($item.Rules -is [array]) -or -not ($item.SourceGroups -is [array]) -or -not ($item.SourceSequences -is [array]) -or
            $item.SourceGroups.Count -lt 1 -or $item.SourceGroups.Count -gt 10000 -or
            $item.SourceSequences.Count -ne $item.SourceGroups.Count -or
            @($item.SourceGroups | Where-Object { -not ($_ -is [string]) -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
            -not (Test-UnsignedInteger $item.Sequence -Minimum 1 -Maximum 10000000)) { return $false }
        $sequence = 0
        $family = ''
        if ($item.Action -cnotin @('reject','direct') -or $item.Kind -notin @('domain','ip','port') -or
            [bool]$item.HasDomain -ne ($item.Kind -eq 'domain') -or
            -not $seen.Add([string]$item.Tag)) { return $false }
        if ($item.Action -ceq 'direct') { $directStarted = $true }
        elseif ($directStarted) { return $false }
        $tagPrefix = 'routing-' + $item.Action + '-'
        if ([string]$item.Tag -cmatch ('^' + $tagPrefix + '(domain|ip|port)$')) { $family = [string]$Matches[1] }
        elseif ([string]$item.Tag -match '^routing-direct-([0-9]+)-(domain|ip|port|source_port)$') {
            if (-not [int]::TryParse([string]$Matches[1], [ref]$sequence) -or $sequence -ne [int]$item.Sequence) { return $false }
            $family = [string]$Matches[2]
        }
        else { return $false }
        if (($family -eq 'source_port' -and $item.Kind -ne 'port') -or ($family -ne 'source_port' -and $family -ne $item.Kind)) { return $false }
        $previousSourceSequence = 0
        foreach ($sourceSequenceValue in $item.SourceSequences) {
            if (-not (Test-UnsignedInteger $sourceSequenceValue -Minimum 1 -Maximum 10000000) -or
                [int]$sourceSequenceValue -le $previousSourceSequence) { return $false }
            $previousSourceSequence = [int]$sourceSequenceValue
        }
        if ([int]$item.Sequence -ne [int]$item.SourceSequences[0]) { return $false }
        $actionType = $item.Action + '-' + $item.Kind
        if ($lastType -ne $actionType) {
            if ($closedTypes.Contains($actionType)) { return $false }
            if ($lastType) { [void]$closedTypes.Add($lastType) }
            [void]$seenTypes.Add($actionType)
            $lastType = $actionType
            $lastSequence = 0
        }
        if ($sequence -lt $lastSequence) { return $false }
        $lastSequence = $sequence
        if (($item.Kind -eq 'port' -and ($item.Rules.Count -lt 1 -or $item.Rules.Count -gt 2)) -or
            ($item.Kind -ne 'port' -and $item.Rules.Count -ne 1)) { return $false }
        $allowed = if ($item.Kind -eq 'domain') { @('domain','domain_suffix','domain_regex') } elseif ($item.Kind -eq 'ip') { @('ip_cidr') } else { @('port','port_range','source_port','source_port_range') }
        $seenPortSource = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($rule in $item.Rules) {
            if ($null -eq $rule -or
                -not ($rule -is [System.Collections.IDictionary]) -and -not ($rule -is [System.Management.Automation.PSCustomObject])) { return $false }
            $ruleFields = @(
                if ($rule -is [System.Collections.IDictionary]) { $rule.Keys }
                else { $rule.PSObject.Properties.Name }
            )
            if ($ruleFields.Count -lt 1 -or @($ruleFields | Where-Object { $_ -notin $allowed }).Count -gt 0) { return $false }
            if ($item.Kind -eq 'port') {
                $hasDestinationPort = @($ruleFields | Where-Object { $_ -in @('port','port_range') }).Count -gt 0
                $hasSourcePort = @($ruleFields | Where-Object { $_ -in @('source_port','source_port_range') }).Count -gt 0
                if ($hasDestinationPort -eq $hasSourcePort) { return $false }
                $portSide = if ($hasSourcePort) { 'source_port' } else { 'port' }
                if (-not $seenPortSource.Add($portSide)) { return $false }
            }
            foreach ($field in $ruleFields) {
                if ($rule -is [System.Collections.IDictionary]) { $values = $rule[[string]$field] }
                else { $values = $rule.PSObject.Properties[[string]$field].Value }
                if (-not ($values -is [array]) -or $values.Count -lt 1 -or $values.Count -gt 1000000) { return $false }
                if ($field -in @('domain','domain_suffix','domain_regex')) {
                    if (@($values | Where-Object { -not ($_ -is [string]) -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { return $false }
                    if ($field -in @('domain','domain_suffix')) {
                        foreach ($value in $values) {
                            try { if ([SingBoxSameType.DomainCompiler]::Normalize([string]$value) -cne [string]$value) { return $false } }
                            catch { return $false }
                        }
                    }
                    if ($field -eq 'domain_regex') {
                        foreach ($value in $values) {
                            if ($value -match '\(\?[=!<]|\[\^' -or -not [SingBoxSameType.DomainCompiler]::IsGeneratedPositiveRegex([string]$value)) { return $false }
                        }
                    }
                }
                elseif ($field -eq 'ip_cidr') {
                    foreach ($value in $values) {
                        if (-not ($value -is [string]) -or $value -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}/(?:[0-9]|[12][0-9]|3[0-2])$') { return $false }
                        $addressText = $value.Substring(0, $value.LastIndexOf('/'))
                        $address = $null
                        if (-not [Net.IPAddress]::TryParse($addressText, [ref]$address) -or
                            $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $addressText) { return $false }
                        try {
                            $normalizedCidrs = [SingBoxSameType.Ranges]::CIDRs(@([SingBoxSameType.Ranges]::IP([string]$value)))
                            if ($normalizedCidrs.Count -ne 1 -or $normalizedCidrs[0] -cne [string]$value) { return $false }
                        }
                        catch { return $false }
                    }
                }
                elseif ($field -in @('port','source_port')) {
                    foreach ($value in $values) { if (-not (Test-UnsignedInteger $value -Maximum 65535)) { return $false } }
                }
                else {
                    foreach ($value in $values) {
                        if (-not ($value -is [string]) -or $value -notmatch '^(?:0|[1-9][0-9]{0,4}):(?:0|[1-9][0-9]{0,4})$') { return $false }
                        $bounds = $value.Split(':')
                        $start = 0; $end = 0
                        if (-not [int]::TryParse($bounds[0], [ref]$start) -or -not [int]::TryParse($bounds[1], [ref]$end) -or
                            $start -lt 0 -or $end -gt 65535 -or $start -ge $end) { return $false }
                    }
                }
            }
        }
    }
    return $true
}

function Add-BinaryRoutingRules {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration,

        [Parameter(Mandatory)]
        [object[]]$RuleSetPlan,

        [string]$ClientName,

        [switch]$LinuxRouteExcludeAddressSets
    )

    $route = Get-MapValue $Configuration 'route'
    $dns = Get-MapValue $Configuration 'dns'
    $ruleSets = [System.Collections.Generic.List[object]]::new()
    $routeRules = [System.Collections.Generic.List[object]]::new()
    $existingRouteRules = Get-MapValue $route 'rules'
    foreach ($existingRule in $existingRouteRules) {
        $routeRules.Add((Copy-JsonValue $existingRule))
    }
    Assert-NodeDnsPolicyShape -Configuration $Configuration
    $dnsRules = [System.Collections.Generic.List[object]]::new()
    $dnsRules.Add((New-ClientAAAARejectRule))
    $nodeDnsPolicy = Get-NodeDnsPolicySpec
    foreach ($nodeDnsRule in $nodeDnsPolicy.DnsRules) {
        $dnsRules.Add((Copy-JsonValue $nodeDnsRule))
    }
    $dnsDomainTags = [System.Collections.Generic.List[string]]::new()

    foreach ($item in $RuleSetPlan) {
        $relativePath = 'rule-set/{0}.srs' -f [string]$item.Tag
        $ruleSets.Add([ordered]@{
            type = 'local'
            tag = [string]$item.Tag
            format = 'binary'
            path = $relativePath
        })
        if ($item.Action -ceq 'reject') {
            if ($item.HasDomain) { $dnsRules.Insert(0, [ordered]@{ rule_set=[string]$item.Tag; action='reject'; no_drop=$true }) }
            else { $routeRules.Add([ordered]@{ rule_set=[string]$item.Tag; action='reject'; method='default'; no_drop=$true }) }
            continue
        }
        # Domains select DNS upstreams only. Business traffic uses numeric sets.
        if (-not [bool]$item.HasDomain) {
            $routeRules.Add((New-EffectiveDirectRule -Tag $item.Tag))
        }
        if ([bool]$item.HasDomain) {
            $dnsDomainTags.Add([string]$item.Tag)
        }
    }

    if ($dnsDomainTags.Count -gt 0) {
        $directGroup = @(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues $dnsDomainTags.ToArray() -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s')
        $dnsRules.AddRange([object[]]$directGroup)
    }
    $proxyGroup = @(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s')
    $dnsRules.AddRange([object[]]$proxyGroup)

    if ($LinuxRouteExcludeAddressSets) {
        if ($ClientName -ne 'linux') { throw 'route_exclude_address_set is limited to the ordinary Linux client profile.' }
        $tunInbounds = @($Configuration['inbounds'] | Where-Object { (Get-MapValue $_ 'type') -eq 'tun' })
        if ($tunInbounds.Count -ne 1 -or (Get-MapValue $tunInbounds[0] 'auto_redirect') -ne $true -or
            (Get-MapValue $tunInbounds[0] 'auto_route') -ne $true) {
            throw 'Linux route exclusion requires one TUN inbound with auto_redirect and auto_route enabled.'
        }
        $ipTags = @($RuleSetPlan | Where-Object { $_.Action -ceq 'direct' -and $_.Kind -eq 'ip' } | ForEach-Object { [string]$_.Tag })
        if ($ipTags.Count -eq 0) { throw 'No effective IPv4 direct rule-set is available for Linux route exclusion.' }
        $publishedIpTags = @($ruleSets | Where-Object { [string]$_.tag -match '^routing-direct-.*ip$' } | ForEach-Object { [string]$_.tag })
        if (($ipTags -join ',') -cne ($publishedIpTags -join ',')) { throw 'Linux route exclusion must reference exactly the published effective IPv4 direct rule-sets.' }
        if ($tunInbounds[0].Contains('route_exclude_address_set')) { throw 'The Linux TUN template already has route_exclude_address_set; refusing to merge unvalidated entries.' }
        $tunInbounds[0]['route_exclude_address_set'] = $ipTags
    }

    $route['rule_set'] = $ruleSets.ToArray()
    $route['rules'] = $routeRules.ToArray()
    $dns['rules'] = $dnsRules.ToArray()
    Assert-EffectiveDirectConfiguration -Configuration $Configuration
}

function Resolve-SingBoxExecutable {
    param([string]$RequestedPath)
    return Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RequestedPath $RequestedPath
}

function Write-RuleSetSource {
    param(
        [Parameter(Mandatory)]
        [object[]]$Rules,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    $document = [ordered]@{
        version = 5
        rules = Copy-JsonValue $Rules
    }
    $compactJson = $document | ConvertTo-Json -Depth 100 -Compress
    $json = Format-JsonText -Text $compactJson
    try { [System.IO.File]::WriteAllText($Destination, "$json`n", [System.Text.UTF8Encoding]::new($false)) }
    catch { throw "无法写入规则集源文件（路径长度 $($Destination.Length)）：$Destination`n$($_.Exception.Message)" }
}

function Get-NormalizedClientPath {
    param([Parameter(Mandatory)][string]$Path)
    $fullPath = [IO.Path]::GetFullPath($Path)
    $pathRoot = [IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.Length -gt $pathRoot.Length) { $fullPath = $fullPath.TrimEnd([char[]]'\/') }
    return $fullPath
}

function Test-ClientPathOverlap {
    param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right)
    $leftPath = Get-NormalizedClientPath $Left
    $rightPath = Get-NormalizedClientPath $Right
    if ($leftPath.Equals($rightPath, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $separator = [IO.Path]::DirectorySeparatorChar
    return $leftPath.StartsWith($rightPath + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $rightPath.StartsWith($leftPath + $separator, [StringComparison]::OrdinalIgnoreCase)
}

function Get-ClientSupportDirectory {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$DefaultOutputDirectory,
        [string]$ExplicitSupportDirectory
    )
    if ($ExplicitSupportDirectory) { return Get-NormalizedClientPath $ExplicitSupportDirectory }
    $outputPath = Get-NormalizedClientPath $OutputDirectory
    $defaultOutputPath = Get-NormalizedClientPath $DefaultOutputDirectory
    $supportRoot = Join-Path $ProjectRoot 'outputs\client-build'
    if ($outputPath.Equals($defaultOutputPath, [StringComparison]::OrdinalIgnoreCase)) {
        return Get-NormalizedClientPath $supportRoot
    }
    $identity = $outputPath.ToUpperInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $key = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    return Get-NormalizedClientPath (Join-Path (Join-Path $supportRoot 'custom') $key)
}

function Assert-ClientPathAncestorsAreLocal {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    $cursor = Get-NormalizedClientPath $Path
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Label path contains a reparse point: $cursor" }
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent.Equals($cursor, [StringComparison]::OrdinalIgnoreCase)) { break }
        $cursor = $parent
    }
}

function Assert-ClientBuildDirectories {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$SupportDirectory,
        [Parameter(Mandatory)][psobject]$BuildPaths,
        [string]$RuntimeExecutable,
        [string[]]$AdditionalProtectedPaths = @()
    )
    $outputPath = Get-NormalizedClientPath $OutputDirectory
    $supportPath = Get-NormalizedClientPath $SupportDirectory
    $supportRoot = [IO.Path]::GetPathRoot($supportPath)
    if ($supportPath.Equals($supportRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing a filesystem root as client support directory.' }
    if (Test-ClientPathOverlap $outputPath $supportPath) { throw 'Client support directory must not overlap the output directory.' }
    $reservedOutputPaths = @(
        $BuildPaths.Destination
        $BuildPaths.Stage
        $BuildPaths.Backup
        $BuildPaths.Journal
        $BuildPaths.Lock
        ($BuildPaths.Journal + '.write')
    )
    foreach ($reservedOutputPath in $reservedOutputPaths) {
        if (Test-ClientPathOverlap $supportPath $reservedOutputPath) { throw "Client support directory overlaps a reserved build transaction path: $reservedOutputPath" }
    }
    $protectedDirectories = @('scripts','src','tests','docs','config','routing','inputs','openwrt','generated','backups') | ForEach-Object {
        Get-NormalizedClientPath (Join-Path $ProjectRoot $_)
    }
    foreach ($protectedDirectory in $protectedDirectories) {
        if (Test-ClientPathOverlap $supportPath $protectedDirectory) { throw "Client support directory overlaps protected project content: $protectedDirectory" }
    }
    $protectedFiles = @(
        (Join-Path (Join-Path $ProjectRoot 'generated') 'sing-box-configs.zip')
        (Join-Path (Join-Path $ProjectRoot 'config') 'sing-box-core-base.json')
        (Join-Path (Join-Path $ProjectRoot 'config') 'client-profiles.json')
        (Join-Path (Join-Path $ProjectRoot 'src') 'SameTypeDirectCompiler.cs')
    )
    $rootFiles = @(Get-ChildItem -LiteralPath $ProjectRoot -File -Force -ErrorAction SilentlyContinue | ForEach-Object { Get-NormalizedClientPath $_.FullName })
    foreach ($protectedFile in @($protectedFiles) + @($AdditionalProtectedPaths) + @($rootFiles)) {
        if (-not $protectedFile) { continue }
        if (Test-ClientPathOverlap $supportPath $protectedFile) { throw "Client support directory overlaps a protected file: $protectedFile" }
    }
    if ($RuntimeExecutable) {
        $runtimePath = Get-NormalizedClientPath $RuntimeExecutable
        $runtimeDirectory = Get-NormalizedClientPath (Split-Path -Parent $runtimePath)
        if ((Test-ClientPathOverlap $supportPath $runtimePath) -or (Test-ClientPathOverlap $supportPath $runtimeDirectory)) {
            throw "Client support directory overlaps the sing-box runtime: $runtimePath"
        }
    }
    if ([IO.File]::Exists($supportPath)) { throw "Client support path is a file: $supportPath" }
    Assert-ClientPathAncestorsAreLocal -Path $supportPath -Label 'Client support'
    Assert-ClientPathAncestorsAreLocal -Path $outputPath -Label 'Client output'
    foreach ($supportEntry in @(
        (Join-Path $supportPath 'build-cache.json'),
        (Join-Path $supportPath 'build-cache.lock'),
        (Join-Path $supportPath 'same-type-plan-cache.json')
    )) {
        if ([IO.File]::Exists($supportEntry) -or [IO.Directory]::Exists($supportEntry)) {
            $item = Get-Item -LiteralPath $supportEntry -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Client support entry is a reparse point: $supportEntry" }
            if ($item.PSIsContainer) { throw "Client support file path is occupied by a directory: $supportEntry" }
        }
    }
}

function Prepare-ClientCachePublication {
    param([Parameter(Mandatory)][string]$StagedCachePath, [Parameter(Mandatory)][string]$SupportDirectory)
    $pendingPath = Join-Path $SupportDirectory ('build-cache.json.' + [guid]::NewGuid().ToString('N') + '.pending')
    try {
        $source = [IO.File]::OpenRead($StagedCachePath)
        try {
            $destination = [IO.FileStream]::new($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
            try { $source.CopyTo($destination); $destination.Flush($true) } finally { $destination.Dispose() }
        }
        finally { $source.Dispose() }
    }
    catch {
        if ([IO.File]::Exists($pendingPath)) { [IO.File]::Delete($pendingPath) }
        throw
    }
    return $pendingPath
}

function Publish-ClientCachePublication {
    param([Parameter(Mandatory)][string]$PendingPath, [Parameter(Mandatory)][string]$CachePath)
    if ([IO.File]::Exists($CachePath)) {
        [IO.File]::Replace($PendingPath, $CachePath, [System.Management.Automation.Language.NullString]::Value)
    }
    else {
        [IO.File]::Move($PendingPath, $CachePath)
    }
}

function Remove-StaleClientCachePublications {
    param([Parameter(Mandatory)][string]$SupportDirectory)
    if (-not [IO.Directory]::Exists($SupportDirectory)) { return }
    foreach ($item in Get-ChildItem -LiteralPath $SupportDirectory -File -Force -ErrorAction Stop) {
        if ($item.Name -cnotmatch '^build-cache\.json\.[0-9a-f]{32}\.pending$') { continue }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Write-Warning "保留重解析点形式的孤立缓存暂存文件：$($item.FullName)"
            continue
        }
        try { [IO.File]::Delete($item.FullName) }
        catch { Write-Warning "无法清理孤立缓存暂存文件：$($item.FullName)：$($_.Exception.Message)" }
    }
}

function Read-CompileCache {
    param([string]$Path)
    try {
        $cache = Read-JsonFile $Path
        if ($cache -isnot [System.Management.Automation.PSCustomObject] -or
            -not (Test-UnsignedInteger $cache.version -Minimum 1 -Maximum 2) -or
            $cache.compiler_sha256 -isnot [string] -or $cache.compiler_sha256 -cnotmatch '^[A-F0-9]{64}$' -or
            $cache.entries -isnot [array]) { return $null }
        $tags = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $cache.entries) {
            if ($entry -isnot [System.Management.Automation.PSCustomObject] -or
                $entry.tag -isnot [string] -or $entry.tag -cnotmatch '^[A-Za-z0-9_-]+$' -or
                -not $tags.Add($entry.tag) -or
                $entry.source_sha256 -isnot [string] -or $entry.source_sha256 -cnotmatch '^[A-F0-9]{64}$' -or
                $entry.binary_sha256 -isnot [string] -or $entry.binary_sha256 -cnotmatch '^[A-F0-9]{64}$') { return $null }
            if ($cache.version -eq 2 -and ($entry.binary_base64 -isnot [string] -or -not $entry.binary_base64)) { return $null }
        }
        return $cache
    }
    catch { return $null }
}

function Compile-BinaryRuleSets {
    param(
        [Parameter(Mandatory)]
        [object[]]$RuleSetPlan,

        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string]$StagingDirectory,
        [string]$ExistingCachePath,
        [string]$ExistingBinaryDirectory
    )

    $sourceDirectory = Join-Path $StagingDirectory 'rule-set-source'
    $binaryDirectory = Join-Path $StagingDirectory 'rule-set'
    New-Item -ItemType Directory -Path $sourceDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
    $compilerHash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
    $oldCache = $null
    if ($ExistingCachePath -and (Test-Path -LiteralPath $ExistingCachePath -PathType Leaf)) {
        $oldCache = Read-CompileCache $ExistingCachePath
    }
    $newCache = [ordered]@{version=2; compiler_sha256=$compilerHash; entries=@()}
    $compiledCount = 0
    $reusedCount = 0

    try {
        foreach ($item in $RuleSetPlan) {
            $sourcePath = Join-Path $sourceDirectory ([string]$item.Tag + '.json')
            $binaryPath = Join-Path $binaryDirectory ([string]$item.Tag + '.srs')
            Write-RuleSetSource -Rules @($item.Rules) -Destination $sourcePath
            $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
            $reused = $false
            if ($oldCache -and $oldCache.compiler_sha256 -eq $compilerHash) {
                $cached = @($oldCache.entries | Where-Object { $_.tag -eq $item.Tag -and $_.source_sha256 -eq $sourceHash })
                $oldBinary = if ($ExistingBinaryDirectory) { Join-Path $ExistingBinaryDirectory ('rule-set/' + $item.Tag + '.srs') } else { $null }
                if ($cached.Count -eq 1 -and $oldCache.version -eq 2) {
                    try {
                        $cachedBytes = [Convert]::FromBase64String([string]$cached[0].binary_base64)
                        $sha = [Security.Cryptography.SHA256]::Create()
                        try { $cachedHash = [BitConverter]::ToString($sha.ComputeHash($cachedBytes)).Replace('-', '') } finally { $sha.Dispose() }
                        if ($cachedHash -ceq $cached[0].binary_sha256) {
                            [IO.File]::WriteAllBytes($binaryPath, $cachedBytes)
                            $reused = $true
                            $reusedCount++
                        }
                    }
                    catch { $reused = $false }
                }
                elseif ($cached.Count -eq 1 -and $oldCache.version -eq 1 -and $oldBinary -and (Test-Path -LiteralPath $oldBinary -PathType Leaf) -and (Get-FileHash -LiteralPath $oldBinary -Algorithm SHA256).Hash -eq $cached[0].binary_sha256) {
                    Copy-Item -LiteralPath $oldBinary -Destination $binaryPath -Force
                    $reused = $true
                    $reusedCount++
                }
            }

            if (-not $reused) {
            $compiledCount++
            $previousNativeExitCodeVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
            $hadPreviousNativeExitCode = $null -ne $previousNativeExitCodeVariable
            $previousNativeExitCode = if ($hadPreviousNativeExitCode) { $previousNativeExitCodeVariable.Value } else { $null }
            try {
                $output = & $Executable rule-set compile $sourcePath -o $binaryPath 2>&1
                $nativeExitCode = $global:LASTEXITCODE
            }
            finally {
                if ($hadPreviousNativeExitCode) {
                    Set-Variable -Name LASTEXITCODE -Scope Global -Value $previousNativeExitCode
                }
                else {
                    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
                }
            }
            if ($nativeExitCode -ne 0) {
                $details = ($output | Out-String).Trim()
                throw "规则集编译失败：$($item.Tag)`n$details"
            }
            if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf) -or (Get-Item -LiteralPath $binaryPath).Length -eq 0) {
                throw "规则集编译未产生有效文件：$binaryPath"
            }
            }
            $newCache.entries += [ordered]@{tag=[string]$item.Tag; source_sha256=$sourceHash; binary_sha256=(Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash; binary_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($binaryPath))}
        }
        Write-JsonAtomically -Configuration $newCache -Destination (Join-Path $StagingDirectory 'build-cache.json') -Overwrite
        Write-Host "SRS 编译：$compiledCount；完整性校验后复用：$reusedCount。"
    }
    finally {
        if (Test-Path -LiteralPath $sourceDirectory) {
            Remove-Item -LiteralPath $sourceDirectory -Recurse -Force
        }
    }
}

function Test-WithSingBox {
    param(
        [Parameter(Mandatory)]
        [string]$Executable,

        [Parameter(Mandatory)]
        [string]$ConfigurationPath,

        [Parameter(Mandatory)]
        [string]$WorkingDirectory
    )

    $previousNativeExitCodeVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $hadPreviousNativeExitCode = $null -ne $previousNativeExitCodeVariable
    $previousNativeExitCode = if ($hadPreviousNativeExitCode) { $previousNativeExitCodeVariable.Value } else { $null }
    try {
        $output = & $Executable -D $WorkingDirectory check -c $ConfigurationPath 2>&1
        $nativeExitCode = $global:LASTEXITCODE
    }
    finally {
        if ($hadPreviousNativeExitCode) {
            Set-Variable -Name LASTEXITCODE -Scope Global -Value $previousNativeExitCode
        }
        else {
            Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
        }
    }
    if ($nativeExitCode -ne 0) {
        $details = ($output | Out-String).Trim()
        throw "sing-box 校验失败：$ConfigurationPath`n$details"
    }
}

function Write-JsonAtomically {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Configuration,

        [Parameter(Mandatory)]
        [string]$Destination,

        [string]$ValidationExecutable,

        [string]$ValidationWorkingDirectory,

        [switch]$Overwrite
    )

    if ((Test-Path -LiteralPath $Destination) -and -not $Overwrite) {
        throw "输出文件已存在：$Destination。使用 -Force 允许覆盖。"
    }

    $temporaryPath = "$Destination.$PID.tmp"
    try {
        $compactJson = $Configuration | ConvertTo-Json -Depth 100 -Compress
        $json = Format-JsonText -Text $compactJson
        [System.IO.File]::WriteAllText($temporaryPath, "$json`n", [System.Text.UTF8Encoding]::new($false))
        if ($ValidationExecutable) {
            Test-WithSingBox -Executable $ValidationExecutable -ConfigurationPath $temporaryPath -WorkingDirectory $ValidationWorkingDirectory
        }
        Move-Item -LiteralPath $temporaryPath -Destination $Destination -Force:$Overwrite
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

$resolvedProfilesPath = (Resolve-Path -LiteralPath $ProfilesPath).Path
$profileDocument = Read-JsonFile $resolvedProfilesPath
$profiles = Copy-JsonValue $profileDocument.profiles
if (-not ($profiles -is [System.Collections.IDictionary])) {
    throw '平台配置 profiles 必须是 JSON 对象。'
}
$linuxRouteExcludeProfileDefault = $false
foreach ($profileName in $profiles.Keys) {
    $profile = $profiles[$profileName]
    if (-not ($profile -is [System.Collections.IDictionary])) {
        throw "平台 '$profileName' 必须使用配置对象。"
    }
    if ($profile.Contains('linux_route_exclude_address_sets')) {
        $profileSetting = $profile['linux_route_exclude_address_sets']
        if (-not ($profileSetting -is [bool])) {
            throw "平台 '$profileName' 的 linux_route_exclude_address_sets 必须是 JSON 布尔值。"
        }
        if ($profileName -cne 'linux') {
            throw "平台 '$profileName' 不得声明 Linux 专属 linux_route_exclude_address_sets。"
        }
        $linuxRouteExcludeProfileDefault = [bool]$profileSetting
    }
}
$profileFileNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($profileName in $profiles.Keys) {
    $fileName = [string]$profiles[$profileName]['file_name']
    if ($fileName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.json$' -or $fileName -ieq 'build-cache.json' -or $fileName -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\.' -or -not $profileFileNames.Add($fileName)) {
        throw "平台输出文件名无效或重复：$fileName"
    }
}

if ($ListClients) {
    foreach ($profileName in $profiles.Keys) {
        [PSCustomObject]@{
            Client      = $profileName
            OutputFile  = $profiles[$profileName]['file_name']
            Description = $profiles[$profileName]['description']
        }
    }
    return
}

$resolvedTemplatePath = (Resolve-Path -LiteralPath $TemplatePath).Path

if (-not $Client -and -not $All) {
    $names = @($profiles.Keys)
    Write-Host '请选择目标客户端：'
    for ($index = 0; $index -lt $names.Count; $index++) {
        $profile = $profiles[$names[$index]]
        Write-Host ("[{0}] {1} - {2}" -f ($index + 1), $names[$index], $profile['description'])
    }
    $selection = Read-Host '输入序号或客户端名称'
    $selectionNumber = 0
    if ([int]::TryParse($selection, [ref]$selectionNumber) -and $selectionNumber -ge 1 -and $selectionNumber -le $names.Count) {
        $Client = $names[$selectionNumber - 1]
    }
    else {
        $Client = $selection
    }
}

if ($All -and $Client) {
    throw '-All 与 -Client 不能同时使用。'
}

$selectedNames = if ($All) { @($profiles.Keys) } else { @($Client) }
foreach ($name in $selectedNames) {
    if (-not $profiles.Contains($name)) {
        $available = ($profiles.Keys -join ', ')
        throw "未知客户端 '$name'。可用值：$available"
    }
}
if ($PSBoundParameters.ContainsKey('LinuxRouteExcludeAddressSets') -and $LinuxRouteExcludeAddressSets.IsPresent -and
    ($SkipRoutingRules -or 'linux' -notin $selectedNames)) {
    throw '-LinuxRouteExcludeAddressSets requires routing rules and the Linux client; -All applies it to Linux only.'
}
$linuxRouteExcludeEnabled = $linuxRouteExcludeProfileDefault
if ($PSBoundParameters.ContainsKey('LinuxRouteExcludeAddressSets')) {
    $linuxRouteExcludeEnabled = $LinuxRouteExcludeAddressSets.IsPresent
}

if ($TunAddress) {
    Assert-IPv4Prefix $TunAddress
}
# Reject deterministic invocation errors before refreshing any source/cache.
# Pending publication recovery remains under the build lock below.
$templateFullPath = [System.IO.Path]::GetFullPath($resolvedTemplatePath)
$outputFullPath = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd([char[]]'\/')
if ($outputFullPath -eq $templateFullPath) { throw '输出目录不能与母版文件相同。' }
$formalOutputFullPath = [IO.Path]::GetFullPath($defaultOutputDirectory).TrimEnd([char[]]'\/')
Assert-BuildOutputNotNested -OutputDirectory $outputFullPath -FormalOutputDirectory $formalOutputFullPath | Out-Null
if ($outputFullPath -ieq $formalOutputFullPath -and (-not $All -or $SkipRoutingRules -or
    @(Compare-Object @('android','ios','linux','macos','windows') $selectedNames).Count -ne 0)) {
    throw 'The formal output requires all five client profiles and routing rules. Use a separate -OutputDirectory for a partial build.'
}
$projectSourceDirectories = @(
    (Join-Path $projectRoot 'scripts')
    (Join-Path $projectRoot 'src')
    (Join-Path $projectRoot 'config')
    (Join-Path $projectRoot 'routing')
)
foreach ($sourceDirectory in $projectSourceDirectories) {
    $sourceDirectoryFullPath = [IO.Path]::GetFullPath($sourceDirectory).TrimEnd([char[]]'\/')
    if ($outputFullPath.Equals($sourceDirectoryFullPath, [StringComparison]::OrdinalIgnoreCase) -or
        $outputFullPath.StartsWith($sourceDirectoryFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        $sourceDirectoryFullPath.StartsWith($outputFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw '输出目录不能包含项目源文件。'
    }
}
$protectedPaths = @(
    $templateFullPath
    $resolvedProfilesPath
    $PSCommandPath
    [IO.Path]::GetFullPath($RoutingRulesPath)
    (Join-Path (Join-Path $projectRoot 'src') 'SameTypeDirectCompiler.cs')
)
foreach ($protectedPath in $protectedPaths) {
    $protectedPathFullPath = [IO.Path]::GetFullPath($protectedPath)
    if ($protectedPathFullPath.StartsWith($outputFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw '输出目录不能包含项目源文件。' }
}
. (Join-Path $PSScriptRoot 'Config-Archive.ps1')
$buildPaths = Get-BuildPaths $outputFullPath
$preflightCore = Resolve-SingBoxExecutable $SingBoxPath
$runtimePathForProtection = $preflightCore
if (-not $runtimePathForProtection -and $SingBoxPath) { $runtimePathForProtection = $SingBoxPath }
$supportFullPath = Get-ClientSupportDirectory -ProjectRoot $projectRoot -OutputDirectory $outputFullPath -DefaultOutputDirectory $defaultOutputDirectory -ExplicitSupportDirectory $SupportDirectory
$additionalProtectedPaths = @(
    $templateFullPath
    $resolvedProfilesPath
    $PSCommandPath
    [IO.Path]::GetFullPath($RoutingRulesPath)
    (Join-Path (Join-Path $projectRoot 'src') 'SameTypeDirectCompiler.cs')
)
Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $outputFullPath -SupportDirectory $supportFullPath -BuildPaths $buildPaths -RuntimeExecutable $runtimePathForProtection -AdditionalProtectedPaths $additionalProtectedPaths
# Reject unknown output objects before a routing-source refresh; repeat the snapshot under the publisher lock.
$null = Get-BuildPreservationSnapshot -Destination $outputFullPath -PackageName 'sing-box-configs.zip'
$supportCachePath = Join-Path $supportFullPath 'build-cache.json'
$supportLockPath = Join-Path $supportFullPath 'build-cache.lock'
if (-not $preflightCore -and ($RequireSingBox -or -not $SkipRoutingRules)) {
    throw '未找到 sing-box。请准备固定版本校验核心，或使用 -SingBoxPath 指定可执行文件。'
}
if (-not $Force -and -not (Test-Path -LiteralPath $buildPaths.Journal) -and -not (Test-Path -LiteralPath $buildPaths.Backup)) {
    if (Test-Path -LiteralPath (Join-Path $outputFullPath 'sing-box-configs.zip')) { throw '输出 ZIP 已存在。使用 -Force 允许替换。' }
    foreach ($name in $selectedNames) {
        $destination = Join-Path $outputFullPath $profiles[$name]['file_name']
        if (Test-Path -LiteralPath $destination) { throw "输出文件已存在：$destination。使用 -Force 允许覆盖。" }
    }
}
if (-not $SkipRoutingRules -and -not $RoutingRulesAlreadyUpdated) {
    $updateScript = Join-Path $PSScriptRoot 'Update-RoutingRules.ps1'
    if (-not (Test-Path -LiteralPath $updateScript -PathType Leaf)) {
        throw "找不到分流规则更新器：$updateScript"
    }

    $updateArguments = @{
        OutputPath = $RoutingRulesPath
        Offline    = $Offline
        AllowSourceShrink = $AllowSourceShrink
    }
    if ($ZstdLibraryPath) {
        $updateArguments['ZstdLibraryPath'] = $ZstdLibraryPath
    }
    & $updateScript @updateArguments
}
if (-not $SkipRoutingRules -and -not (Test-Path -LiteralPath $RoutingRulesPath -PathType Leaf)) {
    throw "找不到合并后的分流规则：$RoutingRulesPath。"
}

$buildLocks = @()
$cachePendingPath = $null
$preservationSnapshot = $null
try {
$buildLocks = Enter-BuildLocks -LockPaths @($buildPaths.Lock, $supportLockPath)
Remove-StaleClientCachePublications -SupportDirectory $supportFullPath
Restore-BuildTransaction $buildPaths
$preservationSnapshot = Get-BuildPreservationSnapshot -Destination $outputFullPath -PackageName 'sing-box-configs.zip'
$templateHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $templateFullPath).Hash
$singBoxExecutable = Resolve-SingBoxExecutable $SingBoxPath
if (-not $singBoxExecutable -and ($RequireSingBox -or -not $SkipRoutingRules)) {
    throw '未找到 sing-box。请准备固定版本校验核心，或使用 -SingBoxPath 指定可执行文件。'
}
if (-not $singBoxExecutable) {
    Write-Warning '未找到 sing-box；将执行内置结构校验，但跳过官方 sing-box check。'
}
$destinations = [System.Collections.Generic.List[object]]::new()
if ((Test-Path -LiteralPath (Join-Path $outputFullPath 'sing-box-configs.zip')) -and -not $Force) {
    throw '输出 ZIP 已存在。使用 -Force 允许替换。'
}
foreach ($name in $selectedNames) {
    $destination = Join-Path $outputFullPath $profiles[$name]['file_name']
    if ([System.IO.Path]::GetFullPath($destination) -eq $templateFullPath) {
        throw "拒绝覆盖母版文件：$templateFullPath"
    }
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        throw "输出文件已存在：$destination。使用 -Force 允许覆盖。"
    }
    $destinations.Add([PSCustomObject]@{ Name = $name; Path = $destination })
}

$ruleSetPlan = @()
$routingPolicyDocument = $null
if (-not $SkipRoutingRules) {
    $routingPolicyDocument = Read-JsonFile $RoutingRulesPath
    $ruleSetPlan = @(Get-BinaryRuleSetPlan -RulesPath $RoutingRulesPath -CachePath (Join-Path $supportFullPath 'same-type-plan-cache.json') -RoutingDocument $routingPolicyDocument)
    if ($ruleSetPlan.Count -eq 0) {
        throw '合并后的分流规则没有产生任何可编译规则集。'
    }
}

$stagingDirectory = $buildPaths.Stage
$generated = [System.Collections.Generic.List[object]]::new()

try {
    if (Test-Path -LiteralPath $outputFullPath) {
        $existingItems = @((Get-Item -LiteralPath $outputFullPath -Force)) + @(Get-ChildItem -LiteralPath $outputFullPath -Recurse -Force)
        if (@($existingItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw '输出目录含重解析点，拒绝复制或发布。' }
    }
    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    if (-not $SkipRoutingRules) {
        $stagingRuleSetDirectory = Join-Path $stagingDirectory 'rule-set'
        Compile-BinaryRuleSets -RuleSetPlan $ruleSetPlan -Executable $singBoxExecutable -StagingDirectory $stagingDirectory -ExistingCachePath $supportCachePath
    }

    foreach ($entry in $destinations) {
        $name = [string]$entry.Name
        $baseDocument = Read-JsonFile $templateFullPath
        $base = Copy-JsonValue $baseDocument
        $overlay = Copy-JsonValue $profiles[$name]['overlay']
        $configuration = Merge-JsonObject -Base $base -Overlay $overlay
        if ($profiles[$name].Contains('tun_overlay')) {
            $tunOverlay = Copy-JsonValue $profiles[$name]['tun_overlay']
            Merge-TunOverlay -Configuration $configuration -Overlay $tunOverlay
        }
        if ($TunAddress) {
            Set-TunAddress -Configuration $configuration -Address $TunAddress
        }
        $enableLinuxRouteExclude = $linuxRouteExcludeEnabled -and $name -eq 'linux' -and -not $SkipRoutingRules
        if ($enableLinuxRouteExclude -and @($ruleSetPlan | Where-Object { $_.Tag -ceq 'routing-reject-port' }).Count) {
            $enableLinuxRouteExclude = $false
        }
        if (-not $SkipRoutingRules) {
            Add-BinaryRoutingRules -Configuration $configuration -RuleSetPlan $ruleSetPlan -ClientName $name -LinuxRouteExcludeAddressSets:$enableLinuxRouteExclude
        }
        Assert-Configuration -Configuration $configuration -Name $name -LinuxRouteExcludeAddressSets:$enableLinuxRouteExclude -RuleSetPlan $ruleSetPlan

        $stagedConfiguration = Join-Path $stagingDirectory $profiles[$name]['file_name']
        $officialCheck = $singBoxExecutable -and $name -ceq 'linux'
        $validationExecutable = if ($officialCheck) { $singBoxExecutable } else { $null }
        Write-JsonAtomically -Configuration $configuration -Destination $stagedConfiguration -ValidationExecutable $validationExecutable -ValidationWorkingDirectory $stagingDirectory -Overwrite

        $generated.Add([PSCustomObject]@{
            Client = $name
            File   = [string]$entry.Path
            Check  = if ($officialCheck) { 'sing-box check passed' } elseif ($singBoxExecutable) { 'built-in check passed (cross-platform)' } else { 'built-in check passed' }
        })
    }

    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $templateFullPath).Hash -ne $templateHashBefore) { throw '母版在生成期间发生变化，拒绝发布。' }
    $archiveNames = @($destinations | ForEach-Object { Split-Path -Leaf $_.Path })
    Assert-BuildPreservationSnapshot -Directory $outputFullPath -Snapshot $preservationSnapshot -ExpectedRoot $outputFullPath -SourceState
    $archiveResult = New-ConfigArchive -Directory $stagingDirectory -ConfigurationNames $archiveNames
    $ruleSetBytes = if ($SkipRoutingRules) { 0 } else { (Get-ChildItem -LiteralPath $stagingRuleSetDirectory -File | Measure-Object Length -Sum).Sum }
    if (-not $SkipRoutingRules) {
        try {
            $cachePendingPath = Prepare-ClientCachePublication -StagedCachePath (Join-Path $stagingDirectory 'build-cache.json') -SupportDirectory $supportFullPath
        }
        catch {
            Write-Warning "编译缓存暂不可用；仍将发布已验证 ZIP，下次构建会重新编译：$($_.Exception.Message)"
            $cachePendingPath = $null
        }
    }
    Complete-ArchiveOnlyStage -Directory $stagingDirectory -ConfigurationNames $archiveNames
    Copy-BuildPreservedDirectoriesToStage -Snapshot $preservationSnapshot -StageDirectory $stagingDirectory
    Publish-BuildTransaction -Paths $buildPaths -PreservationSnapshot $preservationSnapshot
    if ($cachePendingPath) {
        try {
            Publish-ClientCachePublication -PendingPath $cachePendingPath -CachePath $supportCachePath
            $cachePendingPath = $null
        }
        catch {
            Write-Warning "ZIP 已提交；编译缓存未更新，下次构建将重新编译：$($_.Exception.Message)"
        }
    }
}
finally {
    if ($cachePendingPath -and [IO.File]::Exists($cachePendingPath)) {
        try { [IO.File]::Delete($cachePendingPath) } catch { Write-Warning "清理未提交编译缓存失败：$($_.Exception.Message)" }
    }
    if (-not (Test-Path -LiteralPath $buildPaths.Journal)) {
        Remove-BuildDirectory $buildPaths $stagingDirectory
    }
}

$templateHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $templateFullPath).Hash
if ($templateHashAfter -ne $templateHashBefore) {
    throw "母版文件在生成过程中发生变化：$templateFullPath"
}

Write-Host ("ZIP：{0}；{1} 个文件，{2} 字节。" -f (Join-Path $outputFullPath 'sing-box-configs.zip'), $archiveResult.Files, $archiveResult.Bytes)
Write-Host "ZIP SHA256：$($archiveResult.Sha256)"
}
finally {
    for ($lockIndex = $buildLocks.Count - 1; $lockIndex -ge 0; $lockIndex--) { $buildLocks[$lockIndex].Dispose() }
}
if (-not $SkipRoutingRules) {
    Write-Host ("二进制规则集：{0} 个文件，{1} 字节。" -f $ruleSetPlan.Count, $ruleSetBytes)
}
Write-Host "母版 SHA256 保持不变：$templateHashAfter"
