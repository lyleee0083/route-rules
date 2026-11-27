[CmdletBinding()]
param(
    [string]$SingBoxPath,
    [string]$TestRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $root 'scripts'
$configRoot = Join-Path $root 'config'
& (Join-Path $PSScriptRoot 'Test-SameTypeDirectPolicy.ps1')
. (Join-Path $scriptsRoot 'Direct-RoutingPolicy.ps1')
. (Join-Path $scriptsRoot 'DNS-BootstrapPolicy.ps1')
. (Join-Path $scriptsRoot 'Json-Validation.ps1')
. (Join-Path $scriptsRoot 'SingBox-Checker.ps1')

$template = Join-Path $configRoot 'sing-box-core-base.json'
$generator = Join-Path $scriptsRoot 'Generate-SingBoxConfig.ps1'
$routingTransactionTest = Join-Path $PSScriptRoot 'Test-RoutingTransaction.ps1'
$archiveTest = Join-Path $PSScriptRoot 'Test-ConfigArchive.ps1'
$runningOnWindows = $env:OS -eq 'Windows_NT'
$projectFullPath = [IO.Path]::GetFullPath($root).TrimEnd([char[]]'\/')
$ownsTestRoot = [string]::IsNullOrWhiteSpace($TestRoot)
if ($ownsTestRoot) { $TestRoot = Join-Path $root ('outputs\tests\generator\run-' + [guid]::NewGuid().ToString('N')) }
$taskFixtureRoot = [IO.Path]::GetFullPath($TestRoot).TrimEnd([char[]]'\/')
$allowedFixtureRoots = @((Join-Path $projectFullPath 'work'), (Join-Path $projectFullPath 'outputs'))
$fixtureRootAllowed = $false
foreach ($allowedRoot in $allowedFixtureRoots) {
    $allowedFullPath = [IO.Path]::GetFullPath($allowedRoot).TrimEnd([char[]]'\/')
    if ($taskFixtureRoot.StartsWith($allowedFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        $fixtureRootAllowed = $true
        break
    }
}
if (-not $fixtureRootAllowed) { throw 'Generator test root must be a child of project work/ or outputs/.' }
$null = Assert-ClientPlainPathTree -Path $taskFixtureRoot -LeafType Directory -IncludeDescendants
$fixtureCursor = $taskFixtureRoot
while ($fixtureCursor -and ($fixtureCursor.Equals($projectFullPath, [StringComparison]::OrdinalIgnoreCase) -or
    $fixtureCursor.StartsWith($projectFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
    if ([IO.File]::Exists($fixtureCursor) -or [IO.Directory]::Exists($fixtureCursor)) {
        $fixtureItem = Get-Item -LiteralPath $fixtureCursor -Force
        if ($fixtureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Generator test root contains a reparse point: $fixtureCursor" }
    }
    if ($fixtureCursor.Equals($projectFullPath, [StringComparison]::OrdinalIgnoreCase)) { break }
    $fixtureCursor = Split-Path -Parent $fixtureCursor
}
if ([IO.Directory]::Exists($taskFixtureRoot)) {
    $fixtureItems = @(Get-ChildItem -LiteralPath $taskFixtureRoot -Force -Recurse -ErrorAction Stop)
    if (@($fixtureItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
        throw 'Generator test root contains a reparse point.'
    }
}
$testRunRoot = Join-Path $taskFixtureRoot ('generator-' + [guid]::NewGuid().ToString('N').Substring(0,12))
$testOutput = Join-Path $testRunRoot 'all-platforms'
$customOutput = Join-Path $testRunRoot 'custom'
$testSupportDirectory = Join-Path $customOutput 'support\all-clients'
$customSupportDirectory = Join-Path $customOutput 'support\custom-client'
$hashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $template).Hash
$resolvedSingBox = Resolve-PinnedSingBoxChecker -ProjectRoot $root -RequestedPath $SingBoxPath

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw "断言失败：$Message"
    }
}

function Write-ProfileFixture {
    param(
        [Parameter(Mandatory)]$Document,
        [Parameter(Mandatory)][string]$Path
    )
    $text = ($Document | ConvertTo-Json -Depth 100) -replace "`r`n?", "`n"
    [IO.File]::WriteAllText($Path, "$text`n", [Text.UTF8Encoding]::new($false))
}

function New-TestProfileDocument {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$TunOverlay,
        [object]$LinuxRouteExcludeDefault = $null
    )
    $profile = [ordered]@{
        file_name = 'sing-box-' + $Name + '-fixture.json'
        description = 'Platform tuning contract fixture'
        overlay = [ordered]@{}
        tun_overlay = $TunOverlay
    }
    if ($null -ne $LinuxRouteExcludeDefault) {
        $profile['linux_route_exclude_address_sets'] = [bool]$LinuxRouteExcludeDefault
    }
    $profiles = [ordered]@{}
    $profiles[$Name] = $profile
    return [ordered]@{
        schema_version = 1
        minimum_sing_box_version = '1.14.0'
        profiles = $profiles
    }
}

function Test-ExpectedGeneratorFailure {
    param(
        [Parameter(Mandatory)][hashtable]$Arguments,
        [Parameter(Mandatory)][string]$MessagePattern
    )
    $matched = $false
    try {
        & $generator @Arguments | Out-Null
    }
    catch {
        $matched = ([string]$_.Exception.Message -match $MessagePattern)
    }
    return $matched
}

function Format-JsonText {
    param(
        [Parameter(Mandatory)][string]$Text,
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
            if ($escaping) { $escaping = $false }
            elseif ($character -eq '\') { $escaping = $true }
            elseif ($character -eq '"') { $inString = $false }
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

function Assert-LfTextFile {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)

    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    Assert-True (13 -notin $bytes) "$($File.FullName) 必须仅使用 LF 换行"
    if ($File.Extension -eq '.ps1') {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($text -match '[^\x00-\x7F]') {
            $hasUtf8Bom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
            Assert-True $hasUtf8Bom "$($File.FullName) 含非 ASCII 字符时必须使用 UTF-8 BOM"
        }
    }
}

function Assert-PrettyJsonFile {
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)

    $raw = [System.IO.File]::ReadAllText($File.FullName, [System.Text.Encoding]::UTF8)
    Assert-True (-not $raw.Contains("`r")) "$($File.FullName) 必须仅使用 LF 换行"
    Assert-True ($raw.EndsWith("`n")) "$($File.FullName) 末尾必须保留一个 LF"
    Assert-True (-not $raw.Contains("`t")) "$($File.FullName) 的 JSON 缩进必须使用空格"
    Assert-StrictJsonText -Text $raw
    $expected = (Format-JsonText -Text $raw) + "`n"
    Assert-True ($raw -eq $expected) "$($File.FullName) 必须使用两空格展开式 JSON 格式"
}

function Get-RuleFieldValues {
    param(
        [object[]]$Rules,
        [string]$Field
    )

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in @($Rules)) {
        if ($null -eq $rule.PSObject.Properties[$Field]) { continue }
        foreach ($value in @($rule.$Field)) {
            $values.Add([string]$value)
        }
    }
    return @($values | Sort-Object -Unique)
}

function Get-DomainUnionSignature {
    param([object[]]$Rules)
    $suffixes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in @(Get-RuleFieldValues -Rules $Rules -Field 'domain_suffix')) { [void]$suffixes.Add($value) }
    $keptSuffixes = [Collections.Generic.List[string]]::new()
    $keptDomains = [Collections.Generic.List[string]]::new()
    foreach ($field in @('domain_suffix','domain')) {
        foreach ($value in @(Get-RuleFieldValues -Rules $Rules -Field $field)) {
            $probe = $value
            if ($field -eq 'domain_suffix') {
                $dot = $probe.IndexOf('.')
                $probe = if ($dot -ge 0) { $probe.Substring($dot+1) } else { '' }
            }
            $covered = $false
            while ($probe) {
                if ($suffixes.Contains($probe)) { $covered = $true; break }
                $dot = $probe.IndexOf('.')
                $probe = if ($dot -ge 0) { $probe.Substring($dot+1) } else { '' }
            }
            if (-not $covered) {
                if ($field -eq 'domain_suffix') { $keptSuffixes.Add($value) }
                else { $keptDomains.Add($value) }
            }
        }
    }
    return (@{domain=@($keptDomains | Sort-Object);domain_suffix=@($keptSuffixes | Sort-Object);domain_regex=@(Get-RuleFieldValues -Rules $Rules -Field 'domain_regex')} | ConvertTo-Json -Depth 5 -Compress)
}

function Test-DomainCoveredByPositiveNativeRules {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [string[]]$ExactValues,
        [string[]]$SuffixValues
    )

    foreach ($exact in @($ExactValues)) {
        if ([string]::Equals($Domain,[string]$exact,[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($suffix in @($SuffixValues)) {
        if ([string]::Equals($Domain,[string]$suffix,[StringComparison]::OrdinalIgnoreCase) -or
            $Domain.EndsWith('.' + [string]$suffix,[StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-PortUnionSignature {
    param(
        [object[]]$Rules,
        [Parameter(Mandatory)][string]$ScalarField,
        [Parameter(Mandatory)][string]$RangeField
    )

    $intervals = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in @($Rules)) {
        $scalarProperty = $rule.PSObject.Properties[$ScalarField]
        if ($null -ne $scalarProperty) {
            foreach ($value in @($scalarProperty.Value)) {
                $port = [int]::Parse([string]$value,[Globalization.CultureInfo]::InvariantCulture)
                if ($port -lt 1 -or $port -gt 65535) { throw "Invalid port value in ${ScalarField}: $value" }
                $intervals.Add([pscustomobject]@{Start=$port;End=$port})
            }
        }

        $rangeProperty = $rule.PSObject.Properties[$RangeField]
        if ($null -ne $rangeProperty) {
            foreach ($value in @($rangeProperty.Value)) {
                $match = [regex]::Match([string]$value,'^([0-9]+):([0-9]+)$')
                if (-not $match.Success) { throw "Invalid port range in ${RangeField}: $value" }
                $start = [int]::Parse($match.Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture)
                $end = [int]::Parse($match.Groups[2].Value,[Globalization.CultureInfo]::InvariantCulture)
                if ($start -lt 1 -or $end -gt 65535 -or $start -gt $end) { throw "Invalid port range bounds in ${RangeField}: $value" }
                $intervals.Add([pscustomobject]@{Start=$start;End=$end})
            }
        }
    }

    $ordered = @($intervals.ToArray() | Sort-Object -Property Start,End)
    $merged = New-Object 'System.Collections.Generic.List[string]'
    $currentStart = $null
    $currentEnd = $null
    foreach ($interval in $ordered) {
        if ($null -eq $currentStart) {
            $currentStart = [int]$interval.Start
            $currentEnd = [int]$interval.End
        }
        elseif ([int]$interval.Start -le ([int]$currentEnd + 1)) {
            if ([int]$interval.End -gt [int]$currentEnd) { $currentEnd = [int]$interval.End }
        }
        else {
            $merged.Add(([string]$currentStart + ':' + [string]$currentEnd))
            $currentStart = [int]$interval.Start
            $currentEnd = [int]$interval.End
        }
    }
    if ($null -ne $currentStart) { $merged.Add(([string]$currentStart + ':' + [string]$currentEnd)) }
    return ($merged.ToArray() -join ';')
}

function Test-PortUnionSignatureCovers {
    param([string]$Signature,[Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port)
    if ([string]::IsNullOrEmpty($Signature)) { return $false }
    foreach ($range in $Signature.Split(';')) {
        $bounds = $range.Split(':')
        if ($bounds.Count -ne 2) { throw "Invalid normalized port interval: $range" }
        $start = [int]::Parse($bounds[0],[Globalization.CultureInfo]::InvariantCulture)
        $end = [int]::Parse($bounds[1],[Globalization.CultureInfo]::InvariantCulture)
        if ($Port -ge $start -and $Port -le $end) { return $true }
    }
    return $false
}

function Get-IPv4CidrUnionSignature {
    param([string[]]$Cidrs)

    $intervals = [System.Collections.Generic.List[object]]::new()
    foreach ($cidr in @($Cidrs)) {
        $parts = $cidr.Split('/', 2)
        $address = [System.Net.IPAddress]::Parse($parts[0])
        $prefix = [int]$parts[1]
        $bytes = $address.GetAddressBytes()
        [array]::Reverse($bytes)
        $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
        $size = [uint64]1 -shl (32 - $prefix)
        $mask = if ($prefix -eq 0) { [uint64]0 } else { ([uint64]4294967295 -shr (32 - $prefix)) -shl (32 - $prefix) }
        $start = $value -band $mask
        $intervals.Add([PSCustomObject]@{ Start = $start; End = $start + $size - 1 })
    }

    $sortedIntervals = @($intervals | Sort-Object Start,End)
    $merged = [System.Collections.Generic.List[string]]::new()
    $currentStart = $null
    $currentEnd = $null
    foreach ($interval in $sortedIntervals) {
        if ($null -eq $currentStart) {
            $currentStart = [uint64]$interval.Start
            $currentEnd = [uint64]$interval.End
            continue
        }
        if ([uint64]$interval.Start -le $currentEnd + 1) {
            if ([uint64]$interval.End -gt $currentEnd) { $currentEnd = [uint64]$interval.End }
            continue
        }
        $merged.Add("$currentStart-$currentEnd")
        $currentStart = [uint64]$interval.Start
        $currentEnd = [uint64]$interval.End
    }
    if ($null -ne $currentStart) {
        $merged.Add("$currentStart-$currentEnd")
    }
    return $merged -join ';'
}

try {
    [IO.Directory]::CreateDirectory($taskFixtureRoot) | Out-Null
    $null = Assert-ClientPlainPathTree -Path $taskFixtureRoot -LeafType Directory -Required -IncludeDescendants
    [IO.Directory]::CreateDirectory($testRunRoot) | Out-Null
    [IO.Directory]::CreateDirectory($testOutput) | Out-Null
    & $routingTransactionTest
    & $archiveTest

    # The missing explicit checker is a second read-only guard if this contract regresses.
    $unavailableChecker = Join-Path $testRunRoot 'missing-checker.exe'
    $formalZip = Join-Path $root 'generated/sing-box-configs.zip'
    $formalHash = if (Test-Path -LiteralPath $formalZip -PathType Leaf) { (Get-FileHash -LiteralPath $formalZip -Algorithm SHA256).Hash }
    Assert-True (Test-ExpectedGeneratorFailure -Arguments @{ Client='windows'; Force=$true; SingBoxPath=$unavailableChecker } -MessagePattern 'formal output requires all five') 'Single-client force build must reject the formal ZIP target before compilation.'
    Assert-True (Test-ExpectedGeneratorFailure -Arguments @{ All=$true; Force=$true; SkipRoutingRules=$true; RequireSingBox=$true; SingBoxPath=$unavailableChecker } -MessagePattern 'formal output requires all five') 'A rules-free force build must reject the formal ZIP target.'
    $finalFormalHash = if (Test-Path -LiteralPath $formalZip -PathType Leaf) { (Get-FileHash -LiteralPath $formalZip -Algorithm SHA256).Hash }
    Assert-True ($finalFormalHash -ceq $formalHash) 'Rejected builds changed the formal ZIP.'

    $networkCacheDirectory = [System.IO.Path]::GetFullPath((Join-Path $root 'routing\cache')).TrimEnd('\') + '\'
    # Build stages, historical backups and task-local work records may contain
    # third-party payloads or captured files whose line endings are not project
    # source style. They are validated by their own package/archive checks.
    $externalBuildDirectories = @('openwrt/build-stage','openwrt/backups','openwrt/outputs','backups','outputs','work') | ForEach-Object {
        [IO.Path]::GetFullPath((Join-Path $root $_)).TrimEnd('\') + '\'
    }
    $projectTextFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {
        $externalBuildFile=$false
        foreach ($externalDirectory in $externalBuildDirectories) {
            if ($_.FullName.StartsWith($externalDirectory,[StringComparison]::OrdinalIgnoreCase)) { $externalBuildFile=$true }
        }
        $isNetworkCacheFile = $_.FullName.StartsWith($networkCacheDirectory, [System.StringComparison]::OrdinalIgnoreCase)
        $isGeneratedCacheJson = $_.Name.EndsWith('.metadata.json', [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name.EndsWith('.extracted.json', [System.StringComparison]::OrdinalIgnoreCase)
        -not $externalBuildFile -and $_.Extension -in @('.ps1', '.json', '.md', '.lock') -and
            (-not $isNetworkCacheFile -or $isGeneratedCacheJson)
    })
    foreach ($file in $projectTextFiles) { Assert-LfTextFile -File $file }
    foreach ($file in @($projectTextFiles | Where-Object Extension -eq '.json')) { Assert-PrettyJsonFile -File $file }

    if ($resolvedSingBox) {
        $runtimeRoot = Split-Path -Parent $resolvedSingBox
        $externalRuntimeFileNames = @('LICENSE')
        $runtimeTextFiles = @(Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse | Where-Object {
            $_.Name -notin $externalRuntimeFileNames -and
                $_.Extension -in @('.ps1', '.vbs', '.json', '.log', '.pid')
        })
        foreach ($file in $runtimeTextFiles) { Assert-LfTextFile -File $file }
        foreach ($file in @($runtimeTextFiles | Where-Object Extension -eq '.json')) { Assert-PrettyJsonFile -File $file }
    }

    $baseRawText = Get-Content -Raw -LiteralPath $template -Encoding UTF8
    Assert-True (-not $baseRawText.Contains("`r")) '母版必须使用纯 LF 换行'
    Assert-PrettyJsonFile -File (Get-Item -LiteralPath $template)
    $baseDocument = $baseRawText | ConvertFrom-Json
    Assert-DnsBootstrapConfiguration $baseDocument
    $profileDocument = Get-Content -Raw -LiteralPath (Join-Path $configRoot 'client-profiles.json') -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($profileDocument.minimum_sing_box_version -eq '1.14.0') '客户端清单最低核心版本必须为 1.14.0'
    $sourceDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\routing-sources.json') -Encoding UTF8 | ConvertFrom-Json
    $staticDirectDomainDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\static-direct-domain.json') -Encoding UTF8 | ConvertFrom-Json
    $staticProxyDomainDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\static-proxy-domain.json') -Encoding UTF8 | ConvertFrom-Json
    $staticDirectPortDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\static-direct-port.json') -Encoding UTF8 | ConvertFrom-Json
    $staticProxyPortDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\static-proxy-port.json') -Encoding UTF8 | ConvertFrom-Json
    $mergedDocument = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\merged\merged-rules.json') -Encoding UTF8 | ConvertFrom-Json
    $expectedGroups = @($mergedDocument.groups | Sort-Object sequence)
    . (Join-Path $scriptsRoot 'SameTypeDirectPolicy.ps1')
    $expectedRuleSets = Get-SameTypeDirectPlan -Document $mergedDocument
    $expectedRuleSets = ConvertTo-Json -InputObject $expectedRuleSets -Depth 100 -Compress | ConvertFrom-Json
    $expectedTags = @($expectedRuleSets | ForEach-Object Tag)
    Assert-True ($expectedRuleSets.Count -gt 0) 'Resolved same-type plan must not be empty'
    Assert-True (@($expectedRuleSets | Where-Object { $_.Action -cnotin @('reject','direct') }).Count -eq 0) 'Only resolved reject and direct SRS may be published'
    Assert-True ([int]$mergedDocument.version -eq 2) '合并规则必须使用 version 2 顺序格式'
    Assert-True ($sourceDocument.conflict_policy.earlier_rule -eq 'wins') '规则源必须声明前序规则优先'
    Assert-True ($sourceDocument.conflict_policy.later_overlap -eq 'ordered-first-match') '规则源必须声明部分重叠使用首条命中'
    $expectedStaticRuleIds = @('static-reject','static-direct-domain','static-direct-ip','static-direct-port','static-proxy-domain','static-proxy-ip','static-proxy-port')
    $nonRejectIds = @($sourceDocument.rules | Where-Object action -cne 'reject' | Select-Object -First 6 | ForEach-Object id)
    $actualStaticRuleIds = @($sourceDocument.rules[0].id) + $nonRejectIds
    Assert-True (($actualStaticRuleIds -join "`n") -eq ($expectedStaticRuleIds -join "`n")) '静态拒绝必须置顶，其余六类静态规则必须按既定顺序排列'
    $expectedStaticDirectDomains = @('xiawenyun.com','k-channel.yucomic.com','hjqapi.aimeizhi.net')
    $actualStaticDirectDomains = @($staticDirectDomainDocument.rules.domain)
    Assert-True (($actualStaticDirectDomains -join "`n") -eq ($expectedStaticDirectDomains -join "`n")) '静态直连域名必须保持已指定的三个精确域名'
    $expectedStaticDirectDomainSuffixes = @('kookapp.cn')
    $actualStaticDirectDomainSuffixes = @($staticDirectDomainDocument.rules.domain_suffix)
    Assert-True (($actualStaticDirectDomainSuffixes -join "`n") -eq ($expectedStaticDirectDomainSuffixes -join "`n")) '静态直连域名后缀必须保持已指定的 kookapp.cn'
    $expectedStaticProxyDomains = @('24bit.net','apple-relay.apple.com','apple-relay.cloudflare.com','apple-relay.fastly-edge.com','apple-relay.mask.apple-dns.net','cp4.cloudflare.com','gspe1-ssl.ls.apple.com')
    $actualStaticProxyDomains = @($staticProxyDomainDocument.rules.domain)
    Assert-True (($actualStaticProxyDomains -join "`n") -eq ($expectedStaticProxyDomains -join "`n")) '静态代理域名必须保持已指定的精确域名顺序'
    $expectedStaticDirectPorts = @(123)
    $actualStaticDirectPorts = @($staticDirectPortDocument.rules.port)
    Assert-True (($actualStaticDirectPorts -join "`n") -ceq ($expectedStaticDirectPorts -join "`n")) '静态直连端口必须保持精确的端口 123'
    $expectedStaticProxyPorts = @(53,3478,19302)
    $actualStaticProxyPorts = @($staticProxyPortDocument.rules.port)
    Assert-True (($actualStaticProxyPorts -join "`n") -ceq ($expectedStaticProxyPorts -join "`n")) '静态代理端口必须保持精确的端口 53、3478 和 19302'
    Assert-True (($sourceDocument.rules | Where-Object id -eq '18-onedrive').action -eq 'direct') '18-onedrive 必须直连'
    Assert-True (($sourceDocument.rules | Where-Object id -eq '19-bing').action -eq 'direct') '19-bing 必须直连'
    Assert-True ($mergedDocument.conflict_policy.earlier_rule -eq $sourceDocument.conflict_policy.earlier_rule) '合并规则的前序优先策略必须与规则源一致'
    Assert-True ($mergedDocument.conflict_policy.later_overlap -eq $sourceDocument.conflict_policy.later_overlap) '合并规则的部分重叠策略必须与规则源一致'
    $mergedRawText = Get-Content -Raw -LiteralPath (Join-Path $root 'routing\merged\merged-rules.json') -Encoding UTF8
    Assert-True ($mergedRawText -match '"extracted"\s*:\s*\d+[,}]') '合并统计 extracted 必须在 PowerShell 5.1/7 中统一序列化为 JSON 整数'
    Assert-True ([int]$mergedDocument.report.retained -eq ([int]$mergedDocument.report.extracted - [int]$mergedDocument.report.removed + [int]$mergedDocument.report.interval_split_fragments)) '合并统计必须计入端口范围拆分产生的额外片段'
    Assert-True (@($expectedGroups | Where-Object { $_.PSObject.Properties['priority'] }).Count -eq 0) '规则组不得再包含等级编号'
    Assert-True (@($expectedGroups | Where-Object { $_.PSObject.Properties['exclude_rule_sets'] }).Count -eq 0) '合并规则不得包含运行时排除引用'
    Assert-True (-not $mergedRawText.Contains('"domain_keyword"')) '合并规则不得包含 domain_keyword'
    foreach ($group in $expectedGroups) {
        foreach ($rule in @($group.rules | Where-Object { $_.PSObject.Properties['domain_regex'] })) {
            Assert-True ($group.action -ceq 'reject') '只有拒绝组可包含合并阶段生成的例外正则'
            foreach ($pattern in @($rule.domain_regex)) {
                Assert-True ([SingBoxSameType.DomainCompiler]::IsGeneratedPositiveRegex($pattern)) '拒绝组必须使用生成的正向例外正则'
            }
        }
    }
    Assert-True ($null -eq $baseDocument.dns.PSObject.Properties['disable_cache']) '母版不得保留与 optimistic 冲突的 disable_cache'
    Assert-True ($null -eq $baseDocument.dns.PSObject.Properties['disable_expire']) '母版不得保留与 optimistic 冲突的 disable_expire'
    Assert-True ($baseDocument.dns.cache_capacity -eq 65472) 'The maintained template must set DNS cache capacity to 65472.'
    Assert-True ($baseDocument.dns.timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True ($baseDocument.dns.optimistic.enabled -eq $true) '母版必须启用 optimistic DNS 缓存'
    Assert-True ($baseDocument.dns.optimistic.timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True ($baseDocument.dns.reverse_mapping -eq $false) 'DNS-only domains must not maintain unused reverse mappings'
    Assert-True ($null -eq $baseDocument.log.PSObject.Properties['output']) '母版不得把 Core 运行日志持续写入文件'
    Assert-True (($baseDocument.dns.servers | Where-Object tag -eq 'dns-direct').detour -eq 'dns-direct-out') '母版 dns-direct 必须显式使用专用直连出站'
    Assert-True (($baseDocument.dns.servers | Where-Object tag -eq 'dns-proxy').detour -eq 'dns-proxy-out') '母版 dns-proxy 必须显式使用专用代理出站'
    Assert-True (@($baseDocument.outbounds | Where-Object tag -eq 'dns-direct-out').Count -eq 1) '母版必须包含唯一的 dns-direct-out 出站'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-direct-out').type -eq 'selector') 'dns-direct-out 必须是 selector 出站'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-direct-out').outbounds[0] -eq 'direct') 'dns-direct-out 必须只选择 direct'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-direct-out').default -eq 'direct') 'dns-direct-out 默认必须使用 direct'
    Assert-True (@($baseDocument.outbounds | Where-Object tag -eq 'dns-proxy-out').Count -eq 1) '母版必须包含唯一的 dns-proxy-out 出站'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-proxy-out').type -eq 'selector') 'dns-proxy-out 必须是 selector 出站'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-proxy-out').outbounds[0] -eq 'proxy') 'dns-proxy-out 必须只选择 proxy'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'dns-proxy-out').default -eq 'proxy') 'dns-proxy-out 默认必须使用 proxy'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'proxy').connect_timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'proxy').domain_resolver.server -eq 'dns-node') 'proxy 域名解析必须使用独立 dns-node transport'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'proxy').domain_resolver.timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True (@($baseDocument.outbounds | Where-Object tag -eq 'direct').Count -eq 1) '母版必须包含 direct 出站'
    Assert-True (($baseDocument.outbounds | Where-Object tag -eq 'direct').connect_timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True ($baseDocument.route.default_domain_resolver.server -eq 'dns-proxy') '默认域名解析器必须使用 dns-proxy'
    Assert-True ($baseDocument.route.default_domain_resolver.strategy -eq 'ipv4_only') '默认域名解析器必须使用 ipv4_only'
    Assert-True ($baseDocument.route.default_domain_resolver.timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True ($baseDocument.inbounds -is [System.Array]) '母版 inbounds 必须是 JSON 数组'
    Assert-True ($baseDocument.inbounds.Count -eq 2) '母版应只包含 TUN 和专用 dns-in 入站'
    Assert-True ($baseDocument.inbounds[0].type -eq 'tun') '母版必须使用 TUN 入站'
    Assert-True ($baseDocument.inbounds[0].address[0] -eq '172.28.255.1/30') '母版应使用低冲突风险的默认 TUN 地址'
    Assert-True ($baseDocument.inbounds[0].mtu -eq 4064) 'Apple-compatible fallback TUN MTU must remain 4064'
    Assert-True ($baseDocument.inbounds[0].dns_mode -eq 'hijack') '母版 TUN 必须使用 dns_mode=hijack'
    Assert-True ($null -eq $baseDocument.inbounds[0].PSObject.Properties['dns_address']) '母版不得设置 dns_address'
    Assert-True ($baseDocument.inbounds[0].auto_route -eq $true) '母版 TUN 必须启用 auto_route'
    Assert-True ($baseDocument.inbounds[0].stack -eq 'gvisor') 'Apple-compatible fallback TUN stack must remain gvisor'
    Assert-True ($null -eq $baseDocument.inbounds[0].PSObject.Properties['endpoint_independent_nat']) 'Obsolete endpoint_independent_nat must not remain in the base template'
    Assert-True ($baseDocument.inbounds[0].udp_timeout -match '^(?=.*[1-9])[0-9]+(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)$') '母版时长参数必须合法'
    Assert-True ($baseDocument.inbounds[0].strict_route -is [bool] -and -not $baseDocument.inbounds[0].strict_route) 'The shared TUN template must disable strict_route.'
    Assert-True ($baseDocument.inbounds[0].udp_mapping -eq 'endpoint_independent') '母版 TUN UDP 映射必须为 endpoint_independent'
    Assert-True ($baseDocument.inbounds[0].udp_filtering -eq 'endpoint_independent') '母版 TUN UDP 过滤必须为 endpoint_independent'
    Assert-True ($baseDocument.inbounds[0].udp_nat_max -ge 0) '母版 TUN UDP NAT 会话上限必须合法'
    Assert-True ($null -eq $baseDocument.inbounds[0].PSObject.Properties['set_system_proxy']) '母版不得设置系统代理'
    Assert-True ($baseDocument.inbounds[1].type -eq 'direct' -and $baseDocument.inbounds[1].tag -eq 'dns-in' -and $baseDocument.inbounds[1].listen -eq '127.0.0.1' -and $baseDocument.inbounds[1].listen_port -eq 15354) '母版必须在 TUN 后保留 127.0.0.1:15354 dns-in'
    Assert-True ($baseDocument.dns.servers.Count -eq 6 -and @($baseDocument.dns.servers | Where-Object tag -eq 'dns-node').Count -eq 1) '母版必须仅增加一个内部 dns-node transport'
    Assert-True (@($baseDocument.dns.servers | Where-Object tag -eq 'dns-node')[0].type -eq 'udp' -and @($baseDocument.dns.servers | Where-Object tag -eq 'dns-node')[0].server -eq '127.0.0.1' -and @($baseDocument.dns.servers | Where-Object tag -eq 'dns-node')[0].server_port -eq 15354 -and @($baseDocument.dns.servers | Where-Object tag -eq 'dns-node')[0].inet4_bind_address -eq '127.0.0.1') 'dns-node must use the bound loopback transport'
    Assert-True ($null -eq $profileDocument.profiles.windows.overlay.PSObject.Properties['inbounds']) 'Windows 适配档不得复制母版 inbounds'
    Assert-True ($profileDocument.profiles.windows.overlay.experimental.clash_api.external_controller -eq '127.0.0.1:19090') 'Windows 适配档必须启用仅限本机的实时日志接口'
    Assert-True ($null -eq $profileDocument.profiles.windows.overlay.experimental.clash_api.PSObject.Properties['external_ui']) 'Windows 实时日志接口不得启用网页面板'
    Assert-True ($null -eq $profileDocument.profiles.linux.overlay.PSObject.Properties['inbounds']) 'Linux 适配档不得复制母版 inbounds'
    Assert-True ($profileDocument.profiles.windows.tun_overlay.mtu -eq 65535 -and $profileDocument.profiles.windows.tun_overlay.stack -ceq 'mixed') 'Windows profile must select mixed/65535'
    Assert-True ($profileDocument.profiles.linux.tun_overlay.mtu -eq 65535 -and $profileDocument.profiles.linux.tun_overlay.stack -ceq 'mixed' -and $profileDocument.profiles.linux.tun_overlay.auto_route -eq $true -and $profileDocument.profiles.linux.tun_overlay.auto_redirect -eq $true) 'Ordinary Linux profile must select mixed/65535 with Linux routing flags'
    Assert-True ($profileDocument.profiles.linux.linux_route_exclude_address_sets -is [bool] -and $profileDocument.profiles.linux.linux_route_exclude_address_sets) 'Only Linux profile should default direct IPv4 route exclusion on'
    Assert-True ($profileDocument.profiles.android.tun_overlay.mtu -eq 9000 -and $profileDocument.profiles.android.tun_overlay.stack -ceq 'mixed') 'Android profile must select mixed/9000'
    Assert-True ($profileDocument.profiles.macos.tun_overlay.mtu -eq 4064 -and $profileDocument.profiles.macos.tun_overlay.stack -ceq 'gvisor') 'macOS NetworkExtension profile must select gvisor/4064'
    Assert-True ($profileDocument.profiles.ios.tun_overlay.mtu -eq 4064 -and $profileDocument.profiles.ios.tun_overlay.stack -ceq 'gvisor') 'iOS NetworkExtension profile must select gvisor/4064'

    New-Item -ItemType Directory -Path $customOutput -Force | Out-Null
    $listProfilesPath = Join-Path $customOutput 'list-profiles.json'
    $listProfilesDocument = [ordered]@{
        schema_version = 1
        minimum_sing_box_version = '1.14.0'
        profiles = [ordered]@{
            'list-test' = [ordered]@{
                file_name = 'list-test.json'
                description = '自定义客户端清单参数测试'
                overlay = [ordered]@{}
            }
        }
    }
    $listProfilesJson = ($listProfilesDocument | ConvertTo-Json -Depth 10) -replace "`r`n?", "`n"
    [System.IO.File]::WriteAllText($listProfilesPath, "$listProfilesJson`n", [System.Text.UTF8Encoding]::new($false))
    $listedClients = @(& $generator -ListClients -ProfilesPath $listProfilesPath)
    Assert-True ($listedClients.Count -eq 1) '-ListClients 必须读取用户指定的 ProfilesPath'
    Assert-True ($listedClients[0].Client -eq 'list-test') '-ListClients 不得回退到默认客户端清单'

    $preservedReleaseDirectories = @('2026-10-20-baseline','2026-10-25-performance')
    [IO.Directory]::CreateDirectory((Join-Path $testOutput '2026-10-20-baseline\nested\empty')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $testOutput '2026-10-20-baseline\rule-set')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $testOutput '2026-10-25-performance\rule-set')) | Out-Null
    $preservedReleaseFiles = @(
        (Join-Path $testOutput '2026-10-20-baseline\nested\note.txt'),
        (Join-Path $testOutput '2026-10-20-baseline\rule-set\baseline.srs'),
        (Join-Path $testOutput '2026-10-25-performance\rule-set\routing-direct-domain.srs'),
        (Join-Path $testOutput '2026-10-25-performance\rule-set\routing-direct-port.srs'),
        (Join-Path $testOutput '2026-10-25-performance\rule-set\routing-direct-ip.srs')
    )
    $releaseFixtureBytes = @('baseline-note','baseline-srs','domain-srs','port-srs','ip-srs')
    for ($index = 0; $index -lt $preservedReleaseFiles.Count; $index++) {
        [IO.File]::WriteAllText($preservedReleaseFiles[$index],$releaseFixtureBytes[$index],(New-Object Text.UTF8Encoding($false)))
    }
    $preservedReleaseHashes = @{}
    foreach ($file in $preservedReleaseFiles) {
        $relative = $file.Substring($testOutput.Length).TrimStart([char[]]'\/').Replace('\','/')
        $preservedReleaseHashes[$relative] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    }

    $allGeneratorArguments = @{
        All = $true
        OutputDirectory = $testOutput
        SupportDirectory = $testSupportDirectory
        RoutingRulesAlreadyUpdated = $true
    }
    Assert-True ([bool]$resolvedSingBox) '二进制规则集测试必须找到 sing-box 编译器'
    $allGeneratorArguments['SingBoxPath'] = $resolvedSingBox
    & $generator @allGeneratorArguments
    $expectedOutputNameArray = @($preservedReleaseDirectories + 'sing-box-configs.zip')
    $expectedOutputNames = @($expectedOutputNameArray | Sort-Object) -join ','
    $actualOutputNames = @(Get-ChildItem -LiteralPath $testOutput -Force | ForEach-Object Name | Sort-Object) -join ','
    Assert-True ($actualOutputNames -eq $expectedOutputNames) '正式输出必须发布 ZIP 并保留日期版本目录'
    Assert-True ([IO.Directory]::Exists((Join-Path $testOutput '2026-10-20-baseline\nested\empty'))) '发布时必须保留日期版本中的空目录路径'
    foreach ($file in $preservedReleaseFiles) {
        $relative = $file.Substring($testOutput.Length).TrimStart([char[]]'\/').Replace('\','/')
        Assert-True ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ceq $preservedReleaseHashes[$relative]) ('实际生成发布未保留日期版本文件：' + $relative)
    }
    Assert-True (Test-Path -LiteralPath (Join-Path $testSupportDirectory 'build-cache.json') -PathType Leaf) '编译缓存必须写入独立支持目录'
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $testOutput 'sing-box-configs.zip'), $testOutput)

    $expectedFiles = @(
        'sing-box-windows-tun.json',
        'sing-box-linux-tun.json',
        'sing-box-macos-tun.json',
        'sing-box-android.json',
        'sing-box-ios.json'
    )

    . (Join-Path $scriptsRoot 'Config-Archive.ps1')
    $archiveFiles = Get-ConfigArchiveFiles -Directory $testOutput -ConfigurationNames $expectedFiles
    $archiveManifest = @{}
    foreach ($entryName in $archiveFiles.Keys) {
        $entryPath = $archiveFiles[$entryName]
        $archiveManifest[$entryName] = @{Length=(Get-Item -LiteralPath $entryPath).Length;Hash=(Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash}
    }
    Assert-True ($archiveFiles.Count -eq ($expectedFiles.Count + $expectedRuleSets.Count)) '全平台 ZIP 必须包含所有配置与规则集'
    Assert-ConfigArchive -ArchivePath (Join-Path $testOutput 'sing-box-configs.zip') -Manifest $archiveManifest

    foreach ($fileName in $expectedFiles) {
        $path = Join-Path $testOutput $fileName
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "缺少输出文件 $fileName"
        $rawConfiguration = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        Assert-True (-not $rawConfiguration.Contains("`r")) "$fileName 必须使用纯 LF 换行"
        Assert-PrettyJsonFile -File (Get-Item -LiteralPath $path)
        Assert-True (-not $rawConfiguration.Contains('"domain_keyword"')) "$fileName 不得包含 domain_keyword"
        $document = $rawConfiguration | ConvertFrom-Json
        Assert-EffectiveDirectConfiguration -Configuration $document
        Assert-True ($document.route.final -eq 'proxy' -and $document.dns.final -eq 'dns-proxy') "$fileName must default to proxy for routing and DNS"
        Assert-True ($document.route.rules[0].action -eq 'reject' -and $document.route.rules[0].ip_version -eq 6 -and $document.route.rules[0].method -ceq 'default' -and $document.route.rules[0].no_drop -eq $true) "$fileName must preserve the IPv6 reject prelude"
        Assert-True ($null -eq $document.log.PSObject.Properties['output']) "$fileName 不得持续写入 Core 日志文件"
        Assert-True ($document.outbounds -is [System.Array]) "$fileName 的 outbounds 必须保持为 JSON 数组"
        Assert-True (($document.dns.servers | Where-Object tag -eq 'dns-direct').detour -eq 'dns-direct-out') "$fileName 的 dns-direct 必须显式使用专用直连出站"
        Assert-True (($document.outbounds | Where-Object tag -eq 'dns-direct-out').type -eq 'selector') "$fileName 的 dns-direct-out 必须使用 selector 别名"
        Assert-True (($document.outbounds | Where-Object tag -eq 'direct').connect_timeout -eq (($baseDocument.outbounds | Where-Object tag -eq 'direct').connect_timeout)) "$fileName 的 direct 必须使用 5 秒连接超时"
        Assert-True (($document.dns.servers | Where-Object tag -eq 'dns-proxy').detour -eq 'dns-proxy-out') "$fileName 的 dns-proxy 必须显式使用专用代理出站"
        Assert-True (($document.outbounds | Where-Object tag -eq 'dns-proxy-out').type -eq 'selector') "$fileName 的 dns-proxy-out 必须使用 selector 别名"
        Assert-True (($document.outbounds | Where-Object tag -eq 'proxy').connect_timeout -eq (($baseDocument.outbounds | Where-Object tag -eq 'proxy').connect_timeout)) "$fileName 的 proxy 必须使用 8 秒连接超时"
        Assert-True (($document.outbounds | Where-Object tag -eq 'proxy').domain_resolver.server -eq 'dns-node') "$fileName 的 proxy 域名解析必须使用 dns-node"
        Assert-True (($document.outbounds | Where-Object tag -eq 'proxy').domain_resolver.timeout -eq (($baseDocument.outbounds | Where-Object tag -eq 'proxy').domain_resolver.timeout)) "$fileName 的 proxy 域名解析必须使用 5 秒超时"
        Assert-True ($document.dns.servers -is [System.Array]) "$fileName 的 dns.servers 必须保持为 JSON 数组"
        Assert-DnsBootstrapConfiguration $document
        Assert-True ($null -eq $document.dns.PSObject.Properties['disable_cache']) "$fileName 不得包含与 optimistic 冲突的 disable_cache"
        Assert-True ($null -eq $document.dns.PSObject.Properties['disable_expire']) "$fileName 不得包含与 optimistic 冲突的 disable_expire"
        Assert-True ($document.dns.cache_capacity -eq $baseDocument.dns.cache_capacity) "$fileName 必须继承 DNS 缓存容量"
        Assert-True ($document.dns.timeout -eq $baseDocument.dns.timeout) "$fileName 必须继承 8 秒全局 DNS 查询超时"
        Assert-True ($document.dns.optimistic.enabled -eq $true) "$fileName 必须继承 optimistic DNS 缓存"
        Assert-True ($document.dns.optimistic.timeout -eq $baseDocument.dns.optimistic.timeout) "$fileName 必须继承 1h optimistic DNS 超时"
        Assert-True ($document.dns.reverse_mapping -eq $false) "$fileName must disable unused DNS reverse mapping"
        Assert-True ($document.route.default_domain_resolver.server -eq 'dns-proxy') "$fileName 的默认域名解析器必须使用 dns-proxy"
        Assert-True ($document.route.default_domain_resolver.strategy -eq 'ipv4_only') "$fileName 的默认域名解析器必须使用 ipv4_only"
        Assert-True ($document.route.default_domain_resolver.timeout -eq $baseDocument.route.default_domain_resolver.timeout) "$fileName 的默认域名解析器必须使用 8 秒超时"
        Assert-True ($document.route.rules -is [System.Array]) "$fileName 的 route.rules 必须保持为 JSON 数组"
        Assert-True ($document.route.rule_set -is [System.Array]) "$fileName 必须包含二进制分流规则集引用"
        $actualTags = @($document.route.rule_set | ForEach-Object tag)
        Assert-True (($actualTags -join "`n") -eq ($expectedTags -join "`n")) "$fileName 的二进制规则集必须严格保持既定动作段顺序"
        Assert-True (@($document.route.rule_set | Where-Object type -ne 'local').Count -eq 0) "$fileName 的规则集必须全部为 local"
        Assert-True (@($document.route.rule_set | Where-Object format -ne 'binary').Count -eq 0) "$fileName 的规则集必须全部为 binary"
        Assert-True (@($document.route.rule_set | Where-Object { $_.PSObject.Properties['rules'] }).Count -eq 0) "$fileName 不得再包含内联规则正文"
        foreach ($ruleSet in $document.route.rule_set) {
            Assert-True ($ruleSet.path -eq ('rule-set/{0}.srs' -f $ruleSet.tag)) "$fileName 的规则集 $($ruleSet.tag) 路径错误"
            Assert-True (Test-Path -LiteralPath (Join-Path $testOutput $ruleSet.path) -PathType Leaf) "$fileName 引用的规则文件不存在：$($ruleSet.path)"
        }

        Assert-True ($document.inbounds[0].dns_mode -eq 'hijack') "$fileName 必须使用 TUN dns_mode=hijack"
        Assert-True ($null -eq $document.inbounds[0].PSObject.Properties['dns_address']) "$fileName 不得设置 dns_address"
        Assert-True (@($document.route.rules | Where-Object { $_.action -eq 'hijack-dns' -and $_.inbound.Count -eq 1 -and $_.inbound[0] -eq 'dns-in' }).Count -eq 1) "$fileName 必须将 DNS hijack 限定到 dns-in"
        Assert-True (@($document.route.rules | Where-Object { $_.PSObject.Properties['port'] -and 53 -in @($_.port) }).Count -eq 0) "$fileName 不得保留旧端口 53 路由规则"

        $dynamicRouteRules = @($document.route.rules | Select-Object -Skip 2)
        $expectedNumericSets = @($expectedRuleSets | Where-Object { -not $_.HasDomain })
        Assert-True ($dynamicRouteRules.Count -eq $expectedNumericSets.Count) "$fileName must include every planned numeric rule"
        for ($routeIndex = 0; $routeIndex -lt $expectedNumericSets.Count; $routeIndex++) {
            $expected = $expectedNumericSets[$routeIndex]
            $actual = $dynamicRouteRules[$routeIndex]
            $action = if ($expected.Action -ceq 'reject') { 'reject' } else { 'route' }
            Assert-True ($actual.action -ceq $action -and $actual.rule_set -ceq $expected.Tag) "$fileName traffic action or numeric rule-set order differs from the plan"
            if ($action -ceq 'reject') { Assert-True ($actual.method -ceq 'default' -and $actual.no_drop -eq $true) "$fileName must actively reject blocked numeric traffic" }
        }
        $expectedDnsTag = @($expectedRuleSets | Where-Object { $_.HasDomain -and $_.Action -ceq 'reject' } | ForEach-Object Tag)
        Assert-True ((Get-ClientDnsBlockRuleCount -Rules @($document.dns.rules)) -eq (1 + $expectedDnsTag.Count)) "$fileName must include explicit REFUSED for AAAA and any configured domain list"
        if ($expectedDnsTag.Count) {
            $reject = $document.dns.rules[0]
            Assert-True ($reject.action -ceq 'reject' -and $reject.rule_set -ceq $expectedDnsTag[0] -and $reject.no_drop -eq $true -and @($reject.PSObject.Properties).Count -eq 3) "$fileName must reject matching DNS before the node and ordinary handlers"
        }
    }

    $ruleSetDirectory = Join-Path $testOutput 'rule-set'
    $binaryFiles = @(Get-ChildItem -LiteralPath $ruleSetDirectory -Filter '*.srs' -File | Sort-Object Name)
    Assert-True ($binaryFiles.Count -eq $expectedRuleSets.Count) '输出目录必须且只能包含当前计划中的二进制规则集'
    Assert-True (@(Get-ChildItem -LiteralPath $ruleSetDirectory -Filter '*.json' -File).Count -eq 0) '规则输出目录不得残留编译源 JSON'

    $decompiledDirectory = Join-Path $testOutput 'decompiled-rule-set'
    New-Item -ItemType Directory -Path $decompiledDirectory -Force | Out-Null
    $decompiledByTag = @{}
    $compiledValueCount = 0
    foreach ($file in $binaryFiles) {
        $tag = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $decompiledPath = Join-Path $decompiledDirectory ($tag + '.json')
        $decompileOutput = & $resolvedSingBox rule-set decompile $file.FullName -o $decompiledPath 2>&1
        Assert-True ($LASTEXITCODE -eq 0) "无法反编译验证规则集 $tag：$(($decompileOutput | Out-String).Trim())"
        $decompiled = Get-Content -LiteralPath $decompiledPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-True ([int]$decompiled.version -ge 1 -and [int]$decompiled.version -le 5) "规则集 $tag 的 SRS 版本必须兼容 sing-box 1.14"
        $decompiledByTag[$tag] = $decompiled
        $expectedRuleSet = @($expectedRuleSets | Where-Object Tag -eq $tag)[0]
        Assert-True ($null -ne $expectedRuleSet) "找不到规则集 $tag 的源计划"
        Assert-True ((Get-DomainUnionSignature @($expectedRuleSet.Rules)) -ceq (Get-DomainUnionSignature @($decompiled.rules))) "规则集 $tag 的域名覆盖范围在编译后发生变化"
        if ($expectedRuleSet.HasDomain) { Assert-True (@($decompiled.rules).Count -eq 1) "域名动作段 $tag 应合并为单个匹配对象" }
        foreach ($field in @('port','port_range','source_port','source_port_range')) {
            $expectedValues = @(Get-RuleFieldValues -Rules @($expectedRuleSet.Rules) -Field $field)
            $actualValues = @(Get-RuleFieldValues -Rules @($decompiled.rules) -Field $field)
            Assert-True (($actualValues -join "`n") -eq ($expectedValues -join "`n")) "规则集 $tag 的 $field 在编译后发生语义变化"
        }
        $expectedCidrs = @(Get-RuleFieldValues -Rules @($expectedRuleSet.Rules) -Field 'ip_cidr')
        $actualCidrs = @(Get-RuleFieldValues -Rules @($decompiled.rules) -Field 'ip_cidr')
        Assert-True ((Get-IPv4CidrUnionSignature $actualCidrs) -eq (Get-IPv4CidrUnionSignature $expectedCidrs)) "规则集 $tag 的 ip_cidr 覆盖范围在编译后发生变化"
        foreach ($rule in @($decompiled.rules)) {
            foreach ($field in @('domain','domain_suffix','ip_cidr','port','port_range','source_port','source_port_range')) {
                if ($null -ne $rule.PSObject.Properties[$field]) {
                    $compiledValueCount += @($rule.$field).Count
                }
            }
        }
    }
    Assert-True ($compiledValueCount -le [int]$mergedDocument.report.retained) 'SRS 编译后不得增加规则值'

    $directDomainValues = @()
    $directDomainExactValues = @()
    $directDomainSuffixValues = @()
    $directIpValues = @()
    foreach ($expected in $expectedRuleSets) {
        $decompiled = $decompiledByTag[$expected.Tag]
        foreach ($rule in @($decompiled.rules)) {
            if ($expected.Action -eq 'direct') {
                if ($null -ne $rule.PSObject.Properties['domain']) {
                    $directDomainExactValues += @($rule.domain)
                    $directDomainValues += @($rule.domain)
                }
                if ($null -ne $rule.PSObject.Properties['domain_suffix']) {
                    $directDomainSuffixValues += @($rule.domain_suffix)
                    $directDomainValues += @($rule.domain_suffix)
                }
                if ($null -ne $rule.PSObject.Properties['ip_cidr']) { $directIpValues += @($rule.ip_cidr) }
            }
        }
    }
    Assert-True ($directDomainValues.Count -gt 100000) 'SRS 必须保留完整的中国加速域名集合'
    foreach ($staticDomain in $expectedStaticDirectDomains) {
        Assert-True (Test-DomainCoveredByPositiveNativeRules -Domain $staticDomain -ExactValues $directDomainExactValues -SuffixValues $directDomainSuffixValues) "SRS 必须保留静态直连域名 $staticDomain 的匹配语义"
    }
    Assert-True (Test-DomainCoveredByPositiveNativeRules -Domain 'kookapp.cn' -ExactValues $directDomainExactValues -SuffixValues $directDomainSuffixValues) 'SRS 必须保留静态直连后缀 kookapp.cn 的根域名匹配语义'
    Assert-True (Test-DomainCoveredByPositiveNativeRules -Domain 'download.kookapp.cn' -ExactValues $directDomainExactValues -SuffixValues $directDomainSuffixValues) 'SRS 必须保留静态直连后缀 kookapp.cn 的子域名匹配语义'
    Assert-True (-not (Test-DomainCoveredByPositiveNativeRules -Domain 'apple-relay.apple.com' -ExactValues $directDomainExactValues -SuffixValues $directDomainSuffixValues)) 'SRS direct finite domain rules must not consume a static proxy-only domain as a false positive'
    Assert-True ('114.114.114.114/32' -notin $directIpValues) 'SRS 不得把 dnsmasq 上游 DNS 地址当作路由目标'
    $expectedPortRules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($expected in $expectedRuleSets) {
        if ($expected.Kind -ne 'port' -or $expected.Action -cne 'direct') { continue }
        foreach ($rule in @($expected.Rules)) { $expectedPortRules.Add($rule) }
    }
    $actualPortRules = @($decompiledByTag['routing-direct-port'].rules)
    $expectedDestinationPortSignature = Get-PortUnionSignature -Rules $expectedPortRules.ToArray() -ScalarField 'port' -RangeField 'port_range'
    $actualDestinationPortSignature = Get-PortUnionSignature -Rules $actualPortRules -ScalarField 'port' -RangeField 'port_range'
    Assert-True ($actualDestinationPortSignature -ceq $expectedDestinationPortSignature) 'Compiled destination-port interval union changed'
    $expectedSourcePortSignature = Get-PortUnionSignature -Rules $expectedPortRules.ToArray() -ScalarField 'source_port' -RangeField 'source_port_range'
    $actualSourcePortSignature = Get-PortUnionSignature -Rules $actualPortRules -ScalarField 'source_port' -RangeField 'source_port_range'
    Assert-True (-not [string]::IsNullOrEmpty($expectedSourcePortSignature)) 'Expected source-port family must not be empty'
    Assert-True ($actualSourcePortSignature -ceq $expectedSourcePortSignature) 'Compiled source-port interval union changed or was mixed into destination ports'
    foreach ($staticDirectPort in $expectedStaticDirectPorts) {
        Assert-True (Test-PortUnionSignatureCovers -Signature $actualDestinationPortSignature -Port ([int]$staticDirectPort)) "SRS must semantically retain static direct destination port $staticDirectPort"
    }
    foreach ($coveredBoundary in @(52,54,79,81,442,444,3477,3479,19301,19303)) {
        Assert-True (Test-PortUnionSignatureCovers -Signature $actualDestinationPortSignature -Port $coveredBoundary) "Compiled destination-port union must include inclusive interval boundary $coveredBoundary"
    }
    foreach ($excludedBoundary in @(53,80,443,3478,19302)) {
        Assert-True (-not (Test-PortUnionSignatureCovers -Signature $actualDestinationPortSignature -Port $excludedBoundary)) "Compiled destination-port union must leave excluded boundary $excludedBoundary uncovered"
    }
    foreach ($excludedPort in $expectedStaticProxyPorts) {
        Assert-True (-not (Test-PortUnionSignatureCovers -Signature $actualDestinationPortSignature -Port ([int]$excludedPort))) "SRS destination-port union must preserve static proxy exclusion $excludedPort"
    }

    $windowsTun = Get-Content -Raw -LiteralPath (Join-Path $testOutput 'sing-box-windows-tun.json') | ConvertFrom-Json
    Assert-True ($windowsTun.inbounds -is [System.Array]) 'Windows inbounds 必须是 JSON 数组'
    Assert-True ($windowsTun.inbounds[0].address -is [System.Array]) 'TUN address 必须是 JSON 数组'
    Assert-True ($windowsTun.inbounds[0].type -eq 'tun') 'Windows 默认配置应使用 TUN'
    Assert-True ($windowsTun.inbounds[0].mtu -eq 65535 -and $windowsTun.inbounds[0].stack -ceq 'mixed') 'Windows TUN must use mixed/65535'
    Assert-True ($null -eq $windowsTun.inbounds[0].PSObject.Properties['route_exclude_address_set'] -and $null -eq $windowsTun.inbounds[0].PSObject.Properties['auto_redirect']) 'Windows must not inherit Linux route capture options'
    Assert-True ($windowsTun.experimental.clash_api.external_controller -eq '127.0.0.1:19090') 'Windows 应在固定本机地址提供实时日志接口'
    Assert-True ($null -eq $windowsTun.experimental.clash_api.PSObject.Properties['external_ui']) 'Windows 不应启用或下载 Clash 网页面板'

    $linuxTun = Get-Content -Raw -LiteralPath (Join-Path $testOutput 'sing-box-linux-tun.json') | ConvertFrom-Json
    Assert-True ($linuxTun.inbounds[0].mtu -eq 65535 -and $linuxTun.inbounds[0].stack -ceq 'mixed' -and $linuxTun.inbounds[0].auto_route -eq $true -and $linuxTun.inbounds[0].auto_redirect -eq $true) 'Ordinary Linux TUN must use mixed/65535 and Linux route flags'
    Assert-True ($linuxTun.inbounds[0].route_exclude_address_set -is [System.Array]) 'Ordinary Linux must emit a typed route_exclude_address_set array'
    $linuxExcludedTags = @($linuxTun.inbounds[0].route_exclude_address_set)
    $linuxAvailableTags = @($linuxTun.route.rule_set | ForEach-Object { [string]$_.tag })
    $linuxTrafficTags = @($linuxTun.route.rules | Where-Object { $_.PSObject.Properties['outbound'] -and $_.outbound -eq 'direct' } | ForEach-Object { [string]$_.rule_set })
    Assert-True ($linuxExcludedTags.Count -eq 1 -and $linuxExcludedTags[0] -ceq 'routing-direct-ip' -and $linuxExcludedTags[0] -in $linuxAvailableTags -and $linuxExcludedTags[0] -in $linuxTrafficTags) 'Linux route exclusion must reference the exact effective direct IPv4 SRS and its traffic rule'
    Assert-True ($null -eq $linuxTun.inbounds[0].PSObject.Properties['endpoint_independent_nat']) 'Generated Linux config must not retain obsolete endpoint_independent_nat'
    Assert-True ($null -eq $linuxTun.PSObject.Properties['experimental']) 'Linux 不应继承 Windows 实时日志接口'

    $caseInsensitiveLinuxOutput = Join-Path $testRunRoot 'case-insensitive-linux-client'
    & $generator -Client 'Linux' -OutputDirectory $caseInsensitiveLinuxOutput -SupportDirectory $testSupportDirectory -RoutingRulesAlreadyUpdated -Force
    $caseInsensitiveLinuxExpanded = Join-Path $testRunRoot 'case-insensitive-linux-expanded'
    [IO.Directory]::CreateDirectory($caseInsensitiveLinuxExpanded) | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $caseInsensitiveLinuxOutput 'sing-box-configs.zip'), $caseInsensitiveLinuxExpanded)
    $caseInsensitiveLinuxConfig = Get-Content -Raw -LiteralPath (Join-Path $caseInsensitiveLinuxExpanded 'sing-box-linux-tun.json') | ConvertFrom-Json
    Assert-True ($caseInsensitiveLinuxConfig.inbounds[0].route_exclude_address_set -is [System.Array] -and
        (@($caseInsensitiveLinuxConfig.inbounds[0].route_exclude_address_set) -join ',') -ceq ($linuxExcludedTags -join ',')) 'Linux profile lookup and route-exclusion validation must preserve case-insensitive -Client binding.'
    if ($runningOnWindows) {
        # Windows cannot initialize Linux auto_redirect. Check an isolated copy
        # with only that flag disabled; published Linux bytes remain unchanged.
        $linuxRuleCheck = ($linuxTun | ConvertTo-Json -Depth 100) | ConvertFrom-Json
        $linuxRuleCheck.inbounds[0].auto_redirect = $false
        $linuxCheckPath = Join-Path $testOutput 'linux-rules-check.json'
        $linuxCheckText = (Format-JsonText -Text ($linuxRuleCheck | ConvertTo-Json -Depth 100)) + "`n"
        [IO.File]::WriteAllText($linuxCheckPath, $linuxCheckText, [Text.UTF8Encoding]::new($false))
        $linuxCheckOutput = & $resolvedSingBox -D $testOutput check -c $linuxCheckPath 2>&1
        Assert-True ($LASTEXITCODE -eq 0) ("Linux route/DNS official check failed: " + ($linuxCheckOutput | Out-String))
        Write-Host 'Linux route/DNS checked by the official Core on Windows using an isolated auto_redirect=false copy; Linux kernel/runtime validation remains pending.'
    }

    $android = Get-Content -Raw -LiteralPath (Join-Path $testOutput 'sing-box-android.json') | ConvertFrom-Json
    Assert-True ($android.inbounds[0].mtu -eq 9000 -and $android.inbounds[0].stack -ceq 'mixed' -and $null -eq $android.inbounds[0].PSObject.Properties['auto_redirect'] -and $null -eq $android.inbounds[0].PSObject.Properties['route_exclude_address_set']) 'Android VpnService profile must use mixed/9000 without Linux redirection or route exclusions'
    Assert-True ($null -eq $android.PSObject.Properties['experimental']) 'Android 不应继承 Windows 实时日志接口'

    $ios = Get-Content -Raw -LiteralPath (Join-Path $testOutput 'sing-box-ios.json') | ConvertFrom-Json
    Assert-True ($null -eq $ios.PSObject.Properties['experimental']) 'iOS 不应继承 Windows 实时日志接口'

    $macos = Get-Content -Raw -LiteralPath (Join-Path $testOutput 'sing-box-macos-tun.json') | ConvertFrom-Json
    foreach ($appleTun in @($macos.inbounds[0],$ios.inbounds[0])) {
        Assert-True ($appleTun.mtu -eq 4064 -and $appleTun.stack -ceq 'gvisor') 'NetworkExtension profiles must remain gvisor/4064'
        Assert-True ($null -eq $appleTun.PSObject.Properties['auto_redirect'] -and $null -eq $appleTun.PSObject.Properties['route_exclude_address_set']) 'Apple profiles must not inherit Linux-only TUN options'
    }

    foreach ($fileName in $expectedFiles) {
        $document = Get-Content -Raw -LiteralPath (Join-Path $testOutput $fileName) | ConvertFrom-Json
        Assert-True ($document.inbounds[0].type -eq 'tun') "$fileName 必须使用 TUN 入站"
        Assert-True ($document.inbounds[0].address[0] -eq '172.28.255.1/30') "$fileName 必须继承默认 TUN 地址"
        Assert-True ($null -eq $document.inbounds[0].PSObject.Properties['endpoint_independent_nat']) "$fileName must not inherit obsolete endpoint_independent_nat"
        Assert-True ($document.inbounds[0].udp_timeout -eq $baseDocument.inbounds[0].udp_timeout) "$fileName 必须继承 5 分钟 UDP NAT 超时"
        Assert-True ($document.inbounds[0].udp_mapping -eq 'endpoint_independent') "$fileName 必须继承 endpoint_independent UDP 映射"
        Assert-True ($document.inbounds[0].udp_filtering -eq 'endpoint_independent') "$fileName 必须继承 endpoint_independent UDP 过滤"
        Assert-True ($document.inbounds[0].udp_nat_max -eq $baseDocument.inbounds[0].udp_nat_max) "$fileName 必须继承 UDP NAT 会话上限"
        Assert-True ($document.inbounds[0].strict_route -is [bool] -and -not $document.inbounds[0].strict_route) "$fileName must disable strict_route."
        Assert-True ($null -eq $document.inbounds[0].PSObject.Properties['set_system_proxy']) "$fileName 不得设置系统代理"
    }

    $customGenerationOutput = Join-Path $customOutput 'generated-client'
    & $generator -Client android -OutputDirectory $customGenerationOutput -SupportDirectory $customSupportDirectory -TunAddress '10.254.253.1/30' -RoutingRulesAlreadyUpdated -SingBoxPath $resolvedSingBox
    Assert-True ((@(Get-ChildItem -LiteralPath $customGenerationOutput -Force | ForEach-Object Name | Sort-Object) -join ',') -eq 'sing-box-configs.zip') '单平台输出只能保留 ZIP'
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $customGenerationOutput 'sing-box-configs.zip'), $customGenerationOutput)
    $customDocument = Get-Content -Raw -LiteralPath (Join-Path $customGenerationOutput 'sing-box-android.json') | ConvertFrom-Json
    Assert-True ($customDocument.inbounds[0].address[0] -eq '10.254.253.1/30') '-TunAddress 必须覆盖母版默认地址'

    $platformContractRoot = Join-Path $customOutput 'platform-tuning-contracts'
    [IO.Directory]::CreateDirectory($platformContractRoot) | Out-Null
    $linuxOverlay = [ordered]@{ mtu=65535; stack='mixed'; auto_route=$true; auto_redirect=$true }
    $profileWithoutRouteExclude = New-TestProfileDocument -Name 'linux' -TunOverlay $linuxOverlay
    $profileWithoutRouteExcludePath = Join-Path $platformContractRoot 'linux-without-route-exclude.json'
    Write-ProfileFixture -Document $profileWithoutRouteExclude -Path $profileWithoutRouteExcludePath
    $metadataAbsentOutput = Join-Path $platformContractRoot 'metadata-absent-output'
    & $generator -Client linux -TemplatePath $template -ProfilesPath $profileWithoutRouteExcludePath `
        -OutputDirectory $metadataAbsentOutput -SupportDirectory (Join-Path $platformContractRoot 'support-metadata-absent') `
        -SkipRoutingRules -Force
    $metadataAbsentExpanded = Join-Path $platformContractRoot 'metadata-absent-expanded'
    [IO.Directory]::CreateDirectory($metadataAbsentExpanded) | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $metadataAbsentOutput 'sing-box-configs.zip'), $metadataAbsentExpanded)
    $metadataAbsentConfig = Get-Content -Raw -LiteralPath (Join-Path $metadataAbsentExpanded 'sing-box-linux-fixture.json') | ConvertFrom-Json
    Assert-True ($null -eq $metadataAbsentConfig.inbounds[0].PSObject.Properties['route_exclude_address_set']) 'Custom Linux profiles without the optional metadata must keep route exclusion disabled.'

    $explicitFalseOutput = Join-Path $platformContractRoot 'explicit-false-output'
    & $generator -Client linux -TemplatePath $template -ProfilesPath (Join-Path $configRoot 'client-profiles.json') `
        -OutputDirectory $explicitFalseOutput -SupportDirectory (Join-Path $platformContractRoot 'support-explicit-false') `
        -SkipRoutingRules -LinuxRouteExcludeAddressSets:$false -Force
    $explicitFalseExpanded = Join-Path $platformContractRoot 'explicit-false-expanded'
    [IO.Directory]::CreateDirectory($explicitFalseExpanded) | Out-Null
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $explicitFalseOutput 'sing-box-configs.zip'), $explicitFalseExpanded)
    $explicitFalseConfig = Get-Content -Raw -LiteralPath (Join-Path $explicitFalseExpanded 'sing-box-linux-tun.json') | ConvertFrom-Json
    Assert-True ($null -eq $explicitFalseConfig.inbounds[0].PSObject.Properties['route_exclude_address_set']) 'An explicit false switch must override the Linux profile default.'

    foreach ($legacyFlagValue in @($true,$false)) {
        $legacyFlagTemplateDocument = Get-Content -Raw -LiteralPath $template -Encoding UTF8 | ConvertFrom-Json
        $legacyFlagTemplateDocument.inbounds[0] | Add-Member -MemberType NoteProperty -Name 'endpoint_independent_nat' -Value ([bool]$legacyFlagValue) -Force
        $legacyFlagTemplatePath = Join-Path $platformContractRoot ('legacy-bool-' + $legacyFlagValue + '.json')
        Write-ProfileFixture -Document $legacyFlagTemplateDocument -Path $legacyFlagTemplatePath
        $legacyFlagOutput = Join-Path $platformContractRoot ('legacy-bool-' + $legacyFlagValue + '-output')
        & $generator -Client linux -TemplatePath $legacyFlagTemplatePath -ProfilesPath $profileWithoutRouteExcludePath `
            -OutputDirectory $legacyFlagOutput -SupportDirectory (Join-Path $platformContractRoot ('support-legacy-bool-' + $legacyFlagValue)) `
            -SkipRoutingRules -Force
        $legacyFlagExpanded = Join-Path $platformContractRoot ('legacy-bool-' + $legacyFlagValue + '-expanded')
        [IO.Directory]::CreateDirectory($legacyFlagExpanded) | Out-Null
        [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $legacyFlagOutput 'sing-box-configs.zip'), $legacyFlagExpanded)
        $legacyFlagConfig = Get-Content -Raw -LiteralPath (Join-Path $legacyFlagExpanded 'sing-box-linux-fixture.json') | ConvertFrom-Json
        Assert-True ($legacyFlagConfig.inbounds[0].endpoint_independent_nat -is [bool] -and
            $legacyFlagConfig.inbounds[0].endpoint_independent_nat -eq [bool]$legacyFlagValue) 'Legacy custom-template bools may be retained for compatibility but do not control NAT behavior.'
    }

    foreach ($legacyFlagBadValue in @('true',1)) {
        $invalidLegacyFlagTemplateDocument = Get-Content -Raw -LiteralPath $template -Encoding UTF8 | ConvertFrom-Json
        $invalidLegacyFlagTemplateDocument.inbounds[0] | Add-Member -MemberType NoteProperty -Name 'endpoint_independent_nat' -Value $legacyFlagBadValue -Force
        $invalidLegacyFlagTemplatePath = Join-Path $platformContractRoot ('invalid-legacy-flag-' + [string]$legacyFlagBadValue + '.json')
        Write-ProfileFixture -Document $invalidLegacyFlagTemplateDocument -Path $invalidLegacyFlagTemplatePath
        $invalidLegacyFlagOutput = Join-Path $platformContractRoot ('invalid-legacy-flag-' + [string]$legacyFlagBadValue + '-output')
        $invalidLegacyFlagArguments = @{
            Client='linux'; TemplatePath=$invalidLegacyFlagTemplatePath; ProfilesPath=$profileWithoutRouteExcludePath
            OutputDirectory=$invalidLegacyFlagOutput; SupportDirectory=(Join-Path $platformContractRoot ('support-invalid-legacy-flag-' + [string]$legacyFlagBadValue))
            SkipRoutingRules=$true; Force=$true
        }
        Assert-True (Test-ExpectedGeneratorFailure -Arguments $invalidLegacyFlagArguments -MessagePattern 'endpoint_independent_nat.*布尔值') 'Non-boolean legacy NAT metadata must still be rejected.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $invalidLegacyFlagOutput 'sing-box-configs.zip'))) 'Invalid legacy NAT metadata must not be packaged.'
    }

    $explicitTrueWithSkipOutput = Join-Path $platformContractRoot 'explicit-true-with-skip-output'
    $explicitTrueWithSkipArguments = @{
        Client='linux'; TemplatePath=$template; ProfilesPath=(Join-Path $configRoot 'client-profiles.json')
        OutputDirectory=$explicitTrueWithSkipOutput; SupportDirectory=(Join-Path $platformContractRoot 'support-explicit-true-skip')
        SkipRoutingRules=$true; LinuxRouteExcludeAddressSets=$true; Force=$true
    }
    Assert-True (Test-ExpectedGeneratorFailure -Arguments $explicitTrueWithSkipArguments -MessagePattern 'requires routing rules and the Linux client') 'Explicit Linux route exclusion must fail when routing generation is skipped.'
    Assert-True (-not (Test-Path -LiteralPath $explicitTrueWithSkipOutput)) 'Invalid explicit Linux route exclusion must fail before creating output.'

    $explicitTrueNonLinuxOutput = Join-Path $platformContractRoot 'explicit-true-non-linux-output'
    $explicitTrueNonLinuxArguments = @{
        Client='android'; TemplatePath=$template; ProfilesPath=(Join-Path $configRoot 'client-profiles.json')
        OutputDirectory=$explicitTrueNonLinuxOutput; SupportDirectory=(Join-Path $platformContractRoot 'support-explicit-true-android')
        SkipRoutingRules=$true; LinuxRouteExcludeAddressSets=$true; Force=$true
    }
    Assert-True (Test-ExpectedGeneratorFailure -Arguments $explicitTrueNonLinuxArguments -MessagePattern 'requires routing rules and the Linux client') 'Explicit Linux route exclusion must fail for non-Linux client selection.'
    Assert-True (-not (Test-Path -LiteralPath $explicitTrueNonLinuxOutput)) 'Non-Linux route-exclusion request must fail before creating output.'

    $invalidMetadataType = New-TestProfileDocument -Name 'linux' -TunOverlay $linuxOverlay
    $invalidMetadataType.profiles['linux']['linux_route_exclude_address_sets'] = 'true'
    $invalidMetadataTypePath = Join-Path $platformContractRoot 'invalid-metadata-type.json'
    Write-ProfileFixture -Document $invalidMetadataType -Path $invalidMetadataTypePath
    $invalidMetadataTypeListArguments = @{ ListClients=$true; ProfilesPath=$invalidMetadataTypePath }
    Assert-True (Test-ExpectedGeneratorFailure -Arguments $invalidMetadataTypeListArguments -MessagePattern '必须是 JSON 布尔值') 'String metadata must be rejected before profile listing or output.'

    $wrongPlatformMetadata = New-TestProfileDocument -Name 'android' -TunOverlay ([ordered]@{ mtu=9000; stack='mixed' }) -LinuxRouteExcludeDefault $true
    $wrongPlatformMetadataPath = Join-Path $platformContractRoot 'wrong-platform-metadata.json'
    Write-ProfileFixture -Document $wrongPlatformMetadata -Path $wrongPlatformMetadataPath
    $wrongPlatformListArguments = @{ ListClients=$true; ProfilesPath=$wrongPlatformMetadataPath }
    Assert-True (Test-ExpectedGeneratorFailure -Arguments $wrongPlatformListArguments -MessagePattern '不得声明 Linux 专属') 'Linux route-exclusion metadata must be rejected on another profile.'

    foreach ($badStack in @('unsupported-stack',7)) {
        $badStackOverlay = [ordered]@{ mtu=65535; stack=$badStack; auto_route=$true; auto_redirect=$true }
        $badStackProfiles = New-TestProfileDocument -Name 'linux' -TunOverlay $badStackOverlay
        $badStackName = if ($badStack -is [string]) { 'unknown-stack' } else { 'wrong-stack-type' }
        $badStackProfilesPath = Join-Path $platformContractRoot ($badStackName + '.json')
        Write-ProfileFixture -Document $badStackProfiles -Path $badStackProfilesPath
        $badStackOutput = Join-Path $platformContractRoot ($badStackName + '-output')
        $badStackArguments = @{
            Client='linux'; TemplatePath=$template; ProfilesPath=$badStackProfilesPath
            OutputDirectory=$badStackOutput; SupportDirectory=(Join-Path $platformContractRoot ('support-' + $badStackName))
            SkipRoutingRules=$true; Force=$true
        }
        Assert-True (Test-ExpectedGeneratorFailure -Arguments $badStackArguments -MessagePattern 'TUN stack') ('Unsupported TUN stack selection was accepted: ' + $badStackName)
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $badStackOutput 'sing-box-configs.zip'))) ('Invalid TUN stack must not publish an archive: ' + $badStackName)
    }

    $invalidDirectDetourTemplate = Join-Path $customOutput 'invalid-direct-detour-template.json'
    $invalidDirectDetourOutput = Join-Path $customOutput 'invalid-direct-detour-output'
    $invalidDirectDetourDocument = Get-Content -Raw -LiteralPath $template -Encoding UTF8 | ConvertFrom-Json
    $invalidDirectDns = $invalidDirectDetourDocument.dns.servers | Where-Object tag -eq 'dns-direct'
    $invalidDirectDns.detour = 'direct'
    $invalidDirectOutbound = $invalidDirectDetourDocument.outbounds | Where-Object tag -eq 'direct'
    $invalidDirectOutbound.PSObject.Properties.Remove('connect_timeout')
    $invalidDirectDetourJson = ($invalidDirectDetourDocument | ConvertTo-Json -Depth 100 -Compress) -replace "`r`n?", "`n"
    [System.IO.File]::WriteAllText($invalidDirectDetourTemplate, "$invalidDirectDetourJson`n", [System.Text.UTF8Encoding]::new($false))
    $invalidDirectDetourRejected = $false
    try {
        & $generator -Client android -TemplatePath $invalidDirectDetourTemplate -OutputDirectory $invalidDirectDetourOutput -SupportDirectory (Join-Path $customOutput 'support\invalid-detour') -SkipRoutingRules -Force
    }
    catch {
        $invalidDirectDetourRejected = $_.Exception.Message -match '不能指向空 direct 出站'
    }
    Assert-True $invalidDirectDetourRejected '生成器必须拒绝 DNS detour 指向空 direct 出站'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $invalidDirectDetourOutput 'sing-box-android.json'))) '无效 DNS detour 不得生成配置文件'

    if ($runningOnWindows) {
        $failedCheckOutput = Join-Path $customOutput 'failed-check'
        New-Item -ItemType Directory -Path $failedCheckOutput -Force | Out-Null
        $protectedArchive = Join-Path $failedCheckOutput 'sing-box-configs.zip'
        $archiveSentinel = "existing-valid-package`n"
        [System.IO.File]::WriteAllText($protectedArchive, $archiveSentinel, [System.Text.UTF8Encoding]::new($false))
        $protectedVersionDirectory = Join-Path $failedCheckOutput '2026-10-25-performance'
        $protectedVersionFile = Join-Path $protectedVersionDirectory 'rule-set\routing-direct-ip.srs'
        [IO.Directory]::CreateDirectory((Split-Path -Parent $protectedVersionFile)) | Out-Null
        $versionSentinel = 'existing-version-srs'
        [System.IO.File]::WriteAllText($protectedVersionFile, $versionSentinel, [System.Text.UTF8Encoding]::new($false))
        $archiveSentinelHash = (Get-FileHash -LiteralPath $protectedArchive -Algorithm SHA256).Hash
        $versionSentinelHash = (Get-FileHash -LiteralPath $protectedVersionFile -Algorithm SHA256).Hash
        $rejectingChecker = Join-Path $customOutput 'tooling\reject-sing-box.cmd'
        New-Item -ItemType Directory -Path (Split-Path -Parent $rejectingChecker) -Force | Out-Null
        [System.IO.File]::WriteAllText($rejectingChecker, "@exit /b 1`r`n", [System.Text.Encoding]::ASCII)
        $checkFailed = $false
        $lastExitCodeBeforeRejectingCheck = $global:LASTEXITCODE
        try {
            & $generator -Client windows -OutputDirectory $failedCheckOutput -SupportDirectory (Join-Path $customOutput 'support\failed-check') -SingBoxPath $rejectingChecker -Force -SkipRoutingRules
        }
        catch {
            $checkFailed = $_.Exception.Message -match 'sing-box 校验失败'
        }
        Assert-True $checkFailed '官方校验失败时生成器必须报错'
        Assert-True ($global:LASTEXITCODE -eq $lastExitCodeBeforeRejectingCheck) '官方校验失败不得污染调用会话的 LASTEXITCODE'
        Assert-True ((Get-FileHash -LiteralPath $protectedArchive -Algorithm SHA256).Hash -ceq $archiveSentinelHash) '官方校验失败不得覆盖现有 ZIP'
        Assert-True ((Get-FileHash -LiteralPath $protectedVersionFile -Algorithm SHA256).Hash -ceq $versionSentinelHash) '官方校验失败不得修改日期版本内容'
        Assert-True ((@(Get-ChildItem -LiteralPath $failedCheckOutput -Force | ForEach-Object Name | Sort-Object) -join ',') -eq '2026-10-25-performance,sing-box-configs.zip') '官方校验失败不得改变已有发布目录结构'
        Assert-True (@(Get-ChildItem -LiteralPath $failedCheckOutput -Filter '*.tmp' -File).Count -eq 0) '官方校验失败后不得残留临时配置'
        foreach ($transactionPath in @("$failedCheckOutput.build-stage","$failedCheckOutput.build-backup","$failedCheckOutput.build-journal.json","$failedCheckOutput.build-journal.json.write")) {
            Assert-True (-not (Test-Path -LiteralPath $transactionPath)) ('官方校验失败后不得残留发布事务状态：' + $transactionPath)
        }
    }

    $hashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $template).Hash
    Assert-True ($hashAfter -eq $hashBefore) '生成器不得修改母版'

    Write-Host "全部测试通过（$($expectedFiles.Count) 个客户端配置）。"
}
finally {
    if (Test-Path -LiteralPath $testRunRoot) {
        $absolute = [IO.Path]::GetFullPath($testRunRoot).TrimEnd([char[]]'\/')
        $fixtureRoot = [IO.Path]::GetFullPath($taskFixtureRoot).TrimEnd([char[]]'\/')
        if ((Split-Path -Parent $absolute) -ine $fixtureRoot -or (Split-Path -Leaf $absolute) -notmatch '^generator-[a-f0-9]{12}$') { throw 'Unsafe generator test cleanup path.' }
        $items = @((Get-Item -LiteralPath $absolute -Force)) + @(Get-ChildItem -LiteralPath $absolute -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Linked generator test fixture retained; no recursive cleanup.' }
        Remove-Item -LiteralPath $absolute -Recurse -Force -ErrorAction Stop
    }
    if ($ownsTestRoot -and [IO.Directory]::Exists($taskFixtureRoot)) {
        $safeRoot = Assert-ClientPlainPathTree -Path $taskFixtureRoot -LeafType Directory -Required -IncludeDescendants
        $fixtureRootParent = [IO.Path]::GetFullPath((Split-Path -Parent $safeRoot)).TrimEnd([char[]]'\/')
        $expectedParent = [IO.Path]::GetFullPath((Join-Path $projectFullPath 'outputs\tests\generator')).TrimEnd([char[]]'\/')
        if ($fixtureRootParent -ine $expectedParent -or (Split-Path -Leaf $safeRoot) -notmatch '^run-[a-f0-9]{32}$') { throw 'Unsafe default generator test-root cleanup path.' }
        if (@(Get-ChildItem -LiteralPath $safeRoot -Force -ErrorAction Stop).Count) { throw 'Default generator test root is not empty after cleanup.' }
        [IO.Directory]::Delete($safeRoot, $false)
    }
}
