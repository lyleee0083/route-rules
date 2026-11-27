[CmdletBinding()]
param([string]$ArchivePath,[string]$SingBoxPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'Direct-RoutingPolicy.ps1')
. (Join-Path $scriptsRoot 'DNS-BootstrapPolicy.ps1')
. (Join-Path $scriptsRoot 'Official-SingBoxChecker.ps1')
$resolvedSingBox=Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RequestedPath $SingBoxPath
if (-not $resolvedSingBox) { throw 'A verified project checker or explicit checker is required.' }

function Assert-PublishedHeadlessRule {
    param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)][string]$Tag)
    Assert-NoOtherIPv6Fields -Value $Rule
    $allowed=@()
    if ($Tag -match '-domain$') { $allowed=@('domain','domain_suffix','domain_regex') }
    elseif ($Tag -match '-ip$') { $allowed=@('ip_cidr') }
    elseif ($Tag -match '-source_port$') { $allowed=@('source_port','source_port_range') }
    elseif ($Tag -match '-port$') { $allowed=@('port','port_range','source_port','source_port_range') }
    else { throw 'Unknown delivered SRS family.' }
    $names=@($Rule.PSObject.Properties.Name)
    if (-not $names.Count -or @($names | Where-Object { $_ -notin $allowed }).Count) { throw 'Delivered SRS is not a positive same-type predicate.' }
    if ($Rule.PSObject.Properties['domain_regex']) {
        foreach ($pattern in $Rule.domain_regex) {
            if ($pattern -match '\(\?[=!<]|\[\^') { throw 'Positive domain residual may not use lookaround or negative character classes.' }
        }
    }
}

# One port-family file contains positive destination and source predicates.
foreach ($field in @('port','port_range','source_port','source_port_range')) {
    $value=@(123); if ($field -like '*range') { $value=@('123:125') }
    Assert-PublishedHeadlessRule -Tag 'routing-direct-port' -Rule ([pscustomobject]@{ $field=$value })
}
foreach ($invalid in @('{"source_port":[123],"invert":true}','{"port":[123],"ip_cidr":["192.0.2.0/24"]}','{"type":"logical","mode":"or","rules":[{"source_port":[123]}]}')) {
    $rejected=$false
    try { Assert-PublishedHeadlessRule -Tag 'routing-direct-port' -Rule ($invalid | ConvertFrom-Json) } catch { $rejected=$true }
    if (-not $rejected) { throw 'Port-family validation accepted inverse, mixed-family or logical data.' }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
if (-not $ArchivePath) { $ArchivePath = Join-Path $projectRoot 'generated\sing-box-configs.zip' }
else { $ArchivePath = [IO.Path]::GetFullPath($ArchivePath) }
$count=0; $reference=$null; $dnsReference=$null; $srsHashes=@{}
$decompileRoot=Join-Path ([IO.Path]::GetTempPath()) ('sb-published-direct-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $decompileRoot | Out-Null
try {
foreach ($path in @($ArchivePath)) {
    $archive=[IO.Compression.ZipFile]::OpenRead($path)
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName -notmatch '\.json$') { continue }
            $reader=New-Object IO.StreamReader($entry.Open())
            try { $config=$reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
            if (-not $config.PSObject.Properties['route']) { continue }
            Assert-EffectiveDirectConfiguration $config
            Assert-DnsBootstrapConfiguration $config
            $traffic=@($config.route.rules | Where-Object { $_.action -ne 'hijack-dns' })
            $signature=ConvertTo-Json -InputObject $traffic -Depth 100 -Compress
            if ($null -eq $reference) { $reference=$signature }
            elseif ($signature -cne $reference) { throw 'Main platform numeric traffic rules differ.' }
            $dnsSignature=ConvertTo-Json -InputObject @($config.dns.rules) -Depth 100 -Compress
            if ($null -eq $dnsReference) { $dnsReference=$dnsSignature }
            elseif ($dnsSignature -cne $dnsReference) { throw 'Platform effective-direct DNS order differs.' }
            foreach ($set in $config.route.rule_set) {
                $matches=@($archive.Entries | Where-Object FullName -eq $set.path)
                if ($matches.Count -ne 1) { throw 'Missing or duplicate delivered SRS.' }
                $sha=[Security.Cryptography.SHA256]::Create(); $stream=$matches[0].Open()
                try { $hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } finally { $stream.Dispose();$sha.Dispose() }
                if ($srsHashes.ContainsKey([string]$set.tag)) {
                    if ($srsHashes[[string]$set.tag] -ne $hash) { throw 'Different platforms contain different direct SRS bytes.' }
                    continue
                }
                $srsHashes[[string]$set.tag]=$hash
                $binary=Join-Path $decompileRoot ($set.tag+'.srs')
                $output=Join-Path $decompileRoot ($set.tag+'.json')
                [IO.Compression.ZipFileExtensions]::ExtractToFile($matches[0],$binary)
                & $resolvedSingBox rule-set decompile --output $output $binary | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Official final SRS decompile failed.' }
                $data=Get-Content -LiteralPath $output -Encoding UTF8 -Raw | ConvertFrom-Json
                foreach ($headless in $data.rules) {
                    Assert-PublishedHeadlessRule -Tag ([string]$set.tag) -Rule $headless
                }
            }
            $count++
            Write-Output ($entry.FullName + ': DNS-only domain sets, numeric business traffic, IPv6-first rejection and default proxy passed.')
        }
    } finally { $archive.Dispose() }
}
if ($count -ne 5) { throw 'Expected five main profiles; split OpenWrt policy has independent package tests.' }
$stableFamilyTags = @($srsHashes.Keys | Where-Object { $_ -match '^routing-direct-(domain|port|ip)$' } | Sort-Object)
if ($stableFamilyTags.Count -gt 0) {
    $unexpected = @($srsHashes.Keys | Where-Object { $_ -cnotmatch '^routing-(?:direct|reject)-(?:domain|port|ip)$' })
    if (($stableFamilyTags -join ',') -cne 'routing-direct-domain,routing-direct-ip,routing-direct-port' -or $unexpected.Count) {
        throw 'New generated archives must contain the three stable direct families and may contain resolved rejection families.'
    }
}
$archive=[IO.Compression.ZipFile]::OpenRead($ArchivePath)
try {
    $reader=New-Object IO.StreamReader($archive.GetEntry('sing-box-windows-tun.json').Open())
    try { $validJson=$reader.ReadToEnd() } finally { $reader.Dispose() }
} finally { $archive.Dispose() }
$bad=$validJson | ConvertFrom-Json
$firstIpTag=[string](@($bad.route.rule_set | Where-Object { $_.tag -match '^routing-direct-.*ip$' })[0].tag)
$bad.route.rules += [pscustomobject]@{rule_set=$firstIpTag;action='route';outbound='proxy'}
$rejected=$false
try { Assert-EffectiveDirectConfiguration $bad } catch { $rejected=$_.Exception.Message -match 'only contain direct' }
if (-not $rejected) { throw 'Explicit proxy action accepted in final traffic rules.' }
foreach ($invalid in @('{"address":"2001:db8::/64"}','{"inet6_address":[]}','{"ipv6":false}')) {
    $rejected=$false
    try { Assert-NoOtherIPv6Fields -Value ($invalid | ConvertFrom-Json) } catch { $rejected=$_.Exception.Message -match 'IPv6' }
    if (-not $rejected) { throw 'Additional IPv6 data accepted.' }
}
$bad=$validJson | ConvertFrom-Json
$bad.route.rules=@([pscustomobject]@{ inbound=@('dns-in');action='hijack-dns' }) + @($bad.route.rules)
$rejected=$false
try { Assert-EffectiveDirectConfiguration $bad } catch { $rejected=$_.Exception.Message -match 'leading IPv6 rejection' }
if (-not $rejected) { throw 'DNS handling accepted ahead of the IPv6 rejection.' }
# Exercise the final DNS/numeric contract, not only its identifier conventions.
foreach ($mode in @('domain-in-traffic','ip-in-dns','reverse-mapping','fakeip')) {
    $fixture=$validJson | ConvertFrom-Json
    $directDnsStart = 5 + (Get-ClientDnsBlockRuleCount -Rules @($fixture.dns.rules))
    if ($mode -eq 'domain-in-traffic') {
        $fixture.route.rules += [pscustomobject]@{rule_set=@($fixture.dns.rules[$directDnsStart].rule_set)[0];action='route';outbound='direct'}
    } elseif ($mode -eq 'ip-in-dns') {
        $fixture.dns.rules[$directDnsStart].rule_set=$firstIpTag
    } elseif ($mode -eq 'reverse-mapping') { $fixture.dns.reverse_mapping=$true }
    else { $fixture.dns.servers += [pscustomobject]@{type='fakeip';tag='fake'} }
    $rejected=$false
    try { Assert-EffectiveDirectConfiguration $fixture } catch { $rejected=$true }
    if (-not $rejected) { throw ('DNS/numeric contract accepted invalid mode: '+$mode) }
}
Write-Output 'Published routing policy: all five main profiles passed; explicit proxy action rejected. Split OpenWrt is checked independently.'
Write-Output 'DNS/numeric boundary: traffic domain, numeric DNS matcher, reverse mapping and FakeIP rejected.'
Write-Output ('Official SRS verification: '+$srsHashes.Count+' positive same-type sets; byte-identical across all profiles; no inverse/exclusion data.')
} finally {
    $resolved=[IO.Path]::GetFullPath($decompileRoot)
    if ((Split-Path -Parent $resolved) -ne ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $resolved) -notlike 'sb-published-direct-*') { throw 'Unsafe published test cleanup.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
