Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
$linuxInputRoot=Join-Path $openWrtRoot 'inputs/linux'
. (Join-Path $scriptsRoot 'Final-LinuxSnapshot.ps1')
. (Join-Path $scriptsRoot 'Native-NumericPolicy.ps1')
. (Join-Path $PSScriptRoot 'support\NodeDnsSnapshot.ps1')
$source=ConvertTo-OpenWrtNodeDnsFixtureConfiguration -Configuration (Read-StrictJsonFile -Path (Join-Path $linuxInputRoot 'sing-box-openwrt.json'))
if (-not $source.inbounds[0].PSObject.Properties['route_exclude_address_set']) { throw 'Final Linux source must exercise the ordinary Linux direct-IP route-exclusion input.' }
$config=ConvertTo-OpenWrtProxyConfiguration $source
Assert-NativeNumericConfiguration $config
if ($config.inbounds[0].PSObject.Properties['route_exclude_address_set'] -or
    $config.route.PSObject.Properties['rule_set'] -or @($config.route.rules).Count -ne 1) {
    throw 'OpenWrt proxy-only output retained a dangling Linux route-exclusion or rule-set reference.'
}
$sourceMutations=@(
    { param($c) $nodeServer=@($c.dns.servers | Where-Object { $_.tag -ceq 'dns-node' })[0];$nodeServer.server_port=15355 },
    { param($c) $nodeServer=@($c.dns.servers | Where-Object { $_.tag -ceq 'dns-node' })[0];$nodeServer | Add-Member -NotePropertyName detour -NotePropertyValue 'dns-proxy-out' -Force },
    { param($c) $c.inbounds[1].listen='0.0.0.0' },
    { param($c) $c.inbounds+= [pscustomobject]@{type='direct';tag='extra-in';listen='127.0.0.1';listen_port=15356} },
    { param($c) $start=Get-ClientDnsBlockRuleCount -Rules @($c.dns.rules); $c.dns.rules[$start].disable_cache=$false },
    { param($c) $start=Get-ClientDnsBlockRuleCount -Rules @($c.dns.rules); $c.dns.rules[$start+1].timeout='3s' },
    { param($c) $c.route.rules[1].inbound=@('other-inbound') },
    { param($c) $c.outbounds | Where-Object { $_.type -ceq 'vless' } | ForEach-Object { $_.domain_resolver.rewrite_ttl=1800 } },
    { param($c) $c.dns.rules+= [pscustomobject]@{inbound=@('dns-in');action='route';server='dns-direct-backup';timeout='3s'} }
)
foreach ($mutation in $sourceMutations) {
    $bad=$source | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    & $mutation $bad
    $rejected=$false
    try { ConvertTo-OpenWrtProxyConfiguration $bad | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid Linux DNS-node source shape accepted by OpenWrt conversion.' }
}
$mutations=@(
    { param($c) $c.inbounds[0].address=@('10.0.0.1/30') },
    { param($c) $c.inbounds[0].stack='gvisor' },
    { param($c) $c.inbounds[0].auto_route=$true },
    { param($c) $c.inbounds[0].auto_redirect=$true },
    { param($c) $c.inbounds[0].strict_route=$true },
    { param($c) $c.inbounds[0].dns_mode='hijack' },
    { param($c) $c.inbounds[1].listen='0.0.0.0' },
    { param($c) $c.inbounds[1].listen_port=15353 },
    { param($c) $c.dns.disable_cache=$false },
    { param($c) $c.dns.reverse_mapping=$true },
    { param($c) $c.dns.servers[0].server_port=15353 },
    { param($c) $c.dns | Add-Member NoteProperty rules @() },
    { param($c) $c.route.final='direct' },
    { param($c) $c.route.rules += [pscustomobject]@{action='route';outbound='direct';port=123} },
    { param($c) $c.route | Add-Member NoteProperty rule_set @() },
    { param($c) $c.outbounds[0].domain_resolver | Add-Member NoteProperty rewrite_ttl 3600 },
    { param($c) $c.outbounds[0].domain_resolver.server='dns-direct' },
    { param($c) $c.route.default_domain_resolver.server='dns-proxy' }
    { param($c) $c.inbounds[0] | Add-Member NoteProperty route_exclude_address_set @('routing-direct-ip') }
)
foreach ($mutation in $mutations) {
    $bad=$config | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    & $mutation $bad
    $rejected=$false
    try { Assert-NativeNumericConfiguration $bad } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid native proxy-only configuration accepted.' }
}
# Preserve each node's payload byte semantics except its explicitly moved DNS client.
$expected=@($source.outbounds | Where-Object { $_.tag -notin @('dns-proxy-out','dns-direct-out') })
for ($i=0;$i -lt $expected.Count;$i++) {
    $original=$expected[$i] | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $actual=$config.outbounds[$i] | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    $original.PSObject.Properties.Remove('domain_resolver');$actual.PSObject.Properties.Remove('domain_resolver')
    if (($original | ConvertTo-Json -Depth 100 -Compress) -cne ($actual | ConvertTo-Json -Depth 100 -Compress)) { throw 'Node credentials/transport or a non-DNS outbound changed.' }
}
if (($config.log | ConvertTo-Json -Depth 10 -Compress) -cne ($source.log | ConvertTo-Json -Depth 10 -Compress)) { throw 'Linux log policy changed.' }
Write-Output ('OpenWrt proxy contract passed: '+$sourceMutations.Count+' invalid source mutations and '+$mutations.Count+' invalid native mutations rejected; node/transport/log semantics preserved; no DNS hijack or numeric core fallback.')
