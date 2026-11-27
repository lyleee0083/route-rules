[CmdletBinding()]
param([switch]$Published)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'DNS-BootstrapPolicy.ps1')
$template = Get-Content -LiteralPath (Join-Path (Join-Path $projectRoot 'config') 'sing-box-core-base.json') -Encoding UTF8 -Raw | ConvertFrom-Json
Assert-DnsBootstrapConfiguration $template
$directPrimary = @($template.dns.servers | Where-Object tag -eq 'dns-direct')[0]
$directBackup = @($template.dns.servers | Where-Object tag -eq 'dns-direct-backup')[0]
$proxyPrimary = @($template.dns.servers | Where-Object tag -eq 'dns-proxy')[0]
$proxyBackup = @($template.dns.servers | Where-Object tag -eq 'dns-proxy-backup')[0]
$hostsServer = @($template.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]
$mutations = @(
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct')[0]).domain_resolver.server = 'dns-direct' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct-backup')[0]).domain_resolver.server = 'dns-proxy' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct')[0]).detour = 'dns-proxy-out' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-proxy')[0]).detour = 'dns-direct-out' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).type = 'udp' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).predefined.'doh.pub' = @('119.29.29.29') },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).predefined.'dns.google' = @('120.53.53.53') },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).predefined.'dns.google' = @('8.8.8.8','8.8.4.4') },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).predefined | Add-Member NoteProperty 'node.example.invalid' @('198.181.34.87') },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]) | Add-Member NoteProperty detour 'dns-proxy-out' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct-backup')[0]).path = '/resolve' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct')[0]).tls.server_name = 'invalid-do-h.example' },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct')[0]).tls | Add-Member NoteProperty insecure $true },
    { param($c) $c.outbounds[0].domain_resolver.server = 'dns-doh-hosts' },
    { param($c) $c.outbounds[0].domain_resolver.disable_cache = $true },
    { param($c) $c.outbounds[0].domain_resolver.PSObject.Properties.Remove('disable_cache') },
    { param($c) $c.outbounds[0].domain_resolver.disable_cache = 'false' },
    { param($c) $c.outbounds[0].domain_resolver.rewrite_ttl = 300 },
    { param($c) $c.outbounds[0].domain_resolver.rewrite_ttl = '3600' },
    { param($c) $c.outbounds[0].domain_resolver.rewrite_ttl = 3600.0 },
    { param($c) $c.outbounds[0].domain_resolver.PSObject.Properties.Remove('rewrite_ttl') },
    { param($c) $c.outbounds[0].domain_resolver.disable_optimistic_cache = $false },
    { param($c) $c.outbounds[0].domain_resolver.disable_optimistic_cache = 'true' },
    { param($c) $c.outbounds[0].domain_resolver.PSObject.Properties.Remove('disable_optimistic_cache') },
    { param($c) $c.dns | Add-Member NoteProperty disable_cache $true },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-direct')[0]).domain_resolver | Add-Member NoteProperty disable_cache $true },
    { param($c) $c.dns | Add-Member NoteProperty rules @([pscustomobject]@{server='dns-direct';disable_cache=$true}) -Force },
    { param($c) $c.dns.final = 'dns-doh-hosts' },
    { param($c) $c.dns | Add-Member NoteProperty rules @([pscustomobject]@{server='dns-doh-hosts'}) -Force },
    { param($c) $c.dns.servers = @($c.dns.servers | Select-Object -First 4) },
    { param($c) (@($c.dns.servers | Where-Object tag -eq 'dns-doh-hosts')[0]).tag = 'dns-direct' }
)
$mutationIndex = 0
foreach ($mutation in $mutations) {
    $mutationIndex++
    $fixture = $template | ConvertTo-Json -Depth 100 -Compress | ConvertFrom-Json
    & $mutation $fixture
    $rejected = $false
    try { Assert-DnsBootstrapConfiguration $fixture } catch { $rejected = $true }
    if (-not $rejected) { throw ('Invalid DNS mutation #{0} was accepted: {1}' -f $mutationIndex,$mutation.ToString()) }
}
Write-Output ('DNS bootstrap policy: template passed; ' + $mutations.Count + ' cycle/exit/TLS/bootstrap-leak mutations rejected.')
if ($Published) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $count = 0
    foreach ($relativePath in @('generated/sing-box-configs.zip')) {
        $zip = [IO.Compression.ZipFile]::OpenRead((Join-Path $projectRoot $relativePath))
        try {
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -notmatch '(^sing-box.*\.json$|^config\.json$)') { continue }
                $reader = New-Object IO.StreamReader($entry.Open())
                try { $config = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
                Assert-DnsBootstrapConfiguration $config
                $count++
            }
        } finally { $zip.Dispose() }
    }
    if ($count -ne 5) { throw 'Expected five main platform profiles; split OpenWrt DNS has its own tests.' }
    Write-Output 'DNS bootstrap policy: all five main published configurations passed; OpenWrt is validated by Test-OpenWrtPackage.ps1.'
}
