[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root 'scripts\Update-RoutingRules.ps1') -DefinitionsOnly

$lines = @(
    '# comment',
    '',
    'server=/example.com/114.114.114.114',
    'SERVER=/.Example.COM/1.1.1.1 # retained tail comment',
    'THIS IS NOT A RULE',
    'server=/broken.example/',
    'server=/',
    'server=/another.example/8.8.8.8 extra'
)
$expectedItems = New-Object 'System.Collections.Generic.List[string]'
$expectedIgnored = New-Object 'System.Collections.Generic.List[string]'
for ($index = 0; $index -lt $lines.Count; $index++) {
    $token = $lines[$index].Trim().TrimStart([char]0xFEFF)
    if (-not $token -or $token.StartsWith('#')) { continue }
    if ($token -match '^server=/([^/\s]+)/([^/\s]+)(?:\s+#.*)?$') {
        $expectedItems.Add($Matches[1].TrimStart('.').TrimEnd('.').ToLowerInvariant())
    }
    else {
        $expectedIgnored.Add(($index + 1).ToString() + ':' + $token + ':invalid-dnsmasq-line')
    }
}
$batch = [RoutingRuleBatch]::ParseDnsmasqLines($lines, 5, 'dnsmasq-fixture', 'direct', 'fixture.conf')
$actualItems = @($batch.Items | ForEach-Object { [string]$_.Value })
$actualIgnored = @($batch.Ignored | ForEach-Object { '{0}:{1}:{2}' -f $_.Line,$_.Value,$_.Reason })
if (($actualItems -join "`n") -cne ($expectedItems.ToArray() -join "`n")) {
    throw ('Old/new dnsmasq parser accepted rows differ: expected [' + ($expectedItems -join ',') + '], got [' + ($actualItems -join ',') + ']')
}
if (($actualIgnored -join "`n") -cne ($expectedIgnored.ToArray() -join "`n")) {
    throw 'Old/new dnsmasq parser rejected rows or line provenance differ.'
}
if ('example.com' -notin $actualItems -or @($actualItems | Where-Object { $_ -eq 'example.com' }).Count -ne 2) {
    throw 'Mixed-case dnsmasq directives or suffix normalization regressed.'
}
Write-Output 'RoutingRuleCompiler dnsmasq differential passed: mixed-case directives, suffix normalization, comments, and malformed-line provenance.'
