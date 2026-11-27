$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path (Join-Path $projectRoot 'scripts') 'Json-Validation.ps1')

function Assert-FinalLinuxSnapshot {
    param([Parameter(Mandatory)][string]$SourceRoot, [Parameter(Mandatory)][string]$ArchivePath, [switch]$LayoutOnly)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $configPath = Join-Path $SourceRoot 'sing-box-openwrt.json'
    $config = Read-StrictJsonFile -Path $configPath
    $files = [ordered]@{ 'sing-box-linux-tun.json' = $configPath }
    $tags = @{}
    foreach ($ruleSet in $config.route.rule_set) {
        if ($ruleSet.path -cnotmatch '^rule-set/[A-Za-z0-9_-]+\.srs$' -or $ruleSet.tag -notmatch '^[A-Za-z0-9_-]+$') { throw 'Unsafe Linux SRS identifier.' }
        if ($files.Contains($ruleSet.path) -or $tags.ContainsKey([string]$ruleSet.tag)) { throw 'Duplicate Linux SRS tag/path.' }
        $files[$ruleSet.path] = Join-Path $SourceRoot $ruleSet.path
        $tags[[string]$ruleSet.tag] = $true
    }
    $rootItems = @(Get-ChildItem -LiteralPath $SourceRoot -Force)
    $setItems = @(Get-ChildItem -LiteralPath (Join-Path $SourceRoot 'rule-set') -Force)
    if ($rootItems.Count -ne 2 -or @($rootItems | Where-Object { $_.Name -notin @('sing-box-openwrt.json','rule-set') }).Count -or
        @($setItems | Where-Object { $_.PSIsContainer -or $_.Name -notmatch '^[A-Za-z0-9_-]+\.srs$' }).Count -or
        $setItems.Count -ne $config.route.rule_set.Count -or
        @($rootItems + $setItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Unexpected snapshot files or reparse points.' }
    foreach ($setItem in $setItems) { if (-not $files.Contains('rule-set/'+$setItem.Name)) { throw 'Unreferenced snapshot SRS.' } }
    if ($LayoutOnly) { return }
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($name in $files.Keys) {
            $matches = @($archive.Entries | Where-Object FullName -ceq $name)
            if ($matches.Count -ne 1) { throw ('Missing or duplicate final Linux entry: ' + $name) }
            $stream = $matches[0].Open()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
            if ($hash -ne (Get-FileHash -LiteralPath $files[$name] -Algorithm SHA256).Hash) { throw ('Stale OpenWrt source: ' + $name) }
        }
    }
    finally { $sha.Dispose(); $archive.Dispose() }
}
