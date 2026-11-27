# Only call the writer on the private build stage, while holding the build lock.
. (Join-Path $PSScriptRoot 'Json-Validation.ps1')
function Complete-ArchiveOnlyStage {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string[]]$ConfigurationNames)
    # Resolve and validate the complete deletion set before touching the stage.
    $null = Assert-ClientPlainPathTree -Path $Directory -LeafType Directory -Required -IncludeDescendants
    $resolved = Get-ClientNormalizedFullPath -Path (Resolve-Path -LiteralPath $Directory -ErrorAction Stop).Path
    $null = Assert-ClientPlainPathTree -Path $resolved -LeafType Directory -Required -IncludeDescendants
    if (-not $resolved.EndsWith('.build-stage', [StringComparison]::OrdinalIgnoreCase)) { throw 'Archive cleanup requires a private build stage.' }
    $inputs = Get-ConfigArchiveFiles -Directory $resolved -ConfigurationNames $ConfigurationNames
    $archivePath = Join-Path $resolved 'sing-box-configs.zip'
    $null = Assert-ClientPlainPathTree -Path $archivePath -LeafType File -Required
    $manifest = @{}
    foreach ($name in $inputs.Keys) {
        $inputPath = Assert-ClientPlainPathTree -Path $inputs[$name] -LeafType File -Required
        $manifest[$name] = @{Length=(Get-Item -LiteralPath $inputPath -Force -ErrorAction Stop).Length;Hash=(Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash}
    }
    Assert-ConfigArchive -ArchivePath $archivePath -Manifest $manifest
    $stagedCache = Join-Path $resolved 'build-cache.json'
    $ruleDirectory = Join-Path $resolved 'rule-set'
    $null = Assert-ClientPlainPathTree -Path $stagedCache -LeafType File
    $null = Assert-ClientPlainPathTree -Path $ruleDirectory -LeafType Directory
    $allowedTopLevel = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $ConfigurationNames) { [void]$allowedTopLevel.Add($name) }
    [void]$allowedTopLevel.Add('sing-box-configs.zip')
    if ([IO.File]::Exists($stagedCache)) { [void]$allowedTopLevel.Add('build-cache.json') }
    if ([IO.Directory]::Exists($ruleDirectory)) { [void]$allowedTopLevel.Add('rule-set') }
    foreach ($item in @(Get-ChildItem -LiteralPath $resolved -Force -ErrorAction Stop)) {
        if (-not $allowedTopLevel.Contains($item.Name)) { throw "Unexpected archive-stage object: $($item.FullName)" }
    }
    if ([IO.Directory]::Exists($ruleDirectory)) {
        $expectedSets = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $inputs.Keys) { if ($name.StartsWith('rule-set/', [StringComparison]::OrdinalIgnoreCase)) { [void]$expectedSets.Add($name.Substring(9)) } }
        foreach ($item in @(Get-ChildItem -LiteralPath $ruleDirectory -Force -ErrorAction Stop)) {
            if ($item.PSIsContainer -or -not $expectedSets.Remove($item.Name)) { throw "Unexpected file in staged rule directory: $($item.FullName)" }
        }
        if ($expectedSets.Count -ne 0) { throw 'Archive stage is missing a referenced rule set.' }
    }

    # Revalidate the complete tree and every exact target immediately before deletion.
    $null = Assert-ClientPlainPathTree -Path $resolved -LeafType Directory -Required -IncludeDescendants
    foreach ($path in $inputs.Values) {
        $safePath = Assert-ClientPlainPathTree -Path $path -LeafType File -Required
        Remove-Item -LiteralPath $safePath -Force -ErrorAction Stop
    }
    if ([IO.File]::Exists($stagedCache)) {
        $safeCache = Assert-ClientPlainPathTree -Path $stagedCache -LeafType File -Required
        Remove-Item -LiteralPath $safeCache -Force -ErrorAction Stop
    }
    if ([IO.Directory]::Exists($ruleDirectory)) {
        $null = Assert-ClientPlainPathTree -Path $ruleDirectory -LeafType Directory -Required -IncludeDescendants
        if (@(Get-ChildItem -LiteralPath $ruleDirectory -Force -ErrorAction Stop).Count) { throw 'Unexpected files remain in staged rule directory.' }
        Remove-Item -LiteralPath $ruleDirectory -Force -ErrorAction Stop
    }
    $remaining = @(Get-ChildItem -LiteralPath $resolved -Force)
    if ($remaining.Count -ne 1 -or @($remaining | Where-Object { $_.PSIsContainer -or $_.Name -cne 'sing-box-configs.zip' }).Count) { throw 'Archive-only stage has unexpected files.' }
}

function Get-ConfigArchiveFiles {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string[]]$ConfigurationNames)
    if ($ConfigurationNames.Count -eq 0) { throw 'No configurations selected for ZIP.' }
    $Directory = Assert-ClientPlainPathTree -Path $Directory -LeafType Directory -Required -IncludeDescendants
    $files = @{}
    foreach ($name in $ConfigurationNames) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.json$' -or $name -ieq 'build-cache.json' -or $files.ContainsKey($name)) { throw "Invalid or duplicate ZIP configuration: $name" }
        $path = Join-Path $Directory $name
        $path = Assert-ClientPlainPathTree -Path $path -LeafType File -Required
        $document = Read-StrictJsonFile -Path $path
        $files[$name] = $path
        if ($document.PSObject.Properties['route'] -and $document.route.PSObject.Properties['rule_set']) {
            foreach ($ruleSet in @($document.route.rule_set)) {
                if ($ruleSet.type -ne 'local' -or $ruleSet.format -ne 'binary' -or $ruleSet.path -cnotmatch '^rule-set/[A-Za-z0-9_-]+\.srs$') { throw 'ZIP requires local binary rule-set paths.' }
                $files[[string]$ruleSet.path] = Assert-ClientPlainPathTree -Path (Join-Path $Directory $ruleSet.path) -LeafType File -Required
            }
        }
    }
    foreach ($path in $files.Values) {
        $null = Assert-ClientPlainPathTree -Path $path -LeafType File -Required
    }
    $null = Assert-ClientPlainPathTree -Path $Directory -LeafType Directory -Required -IncludeDescendants
    return $files
}

function Assert-ConfigArchive {
    param([Parameter(Mandatory)][string]$ArchivePath, [Parameter(Mandatory)][hashtable]$Manifest)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $ArchivePath = Assert-ClientPlainPathTree -Path $ArchivePath -LeafType File -Required
    $expectedEntries = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($manifestName in $Manifest.Keys) {
        $exactName = [string]$manifestName
        if ($expectedEntries.ContainsKey($exactName)) { throw "Duplicate manifest entry: $exactName" }
        $expectedEntries.Add($exactName, $Manifest[$manifestName])
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if (-not $expectedEntries.ContainsKey($name) -or -not $seen.Add($name)) { throw "Unexpected or duplicate ZIP entry: $name" }
            if ($entry.Length -ne $expectedEntries[$name].Length) { throw "ZIP length mismatch: $name" }
            $stream = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $actualHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '')
                if ($actualHash -cne $expectedEntries[$name].Hash) { throw "ZIP SHA256 mismatch: $name" }
            }
            finally { $stream.Dispose(); $sha.Dispose() }
        }
        if ($seen.Count -ne $expectedEntries.Count) { throw 'ZIP is missing required files.' }
    }
    finally { $archive.Dispose() }
}

function New-ConfigArchive {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string[]]$ConfigurationNames)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $files = Get-ConfigArchiveFiles -Directory $Directory -ConfigurationNames $ConfigurationNames
    $manifest = @{}
    foreach ($name in $files.Keys) {
        $safePath = Assert-ClientPlainPathTree -Path $files[$name] -LeafType File -Required
        $manifest[$name] = @{Length=(Get-Item -LiteralPath $safePath -Force -ErrorAction Stop).Length; Hash=(Get-FileHash -LiteralPath $safePath -Algorithm SHA256).Hash}
    }
    $Directory = Assert-ClientPlainPathTree -Path $Directory -LeafType Directory -Required -IncludeDescendants
    foreach ($path in $files.Values) { $null = Assert-ClientPlainPathTree -Path $path -LeafType File -Required }
    $archivePath = Join-Path $Directory 'sing-box-configs.zip'
    $null = Assert-ClientPlainPathTree -Path $archivePath -LeafType File
    $stream = [IO.File]::Open($archivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $names = [string[]]@($files.Keys)
            [Array]::Sort($names, [StringComparer]::Ordinal)
            foreach ($name in $names) {
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $files[$name], $name, [IO.Compression.CompressionLevel]::Optimal)
            }
        }
        finally { $archive.Dispose() }
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    $null = Assert-ClientPlainPathTree -Path $archivePath -LeafType File -Required
    Assert-ConfigArchive -ArchivePath $archivePath -Manifest $manifest
    return [pscustomobject]@{Files=$manifest.Count; Bytes=(Get-Item -LiteralPath $archivePath).Length; Sha256=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash}
}
