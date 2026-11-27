# Shared project locks; no core, service or system-network changes.
. (Join-Path $PSScriptRoot 'Json-Validation.ps1')
function Resolve-WindowsArchivePath {
    param([string]$ArchivePath, [Parameter(Mandatory)][string]$ProjectRoot)
    $project = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd([char[]]'\/')
    if ([string]::IsNullOrWhiteSpace($ArchivePath)) { $ArchivePath = Join-Path (Join-Path $project 'generated') 'sing-box-configs.zip' }
    $full = Assert-ClientPlainPathTree -Path $ArchivePath -LeafType File -Required
    if ([IO.Path]::GetExtension($full) -ine '.zip') { throw 'Windows configuration input must be a ZIP archive.' }
    return $full
}

function Get-WindowsArchivePublisherRoot {
    param([Parameter(Mandatory)][string]$ArchivePath, [Parameter(Mandatory)][string]$ProjectRoot)
    $generated = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'generated')).TrimEnd([char[]]'\/')
    $archive = [IO.Path]::GetFullPath($ArchivePath)
    if ($archive.StartsWith($generated + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { return $generated }
    return $null
}

function Enter-ExistingWindowsArchiveLock {
    param($Paths, [int]$TimeoutSeconds = 30)
    if (-not [IO.File]::Exists($Paths.Lock)) { return $null }
    $lockItem = Get-Item -LiteralPath $Paths.Lock -Force -ErrorAction Stop
    if ($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or $lockItem.PSIsContainer) { throw 'Refusing an invalid external archive publisher lock.' }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try { return [IO.File]::Open($Paths.Lock, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.FileNotFoundException] { return $null }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Archive publisher lock timeout: $($Paths.Lock)" }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Enter-WindowsDeploymentLocks {
    param([string]$RuntimeDirectory, [string]$ArchivePath, [string]$ProjectRoot, [int]$TimeoutSeconds = 30)

    # Validate both writable trees before creating .runtime or opening either lock.
    $RuntimeDirectory = Assert-ClientPlainPathTree -Path $RuntimeDirectory -LeafType Directory
    $archiveFull = Assert-ClientPlainPathTree -Path $ArchivePath -LeafType File
    $state = Join-Path $RuntimeDirectory '.runtime'
    $controlPath = Join-Path $state 'control.lock'
    $null = Assert-ClientPlainPathTree -Path $state -LeafType Directory
    $null = Assert-ClientPlainPathTree -Path $controlPath -LeafType File
    [IO.Directory]::CreateDirectory($state) | Out-Null
    $null = Assert-ClientPlainPathTree -Path $RuntimeDirectory -LeafType Directory -Required
    $null = Assert-ClientPlainPathTree -Path $state -LeafType Directory -Required
    $null = Assert-ClientPlainPathTree -Path $controlPath -LeafType File
    $control = $null; $build = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        while ($null -eq $control) {
            try { $control = [IO.File]::Open($controlPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
            catch [IO.IOException] {
                if ([DateTime]::UtcNow -ge $deadline) { throw 'Windows start/stop/deployment lock timeout.' }
                Start-Sleep -Milliseconds 200
            }
        }
        if ($ProjectRoot) {
            $publisherRoot = Get-WindowsArchivePublisherRoot -ArchivePath $archiveFull -ProjectRoot $ProjectRoot
            if ($publisherRoot) {
                $paths = Get-BuildPaths $publisherRoot
                $build = Enter-BuildLock $paths -TimeoutSeconds $TimeoutSeconds
            } else {
                $paths = Get-BuildPaths (Split-Path -Parent $archiveFull)
                $build = Enter-ExistingWindowsArchiveLock $paths -TimeoutSeconds $TimeoutSeconds
            }
        } else {
            # Existing test and maintenance callers retain the historical publisher-lock behavior.
            $paths = Get-BuildPaths (Split-Path -Parent $archiveFull)
            $build = Enter-BuildLock $paths -TimeoutSeconds $TimeoutSeconds
        }
        foreach ($pending in @($paths.Journal, $paths.Backup, "$($paths.Journal).write")) {
            if (Test-Path -LiteralPath $pending) { throw 'Main archive has pending recovery; resume its own publisher before deployment.' }
        }
        return [pscustomobject]@{ Control = $control; Build = $build; PublisherPaths = $paths }
    }
    catch {
        if ($null -ne $build) { $build.Dispose() }
        if ($null -ne $control) { $control.Dispose() }
        throw
    }
}

function Exit-WindowsDeploymentLocks {
    param($Locks)
    if ($null -ne $Locks) {
        try { if ($null -ne $Locks.Build) { $Locks.Build.Dispose() } } finally { $Locks.Control.Dispose() }
    }
}

function Get-DeploymentEntryHash {
    param($Entry)
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = $null
    try { $stream = $Entry.Open() } catch { $sha.Dispose(); throw }
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Get-WindowsArchiveIndex {
    param([Parameter(Mandatory)][IO.Compression.ZipArchive]$Archive)
    $entries = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $manifest = @{}
    $configDocuments = @{}
    $referencedSets = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $windowsName = 'sing-box-windows-tun.json'
    $srsCount = 0
    foreach ($entry in $Archive.Entries) {
        $name = [string]$entry.FullName
        if ([string]::IsNullOrEmpty($name) -or $name.EndsWith('/') -or $name.IndexOf([char]92) -ge 0 -or $name.StartsWith('/') -or $name -match '(^|/)\.\.?(/|$)' -or $name.Contains(':')) { throw "Unsafe Windows archive entry: $name" }
        if ($name -match '^[A-Za-z0-9][A-Za-z0-9._-]*\.json$') {
            # Configuration JSON is a root-level file.
        } elseif ($name -match '^rule-set/[A-Za-z0-9_-]+\.srs$') {
            $srsCount++
        } else { throw "Unexpected Windows archive entry: $name" }
        if ($entries.ContainsKey($name)) { throw "Duplicate Windows archive entry: $name" }
        $hash = Get-DeploymentEntryHash $entry
        $entries.Add($name, $entry)
        $manifest[$name] = @{ Length=[long]$entry.Length; Hash=$hash }
        if ($name -match '\.json$') {
            $stream = $entry.Open()
            try {
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
                try { $document = ConvertFrom-StrictJson -Text $reader.ReadToEnd() }
                finally { $reader.Dispose() }
            } finally { $stream.Dispose() }
            $configDocuments[$name] = $document
            if ($document.PSObject.Properties['route'] -and $document.route -and $document.route.PSObject.Properties['rule_set']) {
                foreach ($set in @($document.route.rule_set)) {
                    if (-not $set.PSObject.Properties['path'] -or -not $set.PSObject.Properties['type'] -or -not $set.PSObject.Properties['format'] -or
                        $set.type -ne 'local' -or $set.format -ne 'binary' -or [string]$set.path -notmatch '^rule-set/[A-Za-z0-9_-]+\.srs$') { throw "Invalid rule-set reference in archive config: $name" }
                    if (-not $referencedSets.Add([string]$set.path)) { continue }
                }
            }
        }
    }
    if (-not $entries.ContainsKey($windowsName) -or $srsCount -eq 0) { throw 'Archive must contain the Windows config and its binary rule sets.' }
    foreach ($setPath in $referencedSets) { if (-not $entries.ContainsKey($setPath)) { throw "Archive is missing referenced rule set: $setPath" } }
    foreach ($name in $entries.Keys) {
        if ($name -match '^rule-set/') { if (-not $referencedSets.Contains($name)) { throw "Archive contains an unreferenced rule set: $name" } }
    }
    return [pscustomobject]@{ Entries=$entries; Manifest=$manifest; ConfigDocuments=$configDocuments; WindowsConfig=$configDocuments[$windowsName]; WindowsConfigName=$windowsName }
}

function Import-WindowsArchiveToStage {
    param([Parameter(Mandatory)][string]$ArchivePath, [Parameter(Mandatory)][string]$StageDirectory)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archiveFull = Assert-ClientPlainPathTree -Path $ArchivePath -LeafType File -Required
    $stage = Assert-ClientPlainPathTree -Path $StageDirectory -LeafType Directory -Required -IncludeDescendants
    $ruleDirectory = Join-Path $stage 'rule-set'
    $null = Assert-ClientPlainPathTree -Path $ruleDirectory -LeafType Directory -Required -IncludeDescendants
    $existing = @(Get-ChildItem -LiteralPath $stage -Force)
    if ($existing.Count -ne 1 -or -not $existing[0].PSIsContainer -or $existing[0].Name -cne 'rule-set' -or @(Get-ChildItem -LiteralPath $ruleDirectory -Force).Count) { throw 'Windows archive stage must be empty except for its rule-set directory.' }

    $file = [IO.File]::Open($archiveFull, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    $archiveHash = $null
    $zip = $null
    try {
        $archiveHash = [BitConverter]::ToString($sha.ComputeHash($file)).Replace('-', '')
        $file.Position = 0
        $zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Read, $true)
        $index = Get-WindowsArchiveIndex -Archive $zip
        . (Join-Path $PSScriptRoot 'Direct-RoutingPolicy.ps1')
        Assert-EffectiveDirectConfiguration $index.WindowsConfig

        $expectedHashes = @{}
        $configEntry = $index.Entries[$index.WindowsConfigName]
        $configPath = Join-Path $stage $index.WindowsConfigName
        $null = Assert-ClientPlainPathTree -Path $stage -LeafType Directory -Required -IncludeDescendants
        $null = Assert-ClientPlainPathTree -Path $configPath -LeafType File
        [IO.Compression.ZipFileExtensions]::ExtractToFile($configEntry, $configPath)
        $expectedHashes[$index.WindowsConfigName] = [string]$index.Manifest[$index.WindowsConfigName].Hash
        if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ine $expectedHashes[$index.WindowsConfigName]) { throw 'Windows config extraction differs from selected archive bytes.' }
        foreach ($set in $index.WindowsConfig.route.rule_set) {
            $relative = [string]$set.path
            $entry = $index.Entries[$relative]
            $target = Join-Path $stage ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
            $null = Assert-ClientPlainPathTree -Path $stage -LeafType Directory -Required -IncludeDescendants
            $null = Assert-ClientPlainPathTree -Path $target -LeafType File
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target)
            $expectedHashes[$relative] = [string]$index.Manifest[$relative].Hash
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $expectedHashes[$relative]) { throw "Rule set extraction differs from selected archive bytes: $relative" }
        }
        $zip.Dispose(); $zip = $null
        $file.Position = 0
        $afterHash = [BitConverter]::ToString($sha.ComputeHash($file)).Replace('-', '')
        if ($afterHash -ine $archiveHash) { throw 'Selected archive changed while staging.' }
        return [pscustomobject]@{ ArchivePath=$archiveFull; ArchiveSha256=$archiveHash; ConfigPath=$configPath; ConfigName=$index.WindowsConfigName; ExpectedHashes=$expectedHashes; RuleSetCount=($expectedHashes.Count - 1) }
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        $sha.Dispose()
        $file.Dispose()
    }
}

# Runtime deployment has its own durable journal, independent of ZIP publishing.
# The caller holds both locks and has verified that the actual core is stopped.
function Assert-DeploymentPlainPath {
    param([string]$Path, [switch]$Directory, [switch]$Required)
    $kind = if ($Directory.IsPresent) { 'Directory' } else { 'File' }
    $arguments = @{ Path=$Path; LeafType=$kind }
    if ($Required) { $arguments['Required'] = $true }
    if ($Directory.IsPresent) { $arguments['IncludeDescendants'] = $true }
    $null = Assert-ClientPlainPathTree @arguments
}

function Get-WindowsDeploymentPaths {
    param([string]$RuntimeDirectory)
    $runtime=[IO.Path]::GetFullPath($RuntimeDirectory).TrimEnd('\')
    return [pscustomobject]@{ Runtime=$runtime; Journal=(Join-Path $runtime '.runtime\deployment-journal.json'); Config=(Join-Path $runtime 'sing-box-windows-tun.json'); Sets=(Join-Path $runtime 'rule-set'); ConfigWrite=(Join-Path $runtime '.runtime\deployment-config.write') }
}

function ConvertTo-DeploymentJournalBytes {
    param($Journal)
    $text=$Journal | ConvertTo-Json -Depth 12
    $lines=$text.Replace("`r`n","`n").Split([char]10)
    $unit=0
    foreach ($line in $lines) { if ($line -match '^( +)\S' -and $unit -eq 0) { $unit=$Matches[1].Length } }
    if ($unit -gt 0) {
        $lines=@(foreach ($line in $lines) { $spaces=$line.Length-$line.TrimStart(' ').Length; (' '.PadLeft([int]($spaces/$unit)*2))+$line.TrimStart(' ') })
    }
    return ,((New-Object Text.UTF8Encoding($false)).GetBytes(($lines -join "`n").TrimEnd([char]10)+"`n"))
}

function Test-DeploymentBytePrefix {
    param([byte[]]$Partial, [byte[]]$Complete)
    if ($Partial.Length -gt $Complete.Length) { return $false }
    for ($index=0; $index -lt $Partial.Length; $index++) {
        if ($Partial[$index] -ne $Complete[$index]) { return $false }
    }
    return $true
}

function Write-DeploymentJournal {
    param($Paths, $Journal)
    Assert-DeploymentPlainPath (Join-Path $Paths.Runtime '.runtime') -Directory -Required
    Assert-DeploymentPlainPath $Paths.Journal
    Assert-DeploymentPlainPath ($Paths.Journal+'.write')
    $bytes=ConvertTo-DeploymentJournalBytes $Journal
    $temporary=$Paths.Journal+'.write'
    if (-not [IO.File]::Exists($Paths.Journal)) {
        # Before intent publication no live files have changed. Keep a torn
        # preparation in this transaction's snapshot, not in startup state.
        Assert-DeploymentPlainPath ([string]$Journal.backup) -Directory -Required
        $temporary=Join-Path ([string]$Journal.backup) 'deployment-journal.prepare'
        Assert-DeploymentPlainPath $temporary
    }
    $stream=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if ([IO.File]::Exists($Paths.Journal)) { [IO.File]::Replace($temporary,$Paths.Journal,[System.Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($temporary,$Paths.Journal) }
}

function Get-DeploymentRuleHashes {
    param([string]$Directory)
    Assert-DeploymentPlainPath $Directory -Directory -Required
    $hashes=@{}
    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -Force)) {
        Assert-DeploymentPlainPath $file.FullName -Required
        if ($file.Name -notmatch '^[A-Za-z0-9_-]+\.srs$') { throw 'Unexpected deployment rule object; preserve for review.' }
        $hashes[$file.Name]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    if ($hashes.Count -eq 0) { throw 'Empty deployment rule snapshot.' }
    return $hashes
}

function Convert-DeploymentHashMap {
    param($Value)
    $map=@{}
    if ($Value -is [Collections.IDictionary]) { foreach ($name in $Value.Keys) { $map[$name]=$Value[$name] } }
    else { foreach ($property in $Value.PSObject.Properties) { $map[$property.Name]=$property.Value } }
    if ($map.Count -eq 0) { throw 'Empty deployment hash map.' }
    foreach ($name in $map.Keys) {
        if ($name -notmatch '^[A-Za-z0-9_-]+\.srs$' -or $map[$name] -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid deployment rule snapshot.' }
    }
    return $map
}

function Test-DeploymentRuleHashes {
    param([string]$Directory, $Expected)
    if (-not (Test-Path -LiteralPath $Directory)) { return $false }
    $actual=Get-DeploymentRuleHashes $Directory
    $expectedMap=Convert-DeploymentHashMap $Expected
    if ($actual.Count -ne $expectedMap.Count) { return $false }
    foreach ($name in $expectedMap.Keys) { if (-not $actual.ContainsKey($name) -or $actual[$name] -ine $expectedMap[$name]) { return $false } }
    return $true
}

function Set-DeploymentConfigAtomically {
    param($Paths, [string]$Source)
    Assert-DeploymentPlainPath $Source -Required
    Assert-DeploymentPlainPath $Paths.Config -Required
    Assert-DeploymentPlainPath $Paths.ConfigWrite
    $bytes=[IO.File]::ReadAllBytes($Source)
    $stream=New-Object IO.FileStream($Paths.ConfigWrite,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Replace($Paths.ConfigWrite,$Paths.Config,[System.Management.Automation.Language.NullString]::Value)
}

function Restore-WindowsDeploymentTransaction {
    param($Paths, [string[]]$RecoveryRoot)
    Assert-DeploymentPlainPath (Join-Path $Paths.Runtime '.runtime') -Directory -Required
    Assert-DeploymentPlainPath $Paths.Journal
    if (-not [IO.File]::Exists($Paths.Journal)) {
        foreach ($pending in @(($Paths.Journal+'.write'),$Paths.ConfigWrite)) {
            if (Test-Path -LiteralPath $pending) { throw 'Incomplete journal preparation; preserve for manual review.' }
        }
        return
    }
    $journal=Read-StrictJsonFile -Path $Paths.Journal
    $recoveryRoots = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($candidateRoot in @($RecoveryRoot)) {
        if ([string]::IsNullOrWhiteSpace([string]$candidateRoot)) { continue }
        $normalizedRoot = [IO.Path]::GetFullPath([string]$candidateRoot).TrimEnd([char[]]'\/')
        [void]$recoveryRoots.Add($normalizedRoot)
    }
    $backup=[IO.Path]::GetFullPath([string]$journal.backup).TrimEnd('\')
    if ($journal.version -ne 1 -or $journal.runtime -cne $Paths.Runtime -or $journal.phase -notin @('prepared','committed') -or
        -not $recoveryRoots.Contains((Split-Path -Parent $backup)) -or (Split-Path -Leaf $backup) -notmatch '^windows-before-current-[a-f0-9]{32}$' -or
        $journal.old_config -notmatch '^[0-9a-fA-F]{64}$' -or $journal.new_config -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid runtime deployment journal; retain for review.' }
    Assert-DeploymentPlainPath (Split-Path -Parent $backup) -Directory -Required
    Assert-DeploymentPlainPath $backup -Directory -Required
    Assert-DeploymentPlainPath $Paths.Sets -Directory
    Assert-DeploymentPlainPath $Paths.Config -Required
    Assert-DeploymentPlainPath ($Paths.Journal+'.write')
    Assert-DeploymentPlainPath $Paths.ConfigWrite
    $old=Convert-DeploymentHashMap $journal.old_rules
    $new=Convert-DeploymentHashMap $journal.new_rules
    $oldConfig=Join-Path $backup 'sing-box-windows-tun.json'
    $oldSets=Join-Path $backup 'rule-set'
    Assert-DeploymentPlainPath $oldConfig -Required
    Assert-DeploymentPlainPath $oldSets -Directory
    if ((Get-FileHash -LiteralPath $oldConfig).Hash -ine $journal.old_config) { throw 'Recovery configuration changed; preserve transaction.' }
    $liveHash=(Get-FileHash -LiteralPath $Paths.Config).Hash
    $residues=@()
    if ([IO.File]::Exists($Paths.ConfigWrite)) {
        $pendingHash=(Get-FileHash -LiteralPath $Paths.ConfigWrite).Hash
        if ($pendingHash -ine $journal.old_config -and $pendingHash -ine $journal.new_config) {
            $partial=[IO.File]::ReadAllBytes($Paths.ConfigWrite)
            $recognized=Test-DeploymentBytePrefix $partial ([IO.File]::ReadAllBytes($oldConfig))
            $stagedConfig=Join-Path $backup 'staged\sing-box-windows-tun.json'
            Assert-DeploymentPlainPath (Join-Path $backup 'staged') -Directory
            Assert-DeploymentPlainPath $stagedConfig
            if ([IO.File]::Exists($stagedConfig) -and (Get-FileHash -LiteralPath $stagedConfig).Hash -ieq $journal.new_config) {
                $recognized=$recognized -or (Test-DeploymentBytePrefix $partial ([IO.File]::ReadAllBytes($stagedConfig)))
            }
            if (-not $recognized) { throw 'Temporary deployment configuration changed; preserve for review.' }
        }
        $residues += $Paths.ConfigWrite
    }
    if ([IO.File]::Exists($Paths.Journal+'.write')) {
        $partial=[IO.File]::ReadAllBytes($Paths.Journal+'.write')
        $candidate=[ordered]@{}
        foreach ($property in $journal.PSObject.Properties) { $candidate[$property.Name]=$property.Value }
        $candidate.phase='prepared'
        $recognized=Test-DeploymentBytePrefix $partial (ConvertTo-DeploymentJournalBytes $candidate)
        $candidate.phase='committed'
        $recognized=$recognized -or (Test-DeploymentBytePrefix $partial (ConvertTo-DeploymentJournalBytes $candidate))
        # PS5.1 and PS7 differ in colon spacing. Also derive candidates from
        # the durable original bytes, changing only its top-level phase line.
        $original=[IO.File]::ReadAllText($Paths.Journal,(New-Object Text.UTF8Encoding($false)))
        $phasePattern='(?m)^(\s*"phase"\s*:\s*")(prepared|committed)("\s*,?\s*)$'
        if ([regex]::Matches($original,$phasePattern).Count -eq 1) {
            foreach ($phase in @('prepared','committed')) {
                $expected=[regex]::Replace($original,$phasePattern,('${1}'+$phase+'${3}'))
                $recognized=$recognized -or (Test-DeploymentBytePrefix $partial ((New-Object Text.UTF8Encoding($false)).GetBytes($expected)))
            }
        }
        if (-not $recognized) { throw 'Temporary deployment journal changed; preserve for review.' }
        $residues += ($Paths.Journal+'.write')
    }
    # Validate every live/saved object before preserving an interrupted write.
    if ([IO.Directory]::Exists($oldSets) -and -not (Test-DeploymentRuleHashes $oldSets $old)) { throw 'Recovery rules changed; preserve transaction.' }
    if ($journal.phase -eq 'committed') {
        if ($liveHash -ine $journal.new_config -or -not (Test-DeploymentRuleHashes $Paths.Sets $new)) { throw 'Committed deployment changed; do not overwrite user files.' }
    } else {
        if ($liveHash -ine $journal.old_config -and $liveHash -ine $journal.new_config) { throw 'Runtime configuration changed externally; preserve transaction.' }
        if ([IO.Directory]::Exists($Paths.Sets)) {
            if (-not (Test-DeploymentRuleHashes $Paths.Sets $old) -and -not (Test-DeploymentRuleHashes $Paths.Sets $new)) { throw 'Runtime rules changed externally; preserve transaction.' }
        }
        if (-not [IO.Directory]::Exists($oldSets) -and -not (Test-DeploymentRuleHashes $Paths.Sets $old)) { throw 'Original runtime rules and valid recovery snapshot are missing.' }
        if ([IO.Directory]::Exists($oldSets) -and [IO.Directory]::Exists($Paths.Sets) -and -not (Test-DeploymentRuleHashes $Paths.Sets $old) -and (Test-Path -LiteralPath (Join-Path $backup 'failed-rule-set'))) { throw 'Unexpected failed rule snapshot; preserve transaction.' }
    }
    foreach ($residue in $residues) {
        $kind='journal'
        if ($residue -eq $Paths.ConfigWrite) { $kind='config' }
        $saved=Join-Path $backup ($kind+'.interrupted-'+[guid]::NewGuid().ToString('N'))
        Assert-DeploymentPlainPath $saved
        try { [IO.File]::Move($residue,$saved) }
        catch { throw ('Cannot preserve interrupted file '+$residue+' at '+$saved+': '+$_.Exception.Message) }
    }
    if ($journal.phase -eq 'committed') {
        if ($liveHash -ine $journal.new_config -or -not (Test-DeploymentRuleHashes $Paths.Sets $new)) { throw 'Committed deployment changed; do not overwrite user files.' }
    } else {
        if ($liveHash -ine $journal.old_config -and $liveHash -ine $journal.new_config) { throw 'Runtime configuration changed externally; preserve transaction.' }
        if ([IO.Directory]::Exists($oldSets)) {
            if (-not (Test-DeploymentRuleHashes $oldSets $old)) { throw 'Recovery rules changed; preserve transaction.' }
            if ([IO.Directory]::Exists($Paths.Sets)) {
                if (Test-DeploymentRuleHashes $Paths.Sets $old) {
                    # Recovery may have completed before the journal was removed.
                } elseif (Test-DeploymentRuleHashes $Paths.Sets $new) {
                    $failed=Join-Path $backup 'failed-rule-set'
                    if (Test-Path -LiteralPath $failed) { throw 'Unexpected failed rule snapshot; preserve transaction.' }
                    [IO.Directory]::Move($Paths.Sets,$failed)
                    [IO.Directory]::Move($oldSets,$Paths.Sets)
                } else { throw 'Runtime rules changed externally; preserve transaction.' }
            } else { [IO.Directory]::Move($oldSets,$Paths.Sets) }
        } elseif (-not (Test-DeploymentRuleHashes $Paths.Sets $old)) { throw 'Original runtime rules and valid recovery snapshot are missing.' }
        if ($liveHash -ine $journal.old_config) { Set-DeploymentConfigAtomically $Paths $oldConfig }
        if ((Get-FileHash -LiteralPath $Paths.Config).Hash -ine $journal.old_config -or -not (Test-DeploymentRuleHashes $Paths.Sets $old)) { throw 'Runtime transaction restoration failed.' }
    }
    foreach ($pending in @(($Paths.Journal+'.write'),$Paths.ConfigWrite,$Paths.Journal)) {
        Assert-DeploymentPlainPath $pending
        if ([IO.File]::Exists($pending)) { [IO.File]::Delete($pending) }
    }
}
