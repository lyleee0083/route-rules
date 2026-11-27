# Directory publication helpers. The caller must hold Lock until recovery/cleanup ends.
. (Join-Path $PSScriptRoot 'Json-Validation.ps1')
function Assert-BuildOutputNotNested {
    param([Parameter(Mandatory)][string]$OutputDirectory, [Parameter(Mandatory)][string]$FormalOutputDirectory)
    $output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd([char[]]'\/')
    $formal = [IO.Path]::GetFullPath($FormalOutputDirectory).TrimEnd([char[]]'\/')
    if ($output.StartsWith($formal + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Build output cannot be nested inside the formal output tree.'
    }
    return $output
}
function Get-BuildPaths {
    param([string]$Destination)
    $path = [IO.Path]::GetFullPath($Destination).TrimEnd([char[]]'\/')
    if (-not (Split-Path -Parent $path)) { throw 'Refusing a filesystem root as build output.' }
    return [pscustomobject]@{Destination=$path; Stage="$path.build-stage"; Backup="$path.build-backup"; Journal="$path.build-journal.json"; Lock="$path.build.lock"}
}

function Test-BuildReleaseDirectoryName {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -notmatch '^(?<date>\d{4}-\d{2}-\d{2})(?:-[A-Za-z0-9][A-Za-z0-9_-]*)?$') { return $false }
    $parsed = [DateTime]::MinValue
    return [DateTime]::TryParseExact($Matches.date, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)
}

function Get-BuildFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Get-BuildPreservationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Destination,
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$')][string]$PackageName = 'sing-box-configs.zip'
    )
    $root = Get-ClientNormalizedFullPath -Path $Destination
    if (-not (Split-Path -Parent $root)) { throw 'Refusing a filesystem root as a release output.' }
    $null = Assert-ClientPlainPathTree -Path $root -LeafType Directory -IncludeDescendants
    $rootExisted = [IO.Directory]::Exists($root)

    $directories = [Collections.Generic.List[string]]::new()
    $entries = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $packageExisted = $false
    if ($rootExisted) {
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing release output through a reparse point: $root" }
        foreach ($childPath in [IO.Directory]::GetFileSystemEntries($root)) {
            $child = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing release output reparse point: $($child.FullName)" }
            if ($child.PSIsContainer) {
                if (-not (Test-BuildReleaseDirectoryName -Name $child.Name)) { throw "Unexpected release output directory: $($child.Name)" }
                if (-not $seen.Add($child.Name)) { throw "Duplicate release output path: $($child.Name)" }
                $directories.Add($child.Name)
                $entries.Add([pscustomobject][ordered]@{ RelativePath=$child.Name; Kind='directory'; Length=[long]0; Sha256=$null })
                $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
                $pending.Push([IO.DirectoryInfo]$child)
                while ($pending.Count -gt 0) {
                    $current = $pending.Pop()
                    foreach ($nestedPath in $current.GetFileSystemInfos()) {
                        if ($nestedPath.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing release output reparse point: $($nestedPath.FullName)" }
                        $relative = $nestedPath.FullName.Substring($root.Length).TrimStart([char[]]'\/').Replace('\','/')
                        if (-not $seen.Add($relative)) { throw "Duplicate release output path: $relative" }
                        if ($nestedPath -is [IO.DirectoryInfo]) {
                            $entries.Add([pscustomobject][ordered]@{ RelativePath=$relative; Kind='directory'; Length=[long]0; Sha256=$null })
                            $pending.Push([IO.DirectoryInfo]$nestedPath)
                        }
                        elseif ($nestedPath -is [IO.FileInfo]) {
                            $lengthBefore = ([IO.FileInfo]$nestedPath).Length
                            $hash = Get-BuildFileSha256 -Path $nestedPath.FullName
                            $lengthAfter = (Get-Item -LiteralPath $nestedPath.FullName -Force -ErrorAction Stop).Length
                            if ($lengthBefore -ne $lengthAfter) { throw "Release file changed while snapshotting: $($nestedPath.FullName)" }
                            $entries.Add([pscustomobject][ordered]@{ RelativePath=$relative; Kind='file'; Length=[long]$lengthAfter; Sha256=$hash })
                        }
                        else { throw "Unsupported release output object: $($nestedPath.FullName)" }
                    }
                }
            }
            elseif ($child -is [IO.FileInfo] -and $child.Name -ceq $PackageName) {
                if ($packageExisted) { throw "Duplicate release package: $PackageName" }
                $packageExisted = $true
            }
            else { throw "Unexpected release output file: $($child.Name)" }
        }
    }

    $directoryArray = [string[]]$directories.ToArray()
    [Array]::Sort($directoryArray, [StringComparer]::Ordinal)
    $entryMap = @{}
    $entryPaths = [Collections.Generic.List[string]]::new()
    foreach ($entry in $entries) { $entryMap[$entry.RelativePath] = $entry; $entryPaths.Add([string]$entry.RelativePath) }
    $entryPathArray = [string[]]$entryPaths.ToArray()
    [Array]::Sort($entryPathArray, [StringComparer]::Ordinal)
    $sortedEntries = [Collections.Generic.List[object]]::new()
    foreach ($entryPath in $entryPathArray) { $sortedEntries.Add($entryMap[$entryPath]) }
    return [pscustomobject][ordered]@{
        Version = 1
        Root = $root
        PackageName = $PackageName
        RootExisted = [bool]$rootExisted
        PackageExisted = [bool]$packageExisted
        PreservedDirectories = $directoryArray
        Entries = [object[]]$sortedEntries.ToArray()
    }
}

function Assert-BuildPreservationSnapshotShape {
    param([Parameter(Mandatory)]$Snapshot)
    foreach ($name in @('Version','Root','PackageName','RootExisted','PackageExisted','PreservedDirectories','Entries')) {
        if (-not $Snapshot.PSObject.Properties[$name]) { throw "Invalid release preservation snapshot; missing $name." }
    }
    if (($Snapshot.Version -isnot [int] -and $Snapshot.Version -isnot [long]) -or $Snapshot.Version -ne 1 -or
        $Snapshot.Root -isnot [string] -or -not [IO.Path]::IsPathRooted($Snapshot.Root) -or
        $Snapshot.PackageName -isnot [string] -or $Snapshot.PackageName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$' -or
        $Snapshot.RootExisted -isnot [bool] -or $Snapshot.PackageExisted -isnot [bool] -or
        $Snapshot.PreservedDirectories -isnot [array] -or $Snapshot.Entries -isnot [array]) {
        throw 'Invalid release preservation snapshot envelope.'
    }
    $normalizedRoot = [IO.Path]::GetFullPath([string]$Snapshot.Root).TrimEnd([char[]]'\/')
    if ($normalizedRoot -cne [string]$Snapshot.Root -or -not (Split-Path -Parent $normalizedRoot)) { throw 'Invalid release preservation snapshot root.' }
    if ((-not $Snapshot.RootExisted) -and ($Snapshot.PackageExisted -or $Snapshot.PreservedDirectories.Count -or $Snapshot.Entries.Count)) { throw 'Nonexistent release root has preserved content.' }
    if ($Snapshot.PackageExisted -and -not $Snapshot.RootExisted) { throw 'Nonexistent release root has a package.' }

    $directorySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in $Snapshot.PreservedDirectories) {
        if ($directory -isnot [string] -or -not (Test-BuildReleaseDirectoryName -Name $directory) -or -not $directorySet.Add($directory)) { throw 'Invalid preserved release directory name.' }
    }
    $entryMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Snapshot.Entries) {
        foreach ($name in @('RelativePath','Kind','Length','Sha256')) { if (-not $entry.PSObject.Properties[$name]) { throw "Invalid release entry; missing $name." } }
        $relative = [string]$entry.RelativePath
        if ($entry.RelativePath -isnot [string] -or [string]::IsNullOrEmpty($relative) -or $relative.Contains('\') -or $relative.StartsWith('/') -or $relative.EndsWith('/')) { throw 'Invalid release entry path.' }
        $parts = $relative.Split('/')
        if (@($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' -or $_.Contains(':') }).Count -or -not $directorySet.Contains($parts[0])) { throw 'Release entry escapes its dated directory.' }
        if ($entry.Kind -cne 'directory' -and $entry.Kind -cne 'file') { throw 'Invalid release entry kind.' }
        if ($entry.Kind -eq 'directory') {
            if (($entry.Length -isnot [int] -and $entry.Length -isnot [long]) -or $entry.Length -ne 0 -or $null -ne $entry.Sha256) { throw 'Invalid preserved directory record.' }
        } else {
            if (($entry.Length -isnot [int] -and $entry.Length -isnot [long]) -or $entry.Length -lt 0 -or $entry.Sha256 -isnot [string] -or $entry.Sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Invalid preserved file record.' }
        }
        if ($entryMap.ContainsKey($relative)) { throw "Duplicate preserved release entry: $relative" }
        $entryMap.Add($relative, $entry)
    }
    foreach ($directory in $Snapshot.PreservedDirectories) {
        if (-not $entryMap.ContainsKey($directory) -or $entryMap[$directory].Kind -cne 'directory') { throw "Missing dated directory record: $directory" }
    }
    foreach ($entry in $Snapshot.Entries) {
        $parts = ([string]$entry.RelativePath).Split('/')
        for ($index = 1; $index -lt $parts.Length; $index++) {
            $parent = $parts[0..($index - 1)] -join '/'
            if (-not $entryMap.ContainsKey($parent) -or $entryMap[$parent].Kind -cne 'directory') { throw "Missing preserved parent directory: $parent" }
        }
        if ($entry.Kind -eq 'file') {
            $prefix = ([string]$entry.RelativePath) + '/'
            foreach ($candidate in $entryMap.Keys) { if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "File has child entries: $($entry.RelativePath)" } }
        }
    }
}

function Assert-BuildPreservationSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)]$Snapshot,
        [string]$ExpectedRoot,
        [switch]$RequirePackage,
        [switch]$SourceState
    )
    Assert-BuildPreservationSnapshotShape -Snapshot $Snapshot
    $root = [IO.Path]::GetFullPath($Directory).TrimEnd([char[]]'\/')
    if ($ExpectedRoot) {
        $expected = [IO.Path]::GetFullPath($ExpectedRoot).TrimEnd([char[]]'\/')
        if ($root -ine $expected) { throw 'Release preservation check used an unexpected root.' }
    }
    if ($SourceState -and -not $ExpectedRoot -and $root -ine [string]$Snapshot.Root) { throw 'Source-state validation must use the captured release root.' }
    $actual = Get-BuildPreservationSnapshot -Destination $root -PackageName ([string]$Snapshot.PackageName)
    if ($SourceState -and ($actual.RootExisted -ne $Snapshot.RootExisted -or $actual.PackageExisted -ne $Snapshot.PackageExisted)) { throw 'Release source root or package presence changed after snapshot.' }
    if ($RequirePackage -and (-not $actual.RootExisted -or -not $actual.PackageExisted)) { throw "Release package is missing from $root." }
    if ($actual.PreservedDirectories.Count -ne $Snapshot.PreservedDirectories.Count -or $actual.Entries.Count -ne $Snapshot.Entries.Count) { throw "Preserved release content count changed at $root." }
    for ($index = 0; $index -lt $Snapshot.PreservedDirectories.Count; $index++) {
        if ($actual.PreservedDirectories[$index] -cne $Snapshot.PreservedDirectories[$index]) { throw "Preserved release directory changed at $root." }
    }
    for ($index = 0; $index -lt $Snapshot.Entries.Count; $index++) {
        $expectedEntry = $Snapshot.Entries[$index]
        $actualEntry = $actual.Entries[$index]
        if ($actualEntry.RelativePath -cne $expectedEntry.RelativePath -or $actualEntry.Kind -cne $expectedEntry.Kind -or $actualEntry.Length -ne $expectedEntry.Length -or $actualEntry.Sha256 -cne $expectedEntry.Sha256) { throw "Preserved release content changed: $($expectedEntry.RelativePath)" }
    }
    if ($SourceState -and $Snapshot.RootExisted -eq $false -and $actual.RootExisted) { throw 'Release output appeared after snapshot.' }
}

function Copy-BuildPreservedDirectoriesToStage {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$StageDirectory)
    Assert-BuildPreservationSnapshotShape -Snapshot $Snapshot
    Assert-BuildPreservationSnapshot -Directory ([string]$Snapshot.Root) -Snapshot $Snapshot -ExpectedRoot ([string]$Snapshot.Root) -SourceState
    $stage = [IO.Path]::GetFullPath($StageDirectory).TrimEnd([char[]]'\/')
    if (-not [IO.Directory]::Exists($stage)) { throw "Private release stage is missing: $stage" }
    foreach ($name in $Snapshot.PreservedDirectories) {
        $target = Join-Path $stage $name
        if (Test-Path -LiteralPath $target) { throw "Preserved release destination already exists in stage: $name" }
        [IO.Directory]::CreateDirectory($target) | Out-Null
    }
    foreach ($entry in $Snapshot.Entries) {
        if ($entry.Kind -eq 'directory') {
            $relative = ([string]$entry.RelativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)
            $target = Join-Path $stage $relative
            if (-not [IO.Directory]::Exists($target)) { [IO.Directory]::CreateDirectory($target) | Out-Null }
        }
    }
    foreach ($entry in $Snapshot.Entries) {
        if ($entry.Kind -eq 'file') {
            $relative = ([string]$entry.RelativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)
            $source = Join-Path ([string]$Snapshot.Root) $relative
            $target = Join-Path $stage $relative
            if (Test-Path -LiteralPath $target) { throw "Preserved release file already exists in stage: $relative" }
            [IO.File]::Copy($source, $target, $false)
        }
    }
    Assert-BuildPreservationSnapshot -Directory ([string]$Snapshot.Root) -Snapshot $Snapshot -ExpectedRoot ([string]$Snapshot.Root) -SourceState
    Assert-BuildPreservationSnapshot -Directory $stage -Snapshot $Snapshot -ExpectedRoot $stage -RequirePackage
}

function Enter-BuildLock {
    param($Paths, [int]$TimeoutSeconds = 30)
    foreach ($name in @('Destination','Stage','Backup')) {
        if ($Paths.PSObject.Properties[$name]) {
            $null = Assert-ClientPlainPathTree -Path ([string]$Paths.$name) -LeafType Directory -IncludeDescendants
        }
    }
    foreach ($name in @('Journal','Lock')) {
        if ($Paths.PSObject.Properties[$name]) {
            $filePath = [string]$Paths.$name
            $null = Assert-ClientPlainPathTree -Path $filePath -LeafType File
            if ($name -ceq 'Journal') { $null = Assert-ClientPlainPathTree -Path ($filePath + '.write') -LeafType File }
        }
    }
    $lockPath = Assert-ClientPlainPathTree -Path $Paths.Lock -LeafType File
    [IO.Directory]::CreateDirectory((Split-Path -Parent $lockPath)) | Out-Null
    $null = Assert-ClientPlainPathTree -Path $lockPath -LeafType File
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try { return [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Build lock timeout: $lockPath" }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Enter-BuildLocks {
    param([Parameter(Mandatory)][string[]]$LockPaths, [int]$TimeoutSeconds = 30)
    $uniquePaths = [System.Collections.Generic.List[string]]::new()
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($lockPath in $LockPaths) {
        if (-not $lockPath) { throw 'Build lock path cannot be empty.' }
        $normalizedPath = [IO.Path]::GetFullPath($lockPath)
        if ($seenPaths.Add($normalizedPath)) { $uniquePaths.Add($normalizedPath) }
    }
    $orderedPaths = $uniquePaths.ToArray()
    [Array]::Sort($orderedPaths, [StringComparer]::OrdinalIgnoreCase)
    $locks = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($lockPath in $orderedPaths) {
            $locks.Add((Enter-BuildLock ([pscustomobject]@{Lock=$lockPath}) $TimeoutSeconds))
        }
        return ,$locks.ToArray()
    }
    catch {
        for ($index = $locks.Count - 1; $index -ge 0; $index--) { $locks[$index].Dispose() }
        throw
    }
}

function Remove-BuildDirectory {
    param($Paths, [string]$Path)
    if ($Path -notin @($Paths.Stage, $Paths.Backup, $Paths.Destination)) { throw 'Unrecognized build cleanup path.' }
    $safePath = Assert-ClientPlainPathTree -Path $Path -LeafType Directory -IncludeDescendants
    if ([IO.Directory]::Exists($safePath)) {
        # The shared guard has checked the full ancestor chain and every child without following links.
        Remove-Item -LiteralPath $safePath -Recurse -Force -ErrorAction Stop
    }
}

function Write-BuildJournal {
    param($Paths, $Journal)
    $temporary = "$($Paths.Journal).write"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((Format-JsonText ($Journal | ConvertTo-Json -Depth 100 -Compress)) + "`n")
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if ([IO.File]::Exists($Paths.Journal)) { [IO.File]::Replace($temporary, $Paths.Journal, [System.Management.Automation.Language.NullString]::Value) }
    else { [IO.File]::Move($temporary, $Paths.Journal) }
}

function Complete-BuildCommit {
    param($Paths, $PreservationSnapshot)
    if (-not [IO.Directory]::Exists($Paths.Destination)) { throw 'Committed build destination is missing.' }
    if ($null -ne $PreservationSnapshot) {
        Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $PreservationSnapshot -ExpectedRoot $Paths.Destination -RequirePackage
    }
    Remove-BuildDirectory $Paths $Paths.Backup
    Remove-BuildDirectory $Paths $Paths.Stage
    if ([IO.File]::Exists("$($Paths.Journal).write")) { [IO.File]::Delete("$($Paths.Journal).write") }
    [IO.File]::Delete($Paths.Journal)
}

function Restore-BuildTransaction {
    param($Paths)
    if (-not [IO.File]::Exists($Paths.Journal)) {
        if (Test-Path -LiteralPath $Paths.Backup) { throw 'Build backup without journal; preserve for manual recovery.' }
        Remove-BuildDirectory $Paths $Paths.Stage
        if ([IO.File]::Exists("$($Paths.Journal).write")) { [IO.File]::Delete("$($Paths.Journal).write") }
        return
    }
    $journal = Read-StrictJsonFile -Path $Paths.Journal
    if ($journal.version -ne 1 -or $journal.destination -cne $Paths.Destination -or $journal.phase -notin @('prepared','committed') -or $journal.existed -isnot [bool]) { throw 'Invalid build journal; preserve for manual recovery.' }
    $preservationSnapshot = $null
    $preservationProperty = $journal.PSObject.Properties['preservation']
    if ($null -ne $preservationProperty) {
        $preservationSnapshot = $preservationProperty.Value
        Assert-BuildPreservationSnapshotShape -Snapshot $preservationSnapshot
        if ($preservationSnapshot.Root -cne $Paths.Destination -or $preservationSnapshot.RootExisted -ne $journal.existed) { throw 'Build journal preservation snapshot does not match its destination state.' }
    }
    if ($journal.phase -eq 'committed') { Complete-BuildCommit $Paths $preservationSnapshot; return }
    if ($null -ne $preservationSnapshot) {
        $backupExists = [IO.Directory]::Exists($Paths.Backup)
        $destinationExists = [IO.Directory]::Exists($Paths.Destination)
        if ($backupExists) {
            Assert-BuildPreservationSnapshot -Directory $Paths.Backup -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Backup -SourceState
            if ($destinationExists) { Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Destination -RequirePackage }
        }
        elseif ($journal.existed) {
            if (-not $destinationExists) { throw 'Original build and backup are both missing.' }
            Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Destination -SourceState
        }
        elseif ($destinationExists) {
            Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Destination -RequirePackage
        }
    }
    if ($journal.existed) {
        if ([IO.Directory]::Exists($Paths.Backup)) {
            Remove-BuildDirectory $Paths $Paths.Destination
            [IO.Directory]::Move($Paths.Backup, $Paths.Destination)
            if ($null -ne $preservationSnapshot) { Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Destination -SourceState }
        }
        elseif (-not [IO.Directory]::Exists($Paths.Destination)) { throw 'Original build and backup are both missing.' }
    }
    else {
        if (Test-Path -LiteralPath $Paths.Backup) { throw 'Unexpected build backup.' }
        Remove-BuildDirectory $Paths $Paths.Destination
    }
    if ($null -ne $preservationSnapshot -and $journal.existed) { Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $Paths.Destination -SourceState }
    if ($null -ne $preservationSnapshot -and -not $journal.existed -and [IO.Directory]::Exists($Paths.Destination)) { throw 'Release output remained after rollback of a new publication.' }
    Remove-BuildDirectory $Paths $Paths.Stage
    if ([IO.File]::Exists("$($Paths.Journal).write")) { [IO.File]::Delete("$($Paths.Journal).write") }
    [IO.File]::Delete($Paths.Journal)
}

function Publish-BuildTransaction {
    param($Paths, $PreservationSnapshot)
    if (-not [IO.Directory]::Exists($Paths.Stage) -or (Test-Path -LiteralPath $Paths.Backup) -or (Test-Path -LiteralPath $Paths.Journal)) { throw 'Build transaction is not ready for publication.' }
    $journal = [ordered]@{version=1; destination=$Paths.Destination; phase='prepared'; existed=[IO.Directory]::Exists($Paths.Destination)}
    if ($null -ne $PreservationSnapshot) {
        Assert-BuildPreservationSnapshotShape -Snapshot $PreservationSnapshot
        if ($PreservationSnapshot.Root -cne $Paths.Destination -or $PreservationSnapshot.RootExisted -ne $journal.existed) { throw 'Release preservation snapshot does not match the output directory.' }
        Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $PreservationSnapshot -ExpectedRoot $Paths.Destination -SourceState
        Assert-BuildPreservationSnapshot -Directory $Paths.Stage -Snapshot $PreservationSnapshot -ExpectedRoot $Paths.Stage -RequirePackage
        $journal['preservation'] = $PreservationSnapshot
    }
    Write-BuildJournal $Paths $journal
    try {
        if ($journal.existed) { [IO.Directory]::Move($Paths.Destination, $Paths.Backup) }
        if ($null -ne $PreservationSnapshot -and $journal.existed) {
            Assert-BuildPreservationSnapshot -Directory $Paths.Backup -Snapshot $PreservationSnapshot -ExpectedRoot $Paths.Backup -SourceState
        }
        [IO.Directory]::Move($Paths.Stage, $Paths.Destination)
        if ($null -ne $PreservationSnapshot) { Assert-BuildPreservationSnapshot -Directory $Paths.Destination -Snapshot $PreservationSnapshot -ExpectedRoot $Paths.Destination -RequirePackage }
        $journal.phase = 'committed'
        Write-BuildJournal $Paths $journal
    }
    catch {
        $publishError = $_
        Restore-BuildTransaction $Paths
        throw $publishError
    }
    # Cleanup failure after durable commit must never roll back published files.
    try { Complete-BuildCommit $Paths $PreservationSnapshot }
    catch { Write-Warning "Build committed; cleanup will resume next run: $($_.Exception.Message)" }
}
