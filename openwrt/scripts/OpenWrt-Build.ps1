# Shared local build locks and durable directory publication. No deployment.
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$sharedScriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $sharedScriptsRoot 'Build-Transaction.ps1')
if (-not (Get-Command Format-JsonText -CommandType Function -ErrorAction SilentlyContinue)) {
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $sharedScriptsRoot 'Generate-SingBoxConfig.ps1'), [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count) { throw 'Cannot load JSON formatter.' }
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Format-JsonText'}, $true)
    if (-not $definition) { throw 'JSON formatter missing.' }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Enter-OpenWrtInputLocks {
    param([string]$ArchivePath, [string]$SourceRoot, [int]$TimeoutSeconds = 30)
    $archiveFull = Assert-ClientPlainPathTree -Path $ArchivePath -LeafType File -Required
    $archivePaths = Get-BuildPaths (Split-Path -Parent $archiveFull)
    $sourcePaths = Get-BuildPaths $SourceRoot
    $archiveInputs = @($archiveFull) + @(Get-OpenWrtTransactionPaths -Paths $archivePaths -ExcludeDestination)
    Assert-OpenWrtInputPathSeparation -TransactionPaths (Get-OpenWrtTransactionPaths -Paths $sourcePaths) -InputPaths $archiveInputs
    $handles = [Collections.Generic.List[object]]::new()
    try {
        # Lock order: main publication, snapshot, then output. A reader does
        # not recover the main publisher's transactions on its behalf.
        $handles.Add((Enter-BuildLock $archivePaths $TimeoutSeconds))
        foreach ($pending in @($archivePaths.Journal, $archivePaths.Backup, "$($archivePaths.Journal).write")) {
            if (Test-Path -LiteralPath $pending) { throw 'Main archive has pending recovery; resume its own publisher first.' }
        }
        $handles.Add((Enter-BuildLock $sourcePaths $TimeoutSeconds))
        Restore-BuildTransaction $sourcePaths
        return [pscustomobject]@{ Handles=$handles; SourcePaths=$sourcePaths }
    } catch {
        for ($i=$handles.Count-1; $i -ge 0; $i--) { $handles[$i].Dispose() }
        throw
    }
}

function Exit-OpenWrtInputLocks {
    param($Context)
    if ($Context) {
        for ($i=$Context.Handles.Count-1; $i -ge 0; $i--) { $Context.Handles[$i].Dispose() }
    }
}

function Remove-OpenWrtPayload {
    param([string]$Path, [string]$ExpectedPath)
    $resolved=[IO.Path]::GetFullPath($Path)
    $expected=[IO.Path]::GetFullPath($ExpectedPath)
    if ($resolved -cne $expected -or (Split-Path -Leaf $resolved) -cne '.payload') { throw 'Unsafe payload cleanup path.' }
    Assert-OpenWrtPathAncestors -Path $resolved
    if (Test-Path -LiteralPath $resolved) {
        $items=@((Get-Item -LiteralPath $resolved -Force))+@(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Payload contains a reparse point.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

function ConvertTo-OpenWrtComparisonPath {
    param([Parameter(Mandatory)][string]$Path)
    $normalized = [IO.Path]::GetFullPath($Path)
    $separator = [IO.Path]::DirectorySeparatorChar
    $normalized = $normalized.Replace([char]'/', $separator).Replace([char]'\', $separator)
    $root = [IO.Path]::GetPathRoot($normalized)
    if ($normalized.Length -gt $root.Length) { $normalized = $normalized.TrimEnd($separator) }
    return $normalized
}

function Test-OpenWrtPathContains {
    param([string]$Parent, [string]$Child, [StringComparison]$Comparison)
    if ($Parent.Equals($Child, $Comparison)) { return $true }
    $prefix = $Parent
    $separator = [IO.Path]::DirectorySeparatorChar.ToString()
    if (-not $prefix.EndsWith($separator, $Comparison)) { $prefix += $separator }
    return $Child.StartsWith($prefix, $Comparison)
}

function Test-OpenWrtPathOverlap {
    param([string]$First, [string]$Second, [StringComparison]$Comparison)
    return (Test-OpenWrtPathContains -Parent $First -Child $Second -Comparison $Comparison) -or
        (Test-OpenWrtPathContains -Parent $Second -Child $First -Comparison $Comparison)
}

function Get-OpenWrtTransactionPaths {
    param($Paths,[switch]$ExcludeDestination)
    if (-not $ExcludeDestination) { $Paths.Destination }
    $Paths.Stage
    $Paths.Backup
    $Paths.Journal
    $Paths.Journal + '.write'
    $Paths.Lock
}

function Assert-OpenWrtInputPathSeparation {
    param([string[]]$TransactionPaths,[string[]]$InputPaths)
    $comparison = [StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison = [StringComparison]::OrdinalIgnoreCase }
    foreach ($path in $InputPaths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $inputPath = ConvertTo-OpenWrtComparisonPath -Path $path
        foreach ($transaction in $TransactionPaths) {
            $transactionPath = ConvertTo-OpenWrtComparisonPath -Path $transaction
            if (Test-OpenWrtPathOverlap -First $transactionPath -Second $inputPath -Comparison $comparison) {
                throw "OpenWrt transaction path overlaps an input or protected path: $transactionPath and $inputPath"
            }
        }
    }
}

function Assert-OpenWrtOutputTarget {
    param([string]$OutputDirectory, [string]$SourceRoot, [string]$ArchivePath, [string]$SingBoxPath, [string[]]$RuntimePaths=@(), [string[]]$ProtectedPaths=@())
    $comparison = [StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison = [StringComparison]::OrdinalIgnoreCase }
    $output = ConvertTo-OpenWrtComparisonPath -Path $OutputDirectory
    Assert-OpenWrtPathAncestors -Path $output
    [void](Get-BuildPaths $output)
    $protected = @()
    if (-not [string]::IsNullOrWhiteSpace($SourceRoot)) { $protected += $SourceRoot }
    if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) { $protected += (Split-Path -Parent ([IO.Path]::GetFullPath($ArchivePath))) }
    if (-not [string]::IsNullOrWhiteSpace($SingBoxPath)) { $protected += (Split-Path -Parent ([IO.Path]::GetFullPath($SingBoxPath))) }
    if ($ProtectedPaths) { $protected += $ProtectedPaths }
    foreach ($path in $protected) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $path = ConvertTo-OpenWrtComparisonPath -Path $path
        if (Test-OpenWrtPathOverlap -First $output -Second $path -Comparison $comparison) {
            throw 'Build output overlaps protected source/archive/runtime directory.'
        }
    }
    foreach ($runtimePath in $RuntimePaths) {
        if ([string]::IsNullOrWhiteSpace($runtimePath)) { continue }
        $runtimeFile = ConvertTo-OpenWrtComparisonPath -Path $runtimePath
        if (Test-OpenWrtPathOverlap -First $output -Second $runtimeFile -Comparison $comparison) {
            throw 'Build output overlaps a protected runtime input file.'
        }
    }
    if (Test-Path -LiteralPath $output) {
        if (-not (Get-Item -LiteralPath $output -Force).PSIsContainer) { throw 'Build output must be a directory.' }
        $entries = @((Get-Item -LiteralPath $output -Force)) + @(Get-ChildItem -LiteralPath $output -Recurse -Force)
        if (@($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Output contains a reparse point.' }
    }
}

function Assert-OpenWrtPathAncestors {
    param([Parameter(Mandatory)][string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Refusing path through a reparse point: '+$item.FullName) }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $current) { break }
        $current = $parent
    }
}

function Get-OpenWrtTaskScratchRoot {
    $openWrtRoot = Split-Path -Parent $PSScriptRoot
    return ConvertTo-OpenWrtComparisonPath -Path (Join-Path (Join-Path $openWrtRoot 'outputs') 'build-scratch')
}

function Assert-OpenWrtTaskScratchTreeHasNoReparsePoints {
    param([Parameter(Mandatory)][string]$Path)
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw ('OpenWrt task scratch path is not a plain directory: ' + $root.FullName)
    }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push([IO.Path]::GetFullPath($root.FullName))
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ('OpenWrt task scratch tree contains a reparse point: ' + $item.FullName)
            }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function New-OpenWrtTaskScratchDirectory {
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Prefix)
    $root = Get-OpenWrtTaskScratchRoot
    Assert-OpenWrtPathAncestors -Path $root
    if (-not [IO.Directory]::Exists($root)) { [IO.Directory]::CreateDirectory($root) | Out-Null }
    Assert-OpenWrtPathAncestors -Path $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe OpenWrt task scratch root.' }
    $path = Join-Path $root ($Prefix + '-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { throw 'OpenWrt task scratch path already exists.' }
    [IO.Directory]::CreateDirectory($path) | Out-Null
    Assert-OpenWrtPathAncestors -Path $path
    Assert-OpenWrtTaskScratchTreeHasNoReparsePoints -Path $path
    return [IO.Path]::GetFullPath($path)
}

function Remove-OpenWrtTaskScratchDirectory {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Prefix)
    $root = Get-OpenWrtTaskScratchRoot
    $resolved = ConvertTo-OpenWrtComparisonPath -Path $Path
    $resolvedParent = ConvertTo-OpenWrtComparisonPath -Path (Split-Path -Parent $resolved)
    $comparison = [StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison = [StringComparison]::OrdinalIgnoreCase }
    if (-not $resolvedParent.Equals($root, $comparison) -or
        (Split-Path -Leaf $resolved) -cnotmatch ('^' + [regex]::Escape($Prefix) + '-[a-f0-9]{32}$')) {
        throw 'Unsafe OpenWrt task scratch cleanup target.'
    }
    Assert-OpenWrtPathAncestors -Path $resolved
    if (-not [IO.Directory]::Exists($resolved) -and -not [IO.File]::Exists($resolved)) { return }
    Assert-OpenWrtTaskScratchTreeHasNoReparsePoints -Path $resolved
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Get-OpenWrtBuildSupportDirectory {
    param([Parameter(Mandatory)][string]$OutputDirectory, [string]$BuildSupportDirectory)
    if (-not [string]::IsNullOrWhiteSpace($BuildSupportDirectory)) {
        return ConvertTo-OpenWrtComparisonPath -Path $BuildSupportDirectory
    }
    $output = ConvertTo-OpenWrtComparisonPath -Path $OutputDirectory
    $openWrtRoot = Split-Path -Parent $PSScriptRoot
    $defaultOutput = ConvertTo-OpenWrtComparisonPath -Path (Join-Path $openWrtRoot 'generated')
    $comparison = [StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison = [StringComparison]::OrdinalIgnoreCase }
    if ($output.Equals($defaultOutput, $comparison)) {
        return ConvertTo-OpenWrtComparisonPath -Path (Join-Path (Join-Path $openWrtRoot 'outputs') 'build')
    }
    return ConvertTo-OpenWrtComparisonPath -Path ($output+'.build-support')
}

function Get-OpenWrtBuildManifestPath {
    param([Parameter(Mandatory)][string]$OutputDirectory, [string]$BuildSupportDirectory)
    $supportDirectory = Get-OpenWrtBuildSupportDirectory -OutputDirectory $OutputDirectory -BuildSupportDirectory $BuildSupportDirectory
    return Join-Path $supportDirectory 'build-manifest.json'
}

function Get-OpenWrtArtifactCoordinatorPath {
    param([Parameter(Mandatory)]$PackagePaths)
    return ($PackagePaths.Lock+'.publication.json')
}

function Enter-OpenWrtArtifactLocks {
    param($PackagePaths, $SupportPaths, $CachePaths, [int]$TimeoutSeconds=30)
    Assert-OpenWrtPathAncestors -Path $PackagePaths.Lock
    Assert-OpenWrtPathAncestors -Path $SupportPaths.Lock
    $lockPaths = @($PackagePaths.Lock,$SupportPaths.Lock)
    if ($CachePaths) {
        Assert-OpenWrtPathAncestors -Path $CachePaths.Lock
        $lockPaths += $CachePaths.Lock
    }
    return ,(Enter-BuildLocks -LockPaths $lockPaths -TimeoutSeconds $TimeoutSeconds)
}

function Exit-OpenWrtArtifactLocks {
    param($Handles)
    if ($Handles) {
        for ($i=$Handles.Count-1; $i -ge 0; $i--) { $Handles[$i].Dispose() }
    }
}

function Assert-OpenWrtBuildTargets {
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$BuildSupportDirectory,
        [string]$SourceRoot,
        [string]$ArchivePath,
        [string]$SingBoxPath,
        [string[]]$RuntimePaths=@(),
        [string[]]$ProtectedPaths=@(),
        [string[]]$SupportProtectedPaths=@(),
        [Parameter(Mandatory)][string]$FormalPackageDirectory
    )
    Assert-OpenWrtOutputTarget -OutputDirectory $OutputDirectory -SourceRoot $SourceRoot -ArchivePath $ArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $RuntimePaths -ProtectedPaths (@($ProtectedPaths)+@($BuildSupportDirectory))
    Assert-OpenWrtOutputTarget -OutputDirectory $BuildSupportDirectory -SourceRoot $SourceRoot -ArchivePath $ArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $RuntimePaths -ProtectedPaths (@($ProtectedPaths)+@($SupportProtectedPaths)+@($OutputDirectory)+@($FormalPackageDirectory))
    $packagePaths=Get-BuildPaths (ConvertTo-OpenWrtComparisonPath -Path $OutputDirectory)
    $supportPaths=Get-BuildPaths (ConvertTo-OpenWrtComparisonPath -Path $BuildSupportDirectory)
    $coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
    Assert-OpenWrtArtifactPathAliases -PackagePaths $packagePaths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
    $inputPaths = @($ProtectedPaths) + @($RuntimePaths)
    if ($SourceRoot) { $inputPaths += @(Get-OpenWrtTransactionPaths -Paths (Get-BuildPaths $SourceRoot)) }
    if ($ArchivePath) {
        $archiveDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($ArchivePath))
        $inputPaths += @(Get-OpenWrtTransactionPaths -Paths (Get-BuildPaths $archiveDirectory))
    }
    if ($SingBoxPath) { $inputPaths += Split-Path -Parent ([IO.Path]::GetFullPath($SingBoxPath)) }
    $supportTransactionPaths = @(Get-OpenWrtTransactionPaths -Paths $supportPaths)
    $transactionPaths = @(Get-OpenWrtTransactionPaths -Paths $packagePaths) + $supportTransactionPaths + @($coordinatorPath, "$coordinatorPath.write")
    Assert-OpenWrtInputPathSeparation -TransactionPaths $transactionPaths -InputPaths $inputPaths
    Assert-OpenWrtInputPathSeparation -TransactionPaths $supportTransactionPaths -InputPaths (@($FormalPackageDirectory) + $SupportProtectedPaths)
}

function Assert-OpenWrtArtifactPathAliases {
    param($PackagePaths, $SupportPaths, [Parameter(Mandatory)][string]$CoordinatorPath)
    $packageEntries=@(
        [pscustomobject]@{Name='package.Destination';Path=$PackagePaths.Destination},
        [pscustomobject]@{Name='package.Stage';Path=$PackagePaths.Stage},
        [pscustomobject]@{Name='package.Backup';Path=$PackagePaths.Backup},
        [pscustomobject]@{Name='package.Journal';Path=$PackagePaths.Journal},
        [pscustomobject]@{Name='package.Journal.write';Path=($PackagePaths.Journal+'.write')},
        [pscustomobject]@{Name='package.Lock';Path=$PackagePaths.Lock}
    )
    $supportEntries=@(
        [pscustomobject]@{Name='support.Destination';Path=$SupportPaths.Destination},
        [pscustomobject]@{Name='support.Stage';Path=$SupportPaths.Stage},
        [pscustomobject]@{Name='support.Backup';Path=$SupportPaths.Backup},
        [pscustomobject]@{Name='support.Journal';Path=$SupportPaths.Journal},
        [pscustomobject]@{Name='support.Journal.write';Path=($SupportPaths.Journal+'.write')},
        [pscustomobject]@{Name='support.Lock';Path=$SupportPaths.Lock}
    )
    $coordinatorEntries=@(
        [pscustomobject]@{Name='coordinator';Path=$CoordinatorPath},
        [pscustomobject]@{Name='coordinator.write';Path=($CoordinatorPath+'.write')}
    )
    $entries=@($packageEntries)+@($supportEntries)+@($coordinatorEntries)
    $comparison=[StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison=[StringComparison]::OrdinalIgnoreCase }
    for ($leftIndex=0; $leftIndex -lt $entries.Count; $leftIndex++) {
        $leftPath=ConvertTo-OpenWrtComparisonPath -Path $entries[$leftIndex].Path
        for ($rightIndex=$leftIndex+1; $rightIndex -lt $entries.Count; $rightIndex++) {
            $rightPath=ConvertTo-OpenWrtComparisonPath -Path $entries[$rightIndex].Path
            if (Test-OpenWrtPathOverlap -First $leftPath -Second $rightPath -Comparison $comparison) {
                throw ('OpenWrt artifact transaction paths overlap: '+$entries[$leftIndex].Name+' and '+$entries[$rightIndex].Name+'.')
            }
        }
    }
}

function Assert-OpenWrtTreeHasNoReparsePoints {
    param([Parameter(Mandatory)][string]$Path)
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Build transaction tree contains a reparse point: '+$root.FullName) }
    if (-not $root.PSIsContainer) { return }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root.FullName)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($childPath in [IO.Directory]::GetFileSystemEntries($directory)) {
            $child = Get-Item -LiteralPath $childPath -Force -ErrorAction Stop
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Build transaction tree contains a reparse point: '+$child.FullName) }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
        }
    }
}

function Assert-OpenWrtArtifactPathSet {
    param($PackagePaths, $SupportPaths, [Parameter(Mandatory)][string]$CoordinatorPath)
    Assert-OpenWrtArtifactPathAliases -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath
    foreach ($paths in @($PackagePaths,$SupportPaths)) {
        foreach ($path in @($paths.Destination,$paths.Stage,$paths.Backup,$paths.Journal,"$($paths.Journal).write",$paths.Lock)) {
            Assert-OpenWrtPathAncestors -Path $path
            if (Test-Path -LiteralPath $path) {
                $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Build transaction path is a reparse point: '+$item.FullName) }
                if ($path -in @($paths.Destination,$paths.Stage,$paths.Backup) -and -not $item.PSIsContainer) { throw ('Build transaction directory path is a file: '+$item.FullName) }
                if ($item.PSIsContainer) { Assert-OpenWrtTreeHasNoReparsePoints -Path $path }
            }
        }
    }
    foreach ($path in @($CoordinatorPath,"$CoordinatorPath.write")) {
        Assert-OpenWrtPathAncestors -Path $path
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.PSIsContainer) { throw ('Build coordinator path is not a regular file: '+$item.FullName) }
        }
    }
}

function Assert-OpenWrtDirectoryContainsOnly {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not [IO.Directory]::Exists($Path)) { throw ('Build directory is missing: '+$Path) }
    $entries = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($entries.Count -ne 1 -or $entries[0].PSIsContainer -or $entries[0].Name -cne $Name) { throw ('Unexpected files in build directory: '+$Path) }
}

function Assert-OpenWrtPackageOutputDirectory {
    param([Parameter(Mandatory)][string]$Path, [switch]$RequirePackage)
    if (-not [IO.Directory]::Exists($Path)) { throw ('OpenWrt package output directory is missing: '+$Path) }
    # The shared preservation snapshot validates the package root, accepts only
    # openwrt.zip plus dated release directories, and rejects unknown objects
    # or reparse points throughout those trees. It intentionally does not walk
    # files out of a release directory into the runtime ZIP.
    $null = Get-BuildPreservationSnapshot -Destination $Path -PackageName 'openwrt.zip'
    $packagePath = Join-Path $Path 'openwrt.zip'
    if ($RequirePackage -and -not [IO.File]::Exists($packagePath)) { throw ('OpenWrt package is missing: '+$packagePath) }
    if ([IO.Directory]::Exists($packagePath)) { throw ('OpenWrt package path is not a file: '+$packagePath) }
}

function Write-OpenWrtArtifactCoordinator {
    param([string]$Path, $Journal)
    Write-BuildJournal ([pscustomobject]@{Journal=$Path}) $Journal
}

function Sync-OpenWrtInnerJournal {
    param($Paths, [string]$Phase, [bool]$AllowCompleted, [bool]$ExpectedExisted)
    if ([IO.File]::Exists($Paths.Journal)) {
        $inner = Read-StrictJsonFile -Path $Paths.Journal
        if ($inner.version -ne 1 -or $inner.destination -cne $Paths.Destination -or $inner.existed -isnot [bool] -or $inner.phase -notin @('prepared','committed')) { throw 'Invalid OpenWrt artifact journal; preserve for manual recovery.' }
        if ($inner.existed -ne $ExpectedExisted) { throw 'OpenWrt artifact journal disagrees with its coordinator; preserve for manual recovery.' }
        $inner.phase = $Phase
        Write-BuildJournal $Paths $inner
        return
    }
    if ([IO.Directory]::Exists($Paths.Backup)) { throw 'OpenWrt artifact backup has no journal; preserve for manual recovery.' }
    if ($AllowCompleted) {
        if (-not [IO.Directory]::Exists($Paths.Destination)) { throw 'Committed OpenWrt artifact is missing; preserve for manual recovery.' }
        return
    }
    if ([IO.Directory]::Exists($Paths.Stage)) { throw 'OpenWrt prepared transaction is missing an artifact journal; preserve for manual recovery.' }
    if ($ExpectedExisted -and [IO.Directory]::Exists($Paths.Destination)) { return }
    if (-not $ExpectedExisted -and -not [IO.Directory]::Exists($Paths.Destination)) { return }
    throw 'OpenWrt prepared transaction is missing an artifact journal; preserve for manual recovery.'
}

function Restore-OpenWrtArtifactTransaction {
    param($PackagePaths, $SupportPaths, [string]$CoordinatorPath)
    Assert-OpenWrtArtifactPathSet -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath
    if (-not [IO.File]::Exists($CoordinatorPath)) {
        $beforeSnapshot = Get-BuildPreservationSnapshot -Destination $PackagePaths.Destination -PackageName 'openwrt.zip'
        foreach ($paths in @($PackagePaths,$SupportPaths)) { Restore-BuildTransaction $paths }
        Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $beforeSnapshot -ExpectedRoot $PackagePaths.Destination -SourceState
        if ([IO.File]::Exists("$CoordinatorPath.write")) { [IO.File]::Delete("$CoordinatorPath.write") }
        return
    }
    $journal = Read-StrictJsonFile -Path $CoordinatorPath
    if ($journal.version -ne 2 -or $journal.kind -cne 'openwrt-artifacts' -or $journal.package_destination -cne $PackagePaths.Destination -or $journal.support_destination -cne $SupportPaths.Destination -or $journal.package_existed -isnot [bool] -or $journal.support_existed -isnot [bool] -or $journal.phase -notin @('prepared','committed')) { throw 'Invalid OpenWrt publication coordinator; preserve for manual recovery.' }
    $committed = $journal.phase -eq 'committed'
    $preservationProperty = $journal.PSObject.Properties['package_preservation']
    $preservationSnapshot = $null
    if ($preservationProperty) {
        if ($journal.package_preservation -isnot [string]) { throw 'Invalid OpenWrt package preservation snapshot encoding; preserve for manual recovery.' }
        try { $preservationSnapshot = ConvertFrom-StrictJson -Text $journal.package_preservation }
        catch { throw 'Invalid OpenWrt package preservation snapshot JSON; preserve for manual recovery.' }
        if ($null -eq $preservationSnapshot) { throw 'Invalid OpenWrt package preservation snapshot; preserve for manual recovery.' }
        Assert-BuildPreservationSnapshotShape -Snapshot $preservationSnapshot
        $packageFileExistedProperty = $journal.PSObject.Properties['package_file_existed']
        if ($preservationSnapshot.Root -cne $PackagePaths.Destination -or $preservationSnapshot.PackageName -cne 'openwrt.zip' -or -not $packageFileExistedProperty -or $journal.package_file_existed -isnot [bool] -or $preservationSnapshot.PackageExisted -ne $journal.package_file_existed) { throw 'Invalid OpenWrt package preservation snapshot binding; preserve for manual recovery.' }
        if ($preservationSnapshot.RootExisted -ne $journal.package_existed) { throw 'OpenWrt package preservation snapshot disagrees with its coordinator; preserve for manual recovery.' }
        if ($committed) {
            if (-not [IO.Directory]::Exists($PackagePaths.Destination)) { throw 'Committed OpenWrt package output is missing; preserve for manual recovery.' }
            Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Destination -RequirePackage
            Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -RequirePackage
            if ([IO.Directory]::Exists($PackagePaths.Backup)) { Assert-BuildPreservationSnapshot -Directory $PackagePaths.Backup -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Backup -SourceState }
        } else {
            if ([IO.Directory]::Exists($PackagePaths.Backup)) {
                Assert-BuildPreservationSnapshot -Directory $PackagePaths.Backup -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Backup -SourceState
                if ([IO.Directory]::Exists($PackagePaths.Destination)) {
                    Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Destination -RequirePackage
                    Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -RequirePackage
                }
            } elseif ($journal.package_existed -and [IO.Directory]::Exists($PackagePaths.Destination)) {
                Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -SourceState
            } elseif ($journal.package_existed) { throw 'Prepared OpenWrt package output and backup are both missing; preserve for manual recovery.' } elseif ([IO.Directory]::Exists($PackagePaths.Destination)) {
                Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Destination -RequirePackage
                Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -RequirePackage
            }
            if ([IO.Directory]::Exists($PackagePaths.Stage)) {
                Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Stage -RequirePackage
                Assert-BuildPreservationSnapshot -Directory $PackagePaths.Stage -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Stage -RequirePackage
            }
        }
    }
    Sync-OpenWrtInnerJournal -Paths $PackagePaths -Phase $journal.phase -AllowCompleted $committed -ExpectedExisted $journal.package_existed
    Sync-OpenWrtInnerJournal -Paths $SupportPaths -Phase $journal.phase -AllowCompleted $committed -ExpectedExisted $journal.support_existed
    Restore-BuildTransaction $PackagePaths
    Restore-BuildTransaction $SupportPaths
    if ($preservationSnapshot) {
        if ($committed) { Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -RequirePackage }
        else { Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $preservationSnapshot -ExpectedRoot $PackagePaths.Destination -SourceState }
    }
    if ([IO.File]::Exists("$CoordinatorPath.write")) { [IO.File]::Delete("$CoordinatorPath.write") }
    [IO.File]::Delete($CoordinatorPath)
}

function Publish-OpenWrtBuildArtifacts {
    param($PackagePaths, $SupportPaths, [string]$CoordinatorPath, $PackagePreservationSnapshot)
    Assert-OpenWrtArtifactPathSet -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath
    Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Stage -RequirePackage
    Assert-OpenWrtDirectoryContainsOnly -Path $SupportPaths.Stage -Name 'build-manifest.json'
    if ([IO.Directory]::Exists($PackagePaths.Backup) -or [IO.Directory]::Exists($SupportPaths.Backup) -or [IO.File]::Exists($PackagePaths.Journal) -or [IO.File]::Exists($SupportPaths.Journal) -or [IO.File]::Exists($CoordinatorPath)) { throw 'OpenWrt publication transaction is not ready.' }
    if ($PackagePreservationSnapshot) {
        if ($PackagePreservationSnapshot.Root -cne $PackagePaths.Destination -or $PackagePreservationSnapshot.PackageName -cne 'openwrt.zip' -or $PackagePreservationSnapshot.Version -ne 1 -or $PackagePreservationSnapshot.RootExisted -ne [IO.Directory]::Exists($PackagePaths.Destination)) { throw 'OpenWrt package preservation snapshot does not match the destination.' }
        if ([IO.Directory]::Exists($PackagePaths.Destination)) {
            Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Destination
            Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $PackagePreservationSnapshot -ExpectedRoot $PackagePaths.Destination -SourceState
        }
        Assert-BuildPreservationSnapshot -Directory $PackagePaths.Stage -Snapshot $PackagePreservationSnapshot -ExpectedRoot $PackagePaths.Stage -RequirePackage
    }
    $packageJournal = [ordered]@{version=1;destination=$PackagePaths.Destination;phase='prepared';existed=[IO.Directory]::Exists($PackagePaths.Destination)}
    $supportJournal = [ordered]@{version=1;destination=$SupportPaths.Destination;phase='prepared';existed=[IO.Directory]::Exists($SupportPaths.Destination)}
    $coordinator = [ordered]@{version=2;kind='openwrt-artifacts';package_destination=$PackagePaths.Destination;support_destination=$SupportPaths.Destination;package_existed=$packageJournal.existed;support_existed=$supportJournal.existed;phase='prepared'}
    if ($PackagePreservationSnapshot) {
        $coordinator.package_file_existed=$PackagePreservationSnapshot.PackageExisted
        $coordinator.package_preservation=ConvertTo-Json -InputObject $PackagePreservationSnapshot -Depth 100 -Compress
    }
    try {
        Write-BuildJournal $PackagePaths $packageJournal
        Write-BuildJournal $SupportPaths $supportJournal
        Write-OpenWrtArtifactCoordinator -Path $CoordinatorPath -Journal $coordinator
        Assert-OpenWrtArtifactPathSet -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath
        if ($packageJournal.existed) { [IO.Directory]::Move($PackagePaths.Destination,$PackagePaths.Backup) }
        [IO.Directory]::Move($PackagePaths.Stage,$PackagePaths.Destination)
        if ($supportJournal.existed) { [IO.Directory]::Move($SupportPaths.Destination,$SupportPaths.Backup) }
        [IO.Directory]::Move($SupportPaths.Stage,$SupportPaths.Destination)
        if ($PackagePreservationSnapshot) {
            Assert-OpenWrtPackageOutputDirectory -Path $PackagePaths.Destination -RequirePackage
            Assert-BuildPreservationSnapshot -Directory $PackagePaths.Destination -Snapshot $PackagePreservationSnapshot -ExpectedRoot $PackagePaths.Destination -RequirePackage
        }
        $coordinator.phase='committed'
        Write-OpenWrtArtifactCoordinator -Path $CoordinatorPath -Journal $coordinator
    } catch {
        $publishError = $_
        $isCommitted = $false
        if ([IO.File]::Exists($CoordinatorPath)) {
            try { $isCommitted = (Read-StrictJsonFile -Path $CoordinatorPath).phase -eq 'committed' } catch { $isCommitted = $false }
        }
        if ($isCommitted) {
            try { Restore-OpenWrtArtifactTransaction -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath }
            catch { Write-Warning ('OpenWrt package pair is committed; cleanup will resume next build: '+$_.Exception.Message) }
            return
        }
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath }
        catch { throw ('OpenWrt publication failed and rollback needs recovery: '+$_.Exception.Message) }
        throw $publishError
    }
    try { Restore-OpenWrtArtifactTransaction -PackagePaths $PackagePaths -SupportPaths $SupportPaths -CoordinatorPath $CoordinatorPath }
    catch { Write-Warning ('OpenWrt package pair is committed; cleanup will resume next build: '+$_.Exception.Message) }
}

function Read-OpenWrtBuildManifest {
    param([Parameter(Mandatory)][string]$OutputDirectory, [string]$BuildSupportDirectory)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop }
    $packageDirectory = ConvertTo-OpenWrtComparisonPath -Path $OutputDirectory
    $supportDirectory = Get-OpenWrtBuildSupportDirectory -OutputDirectory $packageDirectory -BuildSupportDirectory $BuildSupportDirectory
    $packagePaths = Get-BuildPaths $packageDirectory
    $supportPaths = Get-BuildPaths $supportDirectory
    $coordinatorPath = Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
    $manifestPath = Join-Path $supportDirectory 'build-manifest.json'
    Assert-OpenWrtArtifactPathSet -PackagePaths $packagePaths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
    foreach ($path in @($packagePaths.Journal,$packagePaths.Backup,"$($packagePaths.Journal).write",$supportPaths.Journal,$supportPaths.Backup,"$($supportPaths.Journal).write",$coordinatorPath,"$coordinatorPath.write")) {
        if (Test-Path -LiteralPath $path) { throw 'OpenWrt publication recovery is pending; manifest is not current metadata.' }
    }
    Assert-OpenWrtPackageOutputDirectory -Path $packageDirectory -RequirePackage
    Assert-OpenWrtDirectoryContainsOnly -Path $supportDirectory -Name 'build-manifest.json'
    $packagePath = Join-Path $packageDirectory 'openwrt.zip'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw 'OpenWrt package or build manifest is missing.' }
    $before = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    $manifest = Read-StrictJsonFile -Path $manifestPath
    $hashProperty = $manifest.PSObject.Properties['package_sha256']
    if (-not $hashProperty -or [string]$manifest.package_sha256 -cnotmatch '^[A-Fa-f0-9]{64}$') { throw 'OpenWrt build manifest has no valid package SHA256.' }
    if ($manifest.PSObject.Properties['package_file'] -and $manifest.package_file -cne 'openwrt.zip') { throw 'OpenWrt build manifest names a different package file.' }
    $entryCountProperty = $manifest.PSObject.Properties['package_entries']
    if ($entryCountProperty) {
        if (($manifest.package_entries -isnot [int] -and $manifest.package_entries -isnot [long]) -or $manifest.package_entries -lt 1) { throw 'OpenWrt build manifest has no valid package entry count.' }
        $archive = [IO.Compression.ZipFile]::OpenRead($packagePath)
        try { $actualEntryCount = $archive.Entries.Count } finally { $archive.Dispose() }
        if ($manifest.package_entries -ne $actualEntryCount) { throw 'OpenWrt build manifest package entry count does not match the current package.' }
    }
    $after = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    foreach ($path in @($packagePaths.Journal,$packagePaths.Backup,"$($packagePaths.Journal).write",$supportPaths.Journal,$supportPaths.Backup,"$($supportPaths.Journal).write",$coordinatorPath,"$coordinatorPath.write")) {
        if (Test-Path -LiteralPath $path) { throw 'OpenWrt publication changed during manifest read; retry after recovery.' }
    }
    if ($before -cne $after -or [string]$manifest.package_sha256 -cne $after) { throw 'OpenWrt build manifest does not match the current package SHA256.' }
    return $manifest
}
