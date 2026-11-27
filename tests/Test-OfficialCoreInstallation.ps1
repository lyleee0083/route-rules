[CmdletBinding()]
param([Parameter(Mandatory)][string]$TestRoot)

Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $projectRoot 'scripts\Official-Cores.ps1')

function Assert-TestCondition {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-TestNoReparse {
    param([string]$Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse point in test path: '+$cursor) }
        }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor=$parent
    }
}

$projectFull=[IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$fixtureParent=[IO.Path]::GetFullPath($TestRoot).TrimEnd('\')
$allowed=$false
foreach ($allowedName in @('work','outputs')) {
    $allowedPath=[IO.Path]::GetFullPath((Join-Path $projectFull $allowedName)).TrimEnd('\')
    if ($fixtureParent.StartsWith($allowedPath+'\',[StringComparison]::OrdinalIgnoreCase)) { $allowed=$true }
}
if (-not $allowed) { throw 'TestRoot must be a child of project work/ or outputs/.' }
Assert-TestNoReparse -Path $fixtureParent
[IO.Directory]::CreateDirectory($fixtureParent) | Out-Null
$runRoot=Join-Path $fixtureParent ([Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($runRoot) | Out-Null

function New-FreshCoreRoot {
    param([string]$Name)
    $path=Join-Path $runRoot $Name
    [IO.Directory]::CreateDirectory($path) | Out-Null
    return $path
}

try {
    $sourceRoot=Join-Path $projectRoot 'openwrt\build-stage\cores'
    $assets=@(Get-OpenWrtOfficialAssets)
    foreach ($asset in $assets) {
        $archive=Join-Path $sourceRoot $asset.Name
        if (-not [IO.File]::Exists($archive)) { throw ('Missing installed official test archive: '+$archive) }
        if ((Get-Item -LiteralPath $archive).Length -ne [long]$asset.Length -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine [string]$asset.SHA256) { throw ('Current official archive is not pinned: '+$archive) }
    }

    $validRoot=New-FreshCoreRoot 'coexist'
    $oldArm=Join-Path (Join-Path $validRoot 'sing-box-arm64') 'sing-box-1.14.3-linux-arm64-musl'
    $oldWindows=Join-Path (Join-Path $validRoot 'sing-box-check') 'sing-box-1.14.3-windows-amd64'
    [IO.Directory]::CreateDirectory($oldArm) | Out-Null
    [IO.Directory]::CreateDirectory($oldWindows) | Out-Null
    $armMarker=Join-Path $oldArm 'legacy.keep'
    $windowsMarker=Join-Path $oldWindows 'legacy.keep'
    [IO.File]::WriteAllText($armMarker,'retain arm64 v1.14.3')
    [IO.File]::WriteAllText($windowsMarker,'retain windows v1.14.3')
    $armMarkerHash=(Get-FileHash -LiteralPath $armMarker -Algorithm SHA256).Hash
    $windowsMarkerHash=(Get-FileHash -LiteralPath $windowsMarker -Algorithm SHA256).Hash
    $validExtract=Join-Path $runRoot 'extract-coexist'
    $null=Install-OpenWrtBuildCores -Root $validRoot -DownloadDirectory $sourceRoot -ExtractionDirectory $validExtract -Offline
    $validPaths=Get-OpenWrtCorePaths -Root $validRoot
    foreach ($platform in @('sing-box-arm64','sing-box-check')) {
        $asset=@($assets | Where-Object { $_.Platform -ceq $platform })
        Assert-TestCondition ($asset.Count -eq 1) ('Expected one official pin for '+$platform)
        $path=[string]$validPaths[$platform]
        Assert-TestCondition ([IO.File]::Exists($path)) ('New pinned binary was not installed: '+$path)
        Assert-TestCondition ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq [string]$asset[0].BinarySHA256) ('Installed core hash differs for '+$platform)
    }
    Assert-TestCondition ([IO.File]::Exists($armMarker) -and (Get-FileHash -LiteralPath $armMarker -Algorithm SHA256).Hash -ceq $armMarkerHash) 'The existing ARM64 1.14.3 version tree must remain unchanged.'
    Assert-TestCondition ([IO.File]::Exists($windowsMarker) -and (Get-FileHash -LiteralPath $windowsMarker -Algorithm SHA256).Hash -ceq $windowsMarkerHash) 'The existing Windows 1.14.3 version tree must remain unchanged.'

    $missingRoot=New-FreshCoreRoot 'missing-pin'
    $missingCores=Join-Path $missingRoot 'cores'
    $missingDownloads=Join-Path $missingRoot 'downloads'
    $missingRejected=$false
    try { $null=Install-OpenWrtBuildCores -Root $missingCores -DownloadDirectory $missingDownloads -ExtractionDirectory (Join-Path $missingRoot 'extract') -Offline }
    catch { $missingRejected=$true }
    Assert-TestCondition $missingRejected 'Offline installation must reject a missing pinned archive.'
    Assert-TestCondition (-not [IO.Directory]::Exists((Join-Path $missingCores 'sing-box-arm64'))) 'A missing first archive must not create a partial sing-box tree.'

    $badRoot=New-FreshCoreRoot 'bad-hash'
    $badCores=Join-Path $badRoot 'cores'
    [IO.Directory]::CreateDirectory($badCores) | Out-Null
    $linuxAsset=@($assets | Where-Object { $_.Platform -ceq 'sing-box-arm64' })[0]
    $windowsAsset=@($assets | Where-Object { $_.Platform -ceq 'sing-box-check' })[0]
    Copy-Item -LiteralPath (Join-Path $sourceRoot $linuxAsset.Name) -Destination (Join-Path $badCores $linuxAsset.Name)
    $badDownloads=Join-Path $badRoot 'downloads'
    [IO.Directory]::CreateDirectory($badDownloads) | Out-Null
    $badCandidate=Join-Path $badDownloads $windowsAsset.Name
    [IO.File]::WriteAllBytes($badCandidate,[byte[]](1,3,3,7,9))
    $badCandidateHash=(Get-FileHash -LiteralPath $badCandidate -Algorithm SHA256).Hash
    $badHashRejected=$false
    try { $null=Install-OpenWrtBuildCores -Root $badCores -DownloadDirectory $badDownloads -ExtractionDirectory (Join-Path $badRoot 'extract') -Offline }
    catch { $badHashRejected=$true }
    Assert-TestCondition $badHashRejected 'An unpinned archive must be rejected.'
    Assert-TestCondition ((Get-FileHash -LiteralPath $badCandidate -Algorithm SHA256).Hash -ceq $badCandidateHash) 'The rejected archive candidate must remain byte-identical.'
    Assert-TestCondition (-not [IO.Directory]::Exists((Join-Path $badCores 'sing-box-check'))) 'A bad Windows archive must not publish a checker tree.'

    $conflictRoot=New-FreshCoreRoot 'conflict'
    $conflictCores=Join-Path $conflictRoot 'cores'
    $linuxVersion=([string]$linuxAsset.Binary).Split('/')[0]
    $conflictTree=Join-Path (Join-Path $conflictCores $linuxAsset.Platform) $linuxVersion
    [IO.Directory]::CreateDirectory($conflictTree) | Out-Null
    $conflictMarker=Join-Path $conflictTree 'unknown.keep'
    [IO.File]::WriteAllText($conflictMarker,'do not replace')
    $conflictHash=(Get-FileHash -LiteralPath $conflictMarker -Algorithm SHA256).Hash
    $conflictRejected=$false
    try { $null=Install-OpenWrtBuildCores -Root $conflictCores -DownloadDirectory $sourceRoot -ExtractionDirectory (Join-Path $conflictRoot 'extract') -Offline }
    catch { $conflictRejected=$true }
    Assert-TestCondition $conflictRejected 'An existing conflicting target version tree must be rejected.'
    Assert-TestCondition ([IO.File]::Exists($conflictMarker) -and (Get-FileHash -LiteralPath $conflictMarker -Algorithm SHA256).Hash -ceq $conflictHash) 'A conflicting existing core tree must remain unchanged.'

    $pathAsset=[pscustomobject]@{ Name='fixture.zip'; Binary='sing-box-1.14.4-windows-amd64/sing-box.exe' }
    $traversalRejected=$false
    try { $null=ConvertTo-OpenWrtOfficialArchivePath -EntryPath '../escape.txt' -Asset $pathAsset }
    catch { $traversalRejected=$true }
    Assert-TestCondition $traversalRejected 'Traversal member paths must be rejected.'

    Add-Type -AssemblyName System.IO.Compression
    $maliciousZip=Join-Path $runRoot 'symlink.zip'
    $fileStream=[IO.File]::Open($maliciousZip,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $zip=[IO.Compression.ZipArchive]::new($fileStream,[IO.Compression.ZipArchiveMode]::Create,$false)
        try {
            $entry=$zip.CreateEntry('sing-box-1.14.4-windows-amd64/sing-box.exe')
            $entry.ExternalAttributes=-1610612736
            $writer=[IO.StreamWriter]::new($entry.Open())
            try { $writer.Write('fixture-link') } finally { $writer.Dispose() }
        }
        finally { $zip.Dispose() }
    }
    finally { if ($fileStream) { $fileStream.Dispose() } }
    $linkStage=Join-Path $runRoot 'link-stage'
    $symlinkRejected=$false
    try { Expand-OpenWrtOfficialAsset -Asset $pathAsset -Archive $maliciousZip -Stage $linkStage }
    catch { $symlinkRejected=$true }
    Assert-TestCondition $symlinkRejected 'A ZIP link member must be rejected before extraction.'
    Assert-TestCondition (-not [IO.File]::Exists((Join-Path $linkStage 'sing-box-1.14.4-windows-amd64\sing-box.exe'))) 'A rejected ZIP link must not materialize a file.'

    Write-Output 'OFFICIAL_CORE_INSTALLATION_TESTS=PASS'
    Write-Output 'COVERAGE=old-version-coexistence,new-version-extraction,bad-hash,conflict-preservation,path-traversal,zip-symlink'
    Write-Output ('FIXTURE_ROOT='+$runRoot)
}
finally {
    if ([IO.Directory]::Exists($runRoot)) {
        $items=@(Get-ChildItem -LiteralPath $runRoot -Force -Recurse -ErrorAction Stop)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'Refusing to clean a fixture containing reparse points.' }
        Remove-Item -LiteralPath $runRoot -Recurse -Force
    }
}
