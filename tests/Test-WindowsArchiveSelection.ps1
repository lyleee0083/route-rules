[CmdletBinding()]
param([string]$TaskDirectory)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($TaskDirectory)) { $TaskDirectory = [IO.Path]::GetTempPath() }
$fixtureParent = [IO.Path]::GetFullPath($TaskDirectory).TrimEnd([char[]]'\/')
if (-not [IO.Directory]::Exists($fixtureParent)) { throw "Test parent directory is missing: $fixtureParent" }
$cursor = $fixtureParent
while ($cursor) {
    try { $attributes = [IO.File]::GetAttributes($cursor) }
    catch { throw "Cannot inspect test parent path: $cursor`n$($_.Exception.Message)" }
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unsafe test parent path: $cursor" }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
    $cursor = $parent
}
$runRoot = Join-Path $fixtureParent ('windows-archive-selection-' + [guid]::NewGuid().ToString('N'))
$acceptedArchive = [IO.Compression.ZipFile]::OpenRead((Join-Path $projectRoot 'generated\sing-box-configs.zip'))
try {
    $acceptedEntry = $acceptedArchive.GetEntry('sing-box-windows-tun.json')
    if ($null -eq $acceptedEntry) { throw 'The accepted client archive has no Windows config fixture.' }
    $acceptedStream = $acceptedEntry.Open()
    try {
        $acceptedReader = New-Object IO.StreamReader($acceptedStream, [Text.Encoding]::UTF8, $true)
        try { $script:archiveSelectionTemplate = $acceptedReader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop }
        finally { $acceptedReader.Dispose() }
    } finally { $acceptedStream.Dispose() }
} finally { $acceptedArchive.Dispose() }
function Assert-ArchiveSelectionTest { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Write-ArchiveSelectionFile { param([string]$Path,[byte[]]$Bytes) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllBytes($Path,$Bytes) }
function New-ArchiveSelectionConfig {
    param([string]$LogLevel)
    $configuration = $script:archiveSelectionTemplate | ConvertTo-Json -Depth 100 | ConvertFrom-Json
    $configuration.log.level = $LogLevel
    $sourceNode = @($configuration.outbounds | Where-Object { $_.type -ceq 'vless' }) | Select-Object -First 1
    if ($null -eq $sourceNode) { throw 'The accepted client config has no VLESS resolver fixture.' }
    $resolver = $sourceNode.domain_resolver
    $configuration.outbounds = @(
        [pscustomobject][ordered]@{ type='direct'; tag='direct' },
        [pscustomobject][ordered]@{ type='direct'; tag='proxy' },
        [pscustomobject][ordered]@{ type='selector'; tag='dns-direct-out'; outbounds=@('direct'); default='direct' },
        [pscustomobject][ordered]@{ type='selector'; tag='dns-proxy-out'; outbounds=@('proxy'); default='proxy' },
        [pscustomobject][ordered]@{ type='vless'; tag='fixture-node'; server='192.0.2.10'; server_port=443; uuid='00000000-0000-0000-0000-000000000000'; domain_resolver=$resolver }
    )
    return $configuration
}
function New-ArchiveSelectionZip {
    param([string]$ArchivePath,[string]$Marker)
    $source = Join-Path $runRoot ('zip-source-' + $Marker)
    [IO.Directory]::CreateDirectory((Join-Path $source 'rule-set')) | Out-Null
    $logLevel = 'info'
    if ($Marker -eq 'selected') { $logLevel = 'warn' }
    elseif ($Marker -eq 'external') { $logLevel = 'debug' }
    elseif ($Marker -eq 'linked') { $logLevel = 'error' }
    $configText = ConvertTo-Json -InputObject (New-ArchiveSelectionConfig -LogLevel $logLevel) -Depth 20
    $configBytes = (New-Object Text.UTF8Encoding($false)).GetBytes($configText.Replace("`r`n","`n") + "`n")
    Write-ArchiveSelectionFile (Join-Path $source 'sing-box-windows-tun.json') $configBytes
    foreach ($name in @('routing-direct-domain.srs','routing-direct-port.srs','routing-direct-ip.srs')) {
        Write-ArchiveSelectionFile (Join-Path (Join-Path $source 'rule-set') $name) ((New-Object Text.UTF8Encoding($false)).GetBytes($Marker + ':' + $name))
    }
    $stream = [IO.File]::Open($ArchivePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            $names = @('sing-box-windows-tun.json','rule-set/routing-direct-domain.srs','rule-set/routing-direct-port.srs','rule-set/routing-direct-ip.srs')
            foreach ($name in $names) {
                $local = Join-Path $source ($name.Replace('/',[IO.Path]::DirectorySeparatorChar))
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$local,$name,[IO.Compression.CompressionLevel]::Optimal)
            }
        } finally { $zip.Dispose() }
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}
function Remove-ArchiveSelectionJunction {
    param([string]$Path,[string]$FixtureRoot,[string]$TargetSentinel,[string]$ExpectedHash)
    $root = [IO.Path]::GetFullPath($FixtureRoot).TrimEnd([char[]]'\/')
    $full = [IO.Path]::GetFullPath($Path)
    $sentinel = [IO.Path]::GetFullPath($TargetSentinel)
    if (-not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        -not $sentinel.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        $sentinel.StartsWith($full + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing junction cleanup outside its fixture or through its target.' }
    $link = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -eq $link) { return }
    if (-not $link.PSIsContainer -or -not ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Refusing to remove a non-reparse fixture object as a junction.' }
    if ((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -cne $ExpectedHash) { throw 'Junction target archive changed; preserving fixture.' }
    [IO.Directory]::Delete($full,$false)
    if (Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue) { throw 'Fixture junction entry remained after non-recursive deletion.' }
    if (-not [IO.File]::Exists($sentinel) -or (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -cne $ExpectedHash) { throw 'Fixture junction deletion changed its target archive.' }
}

. (Join-Path $projectRoot 'scripts\Build-Transaction.ps1')
. (Join-Path $projectRoot 'scripts\Windows-Deployment.ps1')
[IO.Directory]::CreateDirectory($runRoot) | Out-Null
$junctionPath = $null
try {
    $fixtureProject = Join-Path $runRoot 'project'
    $generated = Join-Path $fixtureProject 'generated'
    $versioned = Join-Path $generated '2026-10-25-performance'
    [IO.Directory]::CreateDirectory($versioned) | Out-Null
    $defaultArchive = Join-Path $generated 'sing-box-configs.zip'
    $versionedArchive = Join-Path $versioned 'sing-box-configs.zip'
    New-ArchiveSelectionZip -ArchivePath $defaultArchive -Marker 'old'
    New-ArchiveSelectionZip -ArchivePath $versionedArchive -Marker 'selected'
    $defaultHashBefore = (Get-FileHash -LiteralPath $defaultArchive -Algorithm SHA256).Hash
    $versionedHashBefore = (Get-FileHash -LiteralPath $versionedArchive -Algorithm SHA256).Hash

    $defaultResolved = Resolve-WindowsArchivePath -ArchivePath '' -ProjectRoot $fixtureProject
    $selectedResolved = Resolve-WindowsArchivePath -ArchivePath $versionedArchive -ProjectRoot $fixtureProject
    Assert-ArchiveSelectionTest ($defaultResolved -ceq [IO.Path]::GetFullPath($defaultArchive)) 'Omitting ArchivePath no longer selects the legacy formal ZIP.'
    Assert-ArchiveSelectionTest ($selectedResolved -ceq [IO.Path]::GetFullPath($versionedArchive)) 'The explicit versioned archive path was not selected.'
    Assert-ArchiveSelectionTest ((Get-WindowsArchivePublisherRoot -ArchivePath $selectedResolved -ProjectRoot $fixtureProject) -ceq [IO.Path]::GetFullPath($generated)) 'Versioned generated archive did not map to the root publisher lock.'

    $stage = Join-Path $runRoot 'selected-stage'
    [IO.Directory]::CreateDirectory((Join-Path $stage 'rule-set')) | Out-Null
    $snapshot = Import-WindowsArchiveToStage -ArchivePath $selectedResolved -StageDirectory $stage
    Assert-ArchiveSelectionTest ($snapshot.RuleSetCount -eq 3) 'Selected version did not stage exactly three referenced SRS files.'
    Assert-ArchiveSelectionTest ($snapshot.ArchiveSha256 -ceq $versionedHashBefore) 'Staged archive digest differs from the selected ZIP.'
    $stagedConfig = Read-StrictJsonFile -Path $snapshot.ConfigPath
    Assert-ArchiveSelectionTest ($stagedConfig.log.level -ceq 'warn') 'Staged Windows JSON did not come from the selected ZIP.'
    foreach ($name in @('routing-direct-domain.srs','routing-direct-port.srs','routing-direct-ip.srs')) {
        $relative = 'rule-set/' + $name
        $stagedPath = Join-Path (Join-Path $stage 'rule-set') $name
        $expected = 'selected:' + $name
        Assert-ArchiveSelectionTest ([IO.File]::ReadAllText($stagedPath) -ceq $expected) ('Staged rule-set bytes did not come from the selected ZIP: ' + $name)
        Assert-ArchiveSelectionTest ((Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash -ceq $snapshot.ExpectedHashes[$relative]) ('Staged rule-set hash differs from its archive entry: ' + $name)
    }
    Assert-ArchiveSelectionTest ((Get-FileHash -LiteralPath $defaultArchive -Algorithm SHA256).Hash -ceq $defaultHashBefore) 'Explicit selection modified the default ZIP.'

    $unsafeArchive = Join-Path $runRoot 'unsafe.zip'
    $unsafeStream = [IO.File]::Open($unsafeArchive,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $unsafeZip = [IO.Compression.ZipArchive]::new($unsafeStream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            $unsafeEntry = $unsafeZip.CreateEntry('../escape.txt')
            $unsafeEntryStream = $unsafeEntry.Open()
            try { $unsafeBytes = (New-Object Text.UTF8Encoding($false)).GetBytes('must-not-extract'); $unsafeEntryStream.Write($unsafeBytes,0,$unsafeBytes.Length) } finally { $unsafeEntryStream.Dispose() }
        } finally { $unsafeZip.Dispose() }
        $unsafeStream.Flush($true)
    } finally { $unsafeStream.Dispose() }
    $unsafeStage = Join-Path $runRoot 'unsafe-stage'
    [IO.Directory]::CreateDirectory((Join-Path $unsafeStage 'rule-set')) | Out-Null
    $failed = $false
    try { Import-WindowsArchiveToStage -ArchivePath $unsafeArchive -StageDirectory $unsafeStage | Out-Null } catch { $failed = $true }
    Assert-ArchiveSelectionTest $failed 'A ZIP path-traversal entry was accepted.'
    Assert-ArchiveSelectionTest (@(Get-ChildItem -LiteralPath $unsafeStage -Recurse -File -Force).Count -eq 0) 'Unsafe ZIP content was extracted before validation.'
    Assert-ArchiveSelectionTest (-not (Test-Path -LiteralPath (Join-Path $runRoot 'escape.txt'))) 'Unsafe ZIP entry escaped its stage.'

    $fixtureRuntime = Join-Path $runRoot 'runtime'
    $locks = Enter-WindowsDeploymentLocks -RuntimeDirectory $fixtureRuntime -ArchivePath $selectedResolved -ProjectRoot $fixtureProject -TimeoutSeconds 1
    try {
        $publisherPaths = Get-BuildPaths $generated
        Assert-ArchiveSelectionTest ($locks.PublisherPaths.Lock -ceq $publisherPaths.Lock) 'Deployment did not hold the formal generated publisher lock.'
        Assert-ArchiveSelectionTest ([IO.File]::Exists($publisherPaths.Lock)) 'Formal generated publisher lock was not acquired.'
        $nestedLock = Join-Path $generated '2026-10-25-performance.build.lock'
        Assert-ArchiveSelectionTest (-not [IO.File]::Exists($nestedLock)) 'Versioned archive selection created a lock inside the formal generated tree.'
        $blocked = $false
        try { Enter-BuildLock $publisherPaths -TimeoutSeconds 1 | Out-Null } catch { $blocked = $true }
        Assert-ArchiveSelectionTest $blocked 'Versioned archive deployment did not mutually exclude the formal root publisher.'
    } finally { Exit-WindowsDeploymentLocks $locks }

    $external = Join-Path $runRoot 'external-input'
    [IO.Directory]::CreateDirectory($external) | Out-Null
    $externalArchive = Join-Path $external 'external.zip'
    New-ArchiveSelectionZip -ArchivePath $externalArchive -Marker 'external'
    $externalLocks = Enter-WindowsDeploymentLocks -RuntimeDirectory (Join-Path $runRoot 'external-runtime') -ArchivePath $externalArchive -ProjectRoot $fixtureProject -TimeoutSeconds 1
    try {
        Assert-ArchiveSelectionTest ($null -eq $externalLocks.Build) 'External input opened an unconfigured sibling project lock.'
        Assert-ArchiveSelectionTest (-not [IO.File]::Exists((Join-Path $runRoot 'external-input.build.lock'))) 'External input created a project lock next to the source.'
    } finally { Exit-WindowsDeploymentLocks $externalLocks }

    $target = Join-Path $runRoot 'archive-target'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    $targetArchive = Join-Path $target 'sing-box-configs.zip'
    New-ArchiveSelectionZip -ArchivePath $targetArchive -Marker 'linked'
    $targetArchiveHash = (Get-FileHash -LiteralPath $targetArchive -Algorithm SHA256).Hash
    $junctionPath = Join-Path $runRoot 'archive-junction'
    New-Item -ItemType Junction -Path $junctionPath -Target $target | Out-Null
    $failed = $false
    try { Resolve-WindowsArchivePath -ArchivePath (Join-Path $junctionPath 'sing-box-configs.zip') -ProjectRoot $fixtureProject | Out-Null } catch { $failed = $true }
    Assert-ArchiveSelectionTest $failed 'Archive selection accepted a reparse-point ancestor.'
    Remove-ArchiveSelectionJunction -Path $junctionPath -FixtureRoot $runRoot -TargetSentinel $targetArchive -ExpectedHash $targetArchiveHash
    $junctionPath = $null

    Assert-ArchiveSelectionTest ((Get-FileHash -LiteralPath $defaultArchive -Algorithm SHA256).Hash -ceq $defaultHashBefore) 'Default ZIP hash changed after explicit versioned staging.'
    Assert-ArchiveSelectionTest ((Get-FileHash -LiteralPath $versionedArchive -Algorithm SHA256).Hash -ceq $versionedHashBefore) 'Selected ZIP hash changed during validation.'
    Write-Output 'Windows archive selection fixtures passed: default and explicit paths, full ZIP/path validation, selected JSON and three SRS byte source, root publisher-lock exclusion, external no-sidecar behavior, and reparse ancestor rejection.'
}
finally {
    if ($junctionPath) { Remove-ArchiveSelectionJunction -Path $junctionPath -FixtureRoot $runRoot -TargetSentinel $targetArchive -ExpectedHash $targetArchiveHash }
    if (Test-Path -LiteralPath $runRoot) {
        $resolvedRunRoot = [IO.Path]::GetFullPath($runRoot).TrimEnd([char[]]'\/')
        if ((Split-Path -Parent $resolvedRunRoot) -ine $fixtureParent -or (Split-Path -Leaf $resolvedRunRoot) -notmatch '^windows-archive-selection-[a-f0-9]{32}$') {
            throw "Unsafe archive-selection test cleanup path: $resolvedRunRoot"
        }
        $items = @((Get-Item -LiteralPath $runRoot -Force)) + @(Get-ChildItem -LiteralPath $runRoot -Recurse -Force)
        if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw "Refusing test cleanup through a reparse point: $runRoot" }
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop
    }
}
