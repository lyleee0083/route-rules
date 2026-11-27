[CmdletBinding()]
param(
    [string]$SingBoxPath,
    [ValidateRange(10,600)][int]$ProducerTimeoutSeconds=180,
    [switch]$AliasPreflightOnly,
    [switch]$LockProbe,
    [string]$LockPackageDirectory,
    [string]$LockSupportDirectory,
    [string]$LockMarker,
    [string]$FixtureParentDirectory,
    [string]$SourceRoot,
    [string]$LinuxArchivePath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$projectRoot=Split-Path -Parent $openWrtRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
$canonicalSourceRoot=Join-Path $openWrtRoot 'inputs/linux'
$canonicalLinuxArchive=Join-Path $projectRoot 'outputs/openwrt-client/sing-box-configs.zip'
if ([string]::IsNullOrWhiteSpace($SourceRoot) -xor [string]::IsNullOrWhiteSpace($LinuxArchivePath)) { throw 'SourceRoot and LinuxArchivePath must be supplied together.' }
if ([string]::IsNullOrWhiteSpace($SourceRoot)) { $SourceRoot=$canonicalSourceRoot; $LinuxArchivePath=$canonicalLinuxArchive }
if (-not [IO.Directory]::Exists($SourceRoot) -or -not [IO.File]::Exists($LinuxArchivePath)) { throw 'Publication test source snapshot and Linux archive must both exist.' }
. (Join-Path $scriptsRoot 'OpenWrt-Build.ps1')
. (Join-Path $scriptsRoot 'Native-PackageValidation.ps1')
. (Join-Path $scriptsRoot 'Final-LinuxSnapshot.ps1')
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
. (Join-Path $scriptsRoot 'Mosdns-Policy.ps1')
. (Join-Path $scriptsRoot 'OpenWrt-AdapterCache.ps1')
if (-not $SingBoxPath) { $SingBoxPath=(Get-OpenWrtCorePaths)['sing-box-check'] }
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$goEnvironment=@{}
foreach ($name in @('GOPROXY','GOSUMDB','GOTOOLCHAIN')) { $goEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
try {
    [Environment]::SetEnvironmentVariable('GOPROXY','off','Process')
    [Environment]::SetEnvironmentVariable('GOSUMDB','off','Process')
    [Environment]::SetEnvironmentVariable('GOTOOLCHAIN','local','Process')
    if ($LockProbe) {
        $probeLocks=Enter-OpenWrtArtifactLocks -PackagePaths (Get-BuildPaths $LockPackageDirectory) -SupportPaths (Get-BuildPaths $LockSupportDirectory) -TimeoutSeconds 20
        try {
            [IO.File]::WriteAllText($LockMarker,'acquired',(New-Object Text.UTF8Encoding($false)))
            Start-Sleep -Milliseconds 500
        } finally { Exit-OpenWrtArtifactLocks $probeLocks }
        return
    }
$workRoot=[IO.Path]::GetFullPath((Join-Path $projectRoot 'work')).TrimEnd('\')
$outputsRoot=[IO.Path]::GetFullPath((Join-Path $openWrtRoot 'outputs')).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($FixtureParentDirectory)) {
    $taskDate=[DateTime]::Now.ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)
    $FixtureParentDirectory=Join-Path (Join-Path $workRoot ($taskDate+'-openwrt-publication-test')) 'tmp'
}
$fixtureRootParent=[IO.Path]::GetFullPath($FixtureParentDirectory).TrimEnd('\')
$pathComparison=[StringComparison]::Ordinal
if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $pathComparison=[StringComparison]::OrdinalIgnoreCase }
$underWork=(Test-OpenWrtPathContains -Parent $workRoot -Child $fixtureRootParent -Comparison $pathComparison) -and -not $fixtureRootParent.Equals($workRoot,$pathComparison)
$underOutputs=(Test-OpenWrtPathContains -Parent $outputsRoot -Child $fixtureRootParent -Comparison $pathComparison) -and -not $fixtureRootParent.Equals($outputsRoot,$pathComparison)
if (-not ($underWork -or $underOutputs)) { throw 'FixtureParentDirectory must be a strict subdirectory of project work/ or openwrt/outputs/.' }
$currentFixtureAncestor=$fixtureRootParent
while ($currentFixtureAncestor) {
    if (Test-Path -LiteralPath $currentFixtureAncestor) {
        $ancestorItem=Get-Item -LiteralPath $currentFixtureAncestor -Force -ErrorAction Stop
        if (-not $ancestorItem.PSIsContainer -or ($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw ('Unsafe publication fixture ancestor: '+$ancestorItem.FullName) }
    }
    $parentFixtureAncestor=Split-Path -Parent $currentFixtureAncestor
    if ([string]::IsNullOrWhiteSpace($parentFixtureAncestor) -or $parentFixtureAncestor -ceq $currentFixtureAncestor) { break }
    $currentFixtureAncestor=$parentFixtureAncestor
}
if (-not [IO.Directory]::Exists($fixtureRootParent)) { [IO.Directory]::CreateDirectory($fixtureRootParent) | Out-Null }
$currentFixtureAncestor=$fixtureRootParent
while ($currentFixtureAncestor) {
    if (Test-Path -LiteralPath $currentFixtureAncestor) {
        $ancestorItem=Get-Item -LiteralPath $currentFixtureAncestor -Force -ErrorAction Stop
        if (-not $ancestorItem.PSIsContainer -or ($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw ('Unsafe publication fixture ancestor: '+$ancestorItem.FullName) }
    }
    $parentFixtureAncestor=Split-Path -Parent $currentFixtureAncestor
    if ([string]::IsNullOrWhiteSpace($parentFixtureAncestor) -or $parentFixtureAncestor -ceq $currentFixtureAncestor) { break }
    $currentFixtureAncestor=$parentFixtureAncestor
}
$fixtureRoot=Join-Path $fixtureRootParent ('owpt-'+[guid]::NewGuid().ToString('N'))
function Assert-Publication { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-TransactionAliasRejected {
    param([string]$PackageDirectory,[string]$SupportDirectory,[string]$Description)
    $packagePaths=Get-BuildPaths $PackageDirectory
    $supportPaths=Get-BuildPaths $SupportDirectory
    $coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
    $failed=$false
    try { Assert-OpenWrtArtifactPathSet -PackagePaths $packagePaths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
    catch { $failed=$_.Exception.Message -match '^OpenWrt artifact transaction paths overlap:' }
    Assert-Publication $failed ('Transaction alias was not rejected: '+$Description)
}
function Test-OpenWrtTransactionAliasMatrix {
    param([string]$FixtureRoot)
    $forwardAliasKinds=@('stage','backup','journal','journal-write','lock','coordinator','coordinator-write')
    foreach ($kind in $forwardAliasKinds) {
        $base=Join-Path $FixtureRoot ('alias-forward-'+$kind)
        $packagePaths=Get-BuildPaths $base
        if ($kind -eq 'stage') { $supportDirectory=$packagePaths.Stage }
        elseif ($kind -eq 'backup') { $supportDirectory=$packagePaths.Backup }
        elseif ($kind -eq 'journal') { $supportDirectory=$packagePaths.Journal }
        elseif ($kind -eq 'journal-write') { $supportDirectory=$packagePaths.Journal+'.write' }
        elseif ($kind -eq 'lock') { $supportDirectory=$packagePaths.Lock }
        else {
            $coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
            if ($kind -eq 'coordinator') { $supportDirectory=$coordinatorPath }
            else { $supportDirectory=$coordinatorPath+'.write' }
        }
        Assert-TransactionAliasRejected -PackageDirectory $base -SupportDirectory $supportDirectory -Description ('support destination equals package '+$kind)
    }
    $reverseAliasKinds=@('stage','backup','journal','journal-write','lock')
    foreach ($kind in $reverseAliasKinds) {
        $supportDirectory=Join-Path $FixtureRoot ('alias-reverse-'+$kind)
        $supportPaths=Get-BuildPaths $supportDirectory
        if ($kind -eq 'stage') { $packageDirectory=$supportPaths.Stage }
        elseif ($kind -eq 'backup') { $packageDirectory=$supportPaths.Backup }
        elseif ($kind -eq 'journal') { $packageDirectory=$supportPaths.Journal }
        elseif ($kind -eq 'journal-write') { $packageDirectory=$supportPaths.Journal+'.write' }
        else { $packageDirectory=$supportPaths.Lock }
        Assert-TransactionAliasRejected -PackageDirectory $packageDirectory -SupportDirectory $supportDirectory -Description ('package destination equals support '+$kind)
    }
    foreach ($kind in @('coordinator','coordinator-write')) {
        $base=Join-Path $FixtureRoot ('alias-parent-'+$kind)
        $packagePaths=Get-BuildPaths $base
        $coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
        if ($kind -eq 'coordinator') { $supportDirectory=Join-Path $coordinatorPath 'child' }
        else { $supportDirectory=Join-Path ($coordinatorPath+'.write') 'child' }
        Assert-TransactionAliasRejected -PackageDirectory $base -SupportDirectory $supportDirectory -Description ($kind+' is a parent of the support destination')
    }
}
function Test-OpenWrtProducerAliasPreflight {
    param([string]$FixtureRoot,[string]$ArchivePath,[string]$SourceRoot,[string]$SingBoxPath,[string]$ScriptsRoot)
    $preflightInput=Join-Path $FixtureRoot 'preflight-input'
    New-Item -ItemType Directory -Path $preflightInput | Out-Null
    $preflightArchive=Join-Path $preflightInput 'input.zip'
    Copy-Item -LiteralPath $ArchivePath -Destination $preflightArchive
    $preflightOutput=Join-Path $FixtureRoot 'preflight-output'
    $preflightSupport=$preflightOutput+'.build-stage'
    $failed=$false
    try {
        & (Join-Path $ScriptsRoot 'Build-OpenWrtPackage.ps1') -LinuxArchivePath $preflightArchive -SourceRoot $SourceRoot -OutputDirectory $preflightOutput -BuildSupportDirectory $preflightSupport -Force -SingBoxPath $SingBoxPath | Out-Null
    } catch { $failed=$_.Exception.Message -match '^OpenWrt artifact transaction paths overlap:' }
    Assert-Publication $failed 'Public producer did not reject transaction aliases during preflight.'
    $preflightPackagePaths=Get-BuildPaths $preflightOutput
    $preflightSupportPaths=Get-BuildPaths $preflightSupport
    $preflightCoordinator=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $preflightPackagePaths
    foreach ($pending in @($preflightPackagePaths.Destination,$preflightPackagePaths.Stage,$preflightPackagePaths.Backup,$preflightPackagePaths.Journal,($preflightPackagePaths.Journal+'.write'),$preflightPackagePaths.Lock,$preflightSupportPaths.Destination,$preflightSupportPaths.Stage,$preflightSupportPaths.Backup,$preflightSupportPaths.Journal,($preflightSupportPaths.Journal+'.write'),$preflightSupportPaths.Lock,$preflightCoordinator,($preflightCoordinator+'.write'),((Get-BuildPaths $preflightInput).Lock))) {
        Assert-Publication (-not (Test-Path -LiteralPath $pending)) ('Alias preflight created or modified a path before rejection: '+$pending)
    }
}
function Test-OpenWrtInputTransactionAliases {
    param([string]$FixtureRoot,[string]$ArchivePath,[string]$SourceRoot,[string]$SingBoxPath,[string]$ScriptsRoot)
    $buildScript = Join-Path $ScriptsRoot 'Build-OpenWrtPackage.ps1'
    $syncScript = Join-Path $ScriptsRoot 'Sync-FinalLinuxSnapshot.ps1'
    foreach ($slot in @('Stage','Backup')) {
        $snapshot = Join-Path $FixtureRoot ('input-alias-' + $slot.ToLowerInvariant())
        $snapshotPaths = Get-BuildPaths $snapshot
        $archiveDirectory = $snapshotPaths.$slot
        [IO.Directory]::CreateDirectory($archiveDirectory) | Out-Null
        $inputZip = Join-Path $archiveDirectory 'input.zip'
        [IO.File]::Copy($ArchivePath,$inputZip)
        $hash = (Get-FileHash -LiteralPath $inputZip).Hash
        foreach ($entryPoint in @($syncScript,$buildScript)) {
            $arguments = @{ LinuxArchivePath=$inputZip; SourceRoot=$snapshot }
            if ($entryPoint -eq $buildScript) {
                $arguments['OutputDirectory'] = Join-Path $FixtureRoot ('input-alias-package-' + $slot.ToLowerInvariant())
                $arguments['SingBoxPath'] = $SingBoxPath
            }
            $failed = $false
            try { & $entryPoint @arguments | Out-Null }
            catch { $failed = $_.Exception.Message -match '^OpenWrt transaction path overlaps an input or protected path:' }
            Assert-Publication $failed ('The producer did not reject a source archive inside the snapshot ' + $slot)
            Assert-Publication ((Get-FileHash -LiteralPath $inputZip).Hash -ceq $hash) 'Alias rejection changed the input ZIP.'
            Assert-Publication (-not (Test-Path -LiteralPath $snapshotPaths.Lock) -and -not (Test-Path -LiteralPath (Get-BuildPaths $archiveDirectory).Lock)) 'Alias rejection happened after creating an input lock.'
        }
    }
    $output = Join-Path $FixtureRoot 'archive-in-output-stage'
    $outputPaths = Get-BuildPaths $output
    [IO.Directory]::CreateDirectory($outputPaths.Stage) | Out-Null
    $inputZip = Join-Path $outputPaths.Stage 'input.zip'
    [IO.File]::Copy($ArchivePath,$inputZip)
    $hash = (Get-FileHash -LiteralPath $inputZip).Hash
    $failed = $false
    try { & $buildScript -LinuxArchivePath $inputZip -SourceRoot $SourceRoot -OutputDirectory $output -SingBoxPath $SingBoxPath | Out-Null }
    catch { $failed = $_.Exception.Message -match '^OpenWrt transaction path overlaps an input or protected path:' }
    Assert-Publication $failed 'The package producer accepted an archive inside its output stage.'
    Assert-Publication ((Get-FileHash -LiteralPath $inputZip).Hash -ceq $hash) 'The package producer changed its source archive.'
    Assert-Publication (-not (Test-Path -LiteralPath $outputPaths.Lock) -and -not (Test-Path -LiteralPath (Get-BuildPaths $outputPaths.Stage).Lock)) 'The package producer acquired a lock before rejecting the alias.'
}
function Put-Publication { param([string]$Path,[string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false))) }
function ConvertTo-PublicationPowerShellLiteral {
    param([Parameter(Mandatory)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}
function Test-CleanManifestReaderSession {
    param([string]$FixtureRoot,[string]$BuildModulePath,[string]$OutputDirectory)
    $childScript=Join-Path $FixtureRoot 'fresh-manifest-reader.ps1'
    $moduleLiteral=ConvertTo-PublicationPowerShellLiteral -Value ([IO.Path]::GetFullPath($BuildModulePath))
    $outputLiteral=ConvertTo-PublicationPowerShellLiteral -Value ([IO.Path]::GetFullPath($OutputDirectory))
    $childLines=@(
        '$ErrorActionPreference = ''Stop'''
        '$initialZipTypeLoaded = $null -ne (''System.IO.Compression.ZipFile'' -as [type])'
        'if ($PSVersionTable.PSEdition -eq ''Desktop'' -and $initialZipTypeLoaded) { throw ''Fresh Windows PowerShell process unexpectedly preloaded the ZIP filesystem assembly.'' }'
        ('. ' + $moduleLiteral)
        ('$manifest = Read-OpenWrtBuildManifest -OutputDirectory ' + $outputLiteral)
        'if (-not $manifest.package_sha256 -or $manifest.package_sha256 -notmatch ''^[A-Fa-f0-9]{64}$'') { throw ''Fresh-session manifest result has no valid package SHA-256.'' }'
        'if (-not (''System.IO.Compression.ZipFile'' -as [type])) { throw ''Read-OpenWrtBuildManifest did not load its ZIP dependency.'' }'
        'Write-Output (''FRESH_MANIFEST_READ_PASS initial_zip_type_loaded='' + $initialZipTypeLoaded.ToString().ToLowerInvariant())'
    )
    [IO.File]::WriteAllLines($childScript,[string[]]$childLines,(New-Object Text.UTF8Encoding($false)))
    if ($PSVersionTable.PSEdition -eq 'Core') { $executable=Join-Path $PSHOME 'pwsh.exe' }
    else { $executable=Join-Path $PSHOME 'powershell.exe' }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw ('Current PowerShell executable was not found: '+$executable) }
    $processInfo=New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName=$executable
    $processInfo.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$childScript+'"'
    $processInfo.UseShellExecute=$false
    $processInfo.CreateNoWindow=$true
    $processInfo.RedirectStandardOutput=$true
    $processInfo.RedirectStandardError=$true
    $child=New-Object Diagnostics.Process
    $child.StartInfo=$processInfo
    try {
        if (-not $child.Start()) { throw 'Fresh PowerShell manifest-reader process did not start.' }
        $stdoutTask=$child.StandardOutput.ReadToEndAsync()
        $stderrTask=$child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(60000)) {
            try { $child.Kill() } catch {}
            if (-not $child.WaitForExit(5000)) { throw 'Fresh PowerShell manifest-reader process exceeded 60 seconds and termination was not confirmed.' }
            throw 'Fresh PowerShell manifest-reader session exceeded 60 seconds.'
        }
        $child.WaitForExit()
        if (-not $stdoutTask.Wait(5000) -or -not $stderrTask.Wait(5000)) { throw 'Fresh PowerShell manifest-reader output streams did not close after process exit.' }
        $stdout=[string]$stdoutTask.Result
        $stderr=[string]$stderrTask.Result
        $exitCode=$child.ExitCode
        if ($exitCode -ne 0 -or $stdout -notmatch '(?m)^FRESH_MANIFEST_READ_PASS\s+initial_zip_type_loaded=(true|false)\s*$') {
            throw ('Fresh PowerShell manifest-reader session failed (exit '+$exitCode+'). stdout='+$stdout+' stderr='+$stderr)
        }
    } finally {
        $child.Dispose()
    }
}
function Assert-PublicationPathSafe {
    param([string]$Path,[string]$FixtureRoot)
    $root=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
    $resolved=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ((Split-Path -Leaf $root) -notmatch '^owpt-[a-f0-9]{32}$' -or ($resolved -cne $root -and -not $resolved.StartsWith(($root+'\'),[StringComparison]::OrdinalIgnoreCase))) { throw 'Publication test path escaped its isolated fixture.' }
    $current=$resolved
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item=Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Publication fixture path traverses a reparse point: '+$item.FullName) }
        }
        $parent=Split-Path -Parent $current
        if (-not $parent -or $parent -ceq $current) { break }
        $current=$parent
    }
}
function Assert-PublicationTreeSafe {
    param([string]$FixtureRoot)
    Assert-PublicationPathSafe -Path $FixtureRoot -FixtureRoot $FixtureRoot
    $pending=[Collections.Generic.Stack[string]]::new()
    $pending.Push([IO.Path]::GetFullPath($FixtureRoot))
    while ($pending.Count) {
        $directory=$pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Publication fixture cleanup found a reparse point: '+$item.FullName) }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}
Assert-PublicationPathSafe -Path $fixtureRoot -FixtureRoot $fixtureRoot
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$safeToDeleteFixture=$true
$preserveCacheDiagnosticFixture=$false
try {
    $defaultOutput=Join-Path $openWrtRoot 'generated'
    $defaultManifest=Get-OpenWrtBuildManifestPath -OutputDirectory $defaultOutput
    Assert-Publication ($defaultManifest -ceq (Join-Path (Join-Path $openWrtRoot 'outputs\build') 'build-manifest.json')) 'Default manifest path is not openwrt/outputs/build/build-manifest.json.'
    $formalZip=Join-Path $defaultOutput 'openwrt.zip'
    $formalManifestHash=(Get-FileHash -LiteralPath $defaultManifest -Algorithm SHA256).Hash
    $formalZipHash=(Get-FileHash -LiteralPath $formalZip -Algorithm SHA256).Hash
    $formalManifest=Read-OpenWrtBuildManifest -OutputDirectory $defaultOutput
    Assert-Publication ($formalManifest.package_sha256 -ceq $formalZipHash) 'Default manifest reader rejected or misbound the migrated formal package.'
    Test-CleanManifestReaderSession -FixtureRoot $fixtureRoot -BuildModulePath (Join-Path $scriptsRoot 'OpenWrt-Build.ps1') -OutputDirectory $defaultOutput
    Assert-Publication ((Get-FileHash -LiteralPath $defaultManifest -Algorithm SHA256).Hash -ceq $formalManifestHash) 'Default manifest reader modified the protected support file.'
    Assert-OpenWrtPackageOutputDirectory -Path $defaultOutput -RequirePackage
    Assert-OpenWrtDirectoryContainsOnly -Path (Split-Path -Parent $defaultManifest) -Name 'build-manifest.json'
    if ($AliasPreflightOnly) {
        $formalClientArchive=Join-Path (Join-Path $projectRoot 'generated') 'sing-box-configs.zip'
        $formalSnapshot=Join-Path (Join-Path $openWrtRoot 'inputs') 'linux'
        Assert-Publication ((Test-Path -LiteralPath $formalClientArchive -PathType Leaf) -and (Test-Path -LiteralPath $formalSnapshot -PathType Container)) 'Default producer preflight inputs are missing.'
        Test-OpenWrtTransactionAliasMatrix -FixtureRoot $fixtureRoot
        Test-OpenWrtProducerAliasPreflight -FixtureRoot $fixtureRoot -ArchivePath $formalClientArchive -SourceRoot $formalSnapshot -SingBoxPath $SingBoxPath -ScriptsRoot $scriptsRoot
        Test-OpenWrtInputTransactionAliases -FixtureRoot $fixtureRoot -ArchivePath $formalClientArchive -SourceRoot $formalSnapshot -SingBoxPath $SingBoxPath -ScriptsRoot $scriptsRoot
        Assert-Publication ((Get-FileHash -LiteralPath (Join-Path $defaultOutput 'openwrt.zip') -Algorithm SHA256).Hash -ceq $formalZipHash) 'Alias preflight changed the formal OpenWrt ZIP.'
        Assert-Publication ((Get-FileHash -LiteralPath $defaultManifest -Algorithm SHA256).Hash -ceq $formalManifestHash) 'Alias preflight changed the formal build manifest.'
        Write-Output 'OpenWrt alias preflight passed: package/support transaction path matrix, reverse aliases, coordinator parent-child aliases, producer no-write preflight, and default manifest read.'
        return
    }
    $output=Join-Path $fixtureRoot 'output'
    [IO.Directory]::CreateDirectory($output) | Out-Null
    $releaseOne=Join-Path $output '2026-10-25-performance'
    $releaseTwo=Join-Path $output '2026-10-26-connection-cache'
    [IO.Directory]::CreateDirectory((Join-Path $releaseOne 'rule-set/nested')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $releaseTwo 'checks/empty')) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $releaseOne 'openwrt.zip'),[Text.Encoding]::ASCII.GetBytes('retained historical ZIP bytes'))
    [IO.File]::WriteAllBytes((Join-Path $releaseOne 'rule-set/nested/example.srs'),[byte[]](0,1,2,3,255))
    [IO.File]::WriteAllBytes((Join-Path $releaseTwo 'package.zip'),[Text.Encoding]::ASCII.GetBytes('retained current ZIP bytes'))
    [IO.File]::WriteAllBytes((Join-Path $releaseTwo 'checks/verification.bin'),[byte[]](255,0,17,42))
    $initialPreservation=Get-BuildPreservationSnapshot -Destination $output -PackageName 'openwrt.zip'
    Assert-Publication ($initialPreservation.RootExisted -and -not $initialPreservation.PackageExisted -and $initialPreservation.PreservedDirectories.Count -eq 2) 'Default-style output fixture does not contain exactly two versioned release directories.'
    Assert-OpenWrtPackageOutputDirectory -Path $output
    $supportDirectory=Get-OpenWrtBuildSupportDirectory -OutputDirectory $output
    Assert-Publication ($supportDirectory -ceq ($output+'.build-support')) 'Custom output did not receive an independent automatic support directory.'
    $explicitSupport=Join-Path $fixtureRoot 'explicit-support'
    Assert-Publication ((Get-OpenWrtBuildManifestPath -OutputDirectory $output -BuildSupportDirectory $explicitSupport) -ceq (Join-Path $explicitSupport 'build-manifest.json')) 'Explicit BuildSupportDirectory was not honored.'
    $missingProbe=Join-Path $fixtureRoot 'read-only-probe'
    $readFailed=$false
    try { Read-OpenWrtBuildManifest -OutputDirectory $missingProbe | Out-Null } catch { $readFailed=$_.Exception.Message -match 'missing' }
    Assert-Publication $readFailed 'Manifest reader accepted a missing isolated package.'
    Assert-Publication (-not (Test-Path -LiteralPath ((Get-BuildPaths $missingProbe).Lock))) 'Read-only manifest reader created an output lock file.'
    Assert-Publication (-not (Test-Path -LiteralPath ((Get-BuildPaths (Get-OpenWrtBuildSupportDirectory $missingProbe)).Lock))) 'Read-only manifest reader created a support lock file.'

    $main=$LinuxArchivePath
    $input=Join-Path $fixtureRoot 'input'
    New-Item -ItemType Directory -Path $input | Out-Null
    $archive=Join-Path $input 'sing-box-configs.zip'
    Copy-Item -LiteralPath $main -Destination $archive
    Assert-FinalLinuxSnapshot -SourceRoot $SourceRoot -ArchivePath $archive
    $snapshot=Join-Path $fixtureRoot 'snapshot'
    & (Join-Path $scriptsRoot 'Sync-FinalLinuxSnapshot.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot | Out-Null
    Assert-FinalLinuxSnapshot -SourceRoot $snapshot -ArchivePath $archive
    $snapshotHash=(Get-FileHash -LiteralPath (Join-Path $snapshot 'sing-box-openwrt.json')).Hash
    foreach ($mode in @('config','srs')) {
        $bad=Join-Path $input ('case-'+$mode+'.zip')
        Copy-Item -LiteralPath $archive -Destination $bad
        $zip=[IO.Compression.ZipFile]::Open($bad,[IO.Compression.ZipArchiveMode]::Update)
        try {
            $name='sing-box-linux-tun.json'; $file=Join-Path $snapshot 'sing-box-openwrt.json'
            if ($mode -eq 'srs') {
                $config=Read-StrictJsonFile -Path (Join-Path $snapshot 'sing-box-openwrt.json')
                $name=[string]$config.route.rule_set[0].path
                $file=Join-Path $snapshot $name
            }
            $zip.GetEntry($name).Delete()
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$file,$name.ToUpperInvariant())
        } finally { $zip.Dispose() }
        $failed=$false
        try { Assert-FinalLinuxSnapshot -SourceRoot $snapshot -ArchivePath $bad } catch { $failed=$_.Exception.Message -match 'Missing or duplicate final Linux entry' }
        Assert-Publication $failed ('Snapshot accepted wrong-case '+$mode+' entry.')
        $failed=$false
        try { & (Join-Path $scriptsRoot 'Sync-FinalLinuxSnapshot.ps1') -LinuxArchivePath $bad -SourceRoot $snapshot | Out-Null } catch { $failed=$_.Exception.Message -match 'Missing or duplicate final Linux' }
        Assert-Publication $failed ('Sync accepted wrong-case '+$mode+' entry.')
        Assert-Publication ((Get-FileHash -LiteralPath (Join-Path $snapshot 'sing-box-openwrt.json')).Hash -ceq $snapshotHash) 'Rejected archive changed the committed snapshot.'
    }
    $sourcePaths=Get-BuildPaths $snapshot
    foreach ($pending in @($sourcePaths.Stage,$sourcePaths.Backup,$sourcePaths.Journal)) { Assert-Publication (-not (Test-Path -LiteralPath $pending)) 'Successful snapshot retained transaction material.' }

    # An interrupted prepared snapshot (old source moved, new source absent)
    # must be recovered under the same lock before any producer/reader proceeds.
    $lock=Enter-BuildLock $sourcePaths
    try {
        Write-BuildJournal $sourcePaths ([ordered]@{version=1;destination=$sourcePaths.Destination;phase='prepared';existed=$true})
        [IO.Directory]::Move($sourcePaths.Destination,$sourcePaths.Backup)
    } finally { $lock.Dispose() }
    $context=Enter-OpenWrtInputLocks -ArchivePath $archive -SourceRoot $snapshot
    try { Assert-FinalLinuxSnapshot -SourceRoot $snapshot -ArchivePath $archive }
    finally { Exit-OpenWrtInputLocks $context }
    Assert-Publication (-not (Test-Path -LiteralPath $sourcePaths.Journal)) 'Prepared snapshot recovery did not finish.'

    # Both writer entry points must honor an occupied input lock. No partial
    # stage or output is created by a rejected reader/producer.
    $mainPaths=Get-BuildPaths $input
    foreach ($blocked in @($mainPaths,$sourcePaths)) {
        $lock=Enter-BuildLock $blocked
        try {
            $failed=$false
            try { & (Join-Path $scriptsRoot 'Sync-FinalLinuxSnapshot.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot -LockTimeoutSeconds 1 | Out-Null }
            catch { $failed=$_.Exception.Message -match 'Build lock timeout' }
            Assert-Publication $failed 'Snapshot ignored a publication/input lock.'
            $failed=$false
            try { & (Join-Path $scriptsRoot 'Build-OpenWrtPackage.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot -OutputDirectory (Join-Path $fixtureRoot 'blocked') -Force -LockTimeoutSeconds 1 -SingBoxPath $SingBoxPath | Out-Null }
            catch { $failed=$_.Exception.Message -match 'Build lock timeout' }
            Assert-Publication $failed 'Native builder ignored a publication/input lock.'
            Assert-Publication (-not (Test-Path -LiteralPath (Join-Path $fixtureRoot 'blocked'))) 'Locked builder created output.'
        } finally { $lock.Dispose() }
    }
    Put-Publication $mainPaths.Journal '{}'
    try {
        $failed=$false
        try { $context=Enter-OpenWrtInputLocks -ArchivePath $archive -SourceRoot $snapshot }
        catch { $failed=$_.Exception.Message -match 'Main archive has pending recovery' }
        Assert-Publication $failed 'Reader silently recovered another publisher.'
    } finally { Remove-Item -LiteralPath $mainPaths.Journal }

    $runtimeOutput=Join-Path $fixtureRoot 'runtime-input'
    $runtimeInput=Join-Path $runtimeOutput 'openwrt.zip'
    $failed=$false
    try { Assert-OpenWrtOutputTarget -OutputDirectory $runtimeOutput -SourceRoot $snapshot -ArchivePath $archive -SingBoxPath $SingBoxPath -RuntimePaths @($runtimeInput) }
    catch { $failed=$_.Exception.Message -match 'Build output overlaps a protected runtime input file' }
    Assert-Publication $failed 'Builder allowed publication to replace a runtime executable named as an approved output artifact.'

    $protectedSupportPaths=@(
        (Join-Path $projectRoot 'scripts'),(Join-Path $projectRoot 'src'),(Join-Path $projectRoot 'config'),
        (Join-Path $projectRoot 'tests'),(Join-Path $projectRoot 'docs'),(Join-Path $projectRoot 'routing'),
        (Join-Path $projectRoot 'generated'),(Join-Path $projectRoot 'backups'),
        (Join-Path $openWrtRoot 'scripts'),(Join-Path $openWrtRoot 'src'),(Join-Path $openWrtRoot 'tests'),
        (Join-Path $openWrtRoot 'inputs'),(Join-Path $openWrtRoot 'docs'),(Join-Path $openWrtRoot 'diagnostics'),
        (Join-Path $openWrtRoot 'backups'),(Join-Path $openWrtRoot 'build-stage'),(Join-Path $openWrtRoot 'generated'),$snapshot,
        (Split-Path -Parent $SingBoxPath)
    )
    $blockedSupportPaths=[Collections.Generic.List[string]]::new()
    foreach ($protectedPath in $protectedSupportPaths) { $blockedSupportPaths.Add($protectedPath); $blockedSupportPaths.Add((Join-Path $protectedPath 'child')) }
    $blockedSupportPaths.Add($projectRoot)
    $blockedSupportPaths.Add($openWrtRoot)
    foreach ($blockedSupport in $blockedSupportPaths) {
        $failed=$false
        try {
            Assert-OpenWrtBuildTargets -OutputDirectory (Join-Path $fixtureRoot 'safe-package') -BuildSupportDirectory $blockedSupport -SourceRoot $snapshot -ArchivePath $archive -SingBoxPath $SingBoxPath -RuntimePaths @($SingBoxPath) -ProtectedPaths $protectedSupportPaths -FormalPackageDirectory (Join-Path $openWrtRoot 'generated')
        } catch { $failed=$_.Exception.Message -match 'overlaps protected' }
        Assert-Publication $failed ('Support directory overlapped a protected source or artifact path: '+$blockedSupport)
    }
    $failed=$false
    try {
        Assert-OpenWrtBuildTargets -OutputDirectory $output -BuildSupportDirectory (Join-Path $output 'support') -SourceRoot $snapshot -ArchivePath $archive -SingBoxPath $SingBoxPath -ProtectedPaths @() -FormalPackageDirectory (Join-Path $openWrtRoot 'generated')
    } catch { $failed=$_.Exception.Message -match 'overlaps protected' }
    Assert-Publication $failed 'Support directory nested inside the package output was allowed.'

    Test-OpenWrtTransactionAliasMatrix -FixtureRoot $fixtureRoot
    Test-OpenWrtProducerAliasPreflight -FixtureRoot $fixtureRoot -ArchivePath $archive -SourceRoot $snapshot -SingBoxPath $SingBoxPath -ScriptsRoot $scriptsRoot
    Test-OpenWrtInputTransactionAliases -FixtureRoot $fixtureRoot -ArchivePath $archive -SourceRoot $snapshot -SingBoxPath $SingBoxPath -ScriptsRoot $scriptsRoot

    & (Join-Path $scriptsRoot 'Build-OpenWrtPackage.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot -OutputDirectory $output -Force -SingBoxPath $SingBoxPath | Out-Null
    $coldManifest=Read-OpenWrtBuildManifest -OutputDirectory $output
    Assert-Publication ($coldManifest.adapter_cache.status -ceq 'miss-stored') 'First fixture build did not create a cold adapter-cache entry.'
    $expectedProviderPolicy=Get-MosdnsDnsProviderPolicyMetadata
    $expectedProviderPolicyJson=ConvertTo-Json -InputObject $expectedProviderPolicy -Depth 100 -Compress
    $coldProviderPolicyJson=ConvertTo-Json -InputObject $coldManifest.dns_policy.dns_provider_policy -Depth 100 -Compress
    Assert-Publication ($coldProviderPolicyJson -ceq $expectedProviderPolicyJson) 'Cold build manifest omitted or changed the complete provider-policy metadata.'
    $coldDnsPolicyJson=ConvertTo-Json -InputObject $coldManifest.dns_policy -Depth 100 -Compress
    $coldManifestPath=Get-OpenWrtBuildManifestPath -OutputDirectory $output -BuildSupportDirectory $supportDirectory
    $cacheDirectory=Get-OpenWrtAdapterCacheDirectory -BuildSupportDirectory $supportDirectory
    $cacheFile=Get-OpenWrtAdapterCacheFilePath -CacheDirectory $cacheDirectory
    Copy-Item -LiteralPath $coldManifestPath -Destination (Join-Path $fixtureRoot 'cold-build-manifest.json')
    if (Test-Path -LiteralPath $cacheFile -PathType Leaf) { Copy-Item -LiteralPath $cacheFile -Destination (Join-Path $fixtureRoot 'cold-adapter-cache.json') }
    & (Join-Path $scriptsRoot 'Build-OpenWrtPackage.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot -OutputDirectory $output -Force -SingBoxPath $SingBoxPath | Out-Null
    $warmManifest=Read-OpenWrtBuildManifest -OutputDirectory $output
    $warmManifestPath=Get-OpenWrtBuildManifestPath -OutputDirectory $output -BuildSupportDirectory $supportDirectory
    if (Test-Path -LiteralPath $warmManifestPath -PathType Leaf) { Copy-Item -LiteralPath $warmManifestPath -Destination (Join-Path $fixtureRoot 'warm-build-manifest.json') }
    if (Test-Path -LiteralPath $cacheFile -PathType Leaf) { Copy-Item -LiteralPath $cacheFile -Destination (Join-Path $fixtureRoot 'warm-adapter-cache.json') }
    if ($warmManifest.adapter_cache.status -cne 'hit') {
        $preserveCacheDiagnosticFixture=$true
        throw ('Second fixture build did not restore the adapter-cache entry. cold_status='+[string]$coldManifest.adapter_cache.status+
            ' cold_reason='+[string]$coldManifest.adapter_cache.reason+' cold_fingerprint='+[string]$coldManifest.adapter_cache.fingerprint+
            ' warm_status='+[string]$warmManifest.adapter_cache.status+' warm_reason='+[string]$warmManifest.adapter_cache.reason+
            ' warm_fingerprint='+[string]$warmManifest.adapter_cache.fingerprint+' fixture='+$fixtureRoot+
            ' cold_manifest='+(Join-Path $fixtureRoot 'cold-build-manifest.json')+
            ' warm_manifest='+(Join-Path $fixtureRoot 'warm-build-manifest.json')+
            ' cold_cache='+(Join-Path $fixtureRoot 'cold-adapter-cache.json')+
            ' warm_cache='+(Join-Path $fixtureRoot 'warm-adapter-cache.json'))
    }
    $warmDnsPolicyJson=ConvertTo-Json -InputObject $warmManifest.dns_policy -Depth 100 -Compress
    Assert-Publication ($warmDnsPolicyJson -ceq $coldDnsPolicyJson) 'Warm cache-hit build manifest lost DNS policy fields or changed their values.'
    $paths=Get-BuildPaths $output
    $manifestPath=Get-OpenWrtBuildManifestPath -OutputDirectory $output
    $supportPaths=Get-BuildPaths (Split-Path -Parent $manifestPath)
    $coordinatorPath=Get-OpenWrtArtifactCoordinatorPath -PackagePaths $paths
    $zipPath=Join-Path $output 'openwrt.zip'
    $oldHash=(Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    $oldManifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    Assert-Publication ((Split-Path -Parent $manifestPath) -ceq $supportDirectory) 'Custom manifest path did not use the independent support directory.'
    Assert-OpenWrtPackageOutputDirectory -Path $output -RequirePackage
    Assert-BuildPreservationSnapshot -Directory $output -Snapshot $initialPreservation -ExpectedRoot $output -RequirePackage
    $publishedPreservation=Get-BuildPreservationSnapshot -Destination $output -PackageName 'openwrt.zip'
    Assert-Publication ($publishedPreservation.PackageExisted -and $publishedPreservation.PreservedDirectories.Count -eq 2) 'Published fixture did not retain its two release directories alongside openwrt.zip.'
    Assert-OpenWrtDirectoryContainsOnly -Path $supportDirectory -Name 'build-manifest.json'
    $resolvedManifest=Read-OpenWrtBuildManifest -OutputDirectory $output
    Assert-Publication ($resolvedManifest.package_sha256 -ceq $oldHash) 'Manifest reader did not bind metadata to the ZIP SHA256.'
    $sourceConfig = Read-StrictJsonFile -Path (Join-Path $SourceRoot 'sing-box-openwrt.json')
    $hasRejectList = 'routing-reject-domain' -cin @($sourceConfig.route.rule_set | ForEach-Object tag)
    $expectedEntryCount = 16 + [int]$hasRejectList
    Assert-Publication ($resolvedManifest.package_entries -eq $expectedEntryCount) 'Build manifest entry count must reflect the snapshot reject policy.'
    $publishedArchive=[IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        Assert-Publication (($null -ne $publishedArchive.GetEntry('dns-reject-domains.txt')) -eq $hasRejectList) 'Published reject list must match the snapshot DNS policy.'
        $releaseEntries=@($publishedArchive.Entries | Where-Object { $_.FullName -match '^2026-10-(25|26)-' })
        Assert-Publication ($releaseEntries.Count -eq 0) 'Dated output directories were copied into the runtime ZIP.'
    } finally { $publishedArchive.Dispose() }
    foreach ($pending in @($paths.Stage,$paths.Backup,$paths.Journal)) { Assert-Publication (-not (Test-Path -LiteralPath $pending)) 'Successful publication retained transaction material.' }
    foreach ($pending in @($supportPaths.Stage,$supportPaths.Backup,$supportPaths.Journal,$coordinatorPath)) { Assert-Publication (-not (Test-Path -LiteralPath $pending)) 'Successful paired publication retained support transaction material.' }
    # An untrusted replacement checker must leave the old ZIP intact.
    $dummy=Join-Path $fixtureRoot 'check-tool\failing-check.cmd'
    $shim='@if not "%1"=="rule-set" exit /b 9'+"`n"+'@"'+$SingBoxPath+'" %*'+"`n"+'@exit /b %errorlevel%'+"`n"
    Put-Publication $dummy $shim
    $failed=$false
    try { & (Join-Path $scriptsRoot 'Build-OpenWrtPackage.ps1') -LinuxArchivePath $archive -SourceRoot $snapshot -OutputDirectory $output -Force -SingBoxPath $dummy | Out-Null }
    catch { $failed=$_.Exception.Message -match 'Official Windows sing-box checker digest mismatch' }
    Assert-Publication $failed 'Untrusted official-check replacement accepted.'
    Assert-Publication ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -eq $oldHash) 'Failed check replaced old ZIP.'
    Assert-Publication ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq $oldManifestHash) 'Failed check replaced old manifest.'
    Assert-BuildPreservationSnapshot -Directory $output -Snapshot $publishedPreservation -ExpectedRoot $output -SourceState -RequirePackage
    Assert-Publication ((Read-OpenWrtBuildManifest -OutputDirectory $output).package_sha256 -ceq $oldHash) 'Failed check left a mismatched manifest as current metadata.'

    # Prepared coordinator wins over a stale committed ZIP journal and restores
    # the old pair after a crash halfway through the directory moves.
    $locks=Enter-OpenWrtArtifactLocks -PackagePaths $paths -SupportPaths $supportPaths
    try {
        Copy-Item -LiteralPath $paths.Destination -Destination $paths.Stage -Recurse
        Copy-Item -LiteralPath $supportPaths.Destination -Destination $supportPaths.Stage -Recurse
        $candidateZip=Join-Path $paths.Stage 'openwrt.zip'
        $candidateStream=[IO.File]::Open($candidateZip,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $candidateStream.WriteByte(0) } finally { $candidateStream.Dispose() }
        Write-BuildJournal $paths ([ordered]@{version=1;destination=$paths.Destination;phase='committed';existed=$true})
        Write-BuildJournal $supportPaths ([ordered]@{version=1;destination=$supportPaths.Destination;phase='prepared';existed=$true})
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal ([ordered]@{version=2;kind='openwrt-artifacts';package_destination=$paths.Destination;support_destination=$supportPaths.Destination;package_existed=$true;package_file_existed=$true;support_existed=$true;phase='prepared';package_preservation=(ConvertTo-Json -InputObject $publishedPreservation -Depth 100 -Compress)})
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($paths.Destination,$paths.Backup)
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($paths.Stage,$paths.Destination)
        $pendingReadRejected=$false
        try { Read-OpenWrtBuildManifest -OutputDirectory $output | Out-Null } catch { $pendingReadRejected=$_.Exception.Message -match 'recovery is pending' }
        Assert-Publication $pendingReadRejected 'Manifest reader accepted a package while a prepared pair transaction was pending.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $validPreservationJson=[string]$coordinatorDocument.package_preservation
        $coordinatorDocument.package_preservation='{bad-json'
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        $invalidSnapshotRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $invalidSnapshotRejected=$_.Exception.Message -match 'snapshot JSON' }
        Assert-Publication $invalidSnapshotRejected 'Prepared recovery accepted malformed preservation JSON.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf) -and (Test-Path -LiteralPath $paths.Destination -PathType Container)) 'Malformed-snapshot rejection mutated prepared transaction state.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $coordinatorDocument.package_preservation='{"Version":1}'
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        $invalidSnapshotRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $invalidSnapshotRejected=$_.Exception.Message -match 'Invalid release preservation snapshot' }
        Assert-Publication $invalidSnapshotRejected 'Prepared recovery accepted an incomplete preservation snapshot shape.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf) -and (Test-Path -LiteralPath $paths.Destination -PathType Container)) 'Incomplete-snapshot rejection mutated prepared transaction state.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $coordinatorDocument.package_preservation=$validPreservationJson
        $coordinatorDocument.package_file_existed=$false
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        $invalidSnapshotRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $invalidSnapshotRejected=$_.Exception.Message -match 'snapshot binding' }
        Assert-Publication $invalidSnapshotRejected 'Prepared recovery accepted a preservation package-presence mismatch.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf)) 'Snapshot-binding rejection mutated prepared transaction state.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $wrongRootSnapshot=ConvertFrom-StrictJson -Text $validPreservationJson
        $wrongRootSnapshot.Root=Join-Path $fixtureRoot 'different-output-root'
        $coordinatorDocument.package_file_existed=$true
        $coordinatorDocument.package_preservation=ConvertTo-Json -InputObject $wrongRootSnapshot -Depth 100 -Compress
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        $invalidSnapshotRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $invalidSnapshotRejected=$_.Exception.Message -match 'snapshot binding' }
        Assert-Publication $invalidSnapshotRejected 'Prepared recovery accepted a preservation snapshot for a different root.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf) -and (Test-Path -LiteralPath $paths.Destination -PathType Container)) 'Wrong-root rejection mutated prepared transaction state.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $coordinatorDocument.package_preservation=$validPreservationJson
        $coordinatorDocument.package_existed=$false
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        $invalidSnapshotRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $invalidSnapshotRejected=$_.Exception.Message -match 'disagrees with its coordinator' }
        Assert-Publication $invalidSnapshotRejected 'Prepared recovery accepted a source-directory existence mismatch.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf)) 'Root-binding rejection mutated prepared transaction state.'
        $coordinatorDocument=Read-StrictJsonFile -Path $coordinatorPath
        $coordinatorDocument.package_existed=$true
        $coordinatorDocument.package_file_existed=$true
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal $coordinatorDocument
        Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        Assert-Publication ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -eq $oldHash) 'Prepared interruption did not restore old output.'
        Assert-BuildPreservationSnapshot -Directory $output -Snapshot $publishedPreservation -ExpectedRoot $output -SourceState -RequirePackage
        Assert-Publication ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq $oldManifestHash) 'Prepared interruption did not restore the old manifest bytes.'
        Assert-Publication ((Read-OpenWrtBuildManifest -OutputDirectory $output).package_sha256 -ceq $oldHash) 'Prepared interruption left stale metadata current.'

        # Recovery itself may stop after rolling back one side. The coordinator
        # records whether each original directory existed so that the next
        # invocation can safely recognize that completed half-rollback.
        Copy-Item -LiteralPath $paths.Destination -Destination $paths.Stage -Recurse
        Copy-Item -LiteralPath $supportPaths.Destination -Destination $supportPaths.Stage -Recurse
        $candidateZip=Join-Path $paths.Stage 'openwrt.zip'
        $candidateStream=[IO.File]::Open($candidateZip,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $candidateStream.WriteByte(0) } finally { $candidateStream.Dispose() }
        Write-BuildJournal $paths ([ordered]@{version=1;destination=$paths.Destination;phase='prepared';existed=$true})
        Write-BuildJournal $supportPaths ([ordered]@{version=1;destination=$supportPaths.Destination;phase='prepared';existed=$true})
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal ([ordered]@{version=2;kind='openwrt-artifacts';package_destination=$paths.Destination;support_destination=$supportPaths.Destination;package_existed=$true;package_file_existed=$true;support_existed=$true;phase='prepared';package_preservation=(ConvertTo-Json -InputObject $publishedPreservation -Depth 100 -Compress)})
        [IO.Directory]::Move($paths.Destination,$paths.Backup)
        [IO.Directory]::Move($paths.Stage,$paths.Destination)
        Restore-BuildTransaction $paths
        Assert-Publication (-not (Test-Path -LiteralPath $paths.Journal) -and -not (Test-Path -LiteralPath $paths.Backup)) 'Prepared rollback checkpoint did not finish the package half.'
        Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        Assert-Publication ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -eq $oldHash) 'Resumed prepared rollback did not preserve the old ZIP.'
        Assert-BuildPreservationSnapshot -Directory $output -Snapshot $publishedPreservation -ExpectedRoot $output -SourceState -RequirePackage
        Assert-Publication ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq $oldManifestHash) 'Resumed prepared rollback did not restore the old manifest.'
        Assert-Publication ((Read-OpenWrtBuildManifest -OutputDirectory $output).package_sha256 -ceq $oldHash) 'Resumed prepared rollback left mismatched metadata current.'

        # A committed coordinator wins over mixed inner phases and completes
        # both new directory moves without reverting either artifact.
        Copy-Item -LiteralPath $paths.Destination -Destination $paths.Stage -Recurse
        Copy-Item -LiteralPath $supportPaths.Destination -Destination $supportPaths.Stage -Recurse
        $candidateManifestPath=Join-Path $supportPaths.Stage 'build-manifest.json'
        $candidateManifest=Read-StrictJsonFile -Path $candidateManifestPath
        $candidateManifest | Add-Member -NotePropertyName transaction_probe -NotePropertyValue 'committed-recovery'
        [IO.File]::WriteAllText($candidateManifestPath,(Format-JsonText -Text ($candidateManifest | ConvertTo-Json -Depth 100 -Compress))+"`n",(New-Object Text.UTF8Encoding($false)))
        Write-BuildJournal $paths ([ordered]@{version=1;destination=$paths.Destination;phase='prepared';existed=$true})
        Write-BuildJournal $supportPaths ([ordered]@{version=1;destination=$supportPaths.Destination;phase='prepared';existed=$true})
        Write-OpenWrtArtifactCoordinator -Path $coordinatorPath -Journal ([ordered]@{version=2;kind='openwrt-artifacts';package_destination=$paths.Destination;support_destination=$supportPaths.Destination;package_existed=$true;package_file_existed=$true;support_existed=$true;phase='committed';package_preservation=(ConvertTo-Json -InputObject $publishedPreservation -Depth 100 -Compress)})
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($paths.Destination,$paths.Backup)
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($paths.Stage,$paths.Destination)
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($supportPaths.Destination,$supportPaths.Backup)
        Assert-OpenWrtArtifactPathSet -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        [IO.Directory]::Move($supportPaths.Stage,$supportPaths.Destination)
        $releaseContentPath=Join-Path $releaseTwo 'checks/verification.bin'
        [IO.File]::WriteAllBytes($releaseContentPath,[byte[]](9,8,7,6))
        $preservedContentRejected=$false
        try { Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath }
        catch { $preservedContentRejected=$_.Exception.Message -match 'Preserved release content changed' }
        Assert-Publication $preservedContentRejected 'Committed recovery accepted modified dated-directory bytes.'
        Assert-Publication ((Test-Path -LiteralPath $paths.Backup -PathType Container) -and (Test-Path -LiteralPath $coordinatorPath -PathType Leaf)) 'Rejected committed recovery removed the backup or coordinator.'
        [IO.File]::WriteAllBytes($releaseContentPath,[byte[]](255,0,17,42))
        Restore-OpenWrtArtifactTransaction -PackagePaths $paths -SupportPaths $supportPaths -CoordinatorPath $coordinatorPath
        Assert-Publication ((Read-OpenWrtBuildManifest -OutputDirectory $output).transaction_probe -ceq 'committed-recovery') 'Committed coordinator did not complete metadata publication across mismatched inner phases.'
        Assert-BuildPreservationSnapshot -Directory $output -Snapshot $publishedPreservation -ExpectedRoot $output -RequirePackage
        foreach ($pending in @($paths.Stage,$paths.Backup,$paths.Journal,$supportPaths.Stage,$supportPaths.Backup,$supportPaths.Journal,$coordinatorPath)) { Assert-Publication (-not (Test-Path -LiteralPath $pending)) 'Committed pair recovery retained transaction material.' }
    } finally { Exit-OpenWrtArtifactLocks $locks }

    $validManifestBytes=[IO.File]::ReadAllBytes($manifestPath)
    $badManifest=Read-StrictJsonFile -Path $manifestPath
    $badManifest.package_sha256=('0'*64)
    [IO.File]::WriteAllText($manifestPath,(Format-JsonText -Text ($badManifest | ConvertTo-Json -Depth 100 -Compress))+"`n",(New-Object Text.UTF8Encoding($false)))
    $failed=$false
    try { Read-OpenWrtBuildManifest -OutputDirectory $output | Out-Null } catch { $failed=$_.Exception.Message -match 'does not match' }
    [IO.File]::WriteAllBytes($manifestPath,$validManifestBytes)
    Assert-Publication $failed 'Manifest reader treated a mismatched package SHA256 as current metadata.'
    $badCountManifest=Read-StrictJsonFile -Path $manifestPath
    $badCountManifest.package_entries=14
    [IO.File]::WriteAllText($manifestPath,(Format-JsonText -Text ($badCountManifest | ConvertTo-Json -Depth 100 -Compress))+"`n",(New-Object Text.UTF8Encoding($false)))
    $failed=$false
    try { Read-OpenWrtBuildManifest -OutputDirectory $output | Out-Null } catch { $failed=$_.Exception.Message -match 'entry count does not match' }
    [IO.File]::WriteAllBytes($manifestPath,$validManifestBytes)
    Assert-Publication $failed 'Manifest reader accepted an entry count that disagreed with the package.'
    foreach ($compatibilityEntryCount in @(14,15,16,17)) {
        $compatibilityOutput=Join-Path $fixtureRoot ('manifest-compat-'+$compatibilityEntryCount)
        $compatibilitySupport=Get-OpenWrtBuildSupportDirectory -OutputDirectory $compatibilityOutput
        [IO.Directory]::CreateDirectory($compatibilityOutput) | Out-Null
        [IO.Directory]::CreateDirectory($compatibilitySupport) | Out-Null
        $compatibilityZip=Join-Path $compatibilityOutput 'openwrt.zip'
        $compatibilityArchive=[IO.Compression.ZipFile]::Open($compatibilityZip,[IO.Compression.ZipArchiveMode]::Create)
        try {
            for ($entryIndex=0;$entryIndex -lt $compatibilityEntryCount;$entryIndex++) { [void]$compatibilityArchive.CreateEntry(('payload-{0:D2}.bin' -f $entryIndex)) }
        } finally { $compatibilityArchive.Dispose() }
        $compatibilityManifest=[ordered]@{package_file='openwrt.zip';package_entries=$compatibilityEntryCount;package_sha256=(Get-FileHash -LiteralPath $compatibilityZip -Algorithm SHA256).Hash}
        $compatibilityManifestPath=Get-OpenWrtBuildManifestPath -OutputDirectory $compatibilityOutput
        [IO.File]::WriteAllText($compatibilityManifestPath,(Format-JsonText -Text ($compatibilityManifest | ConvertTo-Json -Compress))+"`n",(New-Object Text.UTF8Encoding($false)))
        $compatibilityRead=Read-OpenWrtBuildManifest -OutputDirectory $compatibilityOutput
        Assert-Publication ($compatibilityRead.package_entries -eq $compatibilityEntryCount) ('Manifest reader rejected the '+$compatibilityEntryCount+'-entry package layout.')
    }
    $foreignOutputFile=Join-Path $output 'unrecognized.txt'
    [IO.File]::WriteAllText($foreignOutputFile,'must be rejected',(New-Object Text.UTF8Encoding($false)))
    $failed=$false
    try { Assert-OpenWrtPackageOutputDirectory -Path $output -RequirePackage } catch { $failed=$true }
    [IO.File]::Delete($foreignOutputFile)
    Assert-Publication $failed 'Package output accepted an unknown top-level file.'
    $junctionTarget=Join-Path $fixtureRoot 'junction-target'
    $junctionPath=Join-Path $releaseOne 'junction'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    $junctionCreated=$false
    try {
        $junctionCommand='mklink /J "'+$junctionPath+'" "'+$junctionTarget+'"'
        $junctionOutput=@(& $env:ComSpec /d /c $junctionCommand 2>&1)
        if ($LASTEXITCODE -ne 0) { throw ('Could not create required reparse-point fixture: '+($junctionOutput -join ' ')) }
        $junctionCreated=$true
        $failed=$false
        try { Assert-OpenWrtPackageOutputDirectory -Path $output -RequirePackage } catch { $failed=$true }
        Assert-Publication $failed 'Package output accepted a reparse point inside a dated release directory.'
    } finally {
        if ($junctionCreated) { [IO.Directory]::Delete($junctionPath,$false) }
    }
    # Check archive corruption using the same prepublication validator.
    $payload=Join-Path $fixtureRoot 'payload'
    [IO.Compression.ZipFile]::ExtractToDirectory($zipPath,$payload)
    foreach ($mode in @('missing','duplicate','corrupt','checksums')) {
        $bad=Join-Path $fixtureRoot ($mode+'.zip')
        Copy-Item -LiteralPath $zipPath -Destination $bad
        $zip=[IO.Compression.ZipFile]::Open($bad,[IO.Compression.ZipArchiveMode]::Update)
        try {
            if ($mode -eq 'missing') { $zip.GetEntry('config.json').Delete() }
            elseif ($mode -eq 'duplicate') { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $payload 'config.json'),'config.json') }
            else {
                $name='config.json'; if ($mode -eq 'checksums') { $name='SHA256SUMS' }
                $stream=$zip.GetEntry($name).Open()
                try { $stream.WriteByte(88) } finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
        $failed=$false
        try { Assert-NativePackageArchive -ZipPath $bad -PayloadDirectory $payload -SingBoxPath $SingBoxPath }
        catch { $failed=$true }
        Assert-Publication $failed ('Invalid archive accepted: '+$mode)
    }
    # Real concurrent producer processes, still targeting only the fixture.
    $executable=Join-Path $PSHOME 'powershell.exe'
    if ($PSVersionTable.PSVersion.Major -ge 7) { $executable=Join-Path $PSHOME 'pwsh.exe' }
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Current PowerShell executable missing.' }
    $children=[Collections.Generic.List[object]]::new()
    try {
        $script=Join-Path $scriptsRoot 'Build-OpenWrtPackage.ps1'
        for ($i=1;$i -le 2;$i++) {
            # Fixture paths contain no spaces; pass each token separately so
            # Start-Process does not double-quote PowerShell arguments.
            $arguments=@('-NoProfile','-File',$script,'-LinuxArchivePath',$archive,'-SourceRoot',$snapshot,'-OutputDirectory',$output,'-Force','-SingBoxPath',$SingBoxPath,'-LockTimeoutSeconds','600')
            $producer=Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput (Join-Path $fixtureRoot ('producer-'+$i+'.out')) -RedirectStandardError (Join-Path $fixtureRoot ('producer-'+$i+'.err')) -PassThru
            # Retain the handle immediately, including for the second producer
            # which can exit before the first producer's wait completes.
            $null=$producer.Handle
            $children.Add($producer)
        }
        foreach ($child in $children) {
            $producerWatch=[Diagnostics.Stopwatch]::StartNew()
            $nextProgressSeconds=15
            while (-not $child.WaitForExit(1000)) {
                if ($producerWatch.Elapsed.TotalSeconds -ge $ProducerTimeoutSeconds) {
                    $producerNumber=$children.IndexOf($child)+1
                    $producerOut=Get-Content -LiteralPath (Join-Path $fixtureRoot ('producer-'+$producerNumber+'.out')) -Tail 10 -ErrorAction SilentlyContinue
                    $producerErr=Get-Content -LiteralPath (Join-Path $fixtureRoot ('producer-'+$producerNumber+'.err')) -Tail 10 -ErrorAction SilentlyContinue
                    throw ('Concurrent fixture producer timed out: '+$producerNumber+' stdout='+($producerOut -join ' ')+' stderr='+($producerErr -join ' '))
                }
                if ($producerWatch.Elapsed.TotalSeconds -ge $nextProgressSeconds) {
                    Write-Output ('Waiting for isolated publication producer '+($children.IndexOf($child)+1)+'; bounded timeout '+$ProducerTimeoutSeconds+'s.')
                    $nextProgressSeconds+=15
                }
            }
            $child.WaitForExit()
            $child.Refresh()
            if ($null -eq $child.ExitCode) { throw 'Concurrent producer exit code is unavailable.' }
            $exitCode=[int]$child.ExitCode
            $stdout=Get-Content -LiteralPath (Join-Path $fixtureRoot ('producer-'+($children.IndexOf($child)+1)+'.out')) -Raw -ErrorAction SilentlyContinue
            $stderr=Get-Content -LiteralPath (Join-Path $fixtureRoot ('producer-'+($children.IndexOf($child)+1)+'.err')) -Raw -ErrorAction SilentlyContinue
            Assert-Publication ($exitCode -eq 0) ('Concurrent producer failed exit='+$exitCode+' stdout='+$stdout+' stderr='+$stderr)
        }
    } finally {
        $allChildrenStopped=$true
        foreach ($child in $children) {
            if (-not $child.HasExited) {
                try { $child.Kill() } catch { }
                if (-not $child.WaitForExit(10000)) { $allChildrenStopped=$false }
            }
            $child.Dispose()
        }
        if (-not $allChildrenStopped) { $safeToDeleteFixture=$false }
    }
    Assert-NativePackageArchive -ZipPath $zipPath -PayloadDirectory $payload -SingBoxPath $SingBoxPath
    Assert-Publication ((Read-OpenWrtBuildManifest -OutputDirectory $output).package_sha256 -ceq (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash) 'Concurrent producers left an unbound build manifest.'
    Assert-OpenWrtPackageOutputDirectory -Path $output -RequirePackage
    Assert-OpenWrtDirectoryContainsOnly -Path $supportDirectory -Name 'build-manifest.json'
    foreach ($pending in @($paths.Stage,$paths.Backup,$paths.Journal,$supportPaths.Stage,$supportPaths.Backup,$supportPaths.Journal,$coordinatorPath)) { Assert-Publication (-not (Test-Path -LiteralPath $pending)) 'Concurrent producers retained package/support transaction material.' }

    # Two callers describing the same pair in reverse semantic order must not
    # deadlock: both lock paths are normalized and sorted by the shared helper.
    $lockPackageX=Join-Path $fixtureRoot 'cross-lock-x'
    $lockPackageY=Join-Path $fixtureRoot 'cross-lock-y'
    $probeScript=$MyInvocation.MyCommand.Path
    $lockChildren=[Collections.Generic.List[object]]::new()
    try {
        foreach ($probe in @(@{Package=$lockPackageX;Support=$lockPackageY;Name='xy'},@{Package=$lockPackageY;Support=$lockPackageX;Name='yx'})) {
            $marker=Join-Path $fixtureRoot ('lock-'+$probe.Name+'.marker')
            $arguments=@('-NoProfile','-File',$probeScript,'-LockProbe','-LockPackageDirectory',$probe.Package,'-LockSupportDirectory',$probe.Support,'-LockMarker',$marker)
            $process=Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput (Join-Path $fixtureRoot ('lock-'+$probe.Name+'.out')) -RedirectStandardError (Join-Path $fixtureRoot ('lock-'+$probe.Name+'.err')) -PassThru
            $null=$process.Handle
            $lockChildren.Add($process)
        }
        foreach ($process in $lockChildren) {
            if (-not $process.WaitForExit(30000)) { throw 'Crossed artifact-lock probe timed out.' }
            $process.WaitForExit()
            $process.Refresh()
            Assert-Publication ($null -ne $process.ExitCode -and $process.ExitCode -eq 0) ('Crossed artifact-lock probe failed: '+$process.Id)
        }
        Assert-Publication (Test-Path -LiteralPath (Join-Path $fixtureRoot 'lock-xy.marker')) 'First crossed lock order did not acquire both locks.'
        Assert-Publication (Test-Path -LiteralPath (Join-Path $fixtureRoot 'lock-yx.marker')) 'Reversed crossed lock order did not acquire both locks.'
    } finally {
        foreach ($process in $lockChildren) {
            if (-not $process.HasExited) {
                try { $process.Kill() } catch { }
                if (-not $process.WaitForExit(10000)) { $safeToDeleteFixture=$false }
            }
            $process.Dispose()
        }
    }
    Write-Output 'OpenWrt publication passed: dated release-tree preservation on success/failure/recovery, strict output and reparse guards, 14-17 entry manifest binding, custom support isolation, paired transaction recovery, concurrent publishers, and ZIP SHA256 binding.'
} finally {
    if (-not $safeToDeleteFixture) { throw ('Child producer state is unknown; preserved publication fixture for inspection: '+$fixtureRoot) }
    $resolved=[IO.Path]::GetFullPath($fixtureRoot)
    if ((Split-Path -Parent $resolved) -ine $fixtureRootParent -or (Split-Path -Leaf $resolved) -notmatch '^owpt-[a-f0-9]{32}$') { throw 'Unsafe publication fixture cleanup.' }
    Assert-PublicationTreeSafe -FixtureRoot $resolved
    if ($preserveCacheDiagnosticFixture) {
        Write-Warning ('Preserved publication cache diagnostic fixture with manifests and cache: '+$resolved)
    } else {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
} finally {
    foreach ($name in $goEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$goEnvironment[$name],'Process') }
}
