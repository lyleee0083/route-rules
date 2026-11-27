[CmdletBinding()]
param([string]$RuntimeDirectory = 'D:\Software\sing-box', [string]$ArchivePath, [string]$BackupRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$runtime = [IO.Path]::GetFullPath($RuntimeDirectory).TrimEnd('\')
if ($runtime -ine 'D:\Software\sing-box') { throw 'This deployment is scoped to the verified Windows runtime.' }
if ((Get-Item -LiteralPath $runtime -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing reparse target.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$projectRootFull = [IO.Path]::GetFullPath($projectRoot).TrimEnd([char[]]'\/')
if ([string]::IsNullOrWhiteSpace($BackupRoot)) { $BackupRoot = Join-Path $projectRootFull 'backups' }
$backupRootFull = [IO.Path]::GetFullPath($BackupRoot).TrimEnd([char[]]'\/')
if ($backupRootFull -ieq $projectRootFull -or
    -not $backupRootFull.StartsWith($projectRootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BackupRoot must be a dedicated directory inside the project root.'
}
$cursor = $backupRootFull
$backupRootReached = $false
while ($cursor) {
    $attributes = $null
    try { $attributes = [IO.File]::GetAttributes($cursor) }
    catch [IO.FileNotFoundException] { }
    catch [IO.DirectoryNotFoundException] { }
    catch { throw "Cannot safely inspect backup path component: $cursor`n$($_.Exception.Message)" }
    if ($null -ne $attributes -and
        (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Unsafe backup path component: $cursor"
    }
    if ($cursor -ieq $projectRootFull) { $backupRootReached = $true }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
    $cursor = $parent
}
if (-not $backupRootReached) { throw 'BackupRoot could not be anchored to the project root.' }
$backupParent = [IO.Path]::GetDirectoryName($backupRootFull)
if (-not [IO.Directory]::Exists($backupParent)) { throw "BackupRoot parent directory is missing: $backupParent" }
function Assert-CoreStopped {
    if (@(Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'").Count) { throw 'Stop the local core before configuration deployment.' }
}
Assert-CoreStopped
. (Join-Path $PSScriptRoot 'Build-Transaction.ps1')
. (Join-Path $PSScriptRoot 'Windows-Deployment.ps1')
$archivePath = Resolve-WindowsArchivePath -ArchivePath $ArchivePath -ProjectRoot $projectRoot
$locks = $null
try {
$locks = Enter-WindowsDeploymentLocks -RuntimeDirectory $runtime -ArchivePath $archivePath -ProjectRoot $projectRoot
Assert-CoreStopped
$deploymentPaths=Get-WindowsDeploymentPaths $runtime
$recoveryRoot = Join-Path $projectRoot 'backups'
$recoveryRoots = @($recoveryRoot)
if ($backupRootFull -ine $recoveryRoot) { $recoveryRoots += $backupRootFull }
Restore-WindowsDeploymentTransaction $deploymentPaths $recoveryRoots
Assert-DeploymentPlainPath $deploymentPaths.Sets -Directory -Required
Assert-DeploymentPlainPath $deploymentPaths.Config -Required
[IO.Directory]::CreateDirectory($backupRootFull) | Out-Null
Assert-DeploymentPlainPath $backupRootFull -Directory -Required
$taskId = [guid]::NewGuid().ToString('N')
$backup = Join-Path $backupRootFull ('windows-before-current-' + $taskId)
if ([IO.Directory]::Exists($backup) -or [IO.File]::Exists($backup)) { throw "Unique recovery directory already exists: $backup" }
$stage = Join-Path $backup 'staged'
New-Item -ItemType Directory -Path (Join-Path $stage 'rule-set') -Force | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($value in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
    $sid = New-Object Security.Principal.SecurityIdentifier($value)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $backup -AclObject $acl
$archiveSnapshot = Import-WindowsArchiveToStage -ArchivePath $archivePath -StageDirectory $stage
$expectedHashes = $archiveSnapshot.ExpectedHashes
$configPath = $archiveSnapshot.ConfigPath
$config = Read-StrictJsonFile -Path $configPath
. (Join-Path $PSScriptRoot 'Direct-RoutingPolicy.ps1')
Assert-EffectiveDirectConfiguration $config
$core = Join-Path $runtime 'sing-box.exe'
$coreHash = (Get-FileHash -LiteralPath $core).Hash
& $core -D $stage check -c $configPath
if ($LASTEXITCODE -ne 0) { throw 'Official Windows core rejected staged config.' }
Assert-CoreStopped
$liveConfig = Join-Path $runtime 'sing-box-windows-tun.json'
$liveSets = Join-Path $runtime 'rule-set'
Copy-Item -LiteralPath $liveConfig -Destination (Join-Path $backup 'sing-box-windows-tun.json')
$oldRules=Get-DeploymentRuleHashes $liveSets
$newRules=Get-DeploymentRuleHashes (Join-Path $stage 'rule-set')
$journal=[ordered]@{ version=1; runtime=$runtime; backup=$backup; phase='prepared'; old_config=(Get-FileHash -LiteralPath (Join-Path $backup 'sing-box-windows-tun.json')).Hash; new_config=$expectedHashes['sing-box-windows-tun.json']; old_rules=$oldRules; new_rules=$newRules }
# Flush the validated stage and saved configuration before publishing intent.
foreach ($file in @(Get-ChildItem -LiteralPath $stage -Recurse -File)+@(Get-Item -LiteralPath (Join-Path $backup 'sing-box-windows-tun.json'))) {
    Assert-DeploymentPlainPath $file.FullName -Required
    $stream=New-Object IO.FileStream($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
}
if ((Get-FileHash -LiteralPath $liveConfig).Hash -ne $journal.old_config -or -not (Test-DeploymentRuleHashes $liveSets $oldRules)) { throw 'Runtime files changed during preparation; no replacement performed.' }
Write-DeploymentJournal $deploymentPaths $journal
try {
    Move-Item -LiteralPath $liveSets -Destination (Join-Path $backup 'rule-set')
    Move-Item -LiteralPath (Join-Path $stage 'rule-set') -Destination $liveSets
    Set-DeploymentConfigAtomically $deploymentPaths $configPath
    & $core -D $runtime check -c $liveConfig
    if ($LASTEXITCODE -ne 0) { throw 'Live disk configuration check failed.' }
    if ((Get-FileHash -LiteralPath $core).Hash -ne $coreHash) { throw 'Unexpected core replacement.' }
    foreach ($file in @(Get-ChildItem -LiteralPath $liveSets -File) + @(Get-Item -LiteralPath $liveConfig)) {
        $relative = $file.Name
        if ($file.Extension -eq '.srs') { $relative = 'rule-set/' + $file.Name }
        if (-not $expectedHashes.ContainsKey($relative) -or (Get-FileHash -LiteralPath $file.FullName).Hash -ne $expectedHashes[$relative]) { throw 'Deployed file differs from the validated archive snapshot.' }
    }
    $journal.phase='committed'
    Write-DeploymentJournal $deploymentPaths $journal
} catch {
    $deploymentError=$_
    Restore-WindowsDeploymentTransaction $deploymentPaths $recoveryRoots
    throw $deploymentError
}
Restore-WindowsDeploymentTransaction $deploymentPaths $recoveryRoots
$result = [ordered]@{ runtime=$runtime; backup=$backup; configuration_sha256=(Get-FileHash $liveConfig).Hash; rule_sets=@($config.route.rule_set).Count; core_replaced=$false; core_sha256=$coreHash; runtime_started=$false; network_settings_changed=$false }
$json = $result | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText((Join-Path $backup 'DEPLOYMENT.json'),$json.Replace("`r`n","`n")+"`n",(New-Object Text.UTF8Encoding($false)))
$json
} finally { Exit-WindowsDeploymentLocks $locks }
