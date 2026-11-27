[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$scriptsRoot=Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'
. (Join-Path $scriptsRoot 'Build-Transaction.ps1')
. (Join-Path $scriptsRoot 'Windows-Deployment.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('dtx-'+[guid]::NewGuid().ToString('N').Substring(0,24))
[IO.Directory]::CreateDirectory($root) | Out-Null
function Assert-DeployTest { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Put-DeployTest { param([string]$Path,[string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false))) }
function Invoke-DeployRecoveryWithLocks {
    param($Paths,[string[]]$RecoveryRoot,[string]$ArchivePath)
    $locks=Enter-WindowsDeploymentLocks -RuntimeDirectory $Paths.Runtime -ArchivePath $ArchivePath -TimeoutSeconds 1
    try { Restore-WindowsDeploymentTransaction $Paths $RecoveryRoot } finally { Exit-WindowsDeploymentLocks $locks }
}
$cases=@('prepared','task-backup-root','old-moved','new-moved','config-staged','config-replaced','restoring','committed','user-config','user-rules','changed-backup','bad-journal','user-temp','commit-user-edit','partial-config','empty-config','partial-old-config','partial-journal','empty-journal','full-journal','foreign-journal','missing-stage','changed-stage','partial-user-config','partial-user-rules','cross-spacing-journal','foreign-journal-hash')
try {
    foreach ($case in $cases) {
        $fixture=Join-Path $root $case
        $runtime=Join-Path $fixture 'runtime'
        $recovery=Join-Path $fixture 'backups'
        if ($case -eq 'task-backup-root') { $recovery=Join-Path $fixture 'task\backup' }
        $recoveryRoots=@($recovery)
        if ($case -eq 'task-backup-root') { $recoveryRoots=@((Join-Path $fixture 'backups'),$recovery) }
        $archivePath=Join-Path $fixture 'generated\sing-box-configs.zip'
        $backup=Join-Path $recovery ('windows-before-current-'+[guid]::NewGuid().ToString('N'))
        $paths=Get-WindowsDeploymentPaths $runtime
        [IO.Directory]::CreateDirectory((Join-Path $runtime '.runtime')) | Out-Null
        Put-DeployTest $paths.Config "old-config`n"
        Put-DeployTest (Join-Path $paths.Sets 'old.srs') 'old-rule'
        $old=Get-DeploymentRuleHashes $paths.Sets
        $oldConfig=Join-Path $backup 'sing-box-windows-tun.json'
        Put-DeployTest $oldConfig "old-config`n"
        $stage=Join-Path $backup 'staged'
        $newConfig=Join-Path $stage 'sing-box-windows-tun.json'
        Put-DeployTest $newConfig "new-config`n"
        Put-DeployTest (Join-Path $stage 'rule-set\new.srs') 'new-rule'
        $new=Get-DeploymentRuleHashes (Join-Path $stage 'rule-set')
        $journal=[ordered]@{version=1;runtime=$paths.Runtime;backup=$backup;phase='prepared';old_config=(Get-FileHash $oldConfig).Hash;new_config=(Get-FileHash $newConfig).Hash;old_rules=$old;new_rules=$new}
        Write-DeploymentJournal $paths $journal
        if ($case -ne 'prepared') { [IO.Directory]::Move($paths.Sets,(Join-Path $backup 'rule-set')) }
        if ($case -notin @('prepared','old-moved')) { [IO.Directory]::Move((Join-Path $stage 'rule-set'),$paths.Sets) }
        if ($case -eq 'config-staged') { Copy-Item -LiteralPath $newConfig -Destination $paths.ConfigWrite }
        if ($case -notin @('prepared','old-moved','new-moved','config-staged')) { Set-DeploymentConfigAtomically $paths $newConfig }
        if ($case -eq 'restoring') {
            [IO.Directory]::Move($paths.Sets,(Join-Path $backup 'failed-rule-set'))
            [IO.Directory]::Move((Join-Path $backup 'rule-set'),$paths.Sets)
        }
        if ($case -in @('committed','commit-user-edit')) { $journal.phase='committed'; Write-DeploymentJournal $paths $journal }
        if ($case -in @('user-config','commit-user-edit')) { Put-DeployTest $paths.Config 'user-config' }
        if ($case -eq 'user-rules') { Put-DeployTest (Join-Path $paths.Sets 'user.srs') 'user-rule' }
        if ($case -eq 'changed-backup') { Put-DeployTest $oldConfig 'changed-backup' }
        if ($case -eq 'bad-journal') { $journal.backup=Join-Path $fixture 'outside'; Write-DeploymentJournal $paths $journal }
        if ($case -eq 'user-temp') { Put-DeployTest $paths.ConfigWrite 'user-owned-temporary' }
        $residue=$null
        if ($case -in @('partial-config','empty-config','partial-old-config','missing-stage','changed-stage','partial-user-config','partial-user-rules')) {
            $residue=$paths.ConfigWrite
            $text='new-'
            if ($case -eq 'empty-config') { $text='' }
            if ($case -eq 'partial-old-config') { $text='old-' }
            Put-DeployTest $residue $text
        }
        if ($case -in @('partial-journal','empty-journal','full-journal','foreign-journal')) {
            $residue=$paths.Journal+'.write'
            $journal.phase='committed'
            $bytes=ConvertTo-DeploymentJournalBytes $journal
            if ($case -eq 'empty-journal') { $bytes=[byte[]]@() }
            if ($case -eq 'partial-journal') { $bytes=[byte[]]$bytes[0..10] }
            [IO.File]::WriteAllBytes($residue,$bytes)
            if ($case -eq 'foreign-journal') { Put-DeployTest $residue '{"foreign":true}' }
        }
        if ($case -in @('cross-spacing-journal','foreign-journal-hash')) {
            $residue=$paths.Journal+'.write'
            $original=Get-Content -LiteralPath $paths.Journal -Raw -Encoding UTF8
            if ($case -eq 'cross-spacing-journal') {
                $original=$original.Replace('":  ','": ').Replace('": ','":  ')
                Put-DeployTest $paths.Journal $original
                $pending=$original.Replace('"prepared"','"committed"')
                $pending=$pending.Substring(0,$pending.Length-3)
            } else { $pending=$original.Replace([string]$journal.old_config,('F'*64)) }
            Put-DeployTest $residue $pending
        }
        if ($case -eq 'missing-stage') { [IO.File]::Delete($newConfig) }
        if ($case -eq 'changed-stage') { Put-DeployTest $newConfig 'changed-stage' }
        if ($case -eq 'partial-user-config') { Put-DeployTest $paths.Config 'user-config' }
        if ($case -eq 'partial-user-rules') { Put-DeployTest (Join-Path $paths.Sets 'user.srs') 'user-rule' }
        $residueHash=$null
        if ($residue) { $residueHash=(Get-FileHash -LiteralPath $residue).Hash }
        $beforeHash=(Get-FileHash $paths.Config).Hash
        $beforeRules=$null
        if (Test-Path -LiteralPath $paths.Sets) { $beforeRules=Get-DeploymentRuleHashes $paths.Sets }
        $failed=$false
        $failureMessage=''
        try { Invoke-DeployRecoveryWithLocks $paths $recoveryRoots $archivePath } catch { $failed=$true; $failureMessage=$_.Exception.Message+' '+$_.ScriptStackTrace }
        $expectedFailure=$case -in @('user-config','user-rules','changed-backup','bad-journal','user-temp','commit-user-edit','foreign-journal','missing-stage','changed-stage','partial-user-config','partial-user-rules','foreign-journal-hash')
        Assert-DeployTest ($failed -eq $expectedFailure) ('Wrong transaction outcome: '+$case+' '+$failureMessage)
        if ($expectedFailure) {
            Assert-DeployTest ([IO.File]::Exists($paths.Journal)) ('Conflict lost journal: '+$case)
            Assert-DeployTest ((Get-FileHash $paths.Config).Hash -eq $beforeHash) ('Conflict overwrote runtime: '+$case)
            Assert-DeployTest (Test-DeploymentRuleHashes $paths.Sets $beforeRules) ('Conflict changed rules: '+$case)
            if ($residue) { Assert-DeployTest ((Get-FileHash -LiteralPath $residue).Hash -eq $residueHash) ('Conflict changed residue: '+$case) }
        } else {
            $expected=$old; $configHash=$journal.old_config
            if ($case -eq 'committed') { $expected=$new; $configHash=$journal.new_config }
            Assert-DeployTest (Test-DeploymentRuleHashes $paths.Sets $expected) ('Wrong restored rules: '+$case)
            Assert-DeployTest ((Get-FileHash $paths.Config).Hash -eq $configHash) ('Wrong restored config: '+$case)
            Assert-DeployTest (-not (Test-Path $paths.Journal)) ('Recovery journal retained after success: '+$case)
            Invoke-DeployRecoveryWithLocks $paths $recoveryRoots $archivePath
            if ($residue) {
                $saved=@(Get-ChildItem -LiteralPath $backup -File | Where-Object { $_.Name -like '*.interrupted-*' })
                Assert-DeployTest ($saved.Count -eq 1 -and (Get-FileHash -LiteralPath $saved[0].FullName).Hash -eq $residueHash) ('Interrupted bytes not retained: '+$case)
            }
        }
    }
    $lockFixture=Join-Path $root 'lock-contention'
    $lockRuntime=Join-Path $lockFixture 'runtime'
    $lockArchive=Join-Path $lockFixture 'generated\sing-box-configs.zip'
    [IO.Directory]::CreateDirectory($lockRuntime) | Out-Null
    $controlPath=Join-Path $lockRuntime '.runtime\control.lock'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $controlPath)) | Out-Null
    $buildPaths=Get-BuildPaths (Split-Path -Parent $lockArchive)
    $heldControl=[IO.File]::Open($controlPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $blocked=$false
    try { $other=Enter-WindowsDeploymentLocks -RuntimeDirectory $lockRuntime -ArchivePath $lockArchive -TimeoutSeconds 1; Exit-WindowsDeploymentLocks $other } catch { $blocked=$true }
    finally { $heldControl.Dispose() }
    Assert-DeployTest $blocked 'Deployment ignored a held start/stop control lock.'
    $locks=Enter-WindowsDeploymentLocks -RuntimeDirectory $lockRuntime -ArchivePath $lockArchive -TimeoutSeconds 1
    try {
        $blocked=$false
        try { $other=Enter-WindowsDeploymentLocks -RuntimeDirectory $lockRuntime -ArchivePath $lockArchive -TimeoutSeconds 1; Exit-WindowsDeploymentLocks $other } catch { $blocked=$true }
        Assert-DeployTest $blocked 'Concurrent deployment entered while the control/build locks were held.'
    } finally { Exit-WindowsDeploymentLocks $locks }
    $heldBuild=Enter-BuildLock $buildPaths -TimeoutSeconds 1
    try {
        $blocked=$false
        try { $other=Enter-WindowsDeploymentLocks -RuntimeDirectory $lockRuntime -ArchivePath $lockArchive -TimeoutSeconds 1; Exit-WindowsDeploymentLocks $other } catch { $blocked=$true }
        Assert-DeployTest $blocked 'Deployment ignored a held archive publication lock.'
        $controlProbe=[IO.File]::Open($controlPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $controlProbe.Dispose()
    } finally { $heldBuild.Dispose() }
    Put-DeployTest $buildPaths.Journal '{}'
    $blocked=$false
    try { $other=Enter-WindowsDeploymentLocks -RuntimeDirectory $lockRuntime -ArchivePath $lockArchive -TimeoutSeconds 1; Exit-WindowsDeploymentLocks $other } catch { $blocked=$true }
    Assert-DeployTest ($blocked -and [IO.File]::Exists($buildPaths.Journal)) 'Pending archive recovery was ignored or modified.'
    $controlProbe=[IO.File]::Open($controlPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $buildProbe=Enter-BuildLock $buildPaths -TimeoutSeconds 1; $buildProbe.Dispose() } finally { $controlProbe.Dispose() }
    [IO.File]::Delete($buildPaths.Journal)
    $sample=(New-Object Text.UTF8Encoding($false)).GetBytes('full validated bytes')
    for ($length=0; $length -le $sample.Length; $length++) {
        $partial=New-Object byte[] $length
        [Array]::Copy($sample,$partial,$length)
        Assert-DeployTest (Test-DeploymentBytePrefix $partial $sample) 'Valid byte prefix rejected.'
        if ($length -gt 0) {
            $partial[$length-1]=$partial[$length-1] -bxor 1
            Assert-DeployTest (-not (Test-DeploymentBytePrefix $partial $sample)) 'Changed byte prefix accepted.'
        }
    }
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile('D:\Software\sing-box\sing-box-control.ps1',[ref]$tokens,[ref]$errors)
    $node=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-NoPendingConfigurationDeployment'},$true) | Select-Object -First 1
    Assert-DeployTest ($null -ne $node) 'Actual controller is missing the startup transaction guard.'
    . ([scriptblock]::Create($node.Extent.Text))
    $runtimeDirectory=Join-Path $root 'startup-state'
    [IO.Directory]::CreateDirectory($runtimeDirectory) | Out-Null
    Assert-NoPendingConfigurationDeployment
    foreach ($name in @('deployment-journal.json','deployment-journal.json.write','deployment-config.write')) {
        $file=Join-Path $runtimeDirectory $name
        Put-DeployTest $file '{}'
        $blocked=$false; try { Assert-NoPendingConfigurationDeployment } catch { $blocked=$true }
        Assert-DeployTest $blocked ('Startup ignored pending '+$name)
        [IO.File]::Delete($file)
    }
    $deployment=Get-Content -LiteralPath (Join-Path $scriptsRoot 'Deploy-WindowsConfig.ps1') -Raw
    Assert-DeployTest ($deployment.IndexOf('Restore-WindowsDeploymentTransaction') -gt $deployment.IndexOf('$locks = Enter-WindowsDeploymentLocks')) 'Recovery is not under the project locks.'
    Write-Output ('Windows durable deployment passed: '+$cases.Count+' recovery/interruption/conflict cases; exclusive control/build lock contention, lock release and pending archive guard; three actual startup guards; private fixtures only.')
} finally {
    $absolute=[IO.Path]::GetFullPath($root)
    if ((Split-Path -Parent $absolute) -ine ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $absolute) -notmatch '^dtx-[a-f0-9]{24}$') { throw 'Unsafe deployment test cleanup.' }
    $items=@(Get-Item -LiteralPath $absolute -Force)+@(Get-ChildItem -LiteralPath $absolute -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Linked test fixture retained; no recursive cleanup.' }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
