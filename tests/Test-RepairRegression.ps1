[CmdletBinding()]
param([string]$SingBoxPath)
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('sing-box-repair-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$scriptsRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'
. (Join-Path $scriptsRoot 'Official-SingBoxChecker.ps1')
$SingBoxPath=Resolve-PinnedSingBoxChecker -ProjectRoot (Split-Path -Parent $PSScriptRoot) -RequestedPath $SingBoxPath
$updater = Join-Path $scriptsRoot 'Update-RoutingRules.ps1'
$generator = Join-Path $scriptsRoot 'Generate-SingBoxConfig.ps1'
. $updater -DefinitionsOnly
. (Join-Path $scriptsRoot 'Build-Transaction.ps1')
function Assert-Repair { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Put-Text { param([string]$Path,[string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
try {
    & (Join-Path $PSScriptRoot 'Test-AuditRegression.ps1') -SingBoxPath $SingBoxPath -ClientArtifactOnly
    $paths = Get-BuildPaths (Join-Path $root 'output')
    $lock = Enter-BuildLock $paths
    try {
        $rejected = $false
        try { $other = Enter-BuildLock $paths -TimeoutSeconds 1; $other.Dispose() } catch { $rejected = $true }
        Assert-Repair $rejected 'Build lock did not exclude contender.'
        Put-Text (Join-Path $paths.Destination 'windows.json') 'old-windows'
        Put-Text (Join-Path $paths.Destination 'android.json') 'old-android'
        Put-Text (Join-Path $paths.Stage 'windows.json') 'new-windows'
        Put-Text (Join-Path $paths.Stage 'android.json') 'new-android'
        $originalCleanup = ${function:Complete-BuildCommit}
        function Complete-BuildCommit { param($Paths) throw 'Injected backup cleanup failure' }
        Publish-BuildTransaction $paths -WarningAction SilentlyContinue
        Assert-Repair (([IO.File]::ReadAllText((Join-Path $paths.Destination 'windows.json'))) -eq 'new-windows') 'Cleanup failure lost published Windows config.'
        Assert-Repair (([IO.File]::ReadAllText((Join-Path $paths.Destination 'android.json'))) -eq 'new-android') 'Cleanup failure lost published Android config.'
        Assert-Repair ((Get-Content $paths.Journal -Raw | ConvertFrom-Json).phase -eq 'committed') 'Commit was not durable.'
        ${function:Complete-BuildCommit} = $originalCleanup
        Restore-BuildTransaction $paths
        Assert-Repair (-not (Test-Path $paths.Backup)) 'Committed cleanup did not resume.'
        Put-Text (Join-Path $paths.Stage 'windows.json') 'uncommitted'
        Write-BuildJournal $paths ([ordered]@{version=1;destination=$paths.Destination;phase='prepared';existed=$true})
        [IO.Directory]::Move($paths.Destination,$paths.Backup)
        [IO.Directory]::Move($paths.Stage,$paths.Destination)
        Restore-BuildTransaction $paths
        Assert-Repair (([IO.File]::ReadAllText((Join-Path $paths.Destination 'windows.json'))) -eq 'new-windows') 'Prepared crash recovery lost original config.'
    }
    finally { $lock.Dispose() }

    $orderedLockRoot = Join-Path $root 'ordered-locks'
    [IO.Directory]::CreateDirectory($orderedLockRoot) | Out-Null
    $firstOrderedLock = Join-Path $orderedLockRoot 'a.lock'
    $heldOrderedLock = Join-Path $orderedLockRoot 'b.lock'
    $heldLastLock = [IO.File]::Open($heldOrderedLock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $orderedLockFailed = $false
        try { $null = Enter-BuildLocks -LockPaths @($heldOrderedLock,$firstOrderedLock) -TimeoutSeconds 1 } catch { $orderedLockFailed = $true }
        Assert-Repair $orderedLockFailed 'Multi-lock acquisition did not observe a held second lock.'
        Assert-Repair ([IO.File]::Exists($firstOrderedLock)) 'Multi-lock acquisition did not acquire locks in sorted order.'
        $releasedPartialLock = Enter-BuildLock ([pscustomobject]@{Lock=$firstOrderedLock}) -TimeoutSeconds 1
        $releasedPartialLock.Dispose()
    }
    finally { $heldLastLock.Dispose() }

    $cache = Join-Path $root 'routing-cache'
    $stage = "$cache.update.stage"
    Put-Text (Join-Path $stage 'sentinel') 'other-writer'
    $held = [IO.File]::Open("$cache.update.lock",[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $failed = $false
        try { & $updater -CacheDirectory $cache -OutputPath (Join-Path $root 'merged.json') -LockTimeoutSeconds 1 } catch { $failed = $true }
        Assert-Repair $failed 'Updater failed to reject lock conflict.'
        Assert-Repair (Test-Path -LiteralPath (Join-Path $stage 'sentinel')) 'Lock contender removed owner stage.'
    }
    finally { $held.Dispose() }

    $resource = [pscustomobject]@{tag='fixture';format='plain';url='https://example.invalid/rules.txt'}
    Put-Text (Join-Path $root 'bad-source.txt') "valid.example`nnot a domain`n"
    $failed = $false
    try { Assert-RemoteSource -Resource $resource -Path (Join-Path $root 'bad-source.txt') } catch { $failed = $true }
    Assert-Repair $failed 'Mixed malformed source was accepted.'
    Put-Text (Join-Path $root 'old-source.txt') "a.example`nb.example`nc.example`nd.example`n"
    Put-Text (Join-Path $root 'new-source.txt') "a.example`n"
    Assert-RemoteSource -Resource $resource -Path (Join-Path $root 'new-source.txt')
    $failed = $false
    try { Assert-SourceCountChange -Resource $resource -NewPath (Join-Path $root 'new-source.txt') -OldPath (Join-Path $root 'old-source.txt') -Selectors @() } catch { $failed = $true }
    Assert-Repair $failed 'Abnormal source shrink was accepted.'

    $geoRoot = Join-Path $root 'corrupt-extraction'
    $geoRaw = Join-Path $geoRoot 'fixture.dat'
    Put-Text $geoRaw 'not-a-geodata-protobuf'
    $geoCache = [ordered]@{version=3;source_sha256=(Get-FileHash $geoRaw -Algorithm SHA256).Hash;selector_signature=(Get-Sha256Text 'test');content_sha256='incorrect';categories=@{test=@(@{domain=@('tampered.example')})}}
    Put-Text (Join-Path $geoRoot 'fixture.extracted.json') ($geoCache | ConvertTo-Json -Depth 10)
    $failed=$false
    try { $null=Get-GeodataCache -Resource ([pscustomobject]@{tag='fixture';format='geosite-dat';url='https://example.invalid/geosite.dat'}) -ResourcePath $geoRaw -Selectors @('test') -CacheRoot $geoRoot } catch { $failed=$true }
    Assert-Repair $failed 'Corrupt extracted cache was trusted instead of reparsing its raw source.'

    foreach ($badNames in @(@('../escape.json'), @('same.json','SAME.json'), @('CON.json'))) {
        $profiles = [ordered]@{}
        $i=0
        foreach ($badName in $badNames) { $i++; $profiles["p$i"] = @{file_name=$badName;description='fixture';overlay=@{}} }
        $profilePath = Join-Path $root 'bad-profiles.json'
        Put-Text $profilePath (@{profiles=$profiles} | ConvertTo-Json -Depth 10)
        $failed=$false
        try { & $generator -ListClients -ProfilesPath $profilePath | Out-Null } catch { $failed=$true }
        Assert-Repair $failed 'Unsafe or duplicate profile filename accepted.'
    }

    $output = Join-Path $root 'generated'
    $support = Join-Path $root 'client-build-support'
    & $generator -All -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath | Out-Null
    $cachePath = Join-Path $support 'build-cache.json'
    $firstCache = Get-Content $cachePath -Raw | ConvertFrom-Json
    $orphanPending = Join-Path $support 'build-cache.json.0123456789abcdef0123456789abcdef.pending'
    $nearMatchPending = Join-Path $support 'build-cache.json.0123456789abcdef0123456789abcdef.pending.extra'
    $reparsePending = Join-Path $support 'build-cache.json.abcdef0123456789abcdef0123456789.pending'
    $reparseTarget = Join-Path $support 'pending-target.txt'
    Put-Text $orphanPending 'interrupted-after-prepare'
    Put-Text $nearMatchPending 'not-an-owned-pending-file'
    Put-Text $reparseTarget 'reparse-target-must-survive'
    $reparsePendingCreated = $false
    try {
        New-Item -ItemType SymbolicLink -Path $reparsePending -Target $reparseTarget -ErrorAction Stop | Out-Null
        $reparsePendingCreated = $true
    }
    catch { Write-Warning "Skipping reparse-pending assertion; symbolic-link creation is unavailable: $($_.Exception.Message)" }
    $reuseOutput = & $generator -All -Force -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath *>&1 | Out-String
    Assert-Repair (-not [IO.File]::Exists($orphanPending)) 'Next cache-lock holder did not remove a strict orphan pending file.'
    Assert-Repair ([IO.File]::Exists($nearMatchPending)) 'Pending cleanup removed a non-matching neighboring file.'
    if ($reparsePendingCreated) {
        $reparseItem = Get-Item -LiteralPath $reparsePending -Force
        Assert-Repair (($reparseItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) 'Pending fixture is not a reparse point.'
        Assert-Repair ([IO.File]::Exists($reparsePending)) 'Pending cleanup removed a reparse-point entry.'
        [IO.File]::Delete($reparsePending)
        Assert-Repair ([IO.File]::Exists($reparseTarget)) 'Removing the reparse entry changed its target.'
    }
    $secondCache = Get-Content $cachePath -Raw | ConvertFrom-Json
    Assert-Repair (($firstCache | ConvertTo-Json -Depth 10 -Compress) -ceq ($secondCache | ConvertTo-Json -Depth 10 -Compress)) 'Compile cache is not deterministic.'
    Assert-Repair ($reuseOutput -match 'SRS.*0.*复用') 'Valid compile cache was not reused.'
    Assert-Repair ((@(Get-ChildItem -LiteralPath $output -Force | ForEach-Object Name | Sort-Object) -join ',') -eq 'sing-box-configs.zip') 'Output must contain only the final ZIP.'
    $validBinaryHash = $secondCache.entries[0].binary_sha256
    $secondCache.entries[0].binary_base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('corrupted-cache-binary'))
    Put-Text $cachePath ($secondCache | ConvertTo-Json -Depth 10)
    & $generator -All -Force -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath | Out-Null
    $repairedCache = Get-Content $cachePath -Raw | ConvertFrom-Json
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $repairedHash=[BitConverter]::ToString($sha.ComputeHash([Convert]::FromBase64String($repairedCache.entries[0].binary_base64))).Replace('-','') } finally {$sha.Dispose()}
    Assert-Repair ($repairedHash -eq $validBinaryHash) 'Damaged cached SRS was reused.'
    $oldHash = (Get-FileHash (Join-Path $output 'sing-box-configs.zip') -Algorithm SHA256).Hash
    $oldCacheHash = (Get-FileHash $cachePath -Algorithm SHA256).Hash
    $invalidTemplate = Join-Path $root 'invalid-template.json'
    $invalidTemplateDocument = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $scriptsRoot) 'config\sing-box-core-base.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $invalidTemplateDocument.dns.reverse_mapping = $true
    Put-Text $invalidTemplate (($invalidTemplateDocument | ConvertTo-Json -Depth 100) + "`n")
    $validationFailed = $false
    try { & $generator -Client android -TemplatePath $invalidTemplate -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath -Force | Out-Null } catch { $validationFailed = $true }
    Assert-Repair $validationFailed 'Invalid generated configuration was accepted.'
    Assert-Repair ((Get-FileHash (Join-Path $output 'sing-box-configs.zip') -Algorithm SHA256).Hash -eq $oldHash) 'Validation failure changed the previous ZIP.'
    Assert-Repair ((Get-FileHash $cachePath -Algorithm SHA256).Hash -eq $oldCacheHash) 'Validation failure changed the previous compile cache.'
    $failed=$false
    try { & $generator -Client windows -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath | Out-Null } catch { $failed=$_.Exception.Message -match '\-Force' }
    Assert-Repair $failed 'Existing ZIP was overwritten without Force.'
    Assert-Repair ((Get-FileHash (Join-Path $output 'sing-box-configs.zip') -Algorithm SHA256).Hash -eq $oldHash) 'Rejected build changed ZIP.'
    & $generator -Client windows -Force -RoutingRulesAlreadyUpdated -OutputDirectory $output -SupportDirectory $support -SingBoxPath $SingBoxPath | Out-Null
    $zip=[IO.Compression.ZipFile]::OpenRead((Join-Path $output 'sing-box-configs.zip'))
    try { Assert-Repair ($null -eq $zip.GetEntry('sing-box-android.json') -and $null -ne $zip.GetEntry('sing-box-windows-tun.json')) 'Single-client ZIP contains stale client configurations.' } finally {$zip.Dispose()}
    Write-Host 'Repair regression tests passed: locks, commit cleanup, crash recovery, source validation, paths, compile cache and partial publication.'
}
finally {
    if ((Split-Path -Parent ([IO.Path]::GetFullPath($root))) -ne ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $root) -notlike 'sing-box-repair-test-*') { throw 'Unsafe test cleanup path.' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
