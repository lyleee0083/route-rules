param(
    [string]$UpdaterPath,
    [string]$TestRoot
)

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
if (-not $UpdaterPath) { $UpdaterPath = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'Update-RoutingRules.ps1' }
. (Join-Path (Split-Path -Parent $UpdaterPath) 'Json-Validation.ps1')
# TestRoot is a parent directory, never a directory owned by this test.
$testParent = if ($TestRoot) { (Resolve-Path -LiteralPath $TestRoot -ErrorAction Stop).Path } else { [IO.Path]::GetTempPath() }
$testParentItem = Get-Item -LiteralPath $testParent -Force -ErrorAction Stop
if (-not $testParentItem.PSIsContainer) { throw 'TestRoot must be an existing parent directory.' }
for ($ancestor = $testParentItem; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'TestRoot cannot pass through a reparse point.' }
}
$testParent = $testParentItem.FullName
$ownedTestRoot = Join-Path $testParent ("rtx-{0}" -f [guid]::NewGuid().ToString('N').Substring(0,12))
$TestRoot = $ownedTestRoot
$ownsTestRoot = $false
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($UpdaterPath, [ref]$tokens, [ref]$errors)
if (@($errors).Count -gt 0) { throw 'Updater parse failed.' }
$functionNames = @(
    'Format-JsonText',
    'Read-JsonFile',
    'Get-NormalizedRoutingPath',
    'Test-RoutingPathOverlap',
    'Assert-RoutingPathHasNoReparsePoint',
    'Assert-RoutingPathTreeHasNoReparsePoint',
    'Get-RoutingPlanRegistry',
    'Assert-RoutingTransactionPathSet',
    'Assert-RoutingTransactionPaths',
    'Remove-RoutingTransactionPath',
    'Get-RoutingTransactionPaths',
    'Resolve-RoutingInputFilePath',
    'Get-RoutingManifestLocalSourcePaths',
    'Get-RoutingProtectedProjectRoots',
    'Enter-RoutingUpdateLocks',
    'Exit-RoutingUpdateLocks',
    'Write-RoutingTransactionJournal',
    'Read-RoutingTransactionJournal',
    'Complete-RoutingCommittedTransaction',
    'Rollback-RoutingPreparedTransaction',
    'Invoke-RoutingTransactionRecovery',
    'Publish-RoutingTransaction',
    'Assert-RoutingFetchPathsSupported'
)
foreach ($functionName in $functionNames) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true) | Select-Object -First 1
    if ($null -eq $definition) { throw "Required function was not found: $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Reset-Case {
    param([string]$Name)
    $root = Join-Path $TestRoot $Name
    if ($Name -notmatch '^[a-z0-9-]+$' -or (Test-Path -LiteralPath $root)) { throw 'Unsafe or reused test case directory.' }
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    return Get-RoutingTransactionPaths -CachePath (Join-Path $root 'cache') -OutputPath (Join-Path $root 'merged.json')
}

function Write-StateFile {
    param([string]$Path, [string]$Value)
    $parent = Split-Path -Parent $Path
    if (-not [System.IO.Directory]::Exists($parent)) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Value, [System.Text.Encoding]::ASCII)
}

function Write-CacheState {
    param([string]$Directory, [string]$Value)
    [System.IO.Directory]::CreateDirectory($Directory) | Out-Null
    Write-StateFile -Path (Join-Path $Directory 'state.txt') -Value $Value
}

function Read-CacheState {
    param([string]$Directory)
    return [System.IO.File]::ReadAllText((Join-Path $Directory 'state.txt'))
}

function New-TestJournal {
    param($Paths, [bool]$CacheExisted, [bool]$OutputExisted, [string]$Phase)
    $journal = [ordered]@{
        version = 1
        phase = $Phase
        cache_path = $Paths.CachePath
        cache_stage_path = $Paths.CacheStagePath
        cache_backup_path = $Paths.CacheBackupPath
        cache_existed = $CacheExisted
        output_path = $Paths.OutputPath
        output_stage_path = $Paths.OutputStagePath
        output_backup_path = $Paths.OutputBackupPath
        output_existed = $OutputExisted
        created_at = [DateTime]::UtcNow.ToString('o')
        updated_at = ''
    }
    Write-RoutingTransactionJournal -Journal $journal -Paths $Paths
    return $journal
}

function Assert-NoTransactionFiles {
    param($Paths, [string]$Context)
    foreach ($path in @($Paths.CacheStagePath, $Paths.CacheBackupPath, $Paths.OutputStagePath, $Paths.OutputBackupPath, $Paths.JournalPath, $Paths.JournalWritePath, $Paths.JournalReplaceBackupPath)) {
        Assert-True (-not [System.IO.File]::Exists($path) -and -not [System.IO.Directory]::Exists($path)) "$Context residue: $path"
    }
}

function Test-AnyPathExists {
    param([string]$Path)
    return [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)
}

function Get-TransactionArtifactPaths {
    param([string]$CachePath, [string]$OutputPath)
    $cache = [System.IO.Path]::GetFullPath($CachePath).TrimEnd('\')
    $output = [System.IO.Path]::GetFullPath($OutputPath).TrimEnd('\')
    return [string[]]@(
        $cache,
        "$cache.update.stage",
        "$cache.update.backup",
        "$cache.update.lock",
        "$output.update.stage",
        "$output.update.backup",
        "$output.update.lock",
        "$output.update.transaction.json",
        "$output.update.transaction.write.tmp",
        "$output.update.transaction.replace.backup"
    )
}

function Invoke-FailFastPathCase {
    param(
        [string]$Name,
        [string]$ManifestPath,
        [string]$CachePath,
        [string]$OutputPath,
        [string[]]$PreserveFilePaths = @()
    )

    $artifacts = @(Get-TransactionArtifactPaths -CachePath $CachePath -OutputPath $OutputPath)
    $beforeArtifacts = @{}
    foreach ($path in $artifacts) { $beforeArtifacts[$path] = Test-AnyPathExists $path }
    $preservedBytes = @{}
    foreach ($path in $PreserveFilePaths) {
        $preservedBytes[$path] = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($path))
    }

    $rejected = $false
    try {
        & $UpdaterPath -ManifestPath $ManifestPath -CacheDirectory $CachePath -OutputPath $OutputPath -Offline
    }
    catch {
        $rejected = $true
    }
    Assert-True $rejected "$Name must reject before running the updater body"
    foreach ($path in $artifacts) {
        Assert-True ((Test-AnyPathExists $path) -eq [bool]$beforeArtifacts[$path]) "$Name changed or created a transaction path before rejection: $path"
    }
    foreach ($path in $PreserveFilePaths) {
        $actual = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($path))
        Assert-True ($actual -ceq $preservedBytes[$path]) "$Name changed protected input bytes: $path"
    }
}

function New-PathFixture {
    param([string]$Name, [string]$ParentPath)
    $root = Join-Path $ParentPath $Name
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    $routingRoot = Join-Path $root 'routing'
    [System.IO.Directory]::CreateDirectory($routingRoot) | Out-Null
    $manifestPath = Join-Path $routingRoot 'routing-sources.json'
    $staticPath = Join-Path $routingRoot 'static.json'
    [System.IO.File]::WriteAllText($manifestPath, '{"version":2,"resources":[],"rules":[{"id":"static","action":"direct","inputs":[{"type":"local","format":"source","path":"static.json"}]}]}', [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText($staticPath, '{"fixture":"preserve"}', [System.Text.Encoding]::ASCII)
    return [PSCustomObject]@{ Root=$root; RoutingRoot=$routingRoot; ManifestPath=$manifestPath; StaticPath=$staticPath }
}

function Write-EmptyManifest {
    param([string]$Path)
    [System.IO.File]::WriteAllText($Path, '{"version":2,"resources":[],"rules":[]}', [System.Text.Encoding]::ASCII)
}

$testBodyError = $null
$testCleanupError = $null

if (-not ('RoutingTransactionLoopbackServer' -as [type])) {
    $loopbackServerSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class RoutingTransactionLoopbackServer : IDisposable
{
    private readonly TcpListener listener;
    private readonly Thread acceptThread;
    private readonly List<Thread> handlerThreads = new List<Thread>();
    private readonly object gate = new object();
    private readonly int expectedRequests;
    private readonly int port;
    private volatile bool stopping;
    private int acceptedRequests;
    private int completedRequests;
    private int activeRequests;
    private int maxActiveRequests;
    private string failure = String.Empty;

    public RoutingTransactionLoopbackServer(int requestCount)
    {
        if (requestCount < 1) throw new ArgumentOutOfRangeException("requestCount");
        expectedRequests = requestCount;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        acceptThread = new Thread(AcceptLoop);
        acceptThread.IsBackground = true;
        acceptThread.Start();
    }

    public string BaseUrl { get { return "http://127.0.0.1:" + port.ToString() + "/"; } }
    public int RequestCount { get { return Interlocked.CompareExchange(ref completedRequests, 0, 0); } }
    public int MaxActiveRequests { get { return Interlocked.CompareExchange(ref maxActiveRequests, 0, 0); } }
    public string Failure { get { lock (gate) { return failure; } } }

    private void SetFailure(string message)
    {
        lock (gate) { if (String.IsNullOrEmpty(failure)) failure = message; }
    }

    private void AcceptLoop()
    {
        try
        {
            while (Interlocked.CompareExchange(ref acceptedRequests, 0, 0) < expectedRequests)
            {
                TcpClient client = listener.AcceptTcpClient();
                Interlocked.Increment(ref acceptedRequests);
                Thread handler = new Thread(delegate() { Handle(client); });
                handler.IsBackground = true;
                lock (handlerThreads) { handlerThreads.Add(handler); }
                handler.Start();
            }
        }
        catch (Exception ex)
        {
            if (!stopping) SetFailure(ex.GetType().Name + ": " + ex.Message);
        }
        Thread[] handlers;
        lock (handlerThreads) { handlers = handlerThreads.ToArray(); }
        foreach (Thread handler in handlers)
        {
            if (!handler.Join(15000)) SetFailure("HTTP fixture handler did not exit.");
        }
    }

    private void Handle(TcpClient client)
    {
        int active = Interlocked.Increment(ref activeRequests);
        int seen;
        do
        {
            seen = Interlocked.CompareExchange(ref maxActiveRequests, 0, 0);
            if (active <= seen) break;
        } while (Interlocked.CompareExchange(ref maxActiveRequests, active, seen) != seen);

        try
        {
            client.ReceiveTimeout = 10000;
            client.SendTimeout = 10000;
            using (NetworkStream stream = client.GetStream())
            {
                MemoryStream requestBytes = new MemoryStream();
                int matched = 0;
                while (requestBytes.Length < 32768 && matched < 4)
                {
                    int next = stream.ReadByte();
                    if (next < 0) throw new IOException("Client closed before request headers completed.");
                    requestBytes.WriteByte((byte)next);
                    if ((matched == 0 || matched == 2) && next == 13) matched++;
                    else if ((matched == 1 || matched == 3) && next == 10) matched++;
                    else matched = next == 13 ? 1 : 0;
                }
                if (matched < 4) throw new IOException("Request headers exceeded the fixture limit.");
                string requestText = Encoding.ASCII.GetString(requestBytes.ToArray());
                string requestLine = requestText.Split(new string[] { "\r\n" }, StringSplitOptions.None)[0];
                string bodyText;
                if (requestLine.StartsWith("GET /one.txt ", StringComparison.Ordinal)) bodyText = "loopback-one.example\n";
                else if (requestLine.StartsWith("GET /two.txt ", StringComparison.Ordinal)) bodyText = "loopback-two.example\n";
                else throw new IOException("Unexpected loopback request: " + requestLine);

                Thread.Sleep(250);
                byte[] body = Encoding.UTF8.GetBytes(bodyText);
                byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " + body.Length.ToString() + "\r\nConnection: close\r\n\r\n");
                stream.Write(header, 0, header.Length);
                stream.Write(body, 0, body.Length);
                stream.Flush();
                Interlocked.Increment(ref completedRequests);
            }
        }
        catch (Exception ex)
        {
            SetFailure(ex.GetType().Name + ": " + ex.Message);
        }
        finally
        {
            Interlocked.Decrement(ref activeRequests);
            client.Close();
        }
    }

    public void StopAndJoin()
    {
        stopping = true;
        try { listener.Stop(); } catch { }
        if (!acceptThread.Join(15000)) throw new TimeoutException("Loopback HTTP fixture accept thread did not exit.");
    }

    public void Dispose() { StopAndJoin(); }
}
'@
    Add-Type -TypeDefinition $loopbackServerSource -Language CSharp -ErrorAction Stop
}

try {
New-Item -ItemType Directory -Path $ownedTestRoot -ErrorAction Stop | Out-Null
$ownsTestRoot = $true

# Default-shaped and custom transaction layouts remain valid without touching project routing data.
$layout = New-PathFixture -Name 'layout-default' -ParentPath $TestRoot
$defaultCache = Join-Path $layout.RoutingRoot 'cache'
$defaultOutput = Join-Path (Join-Path $layout.RoutingRoot 'merged') 'merged-rules.json'
$defaultPaths = Get-RoutingTransactionPaths -CachePath $defaultCache -OutputPath $defaultOutput -ManifestPath $layout.ManifestPath -ProtectedPaths @($layout.StaticPath)
Assert-True ([string]::Equals($defaultPaths.CachePath, [IO.Path]::GetFullPath($defaultCache), [StringComparison]::OrdinalIgnoreCase)) 'default-shaped cache path accepted'
Assert-True ([string]::Equals($defaultPaths.OutputPath, [IO.Path]::GetFullPath($defaultOutput), [StringComparison]::OrdinalIgnoreCase)) 'default-shaped merged output accepted'
$customPaths = Get-RoutingTransactionPaths -CachePath (Join-Path $layout.Root 'custom-cache') -OutputPath (Join-Path $layout.Root 'custom-merged.json') -ManifestPath $layout.ManifestPath -ProtectedPaths @($layout.StaticPath)
Assert-True ([string]::Equals($customPaths.ManifestPath, [IO.Path]::GetFullPath($layout.ManifestPath), [StringComparison]::OrdinalIgnoreCase)) 'legal custom paths accepted'

$pureRejected = $false
try {
    Get-RoutingTransactionPaths -CachePath (Join-Path $layout.Root 'reserved-cache') -OutputPath ((Join-Path $layout.Root 'reserved-cache') + '.update.stage')
}
catch { $pureRejected = $true }
Assert-True $pureRejected 'transaction path construction rejects a derived-path alias without creating files'
$pureRejected = $false
try {
    Get-RoutingTransactionPaths -CachePath (Join-Path $layout.RoutingRoot 'alias\..\cache') -OutputPath (Join-Path (Join-Path $layout.RoutingRoot 'cache') 'merged.json')
}
catch { $pureRejected = $true }
Assert-True $pureRejected 'transaction path construction rejects normalized nested aliases'
$pureRejected = $false
try {
    $null = Get-RoutingTransactionPaths -CachePath (Join-Path $layout.Root 'protected-cache') -OutputPath (Join-Path $layout.Root 'safe.json') -ProtectedPaths @($layout.StaticPath)
}
catch { $pureRejected = $true }
Assert-True (-not $pureRejected) 'nonoverlapping static input does not reject a legal custom transaction'
$pureRejected = $false
try {
    Get-RoutingTransactionPaths -CachePath $layout.RoutingRoot -OutputPath (Join-Path $layout.Root 'source-parent.json') -ProtectedPaths @($layout.StaticPath)
}
catch { $pureRejected = $true }
Assert-True $pureRejected 'transaction directory cannot contain a static source input'
$pureRejected = $false
$maintainedScriptsRoot = Split-Path -Parent $UpdaterPath
try {
    Get-RoutingTransactionPaths -CachePath $maintainedScriptsRoot -OutputPath (Join-Path $layout.Root 'source-code.json') -ProtectedRoots @($maintainedScriptsRoot)
}
catch { $pureRejected = $true }
Assert-True $pureRejected 'maintenance source roots are protected'

# Exercise the real entry point with collisions and verify it fails before lock, stage, or journal creation.
$collisionCases = @()
$case = New-PathFixture -Name 'collision-nested' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='nested cache/output'; Fixture=$case; Cache=(Join-Path $case.Root 'cache'); Output=(Join-Path (Join-Path $case.Root 'cache') 'merged.json'); Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-equal' -ParentPath $TestRoot
$samePath = Join-Path $case.Root 'same-path'
$collisionCases += [PSCustomObject]@{ Name='equal cache/output'; Fixture=$case; Cache=$samePath; Output=$samePath; Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-normalized-alias' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='normalized alias overlap'; Fixture=$case; Cache=(Join-Path $case.Root 'nested\..\cache'); Output=(Join-Path (Join-Path $case.Root 'cache') 'merged.json'); Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-manifest-output' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='manifest is output'; Fixture=$case; Cache=(Join-Path $case.Root 'cache'); Output=$case.ManifestPath; Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-static-output' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='static source is output'; Fixture=$case; Cache=(Join-Path $case.Root 'cache'); Output=$case.StaticPath; Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-source-parent-cache' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='static source inside cache'; Fixture=$case; Cache=$case.RoutingRoot; Output=(Join-Path $case.Root 'merged.json'); Preserve=@($case.ManifestPath,$case.StaticPath) }
$case = New-PathFixture -Name 'collision-reserved-derived' -ParentPath $TestRoot
$collisionCases += [PSCustomObject]@{ Name='output aliases cache stage'; Fixture=$case; Cache=(Join-Path $case.Root 'cache'); Output=((Join-Path $case.Root 'cache') + '.update.stage'); Preserve=@($case.ManifestPath,$case.StaticPath) }
foreach ($collision in $collisionCases) {
    Invoke-FailFastPathCase -Name $collision.Name -ManifestPath $collision.Fixture.ManifestPath -CachePath $collision.Cache -OutputPath $collision.Output -PreserveFilePaths $collision.Preserve
}

# A junction in an input ancestor is rejected before writes and leaves the external sentinel intact.
$junctionFixture = New-PathFixture -Name 'junction-entry' -ParentPath $TestRoot
$sentinelRoot = Join-Path $junctionFixture.Root 'sentinel'
[System.IO.Directory]::CreateDirectory($sentinelRoot) | Out-Null
$sentinelPath = Join-Path $sentinelRoot 'keep.txt'
[System.IO.File]::WriteAllText($sentinelPath, 'outside-sentinel', [System.Text.Encoding]::ASCII)
$junctionPath = Join-Path $junctionFixture.Root 'external-alias'
New-Item -ItemType Junction -Path $junctionPath -Target $sentinelRoot -ErrorAction Stop | Out-Null
$junctionCache = Join-Path $junctionPath 'cache'
Invoke-FailFastPathCase -Name 'reparse ancestor' -ManifestPath $junctionFixture.ManifestPath -CachePath $junctionCache -OutputPath (Join-Path $junctionFixture.Root 'merged.json') -PreserveFilePaths @($junctionFixture.ManifestPath,$junctionFixture.StaticPath,$sentinelPath)
[System.IO.Directory]::Delete($junctionPath)
Assert-True ([System.IO.File]::ReadAllText($sentinelPath) -ceq 'outside-sentinel') 'reparse path rejection preserves external sentinel'

# Cleanup and recovery refuse directory trees containing a junction, retaining both the link and target bytes.
$cleanupFixture = New-PathFixture -Name 'junction-cleanup' -ParentPath $TestRoot
$cleanupSentinelRoot = Join-Path $cleanupFixture.Root 'sentinel'
[System.IO.Directory]::CreateDirectory($cleanupSentinelRoot) | Out-Null
$cleanupSentinel = Join-Path $cleanupSentinelRoot 'keep.txt'
[System.IO.File]::WriteAllText($cleanupSentinel, 'cleanup-sentinel', [System.Text.Encoding]::ASCII)
$cleanupPaths = Get-RoutingTransactionPaths -CachePath (Join-Path $cleanupFixture.Root 'cache') -OutputPath (Join-Path $cleanupFixture.Root 'merged.json') -ManifestPath $cleanupFixture.ManifestPath -ProtectedPaths @($cleanupFixture.StaticPath)
[System.IO.Directory]::CreateDirectory($cleanupPaths.CachePath) | Out-Null
$cacheJunction = Join-Path $cleanupPaths.CachePath 'external'
New-Item -ItemType Junction -Path $cacheJunction -Target $cleanupSentinelRoot -ErrorAction Stop | Out-Null
$cleanupRejected = $false
try { Remove-RoutingTransactionPath -Path $cleanupPaths.CachePath -Paths $cleanupPaths } catch { $cleanupRejected = $true }
Assert-True $cleanupRejected 'recursive transaction cleanup rejects a nested junction'
Assert-True ([System.IO.Directory]::Exists($cleanupPaths.CachePath) -and [System.IO.Directory]::Exists($cacheJunction)) 'rejected cleanup retains the cache tree and junction'
Assert-True ([System.IO.File]::ReadAllText($cleanupSentinel) -ceq 'cleanup-sentinel') 'rejected cleanup preserves external target bytes'

$journalFixture = New-PathFixture -Name 'junction-recovery' -ParentPath $TestRoot
$journalSentinelRoot = Join-Path $journalFixture.Root 'sentinel'
[System.IO.Directory]::CreateDirectory($journalSentinelRoot) | Out-Null
$journalSentinel = Join-Path $journalSentinelRoot 'keep.txt'
[System.IO.File]::WriteAllText($journalSentinel, 'recovery-sentinel', [System.Text.Encoding]::ASCII)
$journalPaths = Get-RoutingTransactionPaths -CachePath (Join-Path $journalFixture.Root 'cache') -OutputPath (Join-Path $journalFixture.Root 'merged.json') -ManifestPath $journalFixture.ManifestPath -ProtectedPaths @($journalFixture.StaticPath)
[System.IO.Directory]::CreateDirectory($journalPaths.CachePath) | Out-Null
$journalJunction = Join-Path $journalPaths.CachePath 'external'
New-Item -ItemType Junction -Path $journalJunction -Target $journalSentinelRoot -ErrorAction Stop | Out-Null
Write-StateFile -Path $journalPaths.JournalPath -Value 'unknown-journal-bytes'
$journalRejected = $false
try { Invoke-RoutingTransactionRecovery -Paths $journalPaths } catch { $journalRejected = $true }
Assert-True $journalRejected 'journal recovery revalidates reparse-bearing transaction trees'
Assert-True ([System.IO.File]::ReadAllText($journalPaths.JournalPath) -ceq 'unknown-journal-bytes') 'unsafe recovery retains unknown journal bytes'
Assert-True ([System.IO.File]::ReadAllText($journalSentinel) -ceq 'recovery-sentinel') 'unsafe recovery preserves external target bytes'

[System.IO.Directory]::Delete($cacheJunction)
[System.IO.Directory]::Delete($journalJunction)
Assert-True ([System.IO.File]::ReadAllText($cleanupSentinel) -ceq 'cleanup-sentinel') 'junction unlink leaves sentinel intact'
Assert-True ([System.IO.File]::ReadAllText($journalSentinel) -ceq 'recovery-sentinel') 'recovery junction unlink leaves sentinel intact'

# A fixed path capability cannot be used to recursively remove arbitrary paths.
$arbitrary = Join-Path $cleanupFixture.Root 'not-a-transaction-path.txt'
[System.IO.File]::WriteAllText($arbitrary, 'keep', [System.Text.Encoding]::ASCII)
$arbitraryRejected = $false
try { Remove-RoutingTransactionPath -Path $arbitrary -Paths $cleanupPaths } catch { $arbitraryRejected = $true }
Assert-True $arbitraryRejected 'cleanup rejects paths absent from the validated transaction plan'
Assert-True ([System.IO.File]::ReadAllText($arbitrary) -ceq 'keep') 'arbitrary cleanup rejection retains the unrelated file'

# Valid custom offline and online entry points remain usable in isolated fixtures.
$offlineFixture = Join-Path $TestRoot 'valid-custom-offline'
[System.IO.Directory]::CreateDirectory($offlineFixture) | Out-Null
$offlineManifest = Join-Path $offlineFixture 'sources.json'
Write-EmptyManifest $offlineManifest
$offlineCache = Join-Path $offlineFixture 'cache'
$offlineOutput = Join-Path $offlineFixture 'merged.json'
& $UpdaterPath -ManifestPath $offlineManifest -CacheDirectory $offlineCache -OutputPath $offlineOutput -Offline
Assert-True ([System.IO.File]::Exists($offlineOutput)) 'valid custom offline update writes isolated output'
Assert-True (-not (Test-AnyPathExists ($offlineOutput + '.update.stage'))) 'offline update creates no transaction output stage'

$onlineFixture = Join-Path $TestRoot 'on'
[System.IO.Directory]::CreateDirectory($onlineFixture) | Out-Null
$onlineManifest = Join-Path $onlineFixture 'sources.json'
$onlineCache = Join-Path $onlineFixture 'cache'
$legacyFetchRoot = Join-Path ($onlineCache + '.update.stage') ('.routing-fetch-' + ('0' * 32))
$legacyHeaderPath = Join-Path $legacyFetchRoot ('one.' + ('0' * 32) + '.headers.tmp')
$legacyHeaderLength = $legacyHeaderPath.Length
if ($legacyHeaderLength -lt 264) {
    $desiredLegacyLength = 264
    if ((264 - $legacyHeaderLength) -eq 1) { $desiredLegacyLength = 265 }
    $remainingPathGrowth = $desiredLegacyLength - $legacyHeaderLength
    $depthParent = $onlineFixture
    $depthComponents = New-Object 'System.Collections.Generic.List[string]'
    while ($remainingPathGrowth -gt 201) {
        $depthComponents.Add(('d' * 200))
        $remainingPathGrowth -= 201
    }
    if ($remainingPathGrowth -eq 1) {
        if ($depthComponents.Count -gt 0) {
            $depthComponents[$depthComponents.Count - 1] += 'd'
        }
        else {
            $depthComponents.Add('d')
            $remainingPathGrowth = 0
        }
    }
    if ($remainingPathGrowth -gt 1) { $depthComponents.Add(('d' * ($remainingPathGrowth - 1))) }
    foreach ($depthComponent in $depthComponents) { $depthParent = Join-Path $depthParent $depthComponent }
    $onlineCache = Join-Path $depthParent 'cache'
}
$legacyFetchRoot = Join-Path ($onlineCache + '.update.stage') ('.routing-fetch-' + ('0' * 32))
$legacyHeaderPath = Join-Path $legacyFetchRoot ('one.' + ('0' * 32) + '.headers.tmp')
$shortHeaderPath = Join-Path $legacyFetchRoot 'r0.h'
$shortRequestHeaderPath = Join-Path $legacyFetchRoot 'r0.h.request'
Assert-True ($legacyHeaderPath.Length -ge 264) 'controlled online fixture reproduces the legacy 264-character header path boundary'
Assert-True ($shortHeaderPath.Length -lt 260 -and $shortRequestHeaderPath.Length -lt 260) 'batch-index fetch temp paths remain below PS5.1 MAX_PATH at the same fixture depth'
$onlineOutput = Join-Path $onlineFixture 'merged.json'

if ($env:OS -eq 'Windows_NT' -and [int]$PSVersionTable.PSVersion.Major -le 5) {
    $deepLeafLength = [Math]::Max(1, (205 - $TestRoot.Length - 1))
    $deepCachePath = Join-Path $TestRoot ('d' * $deepLeafLength)
    $deepStagePath = $deepCachePath + '.update.stage'
    $deepManifestPath = Join-Path $TestRoot 'too-deep-sources.json'
    $deepManifestValue = [ordered]@{
        version = 2
        conflict_policy = [ordered]@{ earlier_rule='wins'; later_overlap='ordered-first-match' }
        resources = @([ordered]@{ tag='deep'; type='remote'; format='plain'; url='http://127.0.0.1:1/not-used.txt' })
        rules = @()
    }
    [System.IO.File]::WriteAllText($deepManifestPath, ($deepManifestValue | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
    $preflightRejected = $false
    try { Assert-RoutingFetchPathsSupported -CachePath $deepCachePath -ResourceCount 1 } catch { $preflightRejected = $_.Exception.Message -match 'Windows PowerShell 5\.1' }
    Assert-True $preflightRejected 'PS5.1 rejects a fetch path that exceeds legacy MAX_PATH before creating its cache root'
    Assert-True (-not (Test-AnyPathExists $deepCachePath) -and -not (Test-AnyPathExists $deepStagePath)) 'pure PS5.1 path preflight creates no cache or stage'
    $deepOutputPath = Join-Path $TestRoot 'too-deep-output.json'
    $deepArtifacts = @(
        $deepCachePath,
        ($deepCachePath + '.update.stage'),
        ($deepCachePath + '.update.backup'),
        ($deepCachePath + '.update.lock'),
        ($deepOutputPath + '.update.stage'),
        ($deepOutputPath + '.update.backup'),
        ($deepOutputPath + '.update.lock'),
        ($deepOutputPath + '.update.transaction.json'),
        ($deepOutputPath + '.update.transaction.write.tmp'),
        ($deepOutputPath + '.update.transaction.replace.backup')
    )
    $entrypointRejected = $false
    try { & $UpdaterPath -ManifestPath $deepManifestPath -CacheDirectory $deepCachePath -OutputPath $deepOutputPath } catch { $entrypointRejected = $true }
    Assert-True $entrypointRejected 'online updater entry point rejects the PS5.1 path before transaction writes'
    foreach ($deepArtifact in $deepArtifacts) { Assert-True (-not (Test-AnyPathExists $deepArtifact)) "PS5.1 preflight rejection created transaction state: $deepArtifact" }
    Assert-True (-not (Test-AnyPathExists $deepCachePath) -and -not (Test-AnyPathExists $deepStagePath)) 'PS5.1 entrypoint rejection leaves deep cache and stage absent'
}

$loopbackServer = [RoutingTransactionLoopbackServer]::new(2)
$proxyEnvironmentNames = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')
$savedProxyEnvironment = @{}
foreach ($environmentName in $proxyEnvironmentNames) {
    $savedProxyEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
    [Environment]::SetEnvironmentVariable($environmentName, $null, 'Process')
}
try {
    $onlineManifestValue = [ordered]@{
        version = 2
        conflict_policy = [ordered]@{ earlier_rule='wins'; later_overlap='ordered-first-match' }
        resources = @(
            [ordered]@{ tag='one'; type='remote'; format='plain'; url=($loopbackServer.BaseUrl + 'one.txt') },
            [ordered]@{ tag='two'; type='remote'; format='plain'; url=($loopbackServer.BaseUrl + 'two.txt') }
        )
        rules = @(
            [ordered]@{ id='one'; action='direct'; inputs=@([ordered]@{ resource='one' }) },
            [ordered]@{ id='two'; action='proxy'; inputs=@([ordered]@{ resource='two' }) }
        )
    }
    [System.IO.File]::WriteAllText($onlineManifest, ($onlineManifestValue | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
    & $UpdaterPath -ManifestPath $onlineManifest -CacheDirectory $onlineCache -OutputPath $onlineOutput -NetworkConcurrency 2
}
finally {
    try { $loopbackServer.StopAndJoin() } finally {
        foreach ($environmentName in $proxyEnvironmentNames) {
            [Environment]::SetEnvironmentVariable($environmentName, $savedProxyEnvironment[$environmentName], 'Process')
        }
    }
}
Assert-True ([string]::IsNullOrEmpty($loopbackServer.Failure)) 'loopback HTTP fixture completed without server errors'
Assert-True ($loopbackServer.RequestCount -eq 2) 'online update fetched exactly the two loopback resources'
Assert-True ($loopbackServer.MaxActiveRequests -gt 1) 'NetworkConcurrency 2 overlaps loopback HTTP requests'
Assert-True ([System.IO.File]::Exists($onlineOutput)) 'valid custom loopback online update publishes isolated output'
Assert-True ([System.IO.Directory]::Exists($onlineCache)) 'valid custom loopback online update publishes isolated cache'
Assert-True ([System.IO.File]::Exists((Join-Path $onlineCache 'one.txt')) -and [System.IO.File]::Exists((Join-Path $onlineCache 'two.txt'))) 'both loopback resource payloads are cached'
Assert-NoTransactionFiles (Get-RoutingTransactionPaths -CachePath $onlineCache -OutputPath $onlineOutput -ManifestPath $onlineManifest) 'valid custom loopback online update'
$fetchStageResidues = @(Get-ChildItem -LiteralPath $onlineFixture -Directory -Filter '.routing-fetch-*' -Recurse -Force -ErrorAction Stop)
$fetchTemporaryResidues = @(Get-ChildItem -LiteralPath $onlineFixture -File -Recurse -Force -ErrorAction Stop | Where-Object { $_.Name -match '^(r\d+\.(d|h)(\.request)?)$|\.(headers|download)\.tmp$' })
Assert-True ($fetchStageResidues.Count -eq 0 -and $fetchTemporaryResidues.Count -eq 0) 'online updater removes short batch-index temporary fetch files before returning'

$paths = Reset-Case 'publish-success'
Write-CacheState $paths.CachePath 'old-cache'
Write-CacheState $paths.CacheStagePath 'new-cache'
Write-StateFile $paths.OutputPath 'old-output'
Write-StateFile $paths.OutputStagePath 'new-output'
Publish-RoutingTransaction -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'new-cache') 'publish success cache'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'new-output') 'publish success output'
Assert-NoTransactionFiles $paths 'publish success'

$paths = Reset-Case 'prepared-cache-published'
Write-CacheState $paths.CachePath 'new-cache'
Write-CacheState $paths.CacheBackupPath 'old-cache'
Write-StateFile $paths.OutputPath 'old-output'
Write-StateFile $paths.OutputStagePath 'new-output'
$null = New-TestJournal $paths $true $true 'prepared'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'prepared cache-published cache rollback'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'prepared cache-published output rollback'
Assert-NoTransactionFiles $paths 'prepared cache-published'

$paths = Reset-Case 'prepared-both-published'
Write-CacheState $paths.CachePath 'new-cache'
Write-CacheState $paths.CacheBackupPath 'old-cache'
Write-StateFile $paths.OutputPath 'new-output'
Write-StateFile $paths.OutputBackupPath 'old-output'
$null = New-TestJournal $paths $true $true 'prepared'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'prepared both-published cache rollback'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'prepared both-published output rollback'
Assert-NoTransactionFiles $paths 'prepared both-published'

$paths = Reset-Case 'prepared-first-publish'
Write-CacheState $paths.CachePath 'new-cache'
Write-StateFile $paths.OutputPath 'new-output'
$null = New-TestJournal $paths $false $false 'prepared'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True (-not [System.IO.Directory]::Exists($paths.CachePath)) 'first publish cache removed'
Assert-True (-not [System.IO.File]::Exists($paths.OutputPath)) 'first publish output removed'
Assert-NoTransactionFiles $paths 'prepared first publish'

$paths = Reset-Case 'committed-cleanup'
Write-CacheState $paths.CachePath 'new-cache'
Write-CacheState $paths.CacheBackupPath 'old-cache'
Write-StateFile $paths.OutputPath 'new-output'
Write-StateFile $paths.OutputBackupPath 'old-output'
$null = New-TestJournal $paths $true $true 'committed'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'new-cache') 'committed cache retained'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'new-output') 'committed output retained'
Assert-NoTransactionFiles $paths 'committed cleanup'

$paths = Reset-Case 'partial-rollback-repeat'
Write-CacheState $paths.CachePath 'new-cache'
Write-CacheState $paths.CacheBackupPath 'old-cache'
Write-StateFile $paths.OutputPath 'old-output'
$null = New-TestJournal $paths $true $true 'prepared'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'repeated rollback cache'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'repeated rollback output'
Assert-NoTransactionFiles $paths 'partial rollback repeat'

$paths = Reset-Case 'orphan-stage'
Write-CacheState $paths.CachePath 'old-cache'
Write-CacheState $paths.CacheStagePath 'uncommitted-cache'
Write-StateFile $paths.OutputPath 'old-output'
Write-StateFile $paths.OutputStagePath 'uncommitted-output'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'orphan stage cache preserved'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'orphan stage output preserved'
Assert-NoTransactionFiles $paths 'orphan stage'

$paths = Reset-Case 'journal-replace-backup'
Write-CacheState $paths.CachePath 'new-cache'
Write-CacheState $paths.CacheBackupPath 'old-cache'
Write-StateFile $paths.OutputPath 'new-output'
Write-StateFile $paths.OutputBackupPath 'old-output'
$null = New-TestJournal $paths $true $true 'prepared'
[System.IO.File]::Move($paths.JournalPath, $paths.JournalReplaceBackupPath)
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'journal replace backup cache rollback'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'journal replace backup output rollback'
Assert-NoTransactionFiles $paths 'journal replace backup'

$paths = Reset-Case 'committed-partial-cleanup'
Write-CacheState $paths.CachePath 'new-cache'
Write-StateFile $paths.OutputPath 'new-output'
Write-StateFile $paths.OutputBackupPath 'old-output'
$null = New-TestJournal $paths $true $true 'committed'
Write-StateFile $paths.JournalReplaceBackupPath 'old-journal-copy'
Invoke-RoutingTransactionRecovery -Paths $paths
Assert-True ((Read-CacheState $paths.CachePath) -eq 'new-cache') 'committed partial cleanup cache retained'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'new-output') 'committed partial cleanup output retained'
Assert-NoTransactionFiles $paths 'committed partial cleanup'

$paths = Reset-Case 'orphan-backup'
Write-CacheState $paths.CachePath 'current-cache'
Write-CacheState $paths.CacheBackupPath 'unknown-cache'
$rejected = $false
try { Invoke-RoutingTransactionRecovery -Paths $paths } catch { $rejected = $true }
Assert-True $rejected 'orphan backup must be rejected'
Assert-True ((Read-CacheState $paths.CacheBackupPath) -eq 'unknown-cache') 'orphan backup must be preserved'
Remove-RoutingTransactionPath -Path $paths.CacheBackupPath -Paths $paths

$paths = Reset-Case 'mismatched-journal'
Write-CacheState $paths.CachePath 'old-cache'
Write-StateFile $paths.OutputPath 'old-output'
$journal = New-TestJournal $paths $true $true 'prepared'
$journal.output_path = Join-Path $TestRoot 'outside.json'
Write-RoutingTransactionJournal -Journal $journal -Paths $paths
$rejected = $false
try { Invoke-RoutingTransactionRecovery -Paths $paths } catch { $rejected = $true }
Assert-True $rejected 'mismatched journal must be rejected'
Assert-True ((Read-CacheState $paths.CachePath) -eq 'old-cache') 'mismatched journal cache preserved'
Assert-True ([System.IO.File]::ReadAllText($paths.OutputPath) -eq 'old-output') 'mismatched journal output preserved'
Remove-RoutingTransactionPath -Path $paths.JournalPath -Paths $paths

$pathsA = Reset-Case 'lock-a'
$pathsB = Get-RoutingTransactionPaths -CachePath $pathsA.CachePath -OutputPath (Join-Path $TestRoot 'lock-b\merged.json')
$firstLocks = @(Enter-RoutingUpdateLocks -Paths $pathsA -TimeoutSeconds 1)
try {
    $timedOut = $false
    try { $secondLocks = @(Enter-RoutingUpdateLocks -Paths $pathsB -TimeoutSeconds 1); Exit-RoutingUpdateLocks $secondLocks } catch { $timedOut = $true }
    Assert-True $timedOut 'same cache lock must conflict'
}
finally {
    Exit-RoutingUpdateLocks $firstLocks
}
$secondLocks = @(Enter-RoutingUpdateLocks -Paths $pathsB -TimeoutSeconds 1)
Exit-RoutingUpdateLocks $secondLocks

$pathsC = Reset-Case 'lock-c'
$pathsD = Get-RoutingTransactionPaths -CachePath (Join-Path $TestRoot 'lock-d\cache') -OutputPath $pathsC.OutputPath
$firstLocks = @(Enter-RoutingUpdateLocks -Paths $pathsC -TimeoutSeconds 1)
try {
    $timedOut = $false
    try { $secondLocks = @(Enter-RoutingUpdateLocks -Paths $pathsD -TimeoutSeconds 1); Exit-RoutingUpdateLocks $secondLocks } catch { $timedOut = $true }
    Assert-True $timedOut 'same output lock must conflict'
}
finally {
    Exit-RoutingUpdateLocks $firstLocks
}

$pathsE = Get-RoutingTransactionPaths -CachePath (Join-Path $TestRoot 'z-holder\cache') -OutputPath (Join-Path $TestRoot 'z-shared\merged.json')
$pathsF = Get-RoutingTransactionPaths -CachePath (Join-Path $TestRoot 'a-probe\cache') -OutputPath $pathsE.OutputPath
$firstLocks = @(Enter-RoutingUpdateLocks -Paths $pathsE -TimeoutSeconds 1)
try {
    $timedOut = $false
    try { $secondLocks = @(Enter-RoutingUpdateLocks -Paths $pathsF -TimeoutSeconds 1); Exit-RoutingUpdateLocks $secondLocks } catch { $timedOut = $true }
    Assert-True $timedOut 'partial lock acquisition must conflict'
    Assert-True ([System.IO.File]::Exists($pathsF.CacheLockPath)) 'partial lock file must exist'
    Assert-True ((Get-Item -LiteralPath $pathsF.CacheLockPath).Length -eq 0) 'partial lock acquisition must clear diagnostic content'
}
finally {
    Exit-RoutingUpdateLocks $firstLocks
}

Write-Output 'transaction recovery and lock tests passed'
}
catch { $testBodyError = $_ }
finally {
    try {
        if ($ownsTestRoot -and (Test-Path -LiteralPath $ownedTestRoot)) {
            $resolved = (Resolve-Path -LiteralPath $ownedTestRoot -ErrorAction Stop).Path
            if ($resolved -cne $ownedTestRoot -or (Split-Path -Parent $resolved).TrimEnd('\') -ine $testParent.TrimEnd('\') -or
                (Split-Path -Leaf $resolved) -notmatch '^rtx-[a-f0-9]{12}$') { throw 'Unsafe test cleanup path.' }
            $ownedJunctions = @(
                (Join-Path (Join-Path $resolved 'junction-entry') 'external-alias'),
                (Join-Path (Join-Path (Join-Path $resolved 'junction-cleanup') 'cache') 'external'),
                (Join-Path (Join-Path (Join-Path $resolved 'junction-recovery') 'cache') 'external')
            )
            foreach ($junction in $ownedJunctions) {
                if (-not (Test-Path -LiteralPath $junction)) { continue }
                $junctionItem = Get-Item -LiteralPath $junction -Force -ErrorAction Stop
                if (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { throw 'Unexpected non-reparse object occupies a test junction path.' }
                [IO.Directory]::Delete($junction)
                if (Test-Path -LiteralPath $junction) { throw 'Task-owned test junction could not be unlinked.' }
            }
            $items = @((Get-Item -LiteralPath $resolved -Force)) + @(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
            if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Refusing test cleanup through a reparse point.' }
            [System.IO.Directory]::Delete($resolved, $true)
        }
    }
    catch { $testCleanupError = $_ }
}
if ($null -ne $testBodyError) {
    if ($null -ne $testCleanupError) { Write-Warning ('Test fixture cleanup also failed: ' + $testCleanupError.Exception.Message) }
    throw $testBodyError
}
if ($null -ne $testCleanupError) { throw $testCleanupError }
