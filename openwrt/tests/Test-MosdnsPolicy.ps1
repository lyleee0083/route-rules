[CmdletBinding()]
param(
    [string]$SourceRoot,
    [string]$SingBoxPath,
    [string]$MosdnsPath
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$projectRoot=Split-Path -Parent $openWrtRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
$linuxInputRoot=Join-Path $openWrtRoot 'inputs/linux'
if (-not $SourceRoot) { $SourceRoot = $linuxInputRoot }
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
if (-not $SingBoxPath) { $SingBoxPath=(Get-OpenWrtCorePaths)['sing-box-check'] }
if (-not $MosdnsPath) { $MosdnsPath = Join-Path $openWrtRoot 'build-stage/cores/mosdns-check/mosdns.exe' }
Assert-OpenWrtOfficialCheckTools -SingBoxPath $SingBoxPath -MosdnsPath $MosdnsPath
. (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
. (Join-Path $scriptsRoot 'Mosdns-Policy.ps1')
. (Join-Path $scriptsRoot 'Native-PackageValidation.ps1')
. (Join-Path $PSScriptRoot 'support\NodeDnsSnapshot.ps1')

function Assert-MosdnsTest {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw ('MosDNS policy test failed: ' + $Message) }
}

if (-not ('MosdnsMetricsLoopbackFixture' -as [type])) {
    $fixtureSource=@'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class MosdnsMetricsLoopbackFixture : IDisposable
{
    private readonly string mode;
    private readonly string body;
    private readonly TcpListener listener;
    private readonly Thread worker;
    private readonly ManualResetEvent accepted = new ManualResetEvent(false);
    private readonly ManualResetEvent clientClosed = new ManualResetEvent(false);
    private volatile TcpClient activeClient;
    private volatile bool disposed;

    public int Port { get; private set; }

    public MosdnsMetricsLoopbackFixture(string fixtureMode, string fixtureBody)
    {
        mode = fixtureMode;
        body = fixtureBody;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = new Thread(Serve);
        worker.IsBackground = true;
        worker.Start();
    }

    private void Serve()
    {
        TcpClient client = null;
        Thread peerMonitor = null;
        try
        {
            client = listener.AcceptTcpClient();
            activeClient = client;
            accepted.Set();
            using (NetworkStream stream = client.GetStream())
            {
                int state = 0;
                int value;
                int count = 0;
                while (state < 4 && count < 32768 && (value = stream.ReadByte()) >= 0)
                {
                    count++;
                    if ((state == 0 || state == 2) && value == 13) state++;
                    else if ((state == 1 || state == 3) && value == 10) state++;
                    else state = value == 13 ? 1 : 0;
                }
                if (mode == "stall")
                {
                    WatchPeerClose(client);
                    return;
                }
                byte[] payload = Encoding.UTF8.GetBytes(body);
                int status = mode == "bad-status" ? 503 : 200;
                string reason = status == 200 ? "OK" : "Service Unavailable";
                string framing = mode == "slow-body" ? "Transfer-Encoding: chunked\r\n" : "Content-Length: " + payload.Length + "\r\n";
                byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " " + reason + "\r\n" + framing + "Connection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n");
                stream.Write(header, 0, header.Length);
                if (mode == "slow-body")
                {
                    peerMonitor = new Thread(delegate() { WatchPeerClose(client); });
                    peerMonitor.IsBackground = true;
                    peerMonitor.Start();
                    byte[] chunk = Encoding.ASCII.GetBytes("4\r\nslow\r\n");
                    for (int index = 0; index < 100 && !disposed && !clientClosed.WaitOne(0); index++)
                    {
                        stream.Write(chunk, 0, chunk.Length);
                        stream.Flush();
                        Thread.Sleep(100);
                    }
                    if (!disposed && !clientClosed.WaitOne(0))
                    {
                        stream.Write(Encoding.ASCII.GetBytes("0\r\n\r\n"), 0, 5);
                        stream.Flush();
                    }
                    return;
                }
                stream.Write(payload, 0, payload.Length);
                stream.Flush();
            }
        }
        catch { }
        finally
        {
            if ((mode == "stall" || mode == "slow-body") && !disposed) clientClosed.WaitOne(250);
            if (peerMonitor != null) peerMonitor.Join(250);
            if (client != null) client.Close();
            activeClient = null;
        }
    }

    private void WatchPeerClose(TcpClient client)
    {
        try
        {
            Socket socket = client.Client;
            while (!disposed)
            {
                if (socket.Poll(50000, SelectMode.SelectRead) && socket.Available == 0)
                {
                    if (!disposed) clientClosed.Set();
                    return;
                }
            }
        }
        catch (SocketException)
        {
            if (!disposed) clientClosed.Set();
        }
        catch (ObjectDisposedException) { }
    }

    public bool WaitForAccepted(int milliseconds) { return accepted.WaitOne(milliseconds); }
    public bool WaitForClientClose(int milliseconds) { return clientClosed.WaitOne(milliseconds); }

    public void Dispose()
    {
        disposed = true;
        try { listener.Stop(); } catch { }
        TcpClient client = activeClient;
        if (client != null) { try { client.Close(); } catch { } }
        if (worker != null) worker.Join(1500);
        accepted.Dispose();
        clientClosed.Dispose();
    }
}
'@
    Add-Type -TypeDefinition $fixtureSource -Language CSharp
}

function New-MosdnsJunctionFixture {
    param([Parameter(Mandatory)][string]$LinkPath,[Parameter(Mandatory)][string]$TargetPath)
    Assert-OpenWrtPathAncestors -Path (Split-Path -Parent ([IO.Path]::GetFullPath($LinkPath)))
    Assert-OpenWrtPathAncestors -Path ([IO.Path]::GetFullPath($TargetPath))
    if (Test-Path -LiteralPath $LinkPath) { throw ('MosDNS junction fixture path already exists: '+$LinkPath) }
    $command='mklink /J "'+$LinkPath+'" "'+$TargetPath+'"'
    $output=& $env:ComSpec /d /c $command 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Could not create MosDNS reparse fixture: '+($output -join ' ')) }
    $link=Get-Item -LiteralPath $LinkPath -Force -ErrorAction Stop
    if (-not $link.PSIsContainer -or -not ($link.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw ('MosDNS reparse fixture is not a junction: '+$LinkPath)
    }
}

function Remove-MosdnsJunctionFixture {
    param([Parameter(Mandatory)][string]$LinkPath,[Parameter(Mandatory)][string]$FixtureRoot)
    $full=[IO.Path]::GetFullPath($LinkPath)
    $root=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
    if (-not (Test-OpenWrtPathContains -Parent $root -Child $full -Comparison (Get-MosdnsPathComparison))) {
        throw ('MosDNS junction fixture is outside its test root: '+$full)
    }
    Assert-OpenWrtPathAncestors -Path (Split-Path -Parent $full)
    $item=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw ('Refusing to remove non-reparse MosDNS fixture object: '+$full)
    }
    [IO.Directory]::Delete($full,$false)
}

function Test-MosdnsBoundedMetricsProbe {
    for ($probeIteration=1;$probeIteration -le 3;$probeIteration++) {
        $normal=New-Object MosdnsMetricsLoopbackFixture('normal',"# HELP mosdns_up MosDNS is up`nmosdns_up 1`n")
        try {
            $ok=Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$normal.Port+'/metrics') -Deadline ([DateTime]::UtcNow.AddSeconds(3))
            Assert-MosdnsTest $ok ('Bounded metrics probe rejected normal loopback HTTP 200 response '+$probeIteration+'.')
        }
        finally { $normal.Dispose() }

        $badStatus=New-Object MosdnsMetricsLoopbackFixture('bad-status','fixture-error-body')
        try {
            $rejected=$false
            $statusExceptionType='no exception'
            $statusExceptionMessage=''
            try { [void](Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$badStatus.Port+'/metrics') -Deadline ([DateTime]::UtcNow.AddSeconds(3))) }
            catch {
                $statusExceptionType=$_.Exception.GetType().FullName
                $statusExceptionMessage=$_.Exception.Message
                $rejected=$statusExceptionMessage.Contains('HTTP 503') -and $statusExceptionMessage.Contains('fixture-error-body')
            }
            Assert-MosdnsTest $rejected ('Bounded metrics probe must reject HTTP 503 and retain its error body on iteration '+$probeIteration+'; captured '+$statusExceptionType+': '+$statusExceptionMessage)
        }
        finally { $badStatus.Dispose() }
    }

    $badBody=New-Object MosdnsMetricsLoopbackFixture('normal','fixture-body-without-metrics-marker')
    try {
        $rejected=$false
        try { [void](Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$badBody.Port+'/metrics') -Deadline ([DateTime]::UtcNow.AddSeconds(3))) }
        catch { $rejected=$_.Exception.Message.Contains('without expected content') }
        Assert-MosdnsTest $rejected 'Bounded metrics probe accepted an HTTP 200 response with an invalid body.'
    }
    finally { $badBody.Dispose() }

    $stall=New-Object MosdnsMetricsLoopbackFixture('stall','')
    try {
        $started=[DateTime]::UtcNow
        $deadline=$started.AddMilliseconds(900)
        $rejected=$false
        try { [void](Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$stall.Port+'/metrics') -Deadline $deadline) }
        catch { $rejected=$_.Exception.Message -match 'deadline' }
        $elapsed=([DateTime]::UtcNow-$started).TotalSeconds
        Assert-MosdnsTest $rejected 'Stalling accepted HTTP connection did not fail at its absolute deadline.'
        Assert-MosdnsTest ($elapsed -lt 4) 'Stalling accepted HTTP connection exceeded the bounded response deadline.'
        Assert-MosdnsTest ($stall.WaitForAccepted(1000)) 'Stalling HTTP fixture did not accept the metrics request.'
        Assert-MosdnsTest ($stall.WaitForClientClose(2000)) 'Timed-out metrics probe did not close the accepted socket.'
    }
    finally { $stall.Dispose() }

    $slowBody=New-Object MosdnsMetricsLoopbackFixture('slow-body','')
    try {
        $started=[DateTime]::UtcNow
        $deadline=$started.AddMilliseconds(900)
        $rejected=$false
        try { [void](Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$slowBody.Port+'/metrics') -Deadline $deadline) }
        catch { $rejected=$_.Exception.Message -match 'deadline' }
        $elapsed=([DateTime]::UtcNow-$started).TotalSeconds
        Assert-MosdnsTest $rejected 'Slow continuous metrics body did not fail at its absolute wall-clock deadline.'
        Assert-MosdnsTest ($elapsed -lt 4) 'Slow continuous metrics body exceeded the bounded response deadline.'
        Assert-MosdnsTest ($slowBody.WaitForAccepted(1000)) 'Slow-body HTTP fixture did not accept the metrics request.'
        Assert-MosdnsTest ($slowBody.WaitForClientClose(2000)) 'Timed-out slow-body probe did not close the accepted socket.'
    }
    finally { $slowBody.Dispose() }
}

function Test-MosdnsWriterSafetyFixtures {
    param([Parameter(Mandatory)]$Plan,[Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$SingBoxPath,[Parameter(Mandatory)][string]$FixtureParent)
    $fixtureRoot=Join-Path $FixtureParent 'writer-safety-fixtures'
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $originalPlanFunction=(Get-Item Function:\Get-MosdnsAdapterPlanFromSnapshot).ScriptBlock
    $script:mosdnsPublicationFixturePlan=$Plan
    Set-Item -Path Function:\Get-MosdnsAdapterPlanFromSnapshot -Value {
        param([string]$SourceRoot,[string]$SingBoxPath)
        return $script:mosdnsPublicationFixturePlan
    }
    try {
        $ancestorTarget=Join-Path $fixtureRoot 'ancestor-target'
        $ancestorLink=Join-Path $fixtureRoot 'ancestor-link'
        $ancestorOutput=Join-Path $ancestorLink 'destination'
        [IO.Directory]::CreateDirectory($ancestorTarget) | Out-Null
        [IO.File]::WriteAllText((Join-Path $ancestorTarget 'sentinel.txt'),'ancestor-target-preserved')
        New-MosdnsJunctionFixture -LinkPath $ancestorLink -TargetPath $ancestorTarget
        $rejected=$false
        try { [void](Write-MosdnsAdapterFromSnapshot -SourceRoot $SourceRoot -OutputDirectory $ancestorOutput -SingBoxPath $SingBoxPath) }
        catch { $rejected=$_.Exception.Message -match 'reparse point' }
        Assert-MosdnsTest $rejected 'Writer accepted an output directory below a junction ancestor.'
        Assert-MosdnsTest (-not (Test-Path -LiteralPath $ancestorOutput)) 'Junction ancestor fixture created output through the link.'
        Remove-MosdnsJunctionFixture -LinkPath $ancestorLink -FixtureRoot $fixtureRoot
        Assert-MosdnsTest ([IO.File]::ReadAllText((Join-Path $ancestorTarget 'sentinel.txt')) -ceq 'ancestor-target-preserved') 'Removing the fixture junction changed its target.'

        $stageTarget=Join-Path $fixtureRoot 'stage-link-target'
        $stageDestination=Join-Path $fixtureRoot 'stage-link-output'
        [IO.Directory]::CreateDirectory($stageTarget) | Out-Null
        [IO.File]::WriteAllText((Join-Path $stageTarget 'sentinel.txt'),'stage-target-preserved')
        $originalStageWriter=(Get-Item Function:\Write-MosdnsAdapterStageFile).ScriptBlock
        $script:mosdnsStageLinkTarget=$stageTarget
        $script:mosdnsStageLinkCreated=$false
        Set-Item -Path Function:\Write-MosdnsAdapterStageFile -Value {
            param([string]$Path,[string]$Text,[Text.Encoding]$Encoding)
            [IO.File]::WriteAllText($Path,$Text,$Encoding)
            if (-not $script:mosdnsStageLinkCreated) {
                $link=Join-Path (Split-Path -Parent $Path) 'linked-child'
                New-MosdnsJunctionFixture -LinkPath $link -TargetPath $script:mosdnsStageLinkTarget
                $script:mosdnsStageLinkCreated=$true
            }
        }
        $stageRejected=$false
        try { [void](Write-MosdnsAdapterFromSnapshot -SourceRoot $SourceRoot -OutputDirectory $stageDestination -SingBoxPath $SingBoxPath) }
        catch { $stageRejected=$_.Exception.Message -match 'reparse point' }
        finally { Set-Item -Path Function:\Write-MosdnsAdapterStageFile -Value $originalStageWriter }
        Assert-MosdnsTest $stageRejected 'Writer accepted a reparse-point child inside its private staging tree.'
        Assert-MosdnsTest $script:mosdnsStageLinkCreated 'Stage-child fixture did not create its junction.'
        Assert-MosdnsTest ([IO.File]::ReadAllText((Join-Path $stageTarget 'sentinel.txt')) -ceq 'stage-target-preserved') 'Stage-child fixture changed its junction target.'
        $stages=@(Get-ChildItem -LiteralPath $stageDestination -Directory -Force | Where-Object { $_.Name -match '^\.mosdns-stage-[0-9a-f]{32}$' })
        Assert-MosdnsTest ($stages.Count -eq 1) 'Writer did not preserve the unsafe staging tree for inspection.'
        $stagePath=$stages[0].FullName
        $stageLink=Join-Path $stagePath 'linked-child'
        Remove-MosdnsJunctionFixture -LinkPath $stageLink -FixtureRoot $fixtureRoot
        Assert-OpenWrtTreeHasNoReparsePoints -Path $stagePath
        [IO.Directory]::Delete($stagePath,$true)
        Assert-MosdnsTest ([IO.File]::ReadAllText((Join-Path $stageTarget 'sentinel.txt')) -ceq 'stage-target-preserved') 'Removing the staged junction changed its target.'

        $raceDestination=Join-Path $fixtureRoot 'rollback-race-output'
        [IO.Directory]::CreateDirectory($raceDestination) | Out-Null
        $originalMoveFunction=(Get-Item Function:\Move-MosdnsAdapterStageFile).ScriptBlock
        $script:mosdnsRaceDestination=$raceDestination
        $script:mosdnsRaceMoveCount=0
        Set-Item -Path Function:\Move-MosdnsAdapterStageFile -Value {
            param([string]$Source,[string]$Destination)
            $script:mosdnsRaceMoveCount++
            if ($script:mosdnsRaceMoveCount -eq 2) {
                [IO.File]::WriteAllText((Join-Path $script:mosdnsRaceDestination 'dns-direct-domains.txt'),'user-modified-first-output')
                [IO.File]::WriteAllText($Destination,'concurrent-second-output')
            }
            [IO.File]::Move($Source,$Destination)
        }
        $raceRejected=$false
        try { [void](Write-MosdnsAdapterFromSnapshot -SourceRoot $SourceRoot -OutputDirectory $raceDestination -SingBoxPath $SingBoxPath) }
        catch { $raceRejected=$_.Exception.Message -match 'publication failed' }
        finally { Set-Item -Path Function:\Move-MosdnsAdapterStageFile -Value $originalMoveFunction }
        Assert-MosdnsTest $raceRejected 'Writer did not report the second-file publication conflict.'
        Assert-MosdnsTest ([IO.File]::ReadAllText((Join-Path $raceDestination 'dns-direct-domains.txt')) -ceq 'user-modified-first-output') 'Rollback deleted concurrently modified first-file user content.'
        Assert-MosdnsTest ([IO.File]::ReadAllText((Join-Path $raceDestination 'mosdns.yaml')) -ceq 'concurrent-second-output') 'Writer overwrote or deleted the concurrent second-file occupant.'
        Assert-MosdnsTest ($script:mosdnsRaceMoveCount -eq 2) 'Rollback race did not fail on the second staged output.'
    }
    finally {
        Set-Item -Path Function:\Get-MosdnsAdapterPlanFromSnapshot -Value $originalPlanFunction
        Remove-Variable -Scope Script -Name mosdnsPublicationFixturePlan -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name mosdnsStageLinkTarget -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name mosdnsStageLinkCreated -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name mosdnsRaceDestination -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name mosdnsRaceMoveCount -ErrorAction SilentlyContinue
    }
}

function Get-MosdnsPrivatePorts {
    param([int]$Count)
    $tcpReservations = New-Object 'System.Collections.Generic.List[object]'
    $udpReservations = New-Object 'System.Collections.Generic.List[object]'
    $result = New-Object 'System.Collections.Generic.List[int]'
    try {
        while ($result.Count -lt $Count) {
            $tcp = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
            $tcp.Start()
            $port = [int]$tcp.LocalEndpoint.Port
            if ($port -in @(15353,15354,15355,15357) -or $result.Contains($port)) { $tcp.Stop(); continue }
            try { $udp = New-Object Net.Sockets.UdpClient($port) }
            catch { $tcp.Stop(); continue }
            $tcpReservations.Add($tcp)
            $udpReservations.Add($udp)
            $result.Add($port)
        }
        return ,$result.ToArray()
    }
    finally {
        foreach ($tcp in $tcpReservations) { $tcp.Stop() }
        foreach ($udp in $udpReservations) { $udp.Dispose() }
    }
}

function Test-MosdnsTcpListener {
    param([int]$Port,[DateTime]$Deadline)
    return Test-MosdnsTcpListenerWithinDeadline -Port $Port -Deadline $Deadline
}

function Test-MosdnsMetricsApi {
    param([int]$Port,[DateTime]$Deadline)
    return Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$Port+'/metrics') -Deadline $Deadline
}

if (-not (Test-Path -LiteralPath $SingBoxPath -PathType Leaf)) { throw ('Missing official sing-box decompiler: ' + $SingBoxPath) }
if (-not (Test-Path -LiteralPath $MosdnsPath -PathType Leaf)) { throw ('Missing official Windows MosDNS validator: ' + $MosdnsPath) }

Test-MosdnsBoundedMetricsProbe
Write-Output 'MosDNS HTTP fixtures passed: normal metrics is accepted, bad status/body are rejected, and stalled-header plus slow-body connections time out and close their sockets.'

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('sb-mosdns-policy-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$child = $null
try {
    $adapterSourceRoot=New-OpenWrtNodeDnsSnapshotFixture -SourceRoot $SourceRoot -FixtureRoot (Join-Path $temporary 'adapter-source')
Write-Output 'Reading final Linux DNS rules and decompiling referenced SRS...'
$plan = Get-MosdnsAdapterPlanFromSnapshot -SourceRoot $adapterSourceRoot -SingBoxPath $SingBoxPath
Write-Output ('Snapshot extracted: ' + $plan.direct_domain_rule_count + ' direct predicates across ' + $plan.direct_rule_set_count + ' DNS rule sets; preparing isolated MosDNS load test...')
Assert-MosdnsTest ($plan.status -ceq 'ready' -and $plan.publication_ready) 'Snapshot translation did not produce a publishable plan.'
Assert-MosdnsTest ($plan.direct_rule_set_count -gt 0) 'No direct DNS SRS sets were extracted.'
Assert-MosdnsTest ($plan.direct_domain_rule_count -eq $plan.domain_lines.Count) 'Domain predicate count mismatch.'
$adapterSourceConfig=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $adapterSourceRoot 'sing-box-openwrt.json')))
$hasRejectList = 'routing-reject-domain' -cin @($adapterSourceConfig.route.rule_set | ForEach-Object tag)
$ordinaryStart = @((Get-NodeDnsPolicySpec -Port 15354).DnsRules).Count + (Get-ClientDnsBlockRuleCount -Rules @($adapterSourceConfig.dns.rules))
$expectedOrdinaryDirectTags=[string[]]@($adapterSourceConfig.dns.rules[$ordinaryStart].rule_set | ForEach-Object { [string]$_ })
$actualExtractedDirectTags=[string[]]@($plan.source_hashes | Where-Object { $_.PSObject.Properties['tag'] -and $_.tag -cne 'routing-reject-domain' } | ForEach-Object { [string]$_.tag })
Assert-MosdnsTest (($actualExtractedDirectTags -join "`n") -ceq ($expectedOrdinaryDirectTags -join "`n") -and $plan.direct_rule_set_count -eq $expectedOrdinaryDirectTags.Count) 'Adapter did not extract exactly the ordinary direct DNS selectors after the validated DNS prelude.'
Assert-MosdnsTest ($plan.full_count -gt 0 -and $plan.domain_count -gt 0 -and $plan.regexp_count -gt 0) 'Expected full, suffix, and precompiled residual regex predicates.'
Assert-MosdnsTest ($plan.domain_lines -notcontains 'invert' -and $plan.candidate_yaml -notmatch 'fakeip|reverse_mapping|dump_file|enable_http3|so_mark|domain_keyword') 'Forbidden DNS feature or negative rule entered the plan.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)exec: \$direct_ordinary_fallback\s+- matches: has_resp\s+exec: accept\s+- exec: \$proxy_ordinary_fallback') 'A direct DNS answer must be accepted before the default proxy fallback can run.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)api:\s+http: 127\.0\.0\.1:15357') 'The metrics API must be bound only to loopback port 15357.'
Assert-MosdnsTest ($plan.candidate_yaml -notmatch '0\.0\.0\.0:15357|\[::\]:15357') 'The metrics API must not bind a LAN or wildcard interface.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)qtype 1\s+- rcode 0\s+- resp_ip 0\.0\.0\.0/0\s+exec: ttl 3600') 'Node TTL rewrite must be guarded by A query, NOERROR, and an IPv4 response.'
Assert-MosdnsTest ($plan.node_ttl_policy -match 'CNAME and TTL=0 records.*OPT is not rewritten') 'Production TTL 3600 must disclose whole-message CNAME/TTL=0 behavior and OPT exclusion.'
$expectedUpstreamIdleTimeouts = @{
    tencent_direct = 120
    ali_direct = 120
    google_proxy = 120
    cloudflare_proxy = 120
}
$upstreamBlocks = [regex]::Matches($plan.candidate_yaml, '(?m)^\s{8}- tag: ([a-z_]+)\r?\n(?<body>(?:(?!^\s{8}- tag: ).*(?:\r?\n|$))*)')
$actualUpstreamTags = New-Object 'System.Collections.Generic.List[string]'
foreach ($block in $upstreamBlocks) {
    $tag = [string]$block.Groups[1].Value
    $actualUpstreamTags.Add($tag)
    Assert-MosdnsTest ($expectedUpstreamIdleTimeouts.ContainsKey($tag)) ('Unexpected DoH upstream tag: ' + $tag)
    $expectedTimeout = [int]$expectedUpstreamIdleTimeouts[$tag]
    Assert-MosdnsTest ($block.Groups['body'].Value -match ('(?m)^\s+idle_timeout:\s*' + $expectedTimeout + '\s*$')) ('DoH idle timeout mismatch for ' + $tag)
    Assert-MosdnsTest ($block.Groups['body'].Value -notmatch '(?m)^\s+(enable_http3|max_conns):') ('DoH upstream ' + $tag + ' must not set HTTP/3 or deprecated max_conns')
}
Assert-MosdnsTest (($actualUpstreamTags -join ',') -ceq 'ali_direct,tencent_direct,cloudflare_proxy,google_proxy') 'MosDNS must define only the four ordinary Ali/Tencent and Cloudflare/Google DoH upstreams.'
Assert-MosdnsTest ([regex]::Matches($plan.candidate_yaml,'(?m)^    type: forward\r?$').Count -eq 4) 'The package must contain exactly four forward plugin definitions.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)- tag: ordinary_cache\s+type: cache\s+args:\s+size: 65472\s+lazy_cache_ttl: 3600') 'Ordinary DNS cache settings changed.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)- tag: node_cache\s+type: cache\s+args:\s+size: 65472\s+lazy_cache_ttl: 0') 'Node DNS cache settings changed.'
$forwardTags = @('direct_ali_forward','direct_tencent_forward','proxy_cloudflare_forward','proxy_google_forward')
foreach ($tag in $forwardTags) {
    Assert-MosdnsTest ($plan.candidate_yaml -match ('(?s)- tag: ' + $tag + '\s+type: forward\s+args:\s+concurrent: 1')) ('Each independent upstream forward must have concurrency 1: ' + $tag)
}
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)- tag: direct_ordinary_fallback\s+type: fallback\s+args:\s+primary: direct_ordinary_primary\s+secondary: direct_ordinary_backup\s+threshold: 300\s+always_standby: false') 'Direct fallback must prefer Ali for 300ms before hedging to Tencent.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)- tag: proxy_ordinary_fallback\s+type: fallback\s+args:\s+primary: proxy_ordinary_primary\s+secondary: proxy_ordinary_backup\s+threshold: 2000\s+always_standby: false') 'Proxy fallback must prefer Cloudflare for 2000ms before hedging to Google.'
Assert-MosdnsTest ($plan.dns_provider_policy.direct_primary -ceq 'Ali DoH direct egress' -and
    $plan.dns_provider_policy.direct_backup -match 'Tencent DoH direct egress.*300ms' -and
    $plan.dns_provider_policy.proxy_primary -ceq 'Cloudflare DoH through sing-box SOCKS' -and
    $plan.dns_provider_policy.proxy_backup -match 'Google DoH through sing-box SOCKS.*2000ms' -and
    $plan.dns_provider_policy.maximum_no_answer_wait_seconds.direct -eq 5.3 -and
    $plan.dns_provider_policy.maximum_no_answer_wait_seconds.proxy -eq 7.0) 'Ordinary DNS provider policy or deadline metadata changed during the node-only correction.'
Assert-MosdnsTest ([regex]::Matches($plan.candidate_yaml, "'!rcode 0'").Count -eq 4 -and [regex]::Matches($plan.candidate_yaml, "'!rcode 3'").Count -eq 4) 'The four ordinary primary/backup branches must retry response codes other than NOERROR or NXDOMAIN.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)exec: metrics_collector ordinary_dns.*?exec: \$ordinary_cache') 'Ordinary DNS must include a standard request metrics collector.'
Assert-MosdnsTest ($plan.candidate_yaml -match '(?s)exec: metrics_collector node_dns.*?exec: \$node_cache') 'Node DNS must include a standard request metrics collector.'
$nodeSequenceMatch = [regex]::Match($plan.candidate_yaml, '(?ms)^  - tag: node_sequence\r?\n(?<body>.*?)(?=^  - tag: ordinary_udp)')
Assert-MosdnsTest ($nodeSequenceMatch.Success -and $nodeSequenceMatch.Groups['body'].Value -match '(?s)\$node_cache.*?\$direct_ordinary_fallback') 'Node A requests must use the independent node cache before the shared ordinary direct fallback.'
Assert-MosdnsTest ($nodeSequenceMatch.Groups['body'].Value -notmatch '\$ordinary_cache|\$proxy_ordinary_fallback|\$direct_domains') 'Node DNS must retain its separate cache and direct-only path regardless of the ordinary direct-domain set.'
Assert-MosdnsTest ($plan.candidate_yaml -notmatch 'node_ali_forward|node_tencent_forward|node_ali_primary|node_tencent_backup|node_fallback|ali_node_direct|tencent_node_direct') 'Node policy must not duplicate direct provider forwards, branches, or metrics collectors.'
Assert-MosdnsTest ($plan.dns_provider_policy.node -match 'inherits the ordinary direct provider policy.*no separate node provider definition' -and
    $plan.dns_provider_policy.node_cache -match 'node_cache only.*65472.*lazy_cache_ttl 0.*TTL 3600.*expired entries are not reused') 'Generated metadata must describe shared direct providers and the independent node cache behavior.'
Assert-MosdnsTest ($plan.dns_provider_policy.node_forward_query_timeout_seconds -eq 5 -and
    $plan.dns_provider_policy.node_maximum_no_answer_wait_seconds -eq 5.3 -and
    $plan.dns_provider_policy.node_parent_resolver_timeout_seconds -eq 5 -and
    $plan.dns_provider_policy.node_deadline_note -match 'parent resolver timeout can stop waiting sooner') 'Node timeout metadata must distinguish the shared MosDNS branch bound from the existing tighter parent resolver deadline.'

$exact = ConvertTo-MosdnsDomainLine -Kind domain -Value 'MosDns-Test-Exact.example'
$suffix = ConvertTo-MosdnsDomainLine -Kind domain_suffix -Value 'MosDns-Test-Suffix.example'
Assert-MosdnsTest ($exact -ceq 'full:mosdns-test-exact.example') 'Sing-box exact domain must map to MosDNS full:.'
Assert-MosdnsTest ($suffix -ceq 'domain:mosdns-test-suffix.example') 'Sing-box suffix domain must map to MosDNS domain: (root plus subdomains).'
$moduleText = [IO.File]::ReadAllText((Join-Path $scriptsRoot 'Mosdns-Policy.ps1'))
$seenDeclarations = @($moduleText -split "`n" | Where-Object { $_ -cmatch '\$seen(Direct|Reject)\s*=\s*New-Object.*HashSet' })
foreach ($name in @('Direct','Reject')) {
    $declaration = @($seenDeclarations | Where-Object { $_ -cmatch ('\$seen' + $name + '\s*=') })
    Assert-MosdnsTest ($declaration.Count -eq 1 -and $declaration[0] -cmatch '\[StringComparer\]::Ordinal\)') "$name deduplication must preserve case-sensitive regexes."
}

$compilerPath = Join-Path (Join-Path $projectRoot 'src') 'SameTypeDirectCompiler.cs'
if (-not ('SingBoxSameType.DomainCompiler' -as [type])) {
    if ($PSVersionTable.PSVersion.Major -ge 6) { Add-Type -Path $compilerPath }
    else { Add-Type -Path $compilerPath -ReferencedAssemblies 'System.Numerics.dll' }
}
$compiler = New-Object SingBoxSameType.DomainCompiler
$compiler.Block('blocked.example.net',$true)
$residual = $compiler.SuffixPattern('example.net')
Assert-MosdnsTest (-not [string]::IsNullOrEmpty($residual)) 'Partial suffix subtraction must produce a positive residual.'
Assert-MosdnsTest ($residual -notmatch '\(\?[=!<]|\\[1-9]|\\k<') 'Residual regex must not use lookaround or backreferences.'
Assert-MosdnsTest ([regex]::IsMatch('example.net',$residual)) 'Residual suffix must retain its root domain.'
Assert-MosdnsTest ([regex]::IsMatch('www.example.net',$residual)) 'Residual suffix must retain ordinary subdomains.'
Assert-MosdnsTest (-not [regex]::IsMatch('blocked.example.net',$residual)) 'Residual suffix must exclude the earlier proxy child.'
Assert-MosdnsTest (-not [regex]::IsMatch('x.blocked.example.net',$residual)) 'Residual suffix must exclude descendants of the earlier proxy child.'

    $payload = Join-Path $temporary 'payload'
    [IO.Directory]::CreateDirectory($payload) | Out-Null
    $published = Write-MosdnsAdapterFromSnapshot -SourceRoot $adapterSourceRoot -OutputDirectory $payload -SingBoxPath $SingBoxPath
    Assert-MosdnsTest ($published.status -ceq 'written') 'Writer did not write its flat policy payload.'
    Assert-MosdnsTest ($published.direct_domain_rule_count -eq $plan.direct_domain_rule_count -and
        $published.full_count -eq $plan.full_count -and $published.domain_count -eq $plan.domain_count -and
        $published.regexp_count -eq $plan.regexp_count) 'Writer return counts differ from the extracted source plan.'
    Assert-MosdnsTest ($published.node_ttl_policy -match 'CNAME and TTL=0 records.*OPT is not rewritten') 'Writer must disclose whole-answer TTL behavior.'
    $payloadNames = @(Get-ChildItem -LiteralPath $payload -File | ForEach-Object Name | Sort-Object)
    $expectedPayload = @('dns-direct-domains.txt','mosdns.yaml')
    if ($hasRejectList) { $expectedPayload += 'dns-reject-domains.txt' }
    Assert-MosdnsTest (($payloadNames -join ',') -ceq (($expectedPayload | Sort-Object) -join ',')) 'Payload has the wrong flat policy files.'
    Assert-MosdnsTest (($plan.reject_domain_lines.Count -gt 0) -eq $hasRejectList) 'Extracted DNS reject policy must match the snapshot.'
    $domainFile = $published.paths.dns_direct_domains
    $yamlFile = $published.paths.mosdns_yaml
    $testEncoding = New-Object Text.UTF8Encoding($false)
    $policyFiles = @($domainFile,$yamlFile)
    if ($hasRejectList) {
        $rejectFile = Join-Path $payload 'dns-reject-domains.txt'
        $policyFiles += $rejectFile
    }
    foreach ($path in $policyFiles) {
        $bytes = [IO.File]::ReadAllBytes($path)
        Assert-MosdnsTest (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'Generated text must be UTF-8 without BOM.'
        $text = [IO.File]::ReadAllText($path)
        Assert-MosdnsTest (-not $text.Contains("`r") -and $text.EndsWith("`n") -and -not $text.EndsWith("`n`n")) 'Generated text must use LF with exactly one final newline.'
    }
    $extraLines = @($exact,$suffix,(ConvertTo-MosdnsDomainLine -Kind domain_regex -Value $residual))
    [IO.File]::AppendAllText($domainFile,($extraLines -join "`n")+"`n",$testEncoding)

    $ports = Get-MosdnsPrivatePorts -Count 3
    Assert-MosdnsTest ($ports[0] -notin @(15353,15354,15355,15357) -and $ports[1] -notin @(15353,15354,15355,15357) -and $ports[2] -notin @(15353,15354,15355,15357)) 'Test ports overlap production DNS/SOCKS/API listeners.'
    $isolated = Join-Path $temporary 'isolated'
    [IO.Directory]::CreateDirectory($isolated) | Out-Null
    Copy-Item -LiteralPath $domainFile -Destination (Join-Path $isolated 'dns-direct-domains.txt')
    if ($hasRejectList) {
        Copy-Item -LiteralPath $rejectFile -Destination (Join-Path $isolated 'dns-reject-domains.txt')
    }
    $yaml = [IO.File]::ReadAllText($yamlFile).Replace('127.0.0.1:15353',('127.0.0.1:' + $ports[0])).Replace('127.0.0.1:15354',('127.0.0.1:' + $ports[1])).Replace('127.0.0.1:15357',('127.0.0.1:' + $ports[2]))
    $configPath = Join-Path $isolated 'mosdns.yaml'
    [IO.File]::WriteAllText($configPath,$yaml,$testEncoding)
    $stdout = Join-Path $temporary 'mosdns.stdout.log'
    $stderr = Join-Path $temporary 'mosdns.stderr.log'
    $arguments = 'start -c "' + $configPath + '" -d "' + $isolated + '"'
    $child = Start-Process -FilePath $MosdnsPath -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $child.Refresh()
        if ($child.HasExited) {
            $outText = if (Test-Path -LiteralPath $stdout) { [IO.File]::ReadAllText($stdout) } else { '' }
            $errText = if (Test-Path -LiteralPath $stderr) { [IO.File]::ReadAllText($stderr) } else { '' }
            throw ('Official MosDNS rejected generated YAML or full/domain/regexp rules: ' + $errText + ' ' + $outText)
        }
        $ready = (Test-MosdnsTcpListener -Port $ports[0] -Deadline $deadline) -and
            (Test-MosdnsTcpListener -Port $ports[1] -Deadline $deadline) -and
            (Test-MosdnsMetricsApi -Port $ports[2] -Deadline $deadline)
        if ($ready) { break }
        Start-Sleep -Milliseconds 100
    }
    Assert-MosdnsTest $ready 'Official MosDNS did not bind both isolated DNS listeners and the loopback metrics API.'
    Test-MosdnsWriterSafetyFixtures -Plan $plan -SourceRoot $adapterSourceRoot -SingBoxPath $SingBoxPath -FixtureParent $temporary
    Write-Output 'MosDNS writer fixtures passed: junction ancestors and stage children are rejected, and rollback preserves a concurrently modified first output plus the second-file conflict.'
    Write-Output ('Official MosDNS v5.3.4 isolated startup passed; loaded ' + $plan.direct_domain_rule_count + ' snapshot predicates (' + $plan.full_count + ' full, ' + $plan.domain_count + ' domain, ' + $plan.regexp_count + ' regexp) plus the synthetic partial-suffix RE2 case; local /metrics returned successfully. No DNS query or production listener was used.')
    Write-Output ('Writer passed with the expected isolated policy files: ' + ($payloadNames -join ', ') + '.')
}
finally {
    if ($child) {
        $child.Refresh()
        if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $child.Dispose()
    }
    $resolved = [IO.Path]::GetFullPath($temporary)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ((Split-Path -Parent $resolved).TrimEnd('\') -ine $tempRoot -or (Split-Path -Leaf $resolved) -notlike 'sb-mosdns-policy-test-*') {
        throw 'Unsafe MosDNS test temporary cleanup target.'
    }
    Assert-OpenWrtPathAncestors -Path $resolved
    Assert-OpenWrtTreeHasNoReparsePoints -Path $resolved
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
