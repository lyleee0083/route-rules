[CmdletBinding()]
param([string]$SingBoxPath,[string]$FixtureDirectory)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'SingBox-Checker.ps1')
. (Join-Path $scriptsRoot 'Direct-RoutingPolicy.ps1')

$allowedFixtureParents = @((Join-Path $projectRoot 'outputs'),(Join-Path $projectRoot 'work'))
if (-not $FixtureDirectory) { $FixtureDirectory = Join-Path $projectRoot 'outputs\test-dns-fallback' }
$fixtureParent = [IO.Path]::GetFullPath($FixtureDirectory).TrimEnd([char[]]'\/')
$fixtureParentAllowed = $false
foreach ($allowedParent in $allowedFixtureParents) {
    $allowedParentFull = [IO.Path]::GetFullPath($allowedParent).TrimEnd([char[]]'\/')
    if ($fixtureParent.StartsWith($allowedParentFull + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        $fixtureParentAllowed = $true
        break
    }
}
if (-not $fixtureParentAllowed) { throw 'DNS fallback fixture output must be a child of project work/ or outputs/.' }
$cursor = $fixtureParent
while ($cursor -and ($cursor.Equals($projectRoot,[StringComparison]::OrdinalIgnoreCase) -or
    $cursor.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase))) {
    if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
        $cursorItem = Get-Item -LiteralPath $cursor -Force
        if ($cursorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('DNS fallback fixture path contains a reparse point: ' + $cursor) }
    }
    if ($cursor.Equals($projectRoot,[StringComparison]::OrdinalIgnoreCase)) { break }
    $cursor = Split-Path -Parent $cursor
}
$null = [IO.Directory]::CreateDirectory($fixtureParent)
$fixtureRoot = Join-Path $fixtureParent ('dns-fallback-runtime-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($fixtureRoot)
$ruleSetDirectory = Join-Path $fixtureRoot 'rule-set'
$null = [IO.Directory]::CreateDirectory($ruleSetDirectory)
$process = $null
$mocks = New-Object 'System.Collections.Generic.List[object]'
$success = $false

if (-not ('RouterRemediation.DnsFallbackMock' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace RouterRemediation
{
    public sealed class DnsFallbackMock : IDisposable
    {
        private readonly string _role;
        private readonly UdpClient _udp;
        private readonly Thread _thread;
        private volatile bool _stopping;
        private readonly ConcurrentDictionary<string, int> _counts = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        public int Port { get; private set; }

        public DnsFallbackMock(string role)
        {
            _role = role;
            _udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            Port = ((IPEndPoint)_udp.Client.LocalEndPoint).Port;
            _thread = new Thread(Listen);
            _thread.IsBackground = true;
            _thread.Start();
        }

        public int Count(string domain)
        {
            int count;
            return _counts.TryGetValue(domain, out count) ? count : 0;
        }

        private void Listen()
        {
            while (!_stopping)
            {
                IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                byte[] query;
                try { query = _udp.Receive(ref remote); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { if (_stopping) return; else continue; }
                try { Handle(query, remote); }
                catch { }
            }
        }

        private static string ReadQuestionName(byte[] packet, ref int offset)
        {
            List<string> labels = new List<string>();
            while (offset < packet.Length)
            {
                int length = packet[offset++];
                if (length == 0) break;
                if ((length & 0xC0) != 0 || offset + length > packet.Length) throw new InvalidOperationException("Unsupported DNS question name.");
                labels.Add(System.Text.Encoding.ASCII.GetString(packet, offset, length));
                offset += length;
            }
            return String.Join(".", labels.ToArray()).ToLowerInvariant();
        }

        private void Handle(byte[] query, IPEndPoint remote)
        {
            if (query == null || query.Length < 17) return;
            int offset = 12;
            string domain = ReadQuestionName(query, ref offset);
            if (offset + 4 > query.Length) return;
            int queryType = (query[offset] << 8) | query[offset + 1];
            int questionEnd = offset + 4;
            _counts.AddOrUpdate(domain, 1, delegate(string key, int oldValue) { return oldValue + 1; });

            if (_role == "dns-direct" &&
                (domain == "direct-timeout.fixture.test" || domain == "multi-family.fixture.test"))
            {
                return;
            }

            int rcode = 0;
            bool noData = false;
            if (_role == "dns-direct" && domain == "direct-servfail.fixture.test") rcode = 2;
            if (_role == "dns-direct" && domain == "direct-nxdomain.fixture.test") rcode = 3;
            if (_role == "dns-direct" && domain == "direct-nodata.fixture.test") noData = true;
            if (_role == "dns-proxy" && domain == "proxy-refused.fixture.test") rcode = 5;
            bool answer = rcode == 0 && !noData && queryType == 1;

            int extraLength = answer ? 16 : 0;
            byte[] response = new byte[questionEnd + extraLength];
            Buffer.BlockCopy(query, 0, response, 0, questionEnd);
            response[2] = (byte)(0x80 | (query[2] & 0x01));
            response[3] = (byte)(0x80 | rcode);
            response[6] = 0;
            response[7] = (byte)(answer ? 1 : 0);
            response[8] = 0; response[9] = 0; response[10] = 0; response[11] = 0;
            if (answer)
            {
                response[questionEnd] = 0xC0; response[questionEnd + 1] = 0x0C;
                response[questionEnd + 2] = 0; response[questionEnd + 3] = 1;
                response[questionEnd + 4] = 0; response[questionEnd + 5] = 1;
                response[questionEnd + 6] = 0; response[questionEnd + 7] = 0;
                response[questionEnd + 8] = 0; response[questionEnd + 9] = 60;
                response[questionEnd + 10] = 0; response[questionEnd + 11] = 4;
                byte suffix = _role == "dns-direct-backup" ? (byte)20 :
                              _role == "dns-proxy" ? (byte)30 :
                              _role == "dns-proxy-backup" ? (byte)40 : (byte)10;
                response[questionEnd + 12] = 192;
                response[questionEnd + 13] = 0;
                response[questionEnd + 14] = 2;
                response[questionEnd + 15] = suffix;
            }
            _udp.Send(response, response.Length, remote);
        }

        public void Dispose()
        {
            _stopping = true;
            _udp.Close();
            _thread.Join(2000);
        }
    }
}
'@
}

function Assert-Fixture {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-FixtureJson {
    param([Parameter(Mandatory)]$Value,[Parameter(Mandatory)][string]$Path)
    $json = ($Value | ConvertTo-Json -Depth 100) -replace "`r`n?", "`n"
    [IO.File]::WriteAllText($Path, "$json`n", [Text.UTF8Encoding]::new($false))
}

function Invoke-FixtureDns {
    param([int]$Port,[string]$Domain,[int]$Id)
    $message = New-Object 'Collections.Generic.List[byte]'
    $message.AddRange([byte[]]@(($Id -shr 8),($Id -band 255),1,0,0,1,0,0,0,0,0,0))
    foreach ($label in $Domain.Split('.')) {
        $message.Add([byte]$label.Length)
        $message.AddRange([Text.Encoding]::ASCII.GetBytes($label))
    }
    $message.AddRange([byte[]]@(0,0,1,0,1))
    $client = New-Object Net.Sockets.TcpClient
    try {
        $client.ReceiveTimeout = 12000
        $client.SendTimeout = 12000
        $client.Connect('127.0.0.1',$Port)
        $stream = $client.GetStream()
        $payload = $message.ToArray()
        $wire = [byte[]]@(($payload.Length -shr 8),($payload.Length -band 255)) + $payload
        $stream.Write($wire,0,$wire.Length)
        $high = $stream.ReadByte(); $low = $stream.ReadByte()
        if ($high -lt 0 -or $low -lt 0) { throw 'Incomplete DNS frame header.' }
        $response = New-Object byte[] (($high -shl 8) -bor $low)
        $offset = 0
        while ($offset -lt $response.Length) {
            $read = $stream.Read($response,$offset,$response.Length-$offset)
            if ($read -eq 0) { throw 'Incomplete DNS response.' }
            $offset += $read
        }
        if ($response.Length -lt 12 -or (([int]$response[0] -shl 8) -bor [int]$response[1]) -ne $Id -or ($response[2] -band 128) -eq 0) {
            throw 'DNS response failed ID/QR validation.'
        }
        $rcode = [int]($response[3] -band 15)
        $answers = ([int]$response[6] -shl 8) -bor [int]$response[7]
        $questionOffset = 12
        while ($questionOffset -lt $response.Length -and $response[$questionOffset] -ne 0) {
            $questionOffset += [int]$response[$questionOffset] + 1
        }
        $questionEnd = $questionOffset + 5
        $address = $null
        if ($answers -gt 0) {
            $rdataOffset = $questionEnd + 12
            if ($response.Length -lt $rdataOffset + 4) { throw 'DNS response answer section is incomplete.' }
            $address = '{0}.{1}.{2}.{3}' -f $response[$rdataOffset],$response[$rdataOffset+1],$response[$rdataOffset+2],$response[$rdataOffset+3]
        }
        return [pscustomobject]@{ domain=$Domain; rcode=$rcode; answers=$answers; address=$address }
    } finally { $client.Dispose() }
}

$resolvedSingBox = Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RequestedPath $SingBoxPath
if (-not $resolvedSingBox) { throw 'Pinned sing-box 1.14.4 checker is unavailable.' }
$directPrimary = [RouterRemediation.DnsFallbackMock]::new('dns-direct')
$directBackup = [RouterRemediation.DnsFallbackMock]::new('dns-direct-backup')
$proxyPrimary = [RouterRemediation.DnsFallbackMock]::new('dns-proxy')
$proxyBackup = [RouterRemediation.DnsFallbackMock]::new('dns-proxy-backup')
$mocks.AddRange([object[]]@($directPrimary,$directBackup,$proxyPrimary,$proxyBackup))

try {
    $directDomains = @('direct-timeout.fixture.test','direct-servfail.fixture.test','direct-nodata.fixture.test','direct-nxdomain.fixture.test','multi-family.fixture.test')
    $sourcePlans = @(
        [pscustomobject]@{ Tag='routing-direct-domain'; Domains=$directDomains },
        [pscustomobject]@{ Tag='routing-direct-1-domain'; Domains=@('multi-family.fixture.test') }
    )
    foreach ($sourcePlan in $sourcePlans) {
        $sourcePath = Join-Path $fixtureRoot ($sourcePlan.Tag + '.json')
        $binaryPath = Join-Path $ruleSetDirectory ($sourcePlan.Tag + '.srs')
        Write-FixtureJson -Value ([ordered]@{version=5;rules=@([ordered]@{domain=$sourcePlan.Domains})}) -Path $sourcePath
        $compileOutput = & $resolvedSingBox rule-set compile $sourcePath -o $binaryPath 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            throw ('Pinned-core rule-set fixture compile failed: ' + ($compileOutput | Out-String).Trim())
        }
    }

    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start()
    try { $inboundPort = $listener.LocalEndpoint.Port } finally { $listener.Stop() }

    $directGroup = @(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues @('routing-direct-domain','routing-direct-1-domain') -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s')
    $proxyGroup = @(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s')
    $dnsServers = @(
        [ordered]@{type='udp';tag='dns-direct';server='127.0.0.1';server_port=$directPrimary.Port},
        [ordered]@{type='udp';tag='dns-direct-backup';server='127.0.0.1';server_port=$directBackup.Port},
        [ordered]@{type='udp';tag='dns-proxy';server='127.0.0.1';server_port=$proxyPrimary.Port},
        [ordered]@{type='udp';tag='dns-proxy-backup';server='127.0.0.1';server_port=$proxyBackup.Port}
    )
    $routeRuleSets = @(
        [ordered]@{type='local';tag='routing-direct-domain';format='binary';path='rule-set/routing-direct-domain.srs'},
        [ordered]@{type='local';tag='routing-direct-1-domain';format='binary';path='rule-set/routing-direct-1-domain.srs'}
    )
    $configuration = [ordered]@{
        log = [ordered]@{level='error';timestamp=$true}
        dns = [ordered]@{servers=$dnsServers;rules=@($directGroup) + @($proxyGroup);final='dns-proxy';strategy='ipv4_only';timeout='8s';cache_capacity=1024;reverse_mapping=$false}
        inbounds = @([ordered]@{type='direct';tag='dns-test';listen='127.0.0.1';listen_port=$inboundPort;network='tcp'})
        outbounds = @([ordered]@{type='direct';tag='direct';connect_timeout='5s'})
        route = [ordered]@{rule_set=$routeRuleSets;rules=@([ordered]@{inbound=@('dns-test');action='hijack-dns'});final='direct';default_domain_resolver=[ordered]@{server='dns-proxy';strategy='ipv4_only';timeout='8s'}}
    }
    $configurationPath = Join-Path $fixtureRoot 'config.json'
    Write-FixtureJson -Value $configuration -Path $configurationPath
    $checkOutput = & $resolvedSingBox -D $fixtureRoot check -c $configurationPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Pinned-core rejected the DNS failover fixture: ' + ($checkOutput | Out-String).Trim()) }

    $stdout = Join-Path $fixtureRoot 'stdout.log'
    $stderr = Join-Path $fixtureRoot 'stderr.log'
    $process = Start-Process -FilePath $resolvedSingBox -ArgumentList @('-D',('"' + $fixtureRoot + '"'),'run','-c',('"' + $configurationPath + '"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    for ($attempt=0; $attempt -lt 50; $attempt++) {
        $process.Refresh()
        if ($process.HasExited) { throw 'Pinned core exited before the DNS fixture became ready.' }
        $probe = New-Object Net.Sockets.TcpClient
        try { $probe.Connect('127.0.0.1',$inboundPort); $ready=$true } catch { Start-Sleep -Milliseconds 100 } finally { $probe.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'Pinned core did not open the isolated DNS test listener.' }

    $timeout = Invoke-FixtureDns -Port $inboundPort -Domain 'direct-timeout.fixture.test' -Id 2101
    Assert-Fixture ($timeout.rcode -eq 0 -and $timeout.address -eq '192.0.2.20') 'Direct primary transport timeout did not fall back to Tencent.'
    Assert-Fixture ($directPrimary.Count($timeout.domain) -eq 1 -and $directBackup.Count($timeout.domain) -eq 1 -and $proxyPrimary.Count($timeout.domain) -eq 0) 'Direct timeout selected the wrong DNS family or failed to reach backup.'

    $servfail = Invoke-FixtureDns -Port $inboundPort -Domain 'direct-servfail.fixture.test' -Id 2102
    Assert-Fixture ($servfail.rcode -eq 0 -and $servfail.address -eq '192.0.2.20') 'Direct SERVFAIL did not fall back to Tencent.'
    Assert-Fixture ($directPrimary.Count($servfail.domain) -eq 1 -and $directBackup.Count($servfail.domain) -eq 1) 'Direct SERVFAIL backup transport counts changed.'

    $nodata = Invoke-FixtureDns -Port $inboundPort -Domain 'direct-nodata.fixture.test' -Id 2103
    Assert-Fixture ($nodata.rcode -eq 0 -and $nodata.answers -eq 0 -and $directPrimary.Count($nodata.domain) -eq 1 -and $directBackup.Count($nodata.domain) -eq 0) 'NOERROR/NODATA must be preserved without querying Tencent.'

    $nxdomain = Invoke-FixtureDns -Port $inboundPort -Domain 'direct-nxdomain.fixture.test' -Id 2104
    Assert-Fixture ($nxdomain.rcode -eq 3 -and $nxdomain.answers -eq 0 -and $directPrimary.Count($nxdomain.domain) -eq 1 -and $directBackup.Count($nxdomain.domain) -eq 0) 'NXDOMAIN must be preserved without querying Tencent.'

    $refused = Invoke-FixtureDns -Port $inboundPort -Domain 'proxy-refused.fixture.test' -Id 2105
    Assert-Fixture ($refused.rcode -eq 0 -and $refused.address -eq '192.0.2.40') 'Proxy REFUSED did not fall back to Google.'
    Assert-Fixture ($directPrimary.Count($refused.domain) -eq 0 -and $directBackup.Count($refused.domain) -eq 0 -and $proxyPrimary.Count($refused.domain) -eq 1 -and $proxyBackup.Count($refused.domain) -eq 1) 'Proxy REFUSED crossed DNS families or missed backup.'

    $unrelated = Invoke-FixtureDns -Port $inboundPort -Domain 'unrelated.fixture.test' -Id 2106
    Assert-Fixture ($unrelated.rcode -eq 0 -and $unrelated.address -eq '192.0.2.30') 'An unrelated query did not use the proxy DNS primary.'
    Assert-Fixture ($directPrimary.Count($unrelated.domain) -eq 0 -and $directBackup.Count($unrelated.domain) -eq 0 -and $proxyPrimary.Count($unrelated.domain) -eq 1 -and $proxyBackup.Count($unrelated.domain) -eq 0) 'An unrelated query matched the direct selector or incorrectly used Google backup.'

    $multiFamily = Invoke-FixtureDns -Port $inboundPort -Domain 'multi-family.fixture.test' -Id 2107
    Assert-Fixture ($multiFamily.rcode -eq 0 -and $multiFamily.address -eq '192.0.2.20') 'A domain matching two direct rule-set families did not use the grouped Ali-to-Tencent path.'
    Assert-Fixture ($directPrimary.Count($multiFamily.domain) -eq 1 -and $directBackup.Count($multiFamily.domain) -eq 1 -and $proxyPrimary.Count($multiFamily.domain) -eq 0) 'Multiple direct family matches duplicated or lost the positive direct selector.'

    $success = $true
    Write-Output 'Pinned sing-box 1.14.4 DNS failover fixtures passed: timeout and SERVFAIL fallback, NOERROR/NODATA and NXDOMAIN preservation, proxy REFUSED fallback, unrelated-domain isolation, and overlapping direct rule-set families.'
} catch {
    Write-Output ('DNS fallback runtime fixture failed: ' + $_.Exception.Message)
    Write-Output ('DNS fallback fixture evidence preserved at: ' + [IO.Path]::GetFullPath($fixtureRoot))
    if (Test-Path -LiteralPath (Join-Path $fixtureRoot 'stdout.log')) { Get-Content -LiteralPath (Join-Path $fixtureRoot 'stdout.log') -Tail 80 }
    if (Test-Path -LiteralPath (Join-Path $fixtureRoot 'stderr.log')) { Get-Content -LiteralPath (Join-Path $fixtureRoot 'stderr.log') -Tail 80 }
    throw
} finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(3000) }
        $process.Dispose()
    }
    foreach ($mock in $mocks) { $mock.Dispose() }
    if ($success) {
        $rootFull = [IO.Path]::GetFullPath($fixtureParent).TrimEnd('\')
        $fixtureFull = [IO.Path]::GetFullPath($fixtureRoot).TrimEnd('\')
        if (-not $fixtureFull.StartsWith($rootFull + '\',[StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($fixtureFull) -notlike 'dns-fallback-runtime-*') {
            throw 'Unsafe DNS fallback fixture cleanup path.'
        }
        $allItems = @(Get-ChildItem -LiteralPath $fixtureFull -Force -Recurse -ErrorAction Stop)
        if (@($allItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
            throw 'DNS fallback fixture contains a reparse point; refusing recursive cleanup.'
        }
        Remove-Item -LiteralPath $fixtureFull -Recurse -Force
    }
}
