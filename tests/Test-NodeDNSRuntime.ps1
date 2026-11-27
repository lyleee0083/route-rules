[CmdletBinding()]
param([string]$TaskDirectory)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'Official-SingBoxChecker.ps1')
. (Join-Path $scriptsRoot 'Node-DnsPolicy.ps1')
. (Join-Path $scriptsRoot 'Direct-RoutingPolicy.ps1')

if ([string]::IsNullOrWhiteSpace($TaskDirectory)) {
    $runParent = Join-Path ([IO.Path]::GetTempPath()) 'sing-box-node-dns-runtime-runs'
} else {
    $runParent = Join-Path ([IO.Path]::GetFullPath($TaskDirectory)) 'runtime-runs'
}
$runParentFull = [IO.Path]::GetFullPath($runParent).TrimEnd([char[]]'\/')
$projectFull = [IO.Path]::GetFullPath($projectRoot).TrimEnd([char[]]'\/')
$tempFull = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]'\/')
$allowedRoots = @((Join-Path $projectFull 'work'), (Join-Path $projectFull 'outputs'), $tempFull)
$runParentAllowed = $false
foreach ($allowedRoot in $allowedRoots) {
    $allowedFull = [IO.Path]::GetFullPath($allowedRoot).TrimEnd([char[]]'\/')
    if ($runParentFull.StartsWith($allowedFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        $runParentAllowed = $true
        break
    }
}
if (-not $runParentAllowed) { throw 'Runtime fixture output must be within project work/, outputs/, or the current TEMP subtree.' }
$cursor = $runParentFull
while ($cursor) {
    $attributes = $null
    try { $attributes = [IO.File]::GetAttributes($cursor) }
    catch [IO.FileNotFoundException] { }
    catch [IO.DirectoryNotFoundException] { }
    catch { throw "Cannot safely inspect runtime fixture path: $cursor`n$($_.Exception.Message)" }
    if ($null -ne $attributes -and (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Unsafe runtime fixture path: $cursor"
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
    $cursor = $parent
}

function Assert-NodeRuntime {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-NodeRuntimeJson {
    param([Parameter(Mandatory)]$Value, [Parameter(Mandatory)][string]$Path)
    $json = ($Value | ConvertTo-Json -Depth 100) -replace "`r`n?", "`n"
    [IO.File]::WriteAllText($Path, "$json`n", [Text.UTF8Encoding]::new($false))
}

function Get-NodeRuntimePort {
    param([int[]]$ReservedPorts = @())
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'), 0)
        $listener.Start()
        try { $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port }
        finally { $listener.Stop() }
        if ($ReservedPorts -notcontains $port) { return $port }
    }
    throw 'Could not allocate a unique loopback-only fixture port.'
}

function Read-NodeRuntimeBytes {
    param([Parameter(Mandatory)][Net.Sockets.NetworkStream]$Stream, [Parameter(Mandatory)][int]$Count)
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -eq 0) { throw 'The local fixture connection closed before its response was complete.' }
        $offset += $read
    }
    return ,$buffer
}

function Invoke-NodeRuntimeDnsTcp {
    param([Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][string]$Domain, [Parameter(Mandatory)][int]$Id)
    $message = New-Object 'Collections.Generic.List[byte]'
    $message.AddRange([byte[]]@(($Id -shr 8), ($Id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in $Domain.Split('.')) {
        $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
        if ($labelBytes.Length -lt 1 -or $labelBytes.Length -gt 63) { throw 'The fixture DNS label is invalid.' }
        $message.Add([byte]$labelBytes.Length)
        $message.AddRange($labelBytes)
    }
    $message.AddRange([byte[]]@(0, 0, 1, 0, 1))
    $payload = $message.ToArray()
    [byte[]]$frame = [byte[]]@(($payload.Length -shr 8), ($payload.Length -band 255)) + $payload
    $client = New-Object Net.Sockets.TcpClient
    $client.ReceiveTimeout = 12000
    $client.SendTimeout = 12000
    try {
        $client.Connect('127.0.0.1', $Port)
        $stream = $client.GetStream()
        $stream.Write($frame, 0, $frame.Length)
        $prefix = Read-NodeRuntimeBytes -Stream $stream -Count 2
        $length = (([int]$prefix[0] -shl 8) -bor [int]$prefix[1])
        if ($length -lt 12 -or $length -gt 4096) { throw 'The DNS fixture response length is invalid.' }
        $response = Read-NodeRuntimeBytes -Stream $stream -Count $length
        $responseId = (([int]$response[0] -shl 8) -bor [int]$response[1])
        if ($responseId -ne $Id -or ($response[2] -band 128) -eq 0) { throw 'DNS response failed ID/QR validation.' }
        $rcode = [int]($response[3] -band 15)
        $answers = (([int]$response[6] -shl 8) -bor [int]$response[7])
        $questionOffset = 12
        while ($questionOffset -lt $response.Length -and $response[$questionOffset] -ne 0) {
            $questionOffset += [int]$response[$questionOffset] + 1
        }
        if ($questionOffset + 5 -gt $response.Length) { throw 'DNS response question section is incomplete.' }
        $questionEnd = $questionOffset + 5
        $address = $null
        if ($answers -gt 0) {
            $rdataOffset = $questionEnd + 12
            if ($response.Length -lt $rdataOffset + 4) { throw 'DNS response A record is incomplete.' }
            $address = '{0}.{1}.{2}.{3}' -f $response[$rdataOffset], $response[$rdataOffset + 1], $response[$rdataOffset + 2], $response[$rdataOffset + 3]
        }
        return [pscustomobject]@{ Domain = $Domain; Rcode = $rcode; Answers = $answers; Address = $address }
    }
    finally { $client.Dispose() }
}

function Invoke-NodeRuntimeSocksConnect {
    param([Parameter(Mandatory)][int]$Port)
    $client = New-Object Net.Sockets.TcpClient
    $client.ReceiveTimeout = 6000
    $client.SendTimeout = 6000
    try {
        $client.Connect('127.0.0.1', $Port)
        $stream = $client.GetStream()
        [byte[]]$greeting = @(5, 1, 0)
        $stream.Write($greeting, 0, $greeting.Length)
        $hello = Read-NodeRuntimeBytes -Stream $stream -Count 2
        if ($hello[0] -ne 5 -or $hello[1] -ne 0) { throw 'The loopback mixed inbound did not accept the SOCKS5 greeting.' }
        [byte[]]$request = @(5, 1, 0, 1, 127, 0, 0, 1, 0, 80)
        $stream.Write($request, 0, $request.Length)
        try {
            $reply = Read-NodeRuntimeBytes -Stream $stream -Count 4
            return [int]$reply[1]
        }
        catch { return -1 }
    }
    finally { $client.Dispose() }
}

function Remove-NodeRuntimeRun {
    param([Parameter(Mandatory)][string]$Path)
    $target = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
    if (-not $target.StartsWith($runParentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($target) -notlike 'dns-node-runtime-*') {
        throw 'Unsafe node DNS runtime cleanup target.'
    }
    $cursor = $target
    $reachedParent = $false
    while ($cursor) {
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($cursor) }
        catch [IO.FileNotFoundException] { }
        catch [IO.DirectoryNotFoundException] { }
        catch { throw ('Cannot inspect fixture cleanup path: ' + $cursor + ' ' + $_.Exception.Message) }
        if ($null -ne $attributes -and (($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw ('Reparse point or non-directory in fixture cleanup path: ' + $cursor)
        }
        if ($cursor.Equals($runParentFull, [StringComparison]::OrdinalIgnoreCase)) { $reachedParent = $true; break }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    if (-not $reachedParent) { throw 'Runtime fixture cleanup escaped its configured parent.' }
    $pendingDirectories = New-Object 'System.Collections.Generic.Stack[string]'
    $pendingDirectories.Push($target)
    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $currentDirectory -Force -ErrorAction Stop) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime fixture contains a reparse point; refusing recursive cleanup.' }
            if ($item.PSIsContainer) { $pendingDirectories.Push($item.FullName) }
        }
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}

if (-not ('ClientNodeDnsRuntime.MockDnsServer' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ClientNodeDnsRuntime
{
    public sealed class MockDnsServer : IDisposable
    {
        private readonly string _role;
        private readonly UdpClient _udp;
        private readonly Thread _thread;
        private readonly ConcurrentDictionary<string, int> _counts = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private volatile bool _stopping;
        public int Port { get; private set; }

        public MockDnsServer(string role)
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
            int value;
            return _counts.TryGetValue(domain, out value) ? value : 0;
        }

        public string Snapshot()
        {
            List<string> rows = new List<string>();
            foreach (KeyValuePair<string, int> row in _counts) rows.Add(row.Key + "=" + row.Value.ToString());
            rows.Sort(StringComparer.OrdinalIgnoreCase);
            return String.Join(";", rows.ToArray());
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

        private void Listen()
        {
            while (!_stopping)
            {
                IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                byte[] query;
                try { query = _udp.Receive(ref remote); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { if (_stopping) return; else continue; }
                try { Handle(query, remote); } catch { }
            }
        }

        private void Handle(byte[] query, IPEndPoint remote)
        {
            if (query == null || query.Length < 17) return;
            int offset = 12;
            string domain = ReadQuestionName(query, ref offset);
            if (offset + 4 > query.Length) return;
            int queryType = (query[offset] << 8) | query[offset + 1];
            int questionEnd = offset + 4;
            int count = _counts.AddOrUpdate(domain, 1, delegate(string key, int oldValue) { return oldValue + 1; });

            if ((_role == "Ali" && (domain == "ordinary-direct-timeout.fixture.test" || domain == "node-fallback.fixture.test")) ||
                (_role == "Cloudflare" && domain == "ordinary-proxy-timeout.fixture.test")) return;

            int rcode = 0;
            bool answer = queryType == 1;
            int ttl = 60;
            byte[] address;
            if (_role == "Ali" && domain == "ordinary-direct-nxdomain.fixture.test") { rcode = 3; answer = false; }
            if (_role == "Ali" && domain == "shared.fixture.test")
            {
                ttl = count == 1 ? 30 : 1;
                address = count == 1 ? new byte[] { 127, 0, 0, 1 } : new byte[] { 127, 0, 0, 2 };
            }
            else if (_role == "Ali" && domain == "expiry.fixture.test")
            {
                ttl = 1;
                address = count == 1 ? new byte[] { 127, 0, 0, 2 } : new byte[] { 127, 0, 0, 3 };
            }
            else if (_role == "Tencent" && domain == "node-fallback.fixture.test") address = new byte[] { 127, 0, 0, 2 };
            else if (_role == "Tencent") address = new byte[] { 192, 0, 2, 20 };
            else if (_role == "Cloudflare") address = new byte[] { 192, 0, 2, 30 };
            else if (_role == "Google") address = new byte[] { 192, 0, 2, 40 };
            else address = new byte[] { 127, 0, 0, 1 };

            answer = answer && rcode == 0;
            int extraLength = answer ? 16 : 0;
            byte[] response = new byte[questionEnd + extraLength];
            Buffer.BlockCopy(query, 0, response, 0, questionEnd);
            response[2] = (byte)(0x80 | (query[2] & 0x01));
            response[3] = (byte)(0x80 | rcode);
            response[6] = 0; response[7] = (byte)(answer ? 1 : 0);
            response[8] = 0; response[9] = 0; response[10] = 0; response[11] = 0;
            if (answer)
            {
                response[questionEnd] = 0xC0; response[questionEnd + 1] = 0x0C;
                response[questionEnd + 2] = 0; response[questionEnd + 3] = 1;
                response[questionEnd + 4] = 0; response[questionEnd + 5] = 1;
                response[questionEnd + 6] = (byte)((ttl >> 24) & 255);
                response[questionEnd + 7] = (byte)((ttl >> 16) & 255);
                response[questionEnd + 8] = (byte)((ttl >> 8) & 255);
                response[questionEnd + 9] = (byte)(ttl & 255);
                response[questionEnd + 10] = 0; response[questionEnd + 11] = 4;
                Buffer.BlockCopy(address, 0, response, questionEnd + 12, 4);
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

    public sealed class LoopbackProbe : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly Thread _thread;
        private volatile bool _stopping;
        private int _accepted;
        public int Port { get; private set; }
        public int Accepted { get { return Interlocked.CompareExchange(ref _accepted, 0, 0); } }

        public LoopbackProbe(string address, int port)
        {
            _listener = new TcpListener(IPAddress.Parse(address), port);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _thread = new Thread(Listen);
            _thread.IsBackground = true;
            _thread.Start();
        }

        private void Listen()
        {
            while (!_stopping)
            {
                TcpClient client;
                try { client = _listener.AcceptTcpClient(); }
                catch (SocketException) { if (_stopping) return; else continue; }
                catch (ObjectDisposedException) { return; }
                Interlocked.Increment(ref _accepted);
                client.Close();
            }
        }

        public void Dispose()
        {
            _stopping = true;
            _listener.Stop();
            _thread.Join(2000);
        }
    }
}
'@
}

$runRoot = $null
$process = $null
$mocks = New-Object 'System.Collections.Generic.List[object]'
$probes = New-Object 'System.Collections.Generic.List[object]'
$success = $false
try {
    $basePath = Join-Path (Join-Path $projectRoot 'config') 'sing-box-core-base.json'
    $baseConfiguration = Get-Content -LiteralPath $basePath -Encoding UTF8 -Raw | ConvertFrom-Json
    Assert-NodeDnsPolicyShape -Configuration $baseConfiguration -Port 15354
    $baseNodePolicy = Get-NodeDnsPolicySpec -Port 15354

    $singBox = Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot -RuntimeFallbackPath ''
    if (-not $singBox) { throw 'Project-pinned sing-box 1.14.4 is unavailable.' }
    $singBox = [IO.Path]::GetFullPath($singBox)
    $coreRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'openwrt\build-stage\cores')).TrimEnd([char[]]'\/')
    if (-not $singBox.StartsWith($coreRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Pinned checker resolved outside the project core directory: ' + $singBox)
    }

    $null = [IO.Directory]::CreateDirectory($runParentFull)
    $runRoot = Join-Path $runParentFull ('dns-node-runtime-' + [guid]::NewGuid().ToString('N'))
    $runRoot = [IO.Path]::GetFullPath($runRoot)
    if (-not $runRoot.StartsWith($runParentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runtime fixture directory escaped its assigned task directory.'
    }
    $null = [IO.Directory]::CreateDirectory($runRoot)
    $ruleSetDirectory = Join-Path $runRoot 'rule-set'
    $null = [IO.Directory]::CreateDirectory($ruleSetDirectory)

    $ali = [ClientNodeDnsRuntime.MockDnsServer]::new('Ali')
    $tencent = [ClientNodeDnsRuntime.MockDnsServer]::new('Tencent')
    $cloudflare = [ClientNodeDnsRuntime.MockDnsServer]::new('Cloudflare')
    $google = [ClientNodeDnsRuntime.MockDnsServer]::new('Google')
    $mocks.AddRange([object[]]@($ali, $tencent, $cloudflare, $google))
    $probeTwo = [ClientNodeDnsRuntime.LoopbackProbe]::new('127.0.0.2', 0)
    $probeThree = [ClientNodeDnsRuntime.LoopbackProbe]::new('127.0.0.3', $probeTwo.Port)
    $probes.AddRange([object[]]@($probeTwo, $probeThree))

    $reservedPorts = [System.Collections.Generic.List[int]]::new()
    foreach ($port in @($ali.Port, $tencent.Port, $cloudflare.Port, $google.Port, $probeTwo.Port)) { $reservedPorts.Add([int]$port) }
    $nodePort = Get-NodeRuntimePort -ReservedPorts $reservedPorts.ToArray(); $reservedPorts.Add($nodePort)
    $userDnsPort = Get-NodeRuntimePort -ReservedPorts $reservedPorts.ToArray(); $reservedPorts.Add($userDnsPort)
    $sharedTriggerPort = Get-NodeRuntimePort -ReservedPorts $reservedPorts.ToArray(); $reservedPorts.Add($sharedTriggerPort)
    $fallbackTriggerPort = Get-NodeRuntimePort -ReservedPorts $reservedPorts.ToArray(); $reservedPorts.Add($fallbackTriggerPort)
    $expiryTriggerPort = Get-NodeRuntimePort -ReservedPorts $reservedPorts.ToArray(); $reservedPorts.Add($expiryTriggerPort)

    $configuration = Get-Content -LiteralPath $basePath -Encoding UTF8 -Raw | ConvertFrom-Json
    $dnsNode = Get-NodeDnsPolicySpec -Port $nodePort

    $mockServers = @(
        [ordered]@{ type = 'udp'; tag = 'dns-direct'; server = '127.0.0.1'; server_port = $ali.Port },
        [ordered]@{ type = 'udp'; tag = 'dns-direct-backup'; server = '127.0.0.1'; server_port = $tencent.Port },
        [ordered]@{ type = 'udp'; tag = 'dns-proxy'; server = '127.0.0.1'; server_port = $cloudflare.Port },
        [ordered]@{ type = 'udp'; tag = 'dns-proxy-backup'; server = '127.0.0.1'; server_port = $google.Port }
    )
    $mockServerMap = @{}
    foreach ($server in $mockServers) { $mockServerMap[[string]$server.tag] = $server }
    $serverList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($baseServer in $configuration.dns.servers) {
        $tag = [string]$baseServer.tag
        if ($tag -eq 'dns-node') { $serverList.Add($dnsNode.DnsServer) }
        elseif ($mockServerMap.ContainsKey($tag)) { $serverList.Add($mockServerMap[$tag]) }
        else { $serverList.Add($baseServer) }
    }
    $configuration.dns.servers = $serverList.ToArray()

    $directRuleSetTag = 'routing-direct-domain'
    $directRuleSetSource = Join-Path $runRoot ($directRuleSetTag + '.json')
    $directRuleSetBinary = Join-Path $ruleSetDirectory ($directRuleSetTag + '.srs')
    $directDomains = @('shared.fixture.test', 'ordinary-direct-timeout.fixture.test', 'ordinary-direct-nxdomain.fixture.test')
    Write-NodeRuntimeJson -Value ([ordered]@{ version = 5; rules = @([ordered]@{ domain = $directDomains }) }) -Path $directRuleSetSource
    $compileOutput = & $singBox rule-set compile $directRuleSetSource -o $directRuleSetBinary 2>&1
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($directRuleSetBinary)) {
        throw ('Pinned-core loopback rule-set compile failed: ' + ($compileOutput | Out-String).Trim())
    }

    $dnsRules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $dnsNode.DnsRules) { $dnsRules.Add($rule) }
    $directGroup = @(New-DnsFallbackRuleGroup -SelectorField 'rule_set' -SelectorValues @($directRuleSetTag) -PrimaryServer 'dns-direct' -BackupServer 'dns-direct-backup' -PrimaryTag 'dns-direct-primary-response' -PrimaryTimeout '2s' -BackupTimeout '3s')
    $proxyGroup = @(New-DnsFallbackRuleGroup -SelectorField 'domain_regex' -SelectorValues @('.*') -PrimaryServer 'dns-proxy' -BackupServer 'dns-proxy-backup' -PrimaryTag 'dns-proxy-primary-response' -PrimaryTimeout '3s' -BackupTimeout '5s')
    $dnsRules.AddRange([object[]]$directGroup)
    $dnsRules.AddRange([object[]]$proxyGroup)
    if ($dnsRules.Count -ne 13) { throw 'Runtime fixture must contain the canonical node-five plus ordinary-direct-four plus ordinary-proxy-four DNS rule shape.' }
    $configuration.dns.rules = $dnsRules.ToArray()

    $inboundList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($inbound in $configuration.inbounds) {
        if ([string]$inbound.tag -eq 'tun-in') { continue }
        if ([string]$inbound.tag -eq 'dns-in') { $inbound.listen_port = $nodePort }
        $inboundList.Add($inbound)
    }
    $inboundList.Add([ordered]@{ type = 'direct'; tag = 'dns-user'; listen = '127.0.0.1'; listen_port = $userDnsPort })
    $inboundList.Add([ordered]@{ type = 'mixed'; tag = 'node-shared-trigger'; listen = '127.0.0.1'; listen_port = $sharedTriggerPort })
    $inboundList.Add([ordered]@{ type = 'mixed'; tag = 'node-fallback-trigger'; listen = '127.0.0.1'; listen_port = $fallbackTriggerPort })
    $inboundList.Add([ordered]@{ type = 'mixed'; tag = 'node-expiry-trigger'; listen = '127.0.0.1'; listen_port = $expiryTriggerPort })
    $configuration.inbounds = $inboundList.ToArray()

    $proxy = @($configuration.outbounds | Where-Object { [string]$_.tag -ceq 'proxy' })[0]
    if ($null -eq $proxy) { throw 'Maintained base does not contain the expected VLESS proxy outbound.' }
    $proxy.server = 'shared.fixture.test'
    $proxy.server_port = $probeTwo.Port
    $proxyCloneJson = ConvertTo-Json -InputObject $proxy -Depth 100 -Compress
    $fallbackProxy = $proxyCloneJson | ConvertFrom-Json
    $fallbackProxy.tag = 'proxy-node-fallback-test'
    $fallbackProxy.server = 'node-fallback.fixture.test'
    $fallbackProxy.server_port = $probeTwo.Port
    $expiryProxy = $proxyCloneJson | ConvertFrom-Json
    $expiryProxy.tag = 'proxy-node-expiry-test'
    $expiryProxy.server = 'expiry.fixture.test'
    $expiryProxy.server_port = $probeTwo.Port
    $expiryProxy.domain_resolver.rewrite_ttl = 2
    $outboundList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($outbound in $configuration.outbounds) { $outboundList.Add($outbound) }
    $outboundList.Add($fallbackProxy)
    $outboundList.Add($expiryProxy)
    $configuration.outbounds = $outboundList.ToArray()
    Assert-NodeRuntime ($proxy.domain_resolver.server -ceq $baseNodePolicy.DomainResolver.server -and
        $proxy.domain_resolver.disable_cache -eq $false -and $proxy.domain_resolver.rewrite_ttl -eq 3600 -and
        $proxy.domain_resolver.disable_optimistic_cache -eq $true -and $proxy.domain_resolver.timeout -ceq '5s') 'Primary VLESS resolver diverged from the production Node-DNS specification.'
    Assert-NodeRuntime ($fallbackProxy.domain_resolver.rewrite_ttl -eq 3600 -and $fallbackProxy.domain_resolver.disable_optimistic_cache -eq $true) 'Node fallback VLESS resolver must retain production TTL and stale-answer policy.'
    Assert-NodeRuntime ($expiryProxy.domain_resolver.rewrite_ttl -eq 2 -and $expiryProxy.domain_resolver.disable_optimistic_cache -eq $true) 'Only the dedicated expiry mirror may use a short TTL, with expired-answer reuse disabled.'
    Assert-NodeRuntime ($configuration.dns.cache_capacity -eq 65472 -and $configuration.dns.optimistic.enabled -eq $true -and
        $configuration.dns.optimistic.timeout -ceq '1h') 'Runtime fixture changed the maintained global DNS cache policy.'

    $configuration.route | Add-Member -NotePropertyName 'rule_set' -NotePropertyValue @([ordered]@{ type = 'local'; tag = $directRuleSetTag; format = 'binary'; path = ('rule-set/' + $directRuleSetTag + '.srs') })
    $routeRules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $configuration.route.rules) { $routeRules.Add($rule) }
    $routeRules.Add([ordered]@{ inbound = @('dns-user'); action = 'hijack-dns' })
    $routeRules.Add([ordered]@{ inbound = @('node-shared-trigger'); action = 'route'; outbound = 'proxy' })
    $routeRules.Add([ordered]@{ inbound = @('node-fallback-trigger'); action = 'route'; outbound = 'proxy-node-fallback-test' })
    $routeRules.Add([ordered]@{ inbound = @('node-expiry-trigger'); action = 'route'; outbound = 'proxy-node-expiry-test' })
    $configuration.route.rules = $routeRules.ToArray()
    foreach ($inbound in $configuration.inbounds) {
        if ([string]$inbound.listen -cne '127.0.0.1') { throw 'Runtime fixture inbound escaped IPv4 loopback.' }
        if ([string]$inbound.type -ceq 'tun') { throw 'Runtime fixture must not contain a TUN inbound.' }
    }
    foreach ($server in $configuration.dns.servers) {
        if ([string]$server.tag -eq 'dns-doh-hosts') { continue }
        if ([string]$server.type -cne 'udp' -or [string]$server.server -cne '127.0.0.1') {
            throw 'Every runtime DNS transport must point only to a UDP loopback mock or loopback dns-in.'
        }
    }
    foreach ($outbound in $configuration.outbounds | Where-Object { [string]$_.type -ceq 'vless' }) {
        if ([string]$outbound.server -notlike '*.fixture.test' -or [int]$outbound.server_port -ne $probeTwo.Port) {
            throw 'Every test VLESS endpoint must resolve to the local loopback probe.'
        }
    }

    $configurationPath = Join-Path $runRoot 'config.json'
    Write-NodeRuntimeJson -Value $configuration -Path $configurationPath
    $checkOutput = & $singBox -D $runRoot check -c $configurationPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Pinned core rejected the loopback runtime fixture: ' + ($checkOutput | Out-String).Trim()) }
    [IO.File]::WriteAllText((Join-Path $runRoot 'check.log'), (($checkOutput | Out-String) + "`n"), [Text.UTF8Encoding]::new($false))

    $metadata = [ordered]@{
        core_path = $singBox
        core_version = 'project-pinned sing-box 1.14.4'
        topology = 'loopback only; no TUN; four UDP provider mocks; one local VLESS TCP probe; all core inbounds bind 127.0.0.1'
        internal_dns_port = $nodePort
        user_dns_port = $userDnsPort
        output_directory = $runRoot
    }
    Write-NodeRuntimeJson -Value $metadata -Path (Join-Path $runRoot 'metadata.json')

    $stdout = Join-Path $runRoot 'stdout.log'
    $stderr = Join-Path $runRoot 'stderr.log'
    $arguments = '-D "' + $runRoot + '" run -c "' + $configurationPath + '"'
    $process = Start-Process -FilePath $singBox -ArgumentList $arguments -WorkingDirectory $runRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        $process.Refresh()
        if ($process.HasExited) { throw 'Pinned core exited before its loopback mixed inbounds became ready.' }
        $probe = New-Object Net.Sockets.TcpClient
        try { $probe.Connect('127.0.0.1', $sharedTriggerPort); $ready = $true }
        catch { Start-Sleep -Milliseconds 100 }
        finally { $probe.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'The local VLESS trigger inbound did not become ready.' }

    $ordinaryShared = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'shared.fixture.test' -Id 4101
    Assert-NodeRuntime ($ordinaryShared.Rcode -eq 0 -and $ordinaryShared.Address -ceq '127.0.0.1') 'Ordinary direct DNS did not retain its first Ali answer.'
    Assert-NodeRuntime ($ali.Count('shared.fixture.test') -eq 1 -and $tencent.Count('shared.fixture.test') -eq 0) 'Ordinary direct DNS selected an unexpected upstream before the node lookup.'

    $null = Invoke-NodeRuntimeSocksConnect -Port $sharedTriggerPort
    Assert-NodeRuntime ($probeTwo.Accepted -ge 1) 'The real VLESS outbound did not dial its local endpoint through dns-node.'
    Assert-NodeRuntime ($ali.Count('shared.fixture.test') -eq 2 -and $tencent.Count('shared.fixture.test') -eq 0) 'The node lookup did not bypass the ordinary dns-direct cache namespace while Ali was healthy.'
    Assert-NodeRuntime ($cloudflare.Count('shared.fixture.test') -eq 0 -and $google.Count('shared.fixture.test') -eq 0) 'A VLESS node lookup queried the proxy DNS providers.'

    $ordinarySharedAgain = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'shared.fixture.test' -Id 4102
    Assert-NodeRuntime ($ordinarySharedAgain.Rcode -eq 0 -and $ordinarySharedAgain.Address -ceq '127.0.0.1') 'The node resolver polluted the ordinary direct answer cache.'
    Assert-NodeRuntime ($ali.Count('shared.fixture.test') -eq 2) 'The ordinary direct cache was not retained after a node lookup.'
    $null = Invoke-NodeRuntimeSocksConnect -Port $sharedTriggerPort
    Assert-NodeRuntime ($probeTwo.Accepted -ge 2 -and $ali.Count('shared.fixture.test') -eq 2) 'The node resolver did not retain its own cached answer.'

    $directFallback = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'ordinary-direct-timeout.fixture.test' -Id 4103
    Assert-NodeRuntime ($directFallback.Rcode -eq 0 -and $directFallback.Address -ceq '192.0.2.20') 'Ordinary direct Ali timeout did not fall back to Tencent.'
    Assert-NodeRuntime ($ali.Count('ordinary-direct-timeout.fixture.test') -eq 1 -and $tencent.Count('ordinary-direct-timeout.fixture.test') -eq 1) 'Ordinary direct fallback did not retain its Ali-then-Tencent sequence.'

    $directNx = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'ordinary-direct-nxdomain.fixture.test' -Id 4104
    Assert-NodeRuntime ($directNx.Rcode -eq 3 -and $directNx.Answers -eq 0 -and $ali.Count('ordinary-direct-nxdomain.fixture.test') -eq 1 -and
        $tencent.Count('ordinary-direct-nxdomain.fixture.test') -eq 0) 'Ordinary direct NXDOMAIN was not preserved without a Tencent query.'

    $proxyFallback = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'ordinary-proxy-timeout.fixture.test' -Id 4105
    Assert-NodeRuntime ($proxyFallback.Rcode -eq 0 -and $proxyFallback.Address -ceq '192.0.2.40') 'Ordinary Cloudflare timeout did not fall back to Google.'
    Assert-NodeRuntime ($cloudflare.Count('ordinary-proxy-timeout.fixture.test') -eq 1 -and $google.Count('ordinary-proxy-timeout.fixture.test') -eq 1) 'Ordinary proxy fallback did not retain its Cloudflare-then-Google sequence.'
    $proxyPrimary = Invoke-NodeRuntimeDnsTcp -Port $userDnsPort -Domain 'ordinary-proxy-primary.fixture.test' -Id 4106
    Assert-NodeRuntime ($proxyPrimary.Rcode -eq 0 -and $proxyPrimary.Address -ceq '192.0.2.30' -and
        $cloudflare.Count('ordinary-proxy-primary.fixture.test') -eq 1 -and $google.Count('ordinary-proxy-primary.fixture.test') -eq 0) 'Ordinary proxy primary path changed.'

    $null = Invoke-NodeRuntimeSocksConnect -Port $fallbackTriggerPort
    Assert-NodeRuntime ($probeTwo.Accepted -ge 3) 'Node Tencent fallback did not resolve the VLESS server to the local probe.'
    Assert-NodeRuntime ($ali.Count('node-fallback.fixture.test') -ge 1 -and $tencent.Count('node-fallback.fixture.test') -ge 1) 'A node Ali timeout did not fall back to Tencent.'
    Assert-NodeRuntime ($cloudflare.Count('node-fallback.fixture.test') -eq 0 -and $google.Count('node-fallback.fixture.test') -eq 0) 'A node fallback lookup crossed into proxy DNS providers.'

    $probeTwoBeforeExpiry = $probeTwo.Accepted
    $probeThreeBeforeExpiry = $probeThree.Accepted
    $null = Invoke-NodeRuntimeSocksConnect -Port $expiryTriggerPort
    Assert-NodeRuntime ($probeTwo.Accepted -ge ($probeTwoBeforeExpiry + 1) -and $ali.Count('expiry.fixture.test') -eq 1) 'The short-TTL mirror did not resolve its first VLESS connection through Ali.'
    Assert-NodeRuntime ($cloudflare.Count('expiry.fixture.test') -eq 0 -and $google.Count('expiry.fixture.test') -eq 0) 'The expiry mirror queried proxy DNS providers.'
    $probeTwoAfterFirstExpiry = $probeTwo.Accepted
    Start-Sleep -Milliseconds 3200
    $null = Invoke-NodeRuntimeSocksConnect -Port $expiryTriggerPort
    Assert-NodeRuntime ($ali.Count('expiry.fixture.test') -ge 2) 'The expiry mirror reused an expired resolver answer instead of querying Ali again.'
    Assert-NodeRuntime ($probeThree.Accepted -ge ($probeThreeBeforeExpiry + 1) -and $probeTwo.Accepted -eq $probeTwoAfterFirstExpiry) 'The expiry mirror returned the expired VLESS endpoint after rewrite_ttl elapsed.'

    $counts = [ordered]@{
        ali = $ali.Snapshot()
        tencent = $tencent.Snapshot()
        cloudflare = $cloudflare.Snapshot()
        google = $google.Snapshot()
        vless_loopback_127_0_0_2_accepts = $probeTwo.Accepted
        vless_loopback_127_0_0_3_accepts = $probeThree.Accepted
    }
    Write-NodeRuntimeJson -Value ([ordered]@{ metadata = $metadata; upstream_counts = $counts; ordinary_direct_answer = $ordinaryShared.Address; node_cache_namespace = 'Ali query count stayed at two while ordinary answer remained 127.0.0.1'; ordinary_direct_fallback = $directFallback.Address; ordinary_direct_nxdomain_rcode = $directNx.Rcode; ordinary_proxy_fallback = $proxyFallback.Address; ordinary_proxy_primary = $proxyPrimary.Address; node_tencent_fallback = 'passed'; short_ttl_no_expired_reuse = 'passed'; result = 'passed' }) -Path (Join-Path $runRoot 'result.json')
    $success = $true
    Write-Output 'Node DNS runtime fixture passed: maintained base and Node spec validated before loopback adaptation; actual VLESS dials used Ali first and Tencent after Ali failure; node and ordinary direct cache namespaces remained distinct; ordinary direct/proxy fallback paths and DNS responses were preserved; the short-TTL mirror did not reuse an expired answer with global optimistic caching enabled.'
    Write-Output ('Runtime fixture evidence: ' + $runRoot)
}
catch {
    $failure = $_.Exception.Message
    if ($null -ne $runRoot -and [IO.Directory]::Exists($runRoot)) {
        try { [IO.File]::WriteAllText((Join-Path $runRoot 'failure.txt'), ($failure + "`n"), [Text.UTF8Encoding]::new($false)) } catch { }
        Write-Output ('Node DNS runtime fixture failed: ' + $failure)
        Write-Output ('Runtime fixture evidence preserved: ' + $runRoot)
        if ([IO.File]::Exists((Join-Path $runRoot 'stdout.log'))) { Get-Content -LiteralPath (Join-Path $runRoot 'stdout.log') -Tail 80 }
        if ([IO.File]::Exists((Join-Path $runRoot 'stderr.log'))) { Get-Content -LiteralPath (Join-Path $runRoot 'stderr.log') -Tail 80 }
    }
    throw
}
finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(5000) }
        $process.Dispose()
    }
    foreach ($probe in $probes) { $probe.Dispose() }
    foreach ($mock in $mocks) { $mock.Dispose() }
    if ($success -and $null -ne $runRoot -and [IO.Directory]::Exists($runRoot)) { Remove-NodeRuntimeRun -Path $runRoot }
}
