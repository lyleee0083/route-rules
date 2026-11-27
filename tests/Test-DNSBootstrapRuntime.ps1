[CmdletBinding()]
param([string]$SingBoxPath = 'D:\Software\sing-box\sing-box.exe', [string]$TaskDirectory)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
. (Join-Path $scriptsRoot 'DNS-BootstrapPolicy.ps1')
$config = Get-Content -LiteralPath (Join-Path (Join-Path $projectRoot 'config') 'sing-box-core-base.json') -Encoding UTF8 -Raw | ConvertFrom-Json
Assert-DnsBootstrapConfiguration $config
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
$fixtureRoot = Join-Path $fixtureParent ('sb-dns-bootstrap-' + [guid]::NewGuid().ToString('N'))
$process = $null
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
function Get-FreeLoopbackPort {
    param([ValidateSet('tcp','udp')][string]$Protocol)
    if ($Protocol -eq 'tcp') {
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        $listener.Start()
        try { return [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
    }
    $client = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    try { return [int]([Net.IPEndPoint]$client.Client.LocalEndPoint).Port } finally { $client.Dispose() }
}
function Invoke-FixtureDns {
    param([int]$Port, [string]$Domain, [int]$Id)
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
        $wire = [byte[]]@(($message.Count -shr 8),($message.Count -band 255)) + $message.ToArray()
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
        if ($response.Length -lt 12 -or (([int]$response[0] -shl 8) -bor [int]$response[1]) -ne $Id -or
            ($response[2] -band 128) -eq 0 -or ($response[3] -band 15) -ne 0 -or
            (([int]$response[6] -shl 8) -bor [int]$response[7]) -lt 1) { throw 'DNS response failed ID/QR/RCODE/answer validation.' }
        return [pscustomobject]@{domain=$Domain;rcode=0;answers=(([int]$response[6] -shl 8) -bor [int]$response[7]);bytes=$response.Length}
    } finally { $client.Dispose() }
}
try {
    # Isolated loopback DNS only: preserve dns-in and its dns-node alias, with no TUN or OS changes.
    $dnsInbounds = @($config.inbounds | Where-Object { $_.tag -ceq 'dns-in' })
    $nodeServers = @($config.dns.servers | Where-Object { $_.tag -ceq 'dns-node' })
    if ($dnsInbounds.Count -ne 1 -or $nodeServers.Count -ne 1) { throw 'The current dns-in and dns-node loopback pair is missing or ambiguous.' }
    $nodePort = Get-FreeLoopbackPort -Protocol udp
    $testPort = Get-FreeLoopbackPort -Protocol tcp
    while ($testPort -eq $nodePort) { $testPort = Get-FreeLoopbackPort -Protocol tcp }
    $dnsInbounds[0].listen_port = $nodePort
    $nodeServers[0].server = '127.0.0.1'
    $nodeServers[0].server_port = $nodePort
    $testInbound = [pscustomobject][ordered]@{type='direct';tag='dns-test';listen='127.0.0.1';listen_port=$testPort;network='tcp'}
    $config.inbounds = @($config.inbounds | Where-Object { $_.type -cne 'tun' }) + @($testInbound)
    $testHijack = [pscustomobject][ordered]@{inbound=@('dns-test');action='hijack-dns'}
    $config.route.rules = @($config.route.rules) + @($testHijack)
    $config.dns.rules = @($config.dns.rules) + @([pscustomobject][ordered]@{domain=@('example.com');action='route';server='dns-direct';timeout='5s'})
    $config.log.level = 'debug'
    $path = Join-Path $fixtureRoot 'config.json'
    [IO.File]::WriteAllText($path,($config | ConvertTo-Json -Depth 100) + "`n",[Text.UTF8Encoding]::new($false))
    & $SingBoxPath -D $fixtureRoot check -c $path
    if ($LASTEXITCODE -ne 0) { throw 'Official core rejected isolated DNS configuration.' }
    $stdout = Join-Path $fixtureRoot 'stdout.log'
    $stderr = Join-Path $fixtureRoot 'stderr.log'
    $process = Start-Process -FilePath $SingBoxPath -ArgumentList @('-D',('"' + $fixtureRoot + '"'),'run','-c',('"' + $path + '"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    for ($attempt=0; $attempt -lt 40; $attempt++) {
        $process.Refresh()
        if ($process.HasExited) { throw 'Isolated DNS core exited during startup.' }
        $probe = New-Object Net.Sockets.TcpClient
        try { $probe.Connect('127.0.0.1',$testPort); $ready=$true } catch { Start-Sleep -Milliseconds 50 } finally { $probe.Dispose() }
        if ($ready) { break }
    }
    if (-not $ready) { throw 'Isolated DNS core did not become ready.' }
    Invoke-FixtureDns -Port $testPort -Domain 'example.com' -Id 1001 | Format-List
    Invoke-FixtureDns -Port $testPort -Domain 'www.google.com' -Id 1002 | Format-List
    Write-Output 'Isolated DNS network checks passed: direct Ali DNS and proxy DNS through the preserved dns-node loopback resolver; no TUN or OS networking changes.'
} catch {
    Write-Output ('Isolated DNS network check failed: ' + $_.Exception.Message)
    if (Test-Path -LiteralPath (Join-Path $fixtureRoot 'stdout.log')) { Get-Content -LiteralPath (Join-Path $fixtureRoot 'stdout.log') -Tail 55 }
    if (Test-Path -LiteralPath (Join-Path $fixtureRoot 'stderr.log')) { Get-Content -LiteralPath (Join-Path $fixtureRoot 'stderr.log') -Tail 55 }
    throw
} finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(3000) }
        $process.Dispose()
    }
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    if ((Split-Path -Parent $resolved) -ine $fixtureParent -or
        (Split-Path -Leaf $resolved) -notmatch '^sb-dns-bootstrap-[a-f0-9]{32}$') { throw 'Unsafe test cleanup path.' }
    $items = @((Get-Item -LiteralPath $resolved -Force)) + @(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'DNS bootstrap fixture contains a reparse point; preserve it.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
