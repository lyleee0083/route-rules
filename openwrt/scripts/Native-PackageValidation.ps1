if (-not (Get-Command New-OpenWrtTaskScratchDirectory -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1')
}

function Assert-NativePackageArchive {
    param([string]$ZipPath,[string]$PayloadDirectory,[string]$SingBoxPath,[string]$ExpectedConnectionCacheMode)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archiveFile=[IO.Path]::GetFullPath($ZipPath)
    $files=@(Get-ChildItem -LiteralPath $PayloadDirectory -File | Where-Object { $_.FullName -ne $archiveFile })
    $names=@($files | ForEach-Object { $_.Name })
    $modePath=Join-Path $PayloadDirectory 'connection-cache.mode'
    $actualConnectionCacheMode='legacy-off'
    if (Test-Path -LiteralPath $modePath -PathType Leaf) {
        $modeText=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($modePath))
        if ($modeText -ceq "off-v1`n") { $actualConnectionCacheMode='off-v1' }
        elseif ($modeText -ceq "ctmark-v1`n") { $actualConnectionCacheMode='ctmark-v1' }
        else { throw 'Connection cache marker must contain exactly off-v1 or ctmark-v1 followed by one LF.' }
    } elseif (Test-Path -LiteralPath $modePath) { throw 'Connection cache marker is not a regular file.' }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedConnectionCacheMode) -and $actualConnectionCacheMode -cne $ExpectedConnectionCacheMode) { throw 'Package connection cache marker does not match the requested build mode.' }
    $archive=[IO.Compression.ZipFile]::OpenRead($ZipPath)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $entries=@($archive.Entries | ForEach-Object { $_.FullName })
        if ($entries.Count -ne $names.Count -or @($entries | Select-Object -Unique).Count -ne $entries.Count -or
            @($entries | Where-Object { $_ -notmatch '^[A-Za-z0-9_.-]+$' }).Count -or
            @(Compare-Object ($names | Sort-Object) ($entries | Sort-Object) -CaseSensitive).Count) { throw 'Invalid native package entry manifest.' }
        $reader=New-Object IO.StreamReader($archive.GetEntry('SHA256SUMS').Open())
        try { $sums=$reader.ReadToEnd() } finally { $reader.Dispose() }
        if ($sums.Contains("`r") -or -not $sums.EndsWith("`n") -or $sums.EndsWith("`n`n")) { throw 'Invalid checksum file format.' }
        $hashes=@{}
        foreach ($line in $sums.TrimEnd([char]10).Split([char]10)) {
            if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$') { throw 'Malformed native checksum line.' }
            $hash=$Matches[1]; $name=$Matches[2]
            if ($name -eq 'SHA256SUMS' -or $hashes.ContainsKey($name) -or $name -cnotin $names) { throw 'Invalid checksum coverage.' }
            $hashes[$name]=$hash
        }
        if ($hashes.Count -ne ($names.Count-1)) { throw 'Incomplete native checksums.' }
        foreach ($file in $files) {
            $stream=$archive.GetEntry($file.Name).Open()
            try { $actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() } finally { $stream.Dispose() }
            if ($actual -cne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -or
                ($file.Name -ne 'SHA256SUMS' -and $actual -cne $hashes[$file.Name])) { throw ('Native payload digest mismatch: '+$file.Name) }
        }
        if ($hashes.ContainsKey('sing-box') -or $hashes.ContainsKey('mosdns')) { throw 'External core binaries must not be packaged.' }
    } finally { $sha.Dispose(); $archive.Dispose() }
    # Every payload byte equals its archive entry. This is schema validation,
    # not ARM service or Linux kernel acceptance.
    & $SingBoxPath -D $PayloadDirectory check -c (Join-Path $PayloadDirectory 'config.json')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned sing-box rejected native package before publication.' }
}

function Get-MosdnsDeadlineRemainingMilliseconds {
    param([Parameter(Mandatory)][DateTime]$Deadline)
    $remaining=($Deadline-[DateTime]::UtcNow).TotalMilliseconds
    if ($remaining -le 0) { throw (New-Object System.TimeoutException('MosDNS runtime validation exceeded its wall-clock deadline.')) }
    return [int][Math]::Max(1,[Math]::Min(2147483647,[Math]::Ceiling($remaining)))
}

function Wait-MosdnsAsyncOperationWithinDeadline {
    param([Parameter(Mandatory)][System.IAsyncResult]$Operation,[Parameter(Mandatory)][DateTime]$Deadline)
    while (-not $Operation.IsCompleted) {
        $remaining=Get-MosdnsDeadlineRemainingMilliseconds -Deadline $Deadline
        Start-Sleep -Milliseconds ([Math]::Min(10,$remaining))
    }
    [void](Get-MosdnsDeadlineRemainingMilliseconds -Deadline $Deadline)
}

function Test-MosdnsTcpListenerWithinDeadline {
    param([Parameter(Mandatory)][int]$Port,[Parameter(Mandatory)][DateTime]$Deadline)
    $client=New-Object Net.Sockets.TcpClient
    $pending=$null
    try {
        $pending=$client.BeginConnect('127.0.0.1',$Port,$null,$null)
        Wait-MosdnsAsyncOperationWithinDeadline -Operation $pending -Deadline $Deadline
        $client.EndConnect($pending)
        return $true
    }
    catch [TimeoutException] { throw }
    catch { return $false }
    finally {
        if ($client) { $client.Dispose() }
    }
}

function Invoke-MosdnsMetricsProbe {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][DateTime]$Deadline,
        [string]$ExpectedMarker='mosdns_',
        [int]$MaximumResponseBytes=8388608
    )
    if ($MaximumResponseBytes -lt 1) { throw 'MosDNS metrics response size limit must be positive.' }
    if (-not ('System.Net.Http.HttpClient' -as [type])) { [void](Add-Type -AssemblyName System.Net.Http) }
    $handler=$null
    $client=$null
    $httpRequest=$null
    $response=$null
    $cancellationSource=$null
    $timedOut=$false
    try {
        $handler=New-Object System.Net.Http.HttpClientHandler
        $handler.UseProxy=$false
        $handler.AllowAutoRedirect=$false
        $client=New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout=[TimeSpan]::FromMilliseconds(-1)
        $client.MaxResponseContentBufferSize=[long]$MaximumResponseBytes
        $httpRequest=New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get,[Uri]$Url)
        $cancellationSource=New-Object System.Threading.CancellationTokenSource
        $remaining=Get-MosdnsDeadlineRemainingMilliseconds -Deadline $Deadline
        $cancellationSource.CancelAfter($remaining)
        $sendTask=$client.SendAsync($httpRequest,[System.Net.Http.HttpCompletionOption]::ResponseContentRead,$cancellationSource.Token)
        try { $response=$sendTask.GetAwaiter().GetResult() }
        catch {
            # Host versions wrap transport exceptions differently; inspect
            # the chain only to distinguish retryable connection failures.
            # HTTP status responses are returned normally with their buffered body.
            $caughtException=$_.Exception
            $webException=$null
            $socketException=$null
            $operationCancelled=$false
            $exceptionCursor=$caughtException
            while ($null -ne $exceptionCursor) {
                if ($exceptionCursor -is [Net.WebException]) { $webException=$exceptionCursor }
                if ($exceptionCursor -is [Net.Sockets.SocketException]) { $socketException=$exceptionCursor }
                if ($exceptionCursor -is [OperationCanceledException]) { $operationCancelled=$true }
                $exceptionCursor=$exceptionCursor.InnerException
            }
            if ($operationCancelled -and ($cancellationSource.IsCancellationRequested -or [DateTime]::UtcNow -ge $Deadline)) {
                $timedOut=$true
                throw (New-Object System.TimeoutException('MosDNS loopback /metrics response exceeded its wall-clock deadline.'))
            }
            if ($null -ne $webException -and $webException.Status -in @(
                [Net.WebExceptionStatus]::NameResolutionFailure,
                [Net.WebExceptionStatus]::ConnectFailure,
                [Net.WebExceptionStatus]::ConnectionClosed,
                [Net.WebExceptionStatus]::ReceiveFailure,
                [Net.WebExceptionStatus]::SendFailure,
                [Net.WebExceptionStatus]::KeepAliveFailure
            )) { return $false }
            if ($null -ne $socketException -and $socketException.SocketErrorCode -in @(
                [Net.Sockets.SocketError]::ConnectionRefused,
                [Net.Sockets.SocketError]::ConnectionReset,
                [Net.Sockets.SocketError]::ConnectionAborted,
                [Net.Sockets.SocketError]::NetworkUnreachable,
                [Net.Sockets.SocketError]::HostUnreachable
            )) { return $false }
            throw
        }

        [void](Get-MosdnsDeadlineRemainingMilliseconds -Deadline $Deadline)
        $status=[int]$response.StatusCode
        $bodyBytes=$response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        [void](Get-MosdnsDeadlineRemainingMilliseconds -Deadline $Deadline)
        if ($bodyBytes.Length -gt $MaximumResponseBytes) { throw ('MosDNS loopback /metrics response exceeded '+$MaximumResponseBytes+' bytes.') }
        $utf8=New-Object Text.UTF8Encoding($false,$true)
        $body=$utf8.GetString($bodyBytes)
        if ($status -ne 200) { throw ('MosDNS loopback /metrics returned HTTP '+$status+': '+$body) }
        if (-not $body.Contains($ExpectedMarker)) { throw ('MosDNS loopback /metrics returned HTTP 200 without expected content: '+$body) }
        return $true
    }
    catch [TimeoutException] { $timedOut=$true; throw }
    finally {
        if ($timedOut -and $cancellationSource) { $cancellationSource.Cancel() }
        if ($timedOut -and $client) { $client.Dispose() }
        if ($response) { $response.Dispose() }
        if ($httpRequest) { $httpRequest.Dispose() }
        if ($client) { $client.Dispose() }
        elseif ($handler) { $handler.Dispose() }
        if ($cancellationSource) { $cancellationSource.Dispose() }
    }
}

function Assert-MosdnsRuntimeConfiguration {
    param([Parameter(Mandatory)][string]$PayloadDirectory,[Parameter(Mandatory)][string]$MosdnsPath)
    # mosdns has no check command. Load the exact generated config with only
    # DNS listener and loopback metrics ports changed in a private fixture;
    # no upstream DNS is queried.
    $temporary=New-OpenWrtTaskScratchDirectory -Prefix 'sb-mosdns-check'
    $child=$null
    $reservations=New-Object 'System.Collections.Generic.List[object]'
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    try {
        $ports=@()
        for ($i=0;$i -lt 2;$i++) {
            $tcp=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
            $tcp.Start()
            $reservations.Add($tcp)
            $port=$tcp.LocalEndpoint.Port
            $udp=New-Object Net.Sockets.UdpClient($port)
            $reservations.Add($udp)
            $ports+= $port
        }
        $apiReservation=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        $apiReservation.Start()
        $reservations.Add($apiReservation)
        $apiPort=$apiReservation.LocalEndpoint.Port
        foreach ($file in Get-ChildItem -LiteralPath $PayloadDirectory -File -Filter '*.mdrs') { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $temporary $file.Name) }
        $text=[IO.File]::ReadAllText((Join-Path $PayloadDirectory 'mosdns.json'))
        $text=$text.Replace('127.0.0.1:15353',('127.0.0.1:'+$ports[0])).Replace('127.0.0.1:15354',('127.0.0.1:'+$ports[1])).Replace('127.0.0.1:15357',('127.0.0.1:'+$apiPort))
        $configPath=Join-Path $temporary 'mosdns.json'
        [IO.File]::WriteAllText($configPath,$text,(New-Object Text.UTF8Encoding($false)))
        foreach ($reservation in $reservations) { if ($reservation -is [Net.Sockets.TcpListener]) { $reservation.Stop() } else { $reservation.Dispose() } }
        $reservations.Clear()
        $stdout=Join-Path $temporary 'stdout.log';$stderr=Join-Path $temporary 'stderr.log'
        $arguments=@('start','-c',('"'+$configPath+'"'),'-d',('"'+$temporary+'"'))
        $launch = @{
            FilePath = $MosdnsPath
            ArgumentList = $arguments
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
            PassThru = $true
        }
        $child = Start-Process @launch
        $ready=$false
        $apiReady=$false
        while ($true) {
            [void](Get-MosdnsDeadlineRemainingMilliseconds -Deadline $deadline)
            $child.Refresh()
            if ($child.HasExited) { throw ('Pinned MosDNS rejected generated configuration: '+[IO.File]::ReadAllText($stderr)+' '+[IO.File]::ReadAllText($stdout)) }
            $ready=$true
            foreach ($port in $ports) {
                if (-not (Test-MosdnsTcpListenerWithinDeadline -Port $port -Deadline $deadline)) { $ready=$false;break }
                $child.Refresh()
                if ($child.HasExited) { throw ('Pinned MosDNS exited while checking generated configuration: '+[IO.File]::ReadAllText($stderr)+' '+[IO.File]::ReadAllText($stdout)) }
            }
            if ($ready) {
                $apiReady=Invoke-MosdnsMetricsProbe -Url ('http://127.0.0.1:'+$apiPort+'/metrics') -Deadline $deadline
                if ($apiReady) { break }
            }
            $child.Refresh()
            if ($child.HasExited) { throw ('Pinned MosDNS exited before generated configuration became ready: '+[IO.File]::ReadAllText($stderr)+' '+[IO.File]::ReadAllText($stdout)) }
            $remaining=Get-MosdnsDeadlineRemainingMilliseconds -Deadline $deadline
            Start-Sleep -Milliseconds ([Math]::Min(100,$remaining))
        }
    } finally {
        foreach ($reservation in $reservations) { if ($reservation -is [Net.Sockets.TcpListener]) { $reservation.Stop() } else { $reservation.Dispose() } }
        if ($child) {
            $processCleanupError=$null
            try {
                $child.Refresh()
                if (-not $child.HasExited) {
                    $killError=$null
                    try { $child.Kill() }
                    catch { $killError=$_.Exception.Message }
                    if (-not $child.WaitForExit(1000)) {
                        if ($killError) { $processCleanupError='Could not terminate the isolated MosDNS validator process: '+$killError }
                        else { $processCleanupError='Isolated MosDNS validator process did not exit during bounded cleanup.' }
                    }
                }
            }
            catch { $processCleanupError='Could not confirm isolated MosDNS validator process cleanup: '+$_.Exception.Message }
            finally { $child.Dispose() }
            if ($processCleanupError) { throw $processCleanupError }
        }
        Remove-OpenWrtTaskScratchDirectory -Path $temporary -Prefix 'sb-mosdns-check'
    }
}
