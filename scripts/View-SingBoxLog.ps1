[CmdletBinding()]
param(
    [ValidateSet('warn', 'error')][string]$Level = 'warn',
    [string]$Controller = 'http://127.0.0.1:19090',
    [ValidateRange(1, 60)][int]$ConnectTimeoutSeconds = 8,
    [ValidateRange(0, 20)][int]$ReconnectAttempts = 5
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$uri = [UriBuilder]::new($Controller)
if ($uri.Scheme -notin @('http','https')) { throw 'Controller 必须为 HTTP 或 HTTPS 地址。' }
$uri.Scheme = if ($uri.Scheme -eq 'https') { 'wss' } else { 'ws' }
$uri.Path = $uri.Path.TrimEnd('/') + '/logs'
$uri.Query = 'level=' + $Level
$uri.Fragment = ''
Write-Host 'sing-box 实时日志（不会写入文件）' -ForegroundColor Cyan
Write-Host '按 Ctrl+C 或关闭窗口退出查看，不会停止 sing-box。' -ForegroundColor DarkGray
$attempt = 0
while ($true) {
    $socket = [Net.WebSockets.ClientWebSocket]::new()
    $socket.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(15)
    $connectCancellation = [Threading.CancellationTokenSource]::new()
    $receiveCancellation = [Threading.CancellationTokenSource]::new()
    try {
        $connectCancellation.CancelAfter([TimeSpan]::FromSeconds($ConnectTimeoutSeconds))
        $connectTask = $socket.ConnectAsync($uri.Uri, $connectCancellation.Token)
        while (-not $connectTask.IsCompleted) { Start-Sleep -Milliseconds 100 }
        [void]$connectTask.GetAwaiter().GetResult()
        Write-Host "已连接：$Controller；等待新产生的 $Level 日志。" -ForegroundColor Green
        $buffer = [byte[]]::new(8192)
        while ($socket.State -eq [Net.WebSockets.WebSocketState]::Open) {
            $message = [IO.MemoryStream]::new()
            try {
                do {
                    $receiveTask = $socket.ReceiveAsync([ArraySegment[byte]]::new($buffer), $receiveCancellation.Token)
                    while (-not $receiveTask.IsCompleted) { Start-Sleep -Milliseconds 100 }
                    $result = $receiveTask.GetAwaiter().GetResult()
                    if ($result.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw '服务器已关闭日志连接。' }
                    if ($result.MessageType -ne [Net.WebSockets.WebSocketMessageType]::Text) { throw '收到非文本日志消息。' }
                    if ($message.Length + $result.Count -gt 1MB) { throw '日志消息超过 1 MiB，已断开保护内存。' }
                    $message.Write($buffer, 0, $result.Count)
                } while (-not $result.EndOfMessage)
                $text = [Text.Encoding]::UTF8.GetString($message.ToArray())
                try {
                    $entry = $text | ConvertFrom-Json
                    $type = ([string]$entry.type).ToUpperInvariant()
                    $color = if ($type -in @('ERROR','FATAL','PANIC')) { 'Red' } else { 'Yellow' }
                    Write-Host ('{0} {1} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $type, $entry.payload) -ForegroundColor $color
                }
                catch { Write-Host $text }
            }
            finally { $message.Dispose() }
        }
        throw '日志连接已结束。'
    }
    catch {
        Write-Host "日志连接中断：$($_.Exception.Message)" -ForegroundColor Yellow
        if ($attempt -ge $ReconnectAttempts) {
            Write-Host '重连次数已用尽。请检查进程及日志接口，不必直接重启服务。' -ForegroundColor Red
            exit 1
        }
        $attempt++
        Write-Host "2 秒后重连（$attempt/$ReconnectAttempts）。" -ForegroundColor DarkGray
    }
    finally {
        $connectCancellation.Cancel()
        $receiveCancellation.Cancel()
        $socket.Abort()
        $socket.Dispose()
        $connectCancellation.Dispose()
        $receiveCancellation.Dispose()
    }
    Start-Sleep -Seconds 2
}
