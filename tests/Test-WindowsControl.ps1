[CmdletBinding()]
param([string]$ControlPath = 'D:\Software\sing-box\sing-box-control.ps1')
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This isolated console test requires Windows.' }
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('sing-box-control-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$fixtureControl = Join-Path $fixtureRoot 'sing-box-control.ps1'
Copy-Item -LiteralPath $ControlPath -Destination $fixtureControl
$fixtureExe = Join-Path $fixtureRoot 'sing-box.exe'
$fixtureProcess = $null
$logProcess = $null
$cancelProcess = $null
try {
    $compilerScript = Join-Path $fixtureRoot 'compile.ps1'
    $compilerText = "Add-Type -TypeDefinition 'public static class Fixture { public static void Main() { System.Threading.Thread.Sleep(60000); } }' -OutputType ConsoleApplication -OutputAssembly '" + $fixtureExe.Replace("'","''") + "'"
    [IO.File]::WriteAllText($compilerScript,$compilerText,[Text.UTF8Encoding]::new($true))
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File $compilerScript
    if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed.' }
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($fixtureControl,[ref]$tokens,[ref]$errors)
    if ($errors) { throw 'Control script parse failed.' }
    foreach ($name in @('Initialize-ConsoleControl','Start-InterruptHelper','Stop-ManagedProcess','Wait-SingBoxReady')) {
        $node=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true) | Select-Object -First 1
        $body=$node.Extent.Text.Replace('$PSCommandPath',("'"+$fixtureControl.Replace("'","''")+"'"))
        . ([scriptblock]::Create($body))
    }
    $rootDirectory=$fixtureRoot
    Initialize-ConsoleControl
    if (Start-InterruptHelper -ProcessId 2147483647 -StartTicks 1) { throw 'Invalid PID helper reported success.' }
    $fixtureId=[SingBoxConsoleControl]::StartHiddenConsoleProcess($fixtureExe, '', $fixtureRoot)
    $fixtureProcess=[Diagnostics.Process]::GetProcessById($fixtureId)
    $identity=$fixtureProcess.StartTime.ToUniversalTime().Ticks
    if ($fixtureProcess.MainModule.FileName -ine $fixtureExe) { throw 'Fixture identity mismatch.' }
    if (Start-InterruptHelper -ProcessId $fixtureId -StartTicks ($identity+1)) { throw 'Mismatched start time accepted.' }
    $fixtureProcess.Refresh()
    if ($fixtureProcess.HasExited) { throw 'Identity rejection terminated fixture.' }
    $result=Stop-ManagedProcess $fixtureProcess
    if ($result -ne 'interrupt' -or -not $fixtureProcess.HasExited) { throw "Graceful fixture stop failed: $result" }
    $hostExecutable = (Get-Process -Id $PID).Path
    $logScript = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'View-SingBoxLog.ps1'
    $logArguments = '-NoProfile -File "{0}" -ReconnectAttempts 0' -f $logScript
    $logId = [SingBoxConsoleControl]::StartHiddenConsoleProcess($hostExecutable, $logArguments, $fixtureRoot)
    $logProcess = [Diagnostics.Process]::GetProcessById($logId)
    Start-Sleep -Seconds 2
    $logProcess.Refresh()
    if ($logProcess.HasExited) { throw 'Log reader failed before cancellation test.' }
    $initializer=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-ConsoleControl'},$true) | Select-Object -First 1
    $cancelScript = Join-Path $fixtureRoot 'cancel-log.ps1'
    $cancelText = 'param([int]$ProcessId)' + "`n" + $initializer.Extent.Text + "`n" + 'Initialize-ConsoleControl; if ([SingBoxConsoleControl]::SendInterrupt($ProcessId)) { exit 0 }; exit 1'
    [IO.File]::WriteAllText($cancelScript,$cancelText,[Text.UTF8Encoding]::new($true))
    $cancelArguments = '-NoProfile -File "{0}" -ProcessId {1}' -f $cancelScript,$logId
    $cancelProcess = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $cancelArguments -WorkingDirectory $fixtureRoot -WindowStyle Hidden -PassThru
    if (-not $cancelProcess.WaitForExit(10000)) { throw 'Log cancellation helper timed out.' }
    if ($cancelProcess.ExitCode -ne 0) { throw "Log cancellation helper failed: $($cancelProcess.ExitCode)" }
    if (-not $logProcess.WaitForExit(10000)) { throw 'Log reader did not exit after Ctrl+C.' }
    Write-Host 'Windows isolated console tests passed: invalid PID, reused PID identity, independent Ctrl+C and exit status. Real sing-box untouched.'
    Write-Host 'Log reader Ctrl+C lifecycle test passed.'
}
finally {
    foreach ($ownedHost in @($logProcess,$cancelProcess)) {
        if ($null -ne $ownedHost) {
            $ownedHost.Refresh()
            if (-not $ownedHost.HasExited) { $ownedHost.Kill(); $null=$ownedHost.WaitForExit(5000) }
            $ownedHost.Dispose()
        }
    }
    if ($null -ne $fixtureProcess) {
        $fixtureProcess.Refresh()
        if (-not $fixtureProcess.HasExited -and $fixtureProcess.MainModule.FileName -ieq $fixtureExe) { $fixtureProcess.Kill(); $null=$fixtureProcess.WaitForExit(5000) }
        $fixtureProcess.Dispose()
    }
    if ((Split-Path -Parent ([IO.Path]::GetFullPath($fixtureRoot))) -ne ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $fixtureRoot) -notlike 'sing-box-control-test-*') { throw 'Unsafe fixture cleanup path.' }
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
