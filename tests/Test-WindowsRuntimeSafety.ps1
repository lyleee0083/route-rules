[CmdletBinding()]
param([string]$ControlPath='D:\Software\sing-box\sing-box-control.ps1')
$ErrorActionPreference='Stop'
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('sing-box-runtime-safety-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$runtimeDirectory=Join-Path $fixture '.runtime'
$controlLogArchiveCount=3
$junction=$null
try {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($ControlPath,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Actual control script has syntax errors.' }
    $node=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-ControlRuntimePaths'},$true) | Select-Object -First 1
    if ($null -eq $node) { throw 'Actual controller lacks runtime path validation.' }
    . ([scriptblock]::Create($node.Extent.Text))
    Assert-ControlRuntimePaths
    [IO.Directory]::CreateDirectory($runtimeDirectory) | Out-Null
    $names=@('control.lock','sing-box.pid','sing-box-process.json',('sing-box-process.json.'+$PID+'.tmp'),
        'sing-box-control.log','sing-box-control.log.1','sing-box-control.log.2','sing-box-control.log.3')
    foreach ($name in $names) {
        $path=Join-Path $runtimeDirectory $name
        [IO.Directory]::CreateDirectory($path) | Out-Null
        $blocked=$false
        try { Assert-ControlRuntimePaths } catch { $blocked=$true }
        if (-not $blocked) { throw ('Directory accepted as runtime file: '+$name) }
        [IO.Directory]::Delete($path)
        [IO.File]::WriteAllText($path,'unchanged')
        Assert-ControlRuntimePaths
        if ([IO.File]::ReadAllText($path) -cne 'unchanged') { throw 'Validation changed a runtime file.' }
        [IO.File]::Delete($path)
    }
    [IO.Directory]::Delete($runtimeDirectory)
    [IO.File]::WriteAllText($runtimeDirectory,'unchanged')
    $blocked=$false
    try { Assert-ControlRuntimePaths } catch { $blocked=$true }
    if (-not $blocked -or [IO.File]::ReadAllText($runtimeDirectory) -cne 'unchanged') { throw 'Wrong-type state directory was accepted or altered.' }
    [IO.File]::Delete($runtimeDirectory)
    $target=Join-Path $fixture 'unrelated'
    [IO.Directory]::CreateDirectory($target) | Out-Null
    $marker=Join-Path $target 'control.lock'
    [IO.File]::WriteAllText($marker,'unrelated')
    $junction=New-Item -ItemType Junction -Path $runtimeDirectory -Target $target
    $blocked=$false
    try { Assert-ControlRuntimePaths } catch { $blocked=$true }
    if (-not $blocked -or [IO.File]::ReadAllText($marker) -cne 'unrelated') { throw 'Linked state directory was accepted or changed its target.' }
    [IO.Directory]::Delete($runtimeDirectory)
    $junction=$null
    foreach ($name in @('Rotate-ControlLog','Remove-ProcessRecord','Write-ProcessRecord','Get-ManagedProcesses')) {
        $function=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true) | Select-Object -First 1
        if ($null -eq $function -or $function.Extent.Text -notmatch 'Assert-ControlRuntimePaths') { throw ('Mutable state entry lacks validation: '+$name) }
    }
    Write-Output 'Windows runtime safety passed: eight wrong-type files, wrong-type directory and junction rejected without writes; ordinary files preserved. No actual start/stop performed.'
} finally {
    if ($null -ne $junction) { [IO.Directory]::Delete($runtimeDirectory) }
    $resolved=[IO.Path]::GetFullPath($fixture)
    if ((Split-Path -Parent $resolved) -ine ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $resolved) -notmatch '^sing-box-runtime-safety-[a-f0-9]{32}$') { throw 'Unsafe runtime fixture cleanup.' }
    if (@(Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Linked fixture retained; no recursive cleanup.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
