[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('sing-box-strict-repairs-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
$configRoot = Join-Path $projectRoot 'config'
$sourceRoot = Join-Path $projectRoot 'src'
. (Join-Path $scriptsRoot 'Official-SingBoxChecker.ps1')
$resolvedSingBox=Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot
function Assert-StrictRepair { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Put-StrictText { param([string]$Path, [string]$Text) [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false))) }
try {
    . (Join-Path $scriptsRoot 'Update-RoutingRules.ps1') -DefinitionsOnly
    . (Join-Path $scriptsRoot 'SameTypeDirectPolicy.ps1')
    foreach ($token in @('127.1', '2130706433', '0x7f000001', '0177.0.0.1', '01.2.3.4', '1.2.3.004', '256.0.0.1', '1.2.3.4/33', '1.2.3.4/+24', '1.2.3.4/ 24')) {
        Assert-StrictRepair ($null -eq (ConvertTo-IPv4Cidr $token)) ('Ambiguous IPv4 source accepted: '+$token)
        $rejected=$false
        try { $null=[SingBoxSameType.Ranges]::IP($token) } catch { $rejected=$true }
        Assert-StrictRepair $rejected ('Ambiguous IPv4 compiler input accepted: '+$token)
    }
    foreach ($pair in @(@('0.0.0.0/0','0.0.0.0/0'), @('127.0.0.1','127.0.0.1/32'), @('192.0.2.129/24','192.0.2.0/24'), @('255.255.255.255/32','255.255.255.255/32'))) {
        Assert-StrictRepair ((ConvertTo-IPv4Cidr $pair[0]).Value -eq $pair[1]) ('Valid IPv4 normalization changed: '+$pair[0])
        $null=[SingBoxSameType.Ranges]::IP($pair[0])
    }
    $legacyTimeout=Get-WebRequestTimeoutArguments -Parameters @{TimeoutSec=$true}
    Assert-StrictRepair ($legacyTimeout.TimeoutSec -eq 180 -and -not $legacyTimeout.ContainsKey('OperationTimeoutSeconds')) 'Legacy download timeout arguments changed.'
    $modernTimeout=Get-WebRequestTimeoutArguments -Parameters @{ConnectionTimeoutSeconds=$true;OperationTimeoutSeconds=$true}
    Assert-StrictRepair ($modernTimeout.TimeoutSec -eq 180 -and $modernTimeout.OperationTimeoutSeconds -eq 180) 'Modern download lacks an operation timeout.'
    $actualTimeout=Get-WebRequestTimeoutArguments
    Assert-StrictRepair ($actualTimeout.ContainsKey('OperationTimeoutSeconds') -eq ((Get-Command Invoke-WebRequest).Parameters.Keys -contains 'OperationTimeoutSeconds')) 'Host download timeout parameter detection failed.'
    $fixture=Join-Path $root 'preflight'
    $fixtureScripts=Join-Path $fixture 'scripts'
    $fixtureConfig=Join-Path $fixture 'config'
    $fixtureSource=Join-Path $fixture 'src'
    $fixturePins=Join-Path $fixture 'scripts'
    foreach ($directory in @($fixtureScripts,$fixtureConfig,$fixtureSource,$fixturePins)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    foreach ($file in @('Generate-SingBoxConfig.ps1','Json-Validation.ps1','Direct-RoutingPolicy.ps1','SameTypeDirectPolicy.ps1','DNS-BootstrapPolicy.ps1','Node-DnsPolicy.ps1','Build-Transaction.ps1','Config-Archive.ps1','Official-SingBoxChecker.ps1')) {
        Copy-Item -LiteralPath (Join-Path $scriptsRoot $file) -Destination $fixtureScripts
    }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Official-Cores.ps1') -Destination $fixturePins
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'SameTypeDirectCompiler.cs') -Destination $fixtureSource
    Copy-Item -LiteralPath (Join-Path $configRoot 'sing-box-core-base.json') -Destination $fixtureConfig
    Copy-Item -LiteralPath (Join-Path $configRoot 'client-profiles.json') -Destination $fixtureConfig
    $marker=Join-Path $fixture 'updater-invoked'
    Put-StrictText (Join-Path $fixtureScripts 'Update-RoutingRules.ps1') ('[IO.File]::WriteAllText('''+$marker+''',''unexpected''); throw ''Updater must not run for invalid invocation.''')
    $blockedOutput=Join-Path $fixture 'output'
    [IO.Directory]::CreateDirectory($blockedOutput) | Out-Null
    Put-StrictText (Join-Path $blockedOutput 'sing-box-configs.zip') 'unchanged fixture'
    $listedClients=@(& (Join-Path $fixtureScripts 'Generate-SingBoxConfig.ps1') -ListClients)
    Assert-StrictRepair ($listedClients.Count -eq 5) 'Copied generator dependencies did not load for the positive control.'
    $expectedFailures=@{
        'existing-output'='输出 ZIP 已存在'
        'protected-output'='输出目录不能包含项目源文件'
        'missing-core'='找不到 sing-box 可执行文件'
    }
    foreach ($case in @('existing-output','protected-output','missing-core')) {
        $arguments=@{All=$true;OutputDirectory=$blockedOutput;SingBoxPath=$resolvedSingBox}
        if ($case -eq 'protected-output') { $arguments.OutputDirectory=$fixture; $arguments.Force=$true }
        if ($case -eq 'missing-core') { $arguments.Force=$true; $arguments.SingBoxPath=Join-Path $fixture 'missing.exe' }
        $failureMessage=''
        try { & (Join-Path $fixtureScripts 'Generate-SingBoxConfig.ps1') @arguments | Out-Null } catch { $failureMessage=$_.Exception.Message }
        Assert-StrictRepair ($failureMessage -match $expectedFailures[$case]) ('Wrong preflight failure for '+$case+': '+$failureMessage)
        Assert-StrictRepair (-not (Test-Path -LiteralPath $marker)) ('Generator refreshed sources before rejecting '+$case)
    }
    $cache = Join-Path $root 'cache'
    [IO.Directory]::CreateDirectory($cache) | Out-Null
    $resource = [pscustomobject]@{ tag='fixture'; url='https://example.invalid/rules.txt'; format='plain' }
    $body = Join-Path $cache 'fixture.txt'
    $metadataPath = Join-Path $cache 'fixture.metadata.json'
    Put-StrictText $body "direct.example`n"
    $hash = (Get-FileHash -LiteralPath $body).Hash
    foreach ($case in @('valid', 'changed-body', 'wrong-url', 'missing-hash', 'invalid-hash', 'malformed', 'null', 'missing', 'missing-body')) {
        Put-StrictText $body "direct.example`n"
        $metadata = [ordered]@{url=$resource.url; sha256=$hash}
        if ($case -eq 'wrong-url') { $metadata.url='https://example.invalid/other.txt' }
        if ($case -eq 'missing-hash') { $metadata.Remove('sha256') }
        if ($case -eq 'invalid-hash') { $metadata.sha256='not-a-hash' }
        Put-StrictText $metadataPath ($metadata | ConvertTo-Json)
        if ($case -eq 'changed-body') { Put-StrictText $body "direct.example`nunexpected.example`n" }
        if ($case -eq 'malformed') { Put-StrictText $metadataPath '{' }
        if ($case -eq 'null') { Put-StrictText $metadataPath 'null' }
        if ($case -eq 'missing') { [IO.File]::Delete($metadataPath) }
        if ($case -eq 'missing-body') { [IO.File]::Delete($body) }
        $accepted=$false
        try { $null=Get-RemoteSource -Resource $resource -CacheRoot $cache -UseCacheOnly; $accepted=$true } catch { }
        Assert-StrictRepair ($accepted -eq ($case -eq 'valid')) ('Unexpected offline-cache decision: '+$case)
    }

    Write-Output 'Strict audit repairs passed: offline rule provenance and hashes.'
}
finally {
    $resolved=[IO.Path]::GetFullPath($root)
    if ((Split-Path -Parent $resolved) -ine ([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) -or (Split-Path -Leaf $resolved) -notmatch '^sing-box-strict-repairs-[a-f0-9]{32}$') { throw 'Unsafe strict-repair test cleanup.' }
    $items=@(Get-Item -LiteralPath $resolved -Force)+@(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Strict-repair fixture contains a reparse point; preserve it.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
