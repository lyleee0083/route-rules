[CmdletBinding()]
param([string]$LinuxArchivePath, [string]$SourceRoot, [ValidateRange(1,600)][int]$LockTimeoutSeconds=30)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Split-Path -Parent $openWrtRoot
$sharedScriptsRoot = Join-Path $projectRoot 'scripts'
$sourceTreeRoot = Join-Path $openWrtRoot 'src'
$nativeSource = Join-Path $sourceTreeRoot 'native'
if (-not $LinuxArchivePath) { $LinuxArchivePath=Join-Path (Join-Path $projectRoot 'generated') 'sing-box-configs.zip' }
if (-not $SourceRoot) { $SourceRoot=Join-Path (Join-Path $openWrtRoot 'inputs') 'linux' }
. (Join-Path $sharedScriptsRoot 'Direct-RoutingPolicy.ps1')
. (Join-Path $PSScriptRoot 'Final-LinuxSnapshot.ps1')
. (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1')
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Snapshot recovery is temporary transaction material, not historical backup.
$protectedSourcePaths=@($PSScriptRoot,$sharedScriptsRoot,$sourceTreeRoot,(Join-Path $openWrtRoot 'build-stage'))
Assert-OpenWrtOutputTarget -OutputDirectory $SourceRoot -SourceRoot $nativeSource -ArchivePath $LinuxArchivePath -ProtectedPaths $protectedSourcePaths
Assert-OpenWrtInputPathSeparation -TransactionPaths (Get-OpenWrtTransactionPaths -Paths (Get-BuildPaths $SourceRoot)) -InputPaths (@($nativeSource) + $protectedSourcePaths)
$context=$null
try {
    $context=Enter-OpenWrtInputLocks -ArchivePath $LinuxArchivePath -SourceRoot $SourceRoot -TimeoutSeconds $LockTimeoutSeconds
    $paths=$context.SourcePaths
    if (Test-Path -LiteralPath $SourceRoot) {
        Assert-FinalLinuxSnapshot -SourceRoot $SourceRoot -ArchivePath $LinuxArchivePath -LayoutOnly
    }
    New-Item -ItemType Directory -Path (Join-Path $paths.Stage 'rule-set') -Force | Out-Null
    $zip=[IO.Compression.ZipFile]::OpenRead($LinuxArchivePath)
    try {
        $entry=@($zip.Entries | Where-Object FullName -ceq 'sing-box-linux-tun.json')
        if ($entry.Count -ne 1) { throw 'Missing or duplicate final Linux configuration.' }
        $reader=New-Object IO.StreamReader($entry[0].Open())
        try { $config=ConvertFrom-StrictJson -Text $reader.ReadToEnd() } finally { $reader.Dispose() }
        Assert-EffectiveDirectConfiguration $config
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry[0],(Join-Path $paths.Stage 'sing-box-openwrt.json'))
        foreach ($set in $config.route.rule_set) {
            if ($set.path -cnotmatch '^rule-set/[A-Za-z0-9_-]+\.srs$') { throw 'Unsafe final Linux SRS path.' }
            $entry=@($zip.Entries | Where-Object FullName -ceq $set.path)
            if ($entry.Count -ne 1) { throw 'Missing or duplicate final Linux SRS.' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry[0],(Join-Path $paths.Stage $set.path))
        }
    } finally { $zip.Dispose() }
    Assert-FinalLinuxSnapshot -SourceRoot $paths.Stage -ArchivePath $LinuxArchivePath
    Publish-BuildTransaction $paths
    Write-Output 'Final Linux snapshot synchronized byte-for-byte; committed transaction staging is cleaned automatically.'
} finally {
    if ($context) {
        try { if (-not (Test-Path -LiteralPath $context.SourcePaths.Journal)) { Remove-BuildDirectory $context.SourcePaths $context.SourcePaths.Stage } }
        finally { Exit-OpenWrtInputLocks $context }
    }
}
