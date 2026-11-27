[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
$scriptsRoot=Join-Path $openWrtRoot 'scripts'
. (Join-Path $scriptsRoot 'Native-PackageValidation.ps1')
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('sb-checksum-case-'+[guid]::NewGuid().ToString('N'))
$payload=Join-Path $fixture 'payload'
[IO.Directory]::CreateDirectory($fixture) | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archivePath=Join-Path $fixture 'candidate.zip'
    Copy-Item -LiteralPath (Join-Path $openWrtRoot 'generated/openwrt.zip') -Destination $archivePath
    [IO.Compression.ZipFile]::ExtractToDirectory($archivePath,$payload)
    $sumsPath=Join-Path $payload 'SHA256SUMS'
    $sums=[IO.File]::ReadAllText($sumsPath)
    $changed=$sums.Replace("  config.json`n","  CONFIG.json`n")
    if ($changed -ceq $sums) { throw 'Expected checksum entry missing.' }
    [IO.File]::WriteAllText($sumsPath,$changed,(New-Object Text.UTF8Encoding($false)))
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Update)
    try {
        $zip.GetEntry('SHA256SUMS').Delete()
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$sumsPath,'SHA256SUMS')
    } finally { $zip.Dispose() }
    $blocked=$false
    try { Assert-NativePackageArchive -ZipPath $archivePath -PayloadDirectory $payload -SingBoxPath (Get-OpenWrtCorePaths)['sing-box-check'] }
    catch { $blocked=$_.Exception.Message -match 'Invalid checksum coverage' }
    if (-not $blocked) { throw 'A case-mismatched checksum filename was accepted or rejected for an unrelated reason.' }

    $modeFixture=Join-Path $fixture 'bad-mode'
    [IO.Directory]::CreateDirectory($modeFixture) | Out-Null
    [IO.File]::WriteAllText((Join-Path $modeFixture 'connection-cache.mode'),"ctmark-v1`n`n",(New-Object Text.UTF8Encoding($false)))
    $modeRejected=$false
    try { Assert-NativePackageArchive -ZipPath (Join-Path $modeFixture 'not-opened.zip') -PayloadDirectory $modeFixture -SingBoxPath (Get-OpenWrtCorePaths)['sing-box-check'] }
    catch { $modeRejected=$_.Exception.Message -match 'Connection cache marker must contain exactly' }
    if (-not $modeRejected) { throw 'A malformed connection cache mode marker was accepted or rejected for an unrelated reason.' }
    Write-Output 'Native SHA256SUMS case mismatch and malformed connection-cache marker rejected before official check; private fixtures only.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    if ((Split-Path -Parent $resolved) -ine ([IO.Path]::GetTempPath()).TrimEnd('\') -or (Split-Path -Leaf $resolved) -notmatch '^sb-checksum-case-[a-f0-9]{32}$') { throw 'Unsafe checksum fixture cleanup.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
