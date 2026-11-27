[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$directory = Join-Path $root 'outputs/ci-dependencies'
$filename = 'zstd-v1.6.0-win64.zip'
$archivePath = Join-Path $directory $filename
$libraryPath = Join-Path $directory 'libzstd.dll'

[void][IO.Directory]::CreateDirectory($directory)
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/meta/zstd/releases/download/v1.6.0/$filename" -OutFile $archivePath -TimeoutSec 60
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ine 'D1B4337932739F4DCA65C9E98517D1DC6724D6F378DFFF2EBB0EAD81B9E6D4F2') {
    throw 'Official Zstandard archive digest mismatch.'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $library = $archive.GetEntry('zstd-v1.6.0-win64/dll/libzstd.dll')
    if (-not $library) { throw 'Missing libzstd.dll in the verified archive.' }
    [IO.Compression.ZipFileExtensions]::ExtractToFile($library,$libraryPath,$true)
}
finally { $archive.Dispose() }
$libraryPath
