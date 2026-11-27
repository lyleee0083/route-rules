# Official release assets only. Downloads are validated before extraction/use.
function Get-OpenWrtOfficialAssets {
    @(
        [pscustomobject]@{ Name='sing-box-1.14.4-linux-arm64-musl.tar.gz'; Repository='SagerNet/sing-box'; Tag='v1.14.4'; SHA256='B95E25F921DC5E17A4CF13327243D1177642C7E35425BF5372862C477C359F56'; Length=[int64]29763014; Binary='sing-box-1.14.4-linux-arm64-musl/sing-box'; BinarySHA256='709D6670C49019955E498872BC39B954461517AD8009968D1CF5592E9087B563'; Platform='sing-box-arm64' },
        [pscustomobject]@{ Name='sing-box-1.14.4-windows-amd64.zip'; Repository='SagerNet/sing-box'; Tag='v1.14.4'; SHA256='99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF'; Length=[int64]32891280; Binary='sing-box-1.14.4-windows-amd64/sing-box.exe'; BinarySHA256='8F30682EE198855440D2A7FE070D5D3653793B2D01BB8C85EEA88F93BBE7C8B9'; Platform='sing-box-check' },
        [pscustomobject]@{ Name='mosdns-linux-arm64.zip'; Repository='IrineSistiana/mosdns'; Tag='v5.3.4'; SHA256='82d80a1a21606fca0bc6b65ac6f90d30cff6bb4a19a6ab6a246cf247dbb78bc0'; Length=[int64]6591859; Binary='mosdns'; BinarySHA256='5E651992DBEC784DF43E0E483428319B0F2892F5FADFD4E39A1462A5D62CB495'; Platform='mosdns-arm64' },
        [pscustomobject]@{ Name='mosdns-windows-amd64.zip'; Repository='IrineSistiana/mosdns'; Tag='v5.3.4'; SHA256='3d55b6647e632ad86a1d86e7cf21b96bb63adfde3b4ffdc098c9af79381638ca'; Length=[int64]6245463; Binary='mosdns.exe'; BinarySHA256='C24E2F12DC4EE708E950F511FB543A239B02A75F32EC10ED7477C651C7715A85'; Platform='mosdns-check' }
    )
}

function Get-OpenWrtCorePaths {
    param([string]$Root=(Join-Path (Split-Path -Parent $PSScriptRoot) 'openwrt/build-stage/cores'))
    $result=@{}
    foreach ($asset in Get-OpenWrtOfficialAssets) {
        $result[$asset.Platform]=Join-Path (Join-Path $Root $asset.Platform) $asset.Binary
    }
    return $result
}

function Assert-OpenWrtOfficialCheckTools {
    param([string]$SingBoxPath,[string]$MosdnsPath)
    $singBoxAsset=@(Get-OpenWrtOfficialAssets | Where-Object { $_.Platform -ceq 'sing-box-check' })
    $mosdnsAsset=@(Get-OpenWrtOfficialAssets | Where-Object { $_.Platform -ceq 'mosdns-check' })
    if ($singBoxAsset.Count -ne 1 -or $mosdnsAsset.Count -ne 1) { throw 'Official checker asset pins are missing or ambiguous.' }
    if ((Get-FileHash -LiteralPath $SingBoxPath -Algorithm SHA256).Hash -cne $singBoxAsset[0].BinarySHA256) { throw 'Official Windows sing-box checker digest mismatch.' }
    if ((Get-FileHash -LiteralPath $MosdnsPath -Algorithm SHA256).Hash -cne $mosdnsAsset[0].BinarySHA256) { throw 'Official Windows mosdns checker digest mismatch.' }
}

function Assert-OpenWrtCorePathHasNoReparseAncestors {
    param([Parameter(Mandatory)][string]$Path)
    $cursor=[IO.Path]::GetFullPath($Path)
    while ($cursor) {
        $item=Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw ('Reparse point in core path: '+$cursor) }
        $parent=[IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $cursor) { break }
        $cursor=$parent
    }
}

function Assert-OpenWrtCoreTreeHasNoReparsePoints {
    param([Parameter(Mandatory)][string]$Path)
    if (-not [IO.Directory]::Exists($Path)) { return }
    Assert-OpenWrtCorePathHasNoReparseAncestors -Path $Path
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse point in extracted core tree: '+$item.FullName) }
    }
}

function ConvertTo-OpenWrtOfficialArchivePath {
    param([Parameter(Mandatory)][string]$EntryPath,[Parameter(Mandatory)]$Asset)
    if ([string]::IsNullOrEmpty($EntryPath) -or $EntryPath.IndexOf([char]0) -ge 0 -or $EntryPath.Contains('\')) { throw ('Unsafe official archive path: '+$EntryPath) }
    $path=$EntryPath
    if ($path.StartsWith('/') -or $path -match '^[A-Za-z]:' -or $path.Contains(':')) { throw ('Unsafe official archive path: '+$EntryPath) }
    $isDirectory=$path.EndsWith('/')
    if ($isDirectory) { $path=$path.Substring(0,$path.Length-1) }
    if ([string]::IsNullOrEmpty($path)) { throw ('Unsafe official archive path: '+$EntryPath) }
    $parts=$path.Split('/')
    foreach ($part in $parts) {
        if ([string]::IsNullOrEmpty($part) -or $part -ceq '.' -or $part -ceq '..') { throw ('Unsafe official archive path: '+$EntryPath) }
    }
    $binaryParts=([string]$Asset.Binary).Split('/')
    if ($binaryParts.Count -gt 1) {
        $root=$binaryParts[0]
        if ($path -cne $root -and -not $path.StartsWith($root+'/',[StringComparison]::Ordinal)) { throw ('Unexpected top-level path in official archive: '+$EntryPath) }
    }
    elseif ($parts.Count -ne 1) { throw ('Unexpected nested path in official archive: '+$EntryPath) }
    return $path
}

function Get-OpenWrtOfficialTreeRecords {
    param([Parameter(Mandatory)][string]$Path)
    $root=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $files=@(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction Stop)
    $records=New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse file in core tree: '+$file.FullName) }
        $relative=$file.FullName.Substring($root.Length).TrimStart('\') -replace '\\','/'
        $records.Add(($relative+'|'+[string]$file.Length+'|'+(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash))
    }
    $array=$records.ToArray()
    [Array]::Sort($array,[StringComparer]::OrdinalIgnoreCase)
    return ,$array
}

function Expand-OpenWrtOfficialAsset {
    param([Parameter(Mandatory)]$Asset,[Parameter(Mandatory)][string]$Archive,[Parameter(Mandatory)][string]$Stage)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Assert-OpenWrtCorePathHasNoReparseAncestors -Path $Stage
    [IO.Directory]::CreateDirectory($Stage) | Out-Null
    if ([string]$Asset.Name -match '\.zip$') {
        $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
        try {
            $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $zip.Entries) {
                $relative=ConvertTo-OpenWrtOfficialArchivePath -EntryPath ([string]$entry.FullName) -Asset $Asset
                if (-not $seen.Add($relative)) { throw ('Duplicate path in official ZIP: '+$entry.FullName) }
                $mode=([int64]$entry.ExternalAttributes -shr 16) -band 0xF000
                $isDirectory=[string]$entry.FullName -like '*/'
                if ($mode -eq 0xA000 -or ($mode -ne 0 -and $mode -ne 0x8000 -and $mode -ne 0x4000)) { throw ('Non-regular ZIP member rejected: '+$entry.FullName) }
                if ($isDirectory -or $mode -eq 0x4000) {
                    $directory=Join-Path $Stage ($relative -replace '/', '\')
                    [IO.Directory]::CreateDirectory($directory) | Out-Null
                }
                else {
                    $destination=Join-Path $Stage ($relative -replace '/', '\')
                    $parent=Split-Path -Parent $destination
                    [IO.Directory]::CreateDirectory($parent) | Out-Null
                    if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { throw ('Conflicting ZIP destination: '+$destination) }
                    $inputStream=$null
                    $outputStream=$null
                    try {
                        $inputStream=$entry.Open()
                        $outputStream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                        $inputStream.CopyTo($outputStream)
                    }
                    finally {
                        if ($outputStream) { $outputStream.Dispose() }
                        if ($inputStream) { $inputStream.Dispose() }
                    }
                }
            }
        }
        finally { $zip.Dispose() }
    }
    else {
        $members=@(& tar.exe -tzf $Archive)
        if ($LASTEXITCODE -ne 0 -or $members.Count -eq 0) { throw 'Unable to read approved tar archive member list.' }
        $verbose=@(& tar.exe -tvzf $Archive)
        if ($LASTEXITCODE -ne 0 -or $verbose.Count -ne $members.Count) { throw 'Unable to verify approved tar archive member types.' }
        for ($i=0; $i -lt $members.Count; $i++) {
            $null=ConvertTo-OpenWrtOfficialArchivePath -EntryPath ([string]$members[$i]) -Asset $Asset
            $line=[string]$verbose[$i]
            if ($line.Length -lt 1 -or ($line[0] -ne '-' -and $line[0] -ne 'd')) { throw ('Non-regular tar member rejected: '+$members[$i]) }
        }
        & tar.exe -xzf $Archive -C $Stage
        if ($LASTEXITCODE -ne 0) { throw 'Official release extraction failed.' }
    }
    Assert-OpenWrtCoreTreeHasNoReparsePoints -Path $Stage
    $binary=Join-Path $Stage ([string]$Asset.Binary -replace '/', '\')
    if (-not [IO.File]::Exists($binary)) { throw ('Missing official binary in extracted asset: '+$Asset.Binary) }
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne [string]$Asset.BinarySHA256) { throw ('Official binary digest mismatch after extraction: '+$Asset.Name) }
}

function Install-OpenWrtBuildCores {
    param(
        [string]$Root=(Join-Path (Split-Path -Parent $PSScriptRoot) 'openwrt/build-stage/cores'),
        [string]$DownloadDirectory,
        [string]$ExtractionDirectory,
        [string[]]$Platforms = @(),
        [switch]$Offline
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $Root=[IO.Path]::GetFullPath($Root)
    if (-not $DownloadDirectory) { $DownloadDirectory=$Root }
    $removeExtractionDirectoryWhenDone=(-not $ExtractionDirectory)
    if (-not $ExtractionDirectory) { $ExtractionDirectory=Join-Path $Root '.extract' }
    $DownloadDirectory=[IO.Path]::GetFullPath($DownloadDirectory)
    $ExtractionDirectory=[IO.Path]::GetFullPath($ExtractionDirectory)
    foreach ($directory in @($Root,$DownloadDirectory,$ExtractionDirectory)) {
        Assert-OpenWrtCorePathHasNoReparseAncestors -Path $directory
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    $assets = @(Get-OpenWrtOfficialAssets)
    foreach ($platform in $Platforms) {
        if ($platform -cnotin $assets.Platform) { throw ('Unknown official core platform: '+$platform) }
    }
    foreach ($asset in $assets) {
        if ($Platforms.Count -and $asset.Platform -cnotin $Platforms) { continue }
        $archive=Join-Path $Root $asset.Name
        if ([IO.Directory]::Exists($archive)) { throw ('Archive path is a directory: '+$archive) }
        if ([IO.File]::Exists($archive)) {
            Assert-OpenWrtCorePathHasNoReparseAncestors -Path $archive
            $candidateArchive=$archive
        }
        else {
            $candidateArchive=Join-Path $DownloadDirectory $asset.Name
            if (-not [IO.File]::Exists($candidateArchive)) {
                if ($Offline) { throw ('Required approved archive is not present in offline download directory: '+$candidateArchive) }
                $download=$candidateArchive+'.download'
                if ([IO.File]::Exists($download) -or [IO.Directory]::Exists($download)) { throw ('Pending download retained; review before retry: '+$download) }
                $url='https://github.com/'+$asset.Repository+'/releases/download/'+$asset.Tag+'/'+$asset.Name
                Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download -TimeoutSec 60
                $downloadFile=Get-Item -LiteralPath $download -Force
                if ($downloadFile.Length -ne [long]$asset.Length -or (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ine $asset.SHA256) { throw ('Official release checksum/length mismatch; candidate retained: '+$download) }
                [IO.File]::Move($download,$candidateArchive)
            }
            Assert-OpenWrtCorePathHasNoReparseAncestors -Path $candidateArchive
        }
        $file=Get-Item -LiteralPath $candidateArchive -Force
        if ($file.Length -ne [long]$asset.Length -or (Get-FileHash -LiteralPath $candidateArchive -Algorithm SHA256).Hash -ine $asset.SHA256) { throw ('Official release checksum/length mismatch; candidate retained: '+$candidateArchive) }
        if ($candidateArchive -cne $archive -and -not [IO.File]::Exists($archive)) {
            $copy=$archive+'.copy-'+[Guid]::NewGuid().ToString('N')
            [IO.File]::Copy($candidateArchive,$copy,$false)
            if ((Get-Item -LiteralPath $copy).Length -ne [long]$asset.Length -or (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ine $asset.SHA256) { throw ('Verified archive copy failed; candidate retained: '+$copy) }
            [IO.File]::Move($copy,$archive)
        }

        $stage=Join-Path $ExtractionDirectory ([string]$asset.Platform+'-'+[Guid]::NewGuid().ToString('N'))
        if ([IO.File]::Exists($stage) -or [IO.Directory]::Exists($stage)) { throw ('Unique extraction stage unexpectedly exists: '+$stage) }
        Expand-OpenWrtOfficialAsset -Asset $asset -Archive $archive -Stage $stage
        $platform=Join-Path $Root $asset.Platform
        $binaryParts=([string]$asset.Binary).Split('/')
        if ($binaryParts.Count -gt 1) {
            $sourceTree=Join-Path $stage $binaryParts[0]
            $targetTree=Join-Path $platform $binaryParts[0]
        }
        else {
            $sourceTree=$stage
            $targetTree=$platform
        }
        if ([IO.Directory]::Exists($platform)) { Assert-OpenWrtCoreTreeHasNoReparsePoints -Path $platform }
        elseif ([IO.File]::Exists($platform)) { throw ('Core platform path is a file: '+$platform) }
        if ([IO.Directory]::Exists($targetTree)) {
            Assert-OpenWrtCoreTreeHasNoReparsePoints -Path $targetTree
            $sourceRecords=Get-OpenWrtOfficialTreeRecords -Path $sourceTree
            $targetRecords=Get-OpenWrtOfficialTreeRecords -Path $targetTree
            if (($sourceRecords -join "`n") -cne ($targetRecords -join "`n")) { throw ('Conflicting versioned core tree retained without overwrite: '+$targetTree) }
        }
        else {
            if ($binaryParts.Count -gt 1) {
                if (-not [IO.Directory]::Exists($platform)) { [IO.Directory]::CreateDirectory($platform) | Out-Null }
                Assert-OpenWrtCorePathHasNoReparseAncestors -Path $platform
            }
            else {
                Assert-OpenWrtCorePathHasNoReparseAncestors -Path (Split-Path -Parent $platform)
            }
            [IO.Directory]::Move($sourceTree,$targetTree)
        }
        $installedBinary=Join-Path $platform ([string]$asset.Binary -replace '/', '\')
        if (-not [IO.File]::Exists($installedBinary) -or (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash -cne [string]$asset.BinarySHA256) { throw ('Installed official binary verification failed: '+$installedBinary) }
        $stageFull=[IO.Path]::GetFullPath($stage).TrimEnd('\')
        $extractFull=[IO.Path]::GetFullPath($ExtractionDirectory).TrimEnd('\')
        if (-not $stageFull.StartsWith($extractFull+'\',[StringComparison]::OrdinalIgnoreCase)) { throw ('Extraction cleanup path escapes its task-owned root: '+$stageFull) }
        if ([IO.Directory]::Exists($stageFull)) {
            Assert-OpenWrtCoreTreeHasNoReparsePoints -Path $stageFull
            Remove-Item -LiteralPath $stageFull -Recurse -Force
        }
    }
    if ($removeExtractionDirectoryWhenDone -and [IO.Directory]::Exists($ExtractionDirectory)) {
        Assert-OpenWrtCoreTreeHasNoReparsePoints -Path $ExtractionDirectory
        if (@(Get-ChildItem -LiteralPath $ExtractionDirectory -Force).Count -eq 0) { Remove-Item -LiteralPath $ExtractionDirectory -Force }
    }
    return (Get-OpenWrtCorePaths -Root $Root)
}
