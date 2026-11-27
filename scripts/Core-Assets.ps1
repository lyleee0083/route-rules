function Get-SingBoxBuildAsset {
    [pscustomobject]@{
        Repository = 'lyleee0083/xiaomi-be7000-singbox'
        Tag = 'sing-box-xiaomi-be7000-0.0.2'
        Commit = '273a764394fb3db315b009d18f19c8046ee4ad76'
        Name = 'sing-box-xiaomi-be7000-0.0.2'
        SHA256 = 'CC9F1AD0590E415016A68258385D773C4FC39339D9A9A69A8184891210CB2785'
        Length = 86155736
    }
}

function Assert-BuildCoreAsset {
    param([Parameter(Mandatory)]$Asset,[Parameter(Mandatory)][string]$Path)
    $path = Assert-ClientPlainPathTree -Path $Path -LeafType File -Required
    $file = Get-Item -LiteralPath $path
    if ($file.Length -ne $Asset.Length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Asset.SHA256) {
        throw ('Build core digest or length mismatch: '+$Asset.Name)
    }
}

function Install-BuildCoreAsset {
    param(
        [Parameter(Mandatory)]$Asset,
        [string]$Root=(Join-Path (Split-Path -Parent $PSScriptRoot) 'openwrt/build-stage/cores')
    )
    if ($Asset.Name -cnotmatch '^[A-Za-z0-9.-]+$' -or $Asset.Tag -cnotmatch '^[A-Za-z0-9.-]+$') {
        throw 'Invalid build core release identifier.'
    }
    . (Join-Path $PSScriptRoot 'Json-Validation.ps1')
    $null = Assert-ClientPlainPathTree -Path $Root -LeafType Directory
    [void][IO.Directory]::CreateDirectory($Root)
    $binary = Join-Path $Root $Asset.Name
    $null = Assert-ClientPlainPathTree -Path $binary -LeafType File
    if (-not [IO.File]::Exists($binary)) {
        $download = $binary+'.download-'+[Guid]::NewGuid().ToString('N')
        $null = Assert-ClientPlainPathTree -Path $download -LeafType File
        $url = 'https://github.com/'+$Asset.Repository+'/releases/download/'+$Asset.Tag+'/'+$Asset.Name
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download -TimeoutSec 180
        Assert-BuildCoreAsset -Asset $Asset -Path $download
        [IO.File]::Move($download,$binary)
    }
    Assert-BuildCoreAsset -Asset $Asset -Path $binary
    & chmod u+x -- $binary
    if ($LASTEXITCODE -ne 0) { throw ('Cannot set build core executable mode: '+$Asset.Name) }
    return $binary
}
