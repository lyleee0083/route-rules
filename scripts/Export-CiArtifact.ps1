[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('clients','xiaomi-be7000')][string]$Component,
    [Parameter(Mandatory)][string]$PackagePath,
    [string]$BuildManifestPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = [IO.File]::ReadAllText((Join-Path $root 'VERSION')).Trim()
if ($version -cnotmatch '^\d+\.\d+\.\d+$' -or $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or
    $env:GITHUB_RUN_ID -notmatch '^\d+$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^\d+$' -or -not $env:GITHUB_OUTPUT) {
    throw 'Valid version and GitHub Actions build identity are required.'
}
if (($Component -eq 'xiaomi-be7000') -ne [bool]$BuildManifestPath) {
    throw 'The BE7000 build must provide its package manifest.'
}

$name = "route-rules-$version"
$artifactRoot = Join-Path $root "outputs/ci-artifacts/$name"
$packageName = "$name.zip"
$package = Join-Path $artifactRoot $packageName
[void][IO.Directory]::CreateDirectory($artifactRoot)
Copy-Item -LiteralPath $PackagePath -Destination $package
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $package).Hash.ToLowerInvariant()
if ($hash -ine (Get-FileHash -Algorithm SHA256 -LiteralPath $PackagePath).Hash) {
    throw 'Artifact ZIP does not match the validated package.'
}

$orchestration = Get-Content -LiteralPath (Join-Path $root 'routing/routing-sources.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$report = (Get-Content -LiteralPath (Join-Path $root 'routing/merged/merged-rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json).report
$inputs = foreach ($source in $orchestration.resources) {
    $sourceStats = @($report.resources | Where-Object Tag -CEQ $source.tag)
    if ($sourceStats.Count -ne 1 -or $sourceStats[0].Sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw ('Missing build source evidence for '+$source.tag)
    }
    [ordered]@{ tag = $source.tag; format = $source.format; url = $source.url; sha256 = $sourceStats[0].Sha256.ToLowerInvariant() }
}
$metadata = [ordered]@{
    version = $version
    component = $Component
    commit = $env:GITHUB_SHA
    run_id = $env:GITHUB_RUN_ID
    run_attempt = $env:GITHUB_RUN_ATTEMPT
    file = $packageName
    sha256 = $hash
    proxy_configuration = 'example-placeholders'
    sources = @($inputs)
}
if ($BuildManifestPath) {
    $native = Get-Content -LiteralPath $BuildManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($native.package_sha256 -ine $hash) { throw 'BE7000 manifest digest does not match the packaged ZIP.' }
    $metadata.build = $native
}
else {
    . (Join-Path $PSScriptRoot 'Core-Assets.ps1')
    $metadata.checker = Get-SingBoxBuildAsset
}

$encoding = New-Object Text.UTF8Encoding($false)
$evidenceRoot = Join-Path $root "outputs/ci-build-info/$name"
[void][IO.Directory]::CreateDirectory($evidenceRoot)
$manifestPath = Join-Path $evidenceRoot 'build-info.json'
[IO.File]::WriteAllText($manifestPath, (($metadata | ConvertTo-Json -Depth 30) + "`n"), $encoding)
[IO.File]::WriteAllText((Join-Path $artifactRoot 'SHA256SUMS.txt'), "$hash  $packageName`n", $encoding)
[IO.File]::AppendAllText($env:GITHUB_OUTPUT, "name=$name`npath=$artifactRoot`nevidence_path=$manifestPath`n", $encoding)
