[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$scriptsRoot = Join-Path $projectRoot 'scripts'
$configRoot = Join-Path $projectRoot 'config'
$sourceRoot = Join-Path $projectRoot 'src'
. (Join-Path $scriptsRoot 'Config-Archive.ps1')
. (Join-Path $scriptsRoot 'SingBox-Checker.ps1')
$resolvedSingBox = Resolve-PinnedSingBoxChecker -ProjectRoot $projectRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('sing-box-zip-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
function Assert-ZipTest { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Write-ZipFixture { param([string]$Path, [string]$Text) [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null; [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false)) }
function Get-FixtureManifest {
    param([string]$Directory,[string[]]$Names)
    $files=Get-ConfigArchiveFiles $Directory $Names
    $manifest=@{}
    foreach ($name in $files.Keys) { $manifest[$name]=@{Length=(Get-Item -LiteralPath $files[$name]).Length;Hash=(Get-FileHash -LiteralPath $files[$name] -Algorithm SHA256).Hash} }
    return $manifest
}
try {
    $fixture=Join-Path $testRoot 'fixture'
    $config='{"route":{"rule_set":[{"type":"local","format":"binary","path":"rule-set/test.srs"}]}}'
    foreach ($name in @('one.json','two.json')) { Write-ZipFixture (Join-Path $fixture $name) $config }
    Write-ZipFixture (Join-Path $fixture 'rule-set/test.srs') 'binary-fixture'
    Write-ZipFixture (Join-Path $fixture 'build-cache.json') '{}'
    Write-ZipFixture (Join-Path $fixture 'old.zip') 'not-for-delivery'
    $result=New-ConfigArchive $fixture @('one.json','two.json')
    Assert-ZipTest ($result.Files -eq 3) 'ZIP included unrelated files or omitted a shared dependency.'
    $manifest=Get-FixtureManifest $fixture @('one.json','two.json')
    $zipPath=Join-Path $fixture 'sing-box-configs.zip'
    Assert-ConfigArchive $zipPath $manifest
    foreach ($mode in @('corrupt','missing','duplicate','case-mismatch')) {
        $null=New-ConfigArchive $fixture @('one.json','two.json')
        $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Update)
        try {
            if ($mode -eq 'missing') { $zip.GetEntry('one.json').Delete() }
            elseif ($mode -eq 'duplicate') { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $fixture 'one.json'),'one.json') }
            elseif ($mode -eq 'case-mismatch') {
                $zip.GetEntry('one.json').Delete()
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $fixture 'one.json'),'One.json')
            }
            else { $stream=$zip.GetEntry('rule-set/test.srs').Open(); try {$stream.WriteByte(88)} finally {$stream.Dispose()} }
        }
        finally { $zip.Dispose() }
        $failed=$false
        try { Assert-ConfigArchive $zipPath $manifest } catch {$failed=$true}
        Assert-ZipTest $failed "ZIP $mode was accepted."
    }
    $result=New-ConfigArchive $fixture @('one.json')
    Assert-ZipTest ($result.Files -eq 2) 'Single-client ZIP included another client.'
    Write-ZipFixture (Join-Path $fixture 'one.json') ($config.Replace('rule-set/test.srs','rule-set/../test.srs'))
    $failed=$false
    try {$null=New-ConfigArchive $fixture @('one.json')} catch {$failed=$true}
    Assert-ZipTest $failed 'ZIP accepted directory traversal.'

    # Exercise the actual generator, including a ZIP verification failure before publication.
    $generator=Join-Path $scriptsRoot 'Generate-SingBoxConfig.ps1'
    $template=Join-Path $configRoot 'sing-box-core-base.json'
    $profiles=Join-Path $configRoot 'client-profiles.json'
    $output=Join-Path $testRoot 'output'
    $support=Join-Path $testRoot 'support-cache'
    Write-ZipFixture (Join-Path $support 'build-cache.json') '{"sentinel":"keep-existing-cache"}'
    & $generator -Client android -SkipRoutingRules -TemplatePath $template -ProfilesPath $profiles -OutputDirectory $output -SupportDirectory $support -SingBoxPath $resolvedSingBox | Out-Null
    Assert-ZipTest ((@(Get-ChildItem -LiteralPath $output -Force | ForEach-Object Name) -join ',') -eq 'sing-box-configs.zip') 'Generator output contains files other than the final ZIP.'
    $originalFiles=@{}
    foreach ($file in Get-ChildItem -LiteralPath $output -Recurse -File) { $originalFiles[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
    $originalCacheHash=Get-FileHash -LiteralPath (Join-Path $support 'build-cache.json') -Algorithm SHA256
    $copyRoot=Join-Path $testRoot 'faulty-generator'
    $copyScripts=Join-Path $copyRoot 'scripts'
    $copyConfig=Join-Path $copyRoot 'config'
    $copySource=Join-Path $copyRoot 'src'
    $copyOpenWrtScripts=Join-Path $copyRoot 'scripts'
    foreach ($directory in @($copyScripts,$copyConfig,$copySource,$copyOpenWrtScripts)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
    foreach ($name in @('Generate-SingBoxConfig.ps1','Build-Transaction.ps1','Json-Validation.ps1','Direct-RoutingPolicy.ps1','SameTypeDirectPolicy.ps1','DNS-BootstrapPolicy.ps1','Node-DnsPolicy.ps1','Config-Archive.ps1','SingBox-Checker.ps1')) { Copy-Item -LiteralPath (Join-Path $scriptsRoot $name) -Destination $copyScripts }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'scripts\Core-Assets.ps1') -Destination $copyOpenWrtScripts
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'SameTypeDirectCompiler.cs') -Destination $copySource
    Copy-Item -LiteralPath $template -Destination $copyConfig
    Copy-Item -LiteralPath $profiles -Destination $copyConfig
    $copyTemplate=Join-Path $copyConfig 'sing-box-core-base.json'
    $copyProfiles=Join-Path $copyConfig 'client-profiles.json'
    $helper=[IO.File]::ReadAllText((Join-Path $scriptsRoot 'Config-Archive.ps1'))
    $helper=$helper.Replace('    Assert-ConfigArchive -ArchivePath $archivePath -Manifest $manifest', "    throw 'Injected ZIP verification failure'")
    Write-ZipFixture (Join-Path $copyScripts 'Config-Archive.ps1') $helper
    $failed=$false
    $failureMessage=''
    try { & (Join-Path $copyScripts 'Generate-SingBoxConfig.ps1') -Client android -SkipRoutingRules -Force -TemplatePath $copyTemplate -ProfilesPath $copyProfiles -OutputDirectory $output -SupportDirectory $support -SingBoxPath $resolvedSingBox | Out-Null }
    catch { $failureMessage=$_.Exception.Message; $failed=$failureMessage -match 'Injected ZIP verification failure' }
    Assert-ZipTest $failed ('Generator did not surface ZIP verification failure. Actual error: ' + $failureMessage)
    foreach ($path in $originalFiles.Keys) { Assert-ZipTest ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $originalFiles[$path]) 'ZIP failure modified a published output.' }
    Assert-ZipTest ((Get-FileHash -LiteralPath (Join-Path $support 'build-cache.json') -Algorithm SHA256).Hash -ceq $originalCacheHash.Hash) 'ZIP failure modified the previous compile cache.'
    Assert-ZipTest (-not (Test-Path -LiteralPath "$output.build-stage")) 'ZIP failure left staging files.'
    $emptyOutput=Join-Path $copyRoot 'generated'
    & (Join-Path $copyScripts 'Generate-SingBoxConfig.ps1') -ListClients -ProfilesPath $copyProfiles | Out-Null
    Assert-ZipTest (-not (Test-Path -LiteralPath $emptyOutput)) 'List-only operation created output.'
    Write-Host 'ZIP tests passed: whitelist, hashes, missing/duplicate/corrupt entries, traversal, single-client selection, and transactional failure protection.'
}
finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    if ((Split-Path -Parent $resolved) -ne ([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) -or (Split-Path -Leaf $resolved) -notlike 'sing-box-zip-test-*') { throw 'Unsafe ZIP test cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
