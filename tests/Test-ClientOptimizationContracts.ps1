[CmdletBinding()]
param(
    [string]$WorkDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $WorkDirectory) { $WorkDirectory = Join-Path $projectRoot ('outputs\tests\client-optimization-contracts\run-' + [guid]::NewGuid().ToString('N')) }
$projectFullPath = [IO.Path]::GetFullPath($projectRoot).TrimEnd([char[]]'\/')
$WorkDirectory = [IO.Path]::GetFullPath($WorkDirectory).TrimEnd([char[]]'\/')
$allowedRoots = @((Join-Path $projectFullPath 'work'), (Join-Path $projectFullPath 'outputs'))
$workDirectoryAllowed = $false
foreach ($allowedRoot in $allowedRoots) {
    $allowedFullPath = [IO.Path]::GetFullPath($allowedRoot).TrimEnd([char[]]'\/')
    if ($WorkDirectory.StartsWith($allowedFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        $workDirectoryAllowed = $true
        break
    }
}
if (-not $workDirectoryAllowed) {
    throw 'Contract-test work directory must be a child of project work/ or outputs/.'
}
$cursor = $WorkDirectory
while ($cursor -and ($cursor.Equals($projectFullPath, [StringComparison]::OrdinalIgnoreCase) -or
    $cursor.StartsWith($projectFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
    if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
        $cursorItem = Get-Item -LiteralPath $cursor -Force
        if ($cursorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Contract-test path contains a reparse point: $cursor" }
    }
    if ($cursor.Equals($projectFullPath, [StringComparison]::OrdinalIgnoreCase)) { break }
    $cursor = Split-Path -Parent $cursor
}
if ([IO.Directory]::Exists($WorkDirectory)) {
    $existingWorkItems = @(Get-ChildItem -LiteralPath $WorkDirectory -Force -Recurse -ErrorAction Stop)
    if (@($existingWorkItems | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
        throw 'Contract-test work directory contains a reparse point.'
    }
}
[IO.Directory]::CreateDirectory($WorkDirectory) | Out-Null

function Assert-Optimization {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

. (Join-Path (Join-Path $projectRoot 'scripts') 'Json-Validation.ps1')
. (Join-Path (Join-Path $projectRoot 'scripts') 'Direct-RoutingPolicy.ps1')
. (Join-Path (Join-Path $projectRoot 'scripts') 'SameTypeDirectPolicy.ps1')
. (Join-Path (Join-Path $projectRoot 'scripts') 'Build-Transaction.ps1')

$generatorPath = Join-Path (Join-Path $projectRoot 'scripts') 'Generate-SingBoxConfig.ps1'
$tokens = $null
$parseErrors = $null
$generatorAst = [Management.Automation.Language.Parser]::ParseFile($generatorPath, [ref]$tokens, [ref]$parseErrors)
Assert-Optimization (@($parseErrors).Count -eq 0) 'Generator source has a PowerShell parse error.'
foreach ($node in $generatorAst.FindAll({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($node.Extent.Text))
}
$updaterPath = Join-Path (Join-Path $projectRoot 'scripts') 'Update-RoutingRules.ps1'
$updaterTokens = $null
$parseErrors = $null
$updaterAst = [Management.Automation.Language.Parser]::ParseFile($updaterPath,[ref]$updaterTokens,[ref]$parseErrors)
Assert-Optimization (@($parseErrors).Count -eq 0) 'Updater source has a PowerShell parse error.'
$resourcePlanFunction = $updaterAst.FindAll({ param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -ceq 'New-ValidatedRemoteResourcePlan' },$false)
Assert-Optimization (@($resourcePlanFunction).Count -eq 1) 'Updater resource-plan validator was not found exactly once.'
. ([scriptblock]::Create($resourcePlanFunction[0].Extent.Text))
$geoResource = [pscustomobject]@{ tag='geo-fixture'; type='remote'; format='geosite-dat'; url='https://example.invalid/geosite.dat' }
$plainResource = [pscustomobject]@{ tag='plain-fixture'; type='remote'; format='plain'; url='https://example.invalid/plain.txt' }
$geoSelectors = @{ 'geo-fixture' = @('category-games@cn','category-social-media-!cn','category-ai-!cn','geolocation-!cn') }
$validatedGeoPlan = @(New-ValidatedRemoteResourcePlan -Resources @($geoResource,$plainResource) -SelectorsByResource $geoSelectors -CacheRoot (Join-Path $WorkDirectory 'resource-plan-cache'))
Assert-Optimization ($validatedGeoPlan.Count -eq 2 -and $validatedGeoPlan[0].Selectors.Count -eq 4 -and $validatedGeoPlan[1].Selectors.Count -eq 0) 'Geo selector syntax or non-Geo empty-selector validation changed.'
Assert-Optimization (@($validatedGeoPlan | Where-Object { $_ -is [array] -or $_.Tag -isnot [string] }).Count -eq 0) 'The two-resource validator returned a nested resource-plan array.'
$duplicateGeoRejected = $false
try { New-ValidatedRemoteResourcePlan -Resources @($geoResource) -SelectorsByResource @{ 'geo-fixture' = @('category-games@cn','category-games@cn') } -CacheRoot (Join-Path $WorkDirectory 'resource-plan-cache') | Out-Null } catch { $duplicateGeoRejected = $true }
Assert-Optimization $duplicateGeoRejected 'Duplicate Geo selectors were not rejected before scheduling.'
$manifestPath = Join-Path $projectRoot 'routing\routing-sources.json'
$manifestDocument = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$manifestSelectors = @{}
foreach ($manifestRule in @($manifestDocument.rules)) {
    foreach ($input in @($manifestRule.inputs)) {
        if (-not $input.PSObject.Properties['resource'] -or -not $input.PSObject.Properties['selector']) { continue }
        $resourceTag = [string]$input.resource
        if (-not $manifestSelectors.ContainsKey($resourceTag)) { $manifestSelectors[$resourceTag] = New-Object 'System.Collections.Generic.List[string]' }
        if (-not $manifestSelectors[$resourceTag].Contains([string]$input.selector)) { $manifestSelectors[$resourceTag].Add([string]$input.selector) }
    }
}
$realResourcePlan = @(New-ValidatedRemoteResourcePlan -Resources @($manifestDocument.resources) -SelectorsByResource $manifestSelectors -CacheRoot (Join-Path $WorkDirectory 'resource-plan-cache'))
Assert-Optimization ($realResourcePlan.Count -eq @($manifestDocument.resources).Count) 'The manifest did not produce one plan item per resource.'
$manifestTags = @($manifestDocument.resources | ForEach-Object tag)
$plannedTags = @($realResourcePlan | ForEach-Object Tag)
Assert-Optimization (($manifestTags -join "`n") -ceq ($plannedTags -join "`n")) 'The resource plan changed the manifest tags or their order.'
Assert-Optimization (@($realResourcePlan | Where-Object { $_ -is [array] -or $_.Tag -isnot [string] }).Count -eq 0) 'The real resource-plan result contains nested arrays or invalid entries.'

$groups = @(
    [pscustomobject]@{ sequence = 1; id = 'proxy-port-first'; action = 'proxy'; rules = @([pscustomobject]@{ port = @(443) }) },
    [pscustomobject]@{ sequence = 2; id = 'effective-direct-ip'; action = 'direct'; rules = @([pscustomobject]@{ ip_cidr = @('192.0.2.0/24') }) },
    [pscustomobject]@{ sequence = 3; id = 'proxy-only-ip'; action = 'proxy'; rules = @([pscustomobject]@{ ip_cidr = @('198.51.100.0/24') }) },
    [pscustomobject]@{ sequence = 4; id = 'blocked-direct-ip'; action = 'direct'; rules = @([pscustomobject]@{ ip_cidr = @('198.51.100.0/24') }) },
    [pscustomobject]@{ sequence = 5; id = 'blocked-direct-port'; action = 'direct'; rules = @([pscustomobject]@{ port = @(443) }) },
    [pscustomobject]@{ sequence = 6; id = 'other-direct-port'; action = 'direct'; rules = @([pscustomobject]@{ port = @(8443) }) },
    [pscustomobject]@{ sequence = 7; id = 'proxy-domain-hole'; action = 'proxy'; rules = @([pscustomobject]@{ domain = @('blocked.example.test') }) },
    [pscustomobject]@{ sequence = 8; id = 'direct-domain-residual'; action = 'direct'; rules = @([pscustomobject]@{ domain = @('Example.test'); domain_suffix = @('example.test') }) },
    [pscustomobject]@{ sequence = 9; id = 'other-direct-source-port'; action = 'direct'; rules = @([pscustomobject]@{ source_port = @(22) }) }
)
$routingDocument = [ordered]@{
    version = 2
    conflict_policy = [pscustomobject]@{ earlier_rule = 'wins'; later_overlap = 'ordered-first-match' }
    groups = $groups
}
$resolvedPlan = Get-SameTypeDirectPlan -Document $routingDocument
Assert-Optimization (Test-BinaryRuleSetPlanShape -Plan $resolvedPlan) 'Same-type compiler output did not pass the cache-shape validator.'
$domainPlanIndex = -1
for ($index = 0; $index -lt $resolvedPlan.Count; $index++) { if ($resolvedPlan[$index].Kind -ceq 'domain') { $domainPlanIndex = $index; break } }
Assert-Optimization ($domainPlanIndex -ge 0 -and @($resolvedPlan[$domainPlanIndex].Rules[0].domain_regex).Count -gt 0) 'Synthetic domain plan must exercise a valid generated positive residual regex.'
$ipPlan = @($resolvedPlan | Where-Object { $_.Kind -eq 'ip' })
Assert-Optimization ($ipPlan.Count -eq 1 -and $ipPlan[0].Rules[0].ip_cidr.Count -eq 1 -and $ipPlan[0].Rules[0].ip_cidr[0] -ceq '192.0.2.0/24') 'Proxy-port or proxy-only IP semantics changed the effective direct IPv4 set.'
$hasExpectedPort = $false
foreach ($portPlan in @($resolvedPlan | Where-Object { $_.Kind -eq 'port' })) {
    if (@($portPlan.Rules[0].port) -contains 8443) { $hasExpectedPort = $true }
}
Assert-Optimization $hasExpectedPort 'Same-type port resolution changed while checking direct IPv4 route exclusion.'
$portFamily = @($resolvedPlan | Where-Object { $_.Kind -eq 'port' })[0]
Assert-Optimization ($portFamily.Rules.Count -eq 2 -and @($portFamily.Rules[1].source_port).Count -eq 1 -and $portFamily.Rules[1].source_port[0] -eq 22) 'The single-value source-port array was lost or rejected by plan-shape validation.'

$templatePath = Join-Path (Join-Path $projectRoot 'config') 'sing-box-core-base.json'
$linuxConfiguration = Copy-JsonValue (Read-JsonFile $templatePath)
$linuxConfiguration.inbounds[0]['auto_redirect'] = $true
Add-BinaryRoutingRules -Configuration $linuxConfiguration -RuleSetPlan $resolvedPlan -ClientName 'linux' -LinuxRouteExcludeAddressSets
Assert-EffectiveDirectConfiguration -Configuration $linuxConfiguration
$excludedTags = @($linuxConfiguration.inbounds[0]['route_exclude_address_set'])
$publishedIpTags = @($linuxConfiguration.route['rule_set'] | Where-Object { [string]$_.tag -match '-ip$' } | ForEach-Object { [string]$_.tag })
Assert-Optimization (($excludedTags -join ',') -ceq ($ipPlan.Tag -join ',')) 'Linux route exclusion must reference only the effective IPv4 direct rule-set tags.'
Assert-Optimization (($excludedTags -join ',') -ceq ($publishedIpTags -join ',')) 'Linux route exclusion and published direct IPv4 sets diverged.'
Assert-Optimization (-not ($excludedTags -match 'proxy-only|routing-proxy')) 'Proxy-only IP policy leaked into route exclusion.'

$defaultConfiguration = Copy-JsonValue (Read-JsonFile $templatePath)
$defaultConfiguration.inbounds[0]['auto_redirect'] = $true
Add-BinaryRoutingRules -Configuration $defaultConfiguration -RuleSetPlan $resolvedPlan -ClientName 'linux'
Assert-Optimization (-not $defaultConfiguration.inbounds[0].Contains('route_exclude_address_set')) 'Linux route exclusion must remain disabled by default.'

$ipPlanIndex = -1
for ($index = 0; $index -lt $resolvedPlan.Count; $index++) { if ($resolvedPlan[$index].Kind -ceq 'ip') { $ipPlanIndex = $index; break } }
Assert-Optimization ($ipPlanIndex -ge 0) 'Synthetic policy must contain an effective IPv4 family.'
$badIpv6Plan = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $resolvedPlan -Depth 100 -Compress)
$badIpv6Plan[$ipPlanIndex].Rules[0].ip_cidr = @('2001:db8::/32')
Assert-Optimization (-not (Test-BinaryRuleSetPlanShape -Plan @($badIpv6Plan))) 'An IPv6 predicate was accepted in the effective IPv4 plan.'
$badArrayPlan = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $resolvedPlan -Depth 100 -Compress)
$badArrayPlan[$ipPlanIndex].Rules[0].ip_cidr = '192.0.2.0/24'
Assert-Optimization (-not (Test-BinaryRuleSetPlanShape -Plan @($badArrayPlan))) 'A scalar IP cache value was accepted in place of the required array.'
$portPlanIndex = -1
for ($index = 0; $index -lt $resolvedPlan.Count; $index++) { if ($resolvedPlan[$index].Kind -ceq 'port') { $portPlanIndex = $index; break } }
Assert-Optimization ($portPlanIndex -ge 0) 'Synthetic policy must contain an effective port family.'
$badSourcePortArrayPlan = ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $resolvedPlan -Depth 100 -Compress)
$badSourcePortArrayPlan[$portPlanIndex].Rules[1].source_port = 22
Assert-Optimization (-not (Test-BinaryRuleSetPlanShape -Plan @($badSourcePortArrayPlan))) 'A scalar source_port cache value was accepted in place of its required array.'

$cachePath = Join-Path $WorkDirectory 'same-type-plan-cache.json'
$rulesPath = Join-Path $WorkDirectory 'synthetic-merged-rules.json'
Write-JsonAtomically -Configuration $routingDocument -Destination $rulesPath -Overwrite
$cachedPlan = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
Assert-Optimization (Test-BinaryRuleSetPlanShape -Plan $cachedPlan) 'Fresh plan cache could not be built.'
foreach ($badVersion in @($true, '2', 2.5)) {
    $mutated = Read-JsonFile $cachePath
    $mutated.version = $badVersion
    $mutatedText = ConvertTo-Json -InputObject $mutated -Depth 100
    [IO.File]::WriteAllText($cachePath, $mutatedText, [Text.UTF8Encoding]::new($false))
    $rebuilt = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
    $reloaded = Read-JsonFile $cachePath
    Assert-Optimization ((Test-UnsignedInteger $reloaded.version -Minimum 2 -Maximum 2) -and (Test-BinaryRuleSetPlanShape -Plan $rebuilt)) 'A malformed plan-cache envelope version was trusted.'
}

$mutated = Read-JsonFile $cachePath
$mutated.plan[$ipPlanIndex].Rules[0].ip_cidr = @('2001:db8::/32')
$mutatedPlanJson = ConvertTo-Json -InputObject @($mutated.plan) -Depth 100 -Compress
$mutated.plan_sha256 = Get-TextSha256 $mutatedPlanJson
[IO.File]::WriteAllText($cachePath, (ConvertTo-Json -InputObject $mutated -Depth 100), [Text.UTF8Encoding]::new($false))
$rebuilt = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
$rebuiltIp = @($rebuilt | Where-Object { $_.Kind -ceq 'ip' })
Assert-Optimization ((Test-BinaryRuleSetPlanShape -Plan $rebuilt) -and $rebuiltIp.Count -eq 1 -and $rebuiltIp[0].Rules[0].ip_cidr[0] -ceq '192.0.2.0/24') 'A checksum-valid but structurally invalid cached plan was reused.'
$mutated = Read-JsonFile $cachePath
$mutated.plan[$portPlanIndex].Rules[1].source_port = 22
$mutatedPlanJson = ConvertTo-Json -InputObject @($mutated.plan) -Depth 100 -Compress
$mutated.plan_sha256 = Get-TextSha256 $mutatedPlanJson
[IO.File]::WriteAllText($cachePath,(ConvertTo-Json -InputObject $mutated -Depth 100),[Text.UTF8Encoding]::new($false))
$rebuilt = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
$rebuiltPort = @($rebuilt | Where-Object { $_.Kind -ceq 'port' })
Assert-Optimization ((Test-BinaryRuleSetPlanShape -Plan $rebuilt) -and $rebuiltPort.Count -eq 1 -and @($rebuiltPort[0].Rules[1].source_port).Count -eq 1 -and $rebuiltPort[0].Rules[1].source_port[0] -eq 22) 'A checksum-valid scalar source_port cache entry was reused instead of rebuilding the valid single-value array.'
$mutated = Read-JsonFile $cachePath
$mutatedDomainRule = $mutated.plan[$domainPlanIndex].Rules[0]
if ($mutatedDomainRule -is [System.Collections.IDictionary]) {
    if ($mutatedDomainRule.Contains('domain')) { $mutatedDomainRule['domain'] = @('bad*.example') }
    else { $mutatedDomainRule['domain_suffix'] = @('bad*.example') }
}
elseif ($null -ne $mutatedDomainRule.PSObject.Properties['domain']) { $mutatedDomainRule.domain = @('bad*.example') }
else { $mutatedDomainRule.domain_suffix = @('bad*.example') }
$mutatedPlanJson = ConvertTo-Json -InputObject @($mutated.plan) -Depth 100 -Compress
$mutated.plan_sha256 = Get-TextSha256 $mutatedPlanJson
[IO.File]::WriteAllText($cachePath,(ConvertTo-Json -InputObject $mutated -Depth 100),[Text.UTF8Encoding]::new($false))
$rebuilt = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
$rebuiltDomain = @($rebuilt | Where-Object { $_.Kind -ceq 'domain' })
Assert-Optimization ($rebuiltDomain.Count -eq 1 -and $rebuiltDomain[0].Rules[0].domain[0] -ceq 'example.test' -and (Test-BinaryRuleSetPlanShape -Plan $rebuilt)) 'A checksum-valid bad exact/suffix value was reused instead of rebuilding the plan.'
$mutated = Read-JsonFile $cachePath
$mutated.plan[$domainPlanIndex].Rules[0].domain_regex = @('(?i)^(?:example$')
$mutatedPlanJson = ConvertTo-Json -InputObject @($mutated.plan) -Depth 100 -Compress
$mutated.plan_sha256 = Get-TextSha256 $mutatedPlanJson
[IO.File]::WriteAllText($cachePath,(ConvertTo-Json -InputObject $mutated -Depth 100),[Text.UTF8Encoding]::new($false))
$rebuilt = @(Get-BinaryRuleSetPlan -RulesPath $rulesPath -CachePath $cachePath -RoutingDocument $routingDocument)
$rebuiltDomain = @($rebuilt | Where-Object { $_.Kind -ceq 'domain' })
Assert-Optimization ($rebuiltDomain.Count -eq 1 -and [SingBoxSameType.DomainCompiler]::IsGeneratedPositiveRegex([string]$rebuiltDomain[0].Rules[0].domain_regex[0]) -and (Test-BinaryRuleSetPlanShape -Plan $rebuilt)) 'A checksum-valid malformed regex was reused instead of rebuilding the plan.'

$guardOutput = Join-Path $WorkDirectory 'guard-output'
$guardSupport = Join-Path $WorkDirectory 'guard-support'
$guardBuildPaths = Get-BuildPaths $guardOutput
[IO.Directory]::CreateDirectory($guardSupport) | Out-Null
$cacheEntry = Join-Path $guardSupport 'same-type-plan-cache.json'
[IO.Directory]::CreateDirectory($cacheEntry) | Out-Null
$directoryRejected = $false
try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $guardOutput -SupportDirectory $guardSupport -BuildPaths $guardBuildPaths } catch { $directoryRejected = $true }
Assert-Optimization $directoryRejected 'Plan-cache path occupied by a directory was accepted.'
[IO.Directory]::Delete($cacheEntry)
$externalCacheTarget = Join-Path $WorkDirectory 'plan-cache-link-target.json'
[IO.File]::WriteAllText($externalCacheTarget, 'sentinel', [Text.UTF8Encoding]::new($false))
$linkCreated = $false
try {
    New-Item -ItemType SymbolicLink -Path $cacheEntry -Target $externalCacheTarget -ErrorAction Stop | Out-Null
    $linkCreated = $true
}
catch { Write-Warning "Skipping plan-cache reparse-link case; symbolic-link creation is unavailable: $($_.Exception.Message)" }
if ($linkCreated) {
    try {
        $linkRejected = $false
        try { Assert-ClientBuildDirectories -ProjectRoot $projectRoot -OutputDirectory $guardOutput -SupportDirectory $guardSupport -BuildPaths $guardBuildPaths } catch { $linkRejected = $true }
        Assert-Optimization $linkRejected 'Plan-cache reparse-point path was accepted.'
    }
    finally { [IO.File]::Delete($cacheEntry) }
    Assert-Optimization ([IO.File]::ReadAllText($externalCacheTarget) -ceq 'sentinel') 'Removing the plan-cache link changed its target.'
}

Write-Output 'Client optimization contracts passed: strict plan-cache envelope/shape, support-path guarding, grouped and legacy DNS policy, and Linux effective IPv4 exclusion semantics.'
