[CmdletBinding()]
param([string]$SingBoxPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$openWrtRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path (Join-Path (Split-Path -Parent $openWrtRoot) 'scripts') 'Official-Cores.ps1')
. (Join-Path (Join-Path $openWrtRoot 'scripts') 'OpenWrt-Build.ps1')
. (Join-Path (Join-Path $openWrtRoot 'scripts') 'OpenWrt-AdapterCache.ps1')
. (Join-Path (Join-Path $openWrtRoot 'scripts') 'Mosdns-Policy.ps1')
if (-not $SingBoxPath) { $SingBoxPath=(Get-OpenWrtCorePaths)['sing-box-check'] }
if (-not (Test-Path -LiteralPath $SingBoxPath -PathType Leaf)) { throw 'Official sing-box cache fingerprint dependency is missing.' }
if ([string]::IsNullOrWhiteSpace($env:TEMP)) { throw 'TEMP must point to the current task temporary directory.' }
$fixtureRoot=Join-Path ([IO.Path]::GetFullPath($env:TEMP)) ('owpc-'+[guid]::NewGuid().ToString('N'))
$resolvedRoot=[IO.Path]::GetFullPath($fixtureRoot)
$tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
if ((Split-Path -Parent $resolvedRoot).TrimEnd('\') -ine $tempRoot -or (Split-Path -Leaf $resolvedRoot) -notmatch '^owpc-[0-9a-f]{32}$') { throw 'Unsafe adapter cache test fixture path.' }
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
function Assert-CacheTest { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-CacheFixtureTree {
    param([string]$Root)
    $stack=New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push([IO.Path]::GetFullPath($Root))
    while ($stack.Count) {
        $directory=$stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Cache test cleanup found a reparse point: '+$item.FullName) }
            if ($item.PSIsContainer) { $stack.Push($item.FullName) }
        }
    }
}
function Find-CachePolicyLeaf {
    param([AllowNull()]$Schema,[string[]]$Path=@(),[int]$MinimumDepth=1,[ValidateSet('any','string','integer','double','bool')][string]$TypeName='any')
    if ($Schema -is [System.Collections.IDictionary]) {
        foreach ($name in [string[]]@($Schema.Keys | ForEach-Object { [string]$_ })) {
            $found=Find-CachePolicyLeaf -Schema $Schema[$name] -Path (@($Path)+@($name)) -MinimumDepth $MinimumDepth -TypeName $TypeName
            if ($null -ne $found) { return $found }
        }
        return $null
    }
    $matchesType=($TypeName -ceq 'any') -or ($TypeName -ceq 'string' -and $Schema -is [string]) -or ($TypeName -ceq 'bool' -and $Schema -is [bool]) -or ($TypeName -ceq 'integer' -and (Test-OpenWrtAdapterCacheInteger -Value $Schema -AllowZero)) -or ($TypeName -ceq 'double' -and $Schema -is [double])
    if ($Path.Count -ge $MinimumDepth -and $matchesType) {
        return [pscustomobject]@{Path=[string[]]$Path;Value=$Schema}
    }
    return $null
}
function Get-CachePolicyPathParent {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string[]]$Path)
    $target=$Policy
    for($pathIndex=0;$pathIndex -lt ($Path.Count-1);$pathIndex++) {
        $property=$target.PSObject.Properties[$Path[$pathIndex]]
        if (-not $property) { throw 'Policy fixture path is missing.' }
        $target=$property.Value
    }
    return $target
}
function Set-CachePolicyLeafValue {
    param([Parameter(Mandatory)]$Policy,[Parameter(Mandatory)][string[]]$Path,[Parameter(Mandatory)][AllowNull()]$Value)
    $target=Get-CachePolicyPathParent -Policy $Policy -Path $Path
    $lastName=$Path[-1]
    if ($target -is [System.Collections.IDictionary]) { $target[$lastName]=$Value }
    else {
        $property=$target.PSObject.Properties[$lastName]
        if (-not $property) { throw 'Policy fixture field is missing.' }
        $property.Value=$Value
    }
}
try {
    $adapterCacheSourceText=[IO.File]::ReadAllText((Join-Path (Join-Path $openWrtRoot 'scripts') 'OpenWrt-AdapterCache.ps1'))
    $converterListStart=$adapterCacheSourceText.IndexOf('$converterPaths = @(',[StringComparison]::Ordinal)
    $converterListEnd=$adapterCacheSourceText.IndexOf('$converterFiles = New-Object',[Math]::Max(0,$converterListStart),[StringComparison]::Ordinal)
    Assert-CacheTest ($converterListStart -ge 0 -and $converterListEnd -gt $converterListStart) 'Could not locate adapter-cache converter dependency list.'
    $converterListText=$adapterCacheSourceText.Substring($converterListStart,$converterListEnd-$converterListStart)
    $nodePolicyDependency="(Join-Path `$projectRoot 'scripts\Node-DnsPolicy.ps1')"
    Assert-CacheTest ($converterListText.Contains($nodePolicyDependency)) 'Node DNS policy helper is missing from adapter-cache fingerprint dependencies.'

    $sourceOne=Join-Path $fixtureRoot 'source-one'
    [IO.Directory]::CreateDirectory((Join-Path $sourceOne 'rule-set')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $sourceOne 'sing-box-openwrt.json'),'{}',(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllBytes((Join-Path $sourceOne 'rule-set/sample.srs'),[byte[]]@(1,2,3,4))
    $fingerprintOne=Get-OpenWrtAdapterCacheFingerprint -SourceRoot $sourceOne -SingBoxPath $SingBoxPath
    [IO.File]::WriteAllBytes((Join-Path $sourceOne 'rule-set/sample.srs'),[byte[]]@(1,2,3,5))
    $fingerprintTwo=Get-OpenWrtAdapterCacheFingerprint -SourceRoot $sourceOne -SingBoxPath $SingBoxPath
    Assert-CacheTest ($fingerprintOne -cne $fingerprintTwo) 'An SRS content change did not alter the adapter cache fingerprint.'
    $fingerprintCacheMode=Get-OpenWrtAdapterCacheFingerprint -SourceRoot $sourceOne -SingBoxPath $SingBoxPath -ConnectionCacheMode 'ctmark-v1'
    Assert-CacheTest ($fingerprintTwo -cne $fingerprintCacheMode) 'A change from off-v1 to ctmark-v1 did not alter the adapter cache fingerprint.'

    $cacheDirectory=Join-Path $fixtureRoot 'cache'
    $providerPolicy=Get-MosdnsDnsProviderPolicyMetadata
    $cachePayload=[ordered]@{
        version=2
        fingerprint=$fingerprintTwo
        files=[ordered]@{routing_policy_nft="nft-set`n";dns_direct_domains="full:example.test`n";mosdns_yaml="plugins:`n"}
        numeric=[ordered]@{numeric_predicates=1;cidrs=1;ip_intervals=1;destination_intervals=1;source_intervals=1;decompiled_srs_count=1}
        dns_policy=[ordered]@{
            status='written';publication_ready=$true;direct_rule_set_count=1;direct_domain_rule_count=1
            full_count=1;domain_count=0;regexp_count=0
            source_hashes=@(
                [pscustomobject][ordered]@{path='sing-box-openwrt.json';sha256=('a'*64)},
                [pscustomobject][ordered]@{tag='routing-direct-domain';sha256=('b'*64);predicates=1}
            )
            node_ttl_policy='isolated test metadata'
            dns_provider_policy=$providerPolicy
        }
    }
    $coldOutput=Join-Path $fixtureRoot 'cold-output'
    [IO.Directory]::CreateDirectory($coldOutput) | Out-Null
    [IO.File]::WriteAllText((Join-Path $coldOutput 'routing-policy.nft'),$cachePayload.files.routing_policy_nft,(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $coldOutput 'dns-direct-domains.txt'),$cachePayload.files.dns_direct_domains,(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $coldOutput 'mosdns.yaml'),$cachePayload.files.mosdns_yaml,(New-Object Text.UTF8Encoding($false)))
    $coldDnsPolicy=[pscustomobject][ordered]@{
        status='written';publication_ready=$true
        paths=[pscustomobject][ordered]@{dns_direct_domains=(Join-Path $coldOutput 'dns-direct-domains.txt');mosdns_yaml=(Join-Path $coldOutput 'mosdns.yaml')}
        direct_rule_set_count=1;direct_domain_rule_count=1;full_count=1;domain_count=0;regexp_count=0
        node_ttl_policy='isolated test metadata'
        dns_provider_policy=$providerPolicy
        source_hashes=@($cachePayload.dns_policy.source_hashes)
    }
    $coldNumeric=[pscustomobject][ordered]@{numeric_predicates=1;cidrs=1;ip_intervals=1;destination_intervals=1;source_intervals=1;decompiled_srs_count=1}
    $cachePayload=New-OpenWrtAdapterCachePayload -Fingerprint $fingerprintTwo -PayloadDirectory $coldOutput -Numeric $coldNumeric -DnsPolicy $coldDnsPolicy
    Assert-CacheTest ($cachePayload.version -eq 2 -and (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $cachePayload.dns_policy.dns_provider_policy -Schema $providerPolicy)) 'Cold cache payload did not preserve the source provider-policy schema and types.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $hit=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $hit.Hit 'A valid adapter cache did not hit.'
    $warmOutput=Join-Path $fixtureRoot 'warm-output'
    [IO.Directory]::CreateDirectory($warmOutput) | Out-Null
    $warm=Restore-OpenWrtAdapterCachePayload -Payload $hit.Payload -OutputDirectory $warmOutput
    $coldPropertyNames=[string[]]@($coldDnsPolicy.PSObject.Properties | ForEach-Object { $_.Name })
    $warmPropertyNames=[string[]]@($warm.DnsPolicy.PSObject.Properties | ForEach-Object { $_.Name })
    Assert-CacheTest (($coldPropertyNames -join "`n") -ceq ($warmPropertyNames -join "`n")) 'Warm DNS policy metadata omitted or reordered a cold-writer field.'
    foreach ($propertyName in $coldPropertyNames) {
        if ($propertyName -ceq 'paths') {
            Assert-CacheTest ($warm.DnsPolicy.paths.dns_direct_domains -ceq (Join-Path $warmOutput 'dns-direct-domains.txt') -and $warm.DnsPolicy.paths.mosdns_yaml -ceq (Join-Path $warmOutput 'mosdns.yaml')) 'Warm DNS policy paths do not point to restored outputs.'
        } else {
            $coldValueJson=ConvertTo-Json -InputObject $coldDnsPolicy.PSObject.Properties[$propertyName].Value -Depth 100 -Compress
            $warmValueJson=ConvertTo-Json -InputObject $warm.DnsPolicy.PSObject.Properties[$propertyName].Value -Depth 100 -Compress
            Assert-CacheTest ($coldValueJson -ceq $warmValueJson) ('Warm DNS policy field differs from the cold writer: '+$propertyName)
        }
    }
    Assert-CacheTest (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $warm.DnsPolicy.dns_provider_policy -Schema $providerPolicy) 'Warm DNS provider-policy values or types differ from the source policy.'
    Assert-CacheTest ($warm.DnsPolicy.publication_ready -is [bool] -and $warm.DnsPolicy.source_hashes[1].predicates.GetType().FullName -ceq 'System.Int32') 'Warm DNS metadata lost its boolean or integer source-hash types.'
    $modeMiss=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintCacheMode
    Assert-CacheTest (-not $modeMiss.Hit) 'An off-mode adapter payload was restored for the cache-enabled build mode.'
    Assert-CacheTest (@($hit.Payload.dns_policy.source_hashes).Count -eq 2 -and $hit.Payload.dns_policy.source_hashes[1].tag -ceq 'routing-direct-domain') 'Production-shaped path/tag source hash metadata did not survive a cache hit.'
    $cachePayload.dns_policy.full_count=0
    $cachePayload.dns_policy.domain_count=1
    $cachePayload.dns_policy.regexp_count=0
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $zeroExact=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $zeroExact.Hit 'A valid cache with zero exact-domain rules was rejected.'
    $cachePayload.dns_policy.full_count=0
    $cachePayload.dns_policy.domain_count=0
    $cachePayload.dns_policy.regexp_count=1
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $zeroExactAndSuffix=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $zeroExactAndSuffix.Hit 'A valid regex-only cache with zero exact and suffix rules was rejected.'
    $cachePayload.dns_policy.full_count=1
    $cachePayload.dns_policy.domain_count=0
    $cachePayload.dns_policy.regexp_count=0
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $hit=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $hit.Hit 'A valid full-domain-only cache no longer hit after zero-category cases.'
    $cacheBytes=[IO.File]::ReadAllBytes((Get-OpenWrtAdapterCacheFilePath -CacheDirectory $cacheDirectory))
    $cacheText=[IO.File]::ReadAllText((Get-OpenWrtAdapterCacheFilePath -CacheDirectory $cacheDirectory))
    Assert-CacheTest (-not ($cacheBytes.Length -ge 3 -and $cacheBytes[0] -eq 239 -and $cacheBytes[1] -eq 187 -and $cacheBytes[2] -eq 191)) 'Adapter cache JSON unexpectedly has a UTF-8 BOM.'
    if (-not ($cacheText -match "(?m)^  `"version`": 1,$" -and $cacheText.EndsWith("`n",[StringComparison]::Ordinal) -and $cacheText -notmatch "`r")) {
        $preview=$cacheText.Substring(0,[Math]::Min(120,$cacheText.Length)).Replace("`n",'<LF>').Replace("`r",'<CR>')
        throw ('Adapter cache JSON does not use expanded UTF-8/LF format. Prefix=' + $preview)
    }
    $stale=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintOne
    Assert-CacheTest (-not $stale.Hit -and $stale.Reason -match 'fingerprint') 'A stale fingerprint was accepted.'

    $cacheFile=Get-OpenWrtAdapterCacheFilePath -CacheDirectory $cacheDirectory
    $validCacheText=[IO.File]::ReadAllText($cacheFile)
    $numericRoundTripPayload=ConvertFrom-StrictJson -Text $validCacheText
    $directDoublePath=[string[]]@('maximum_no_answer_wait_seconds','direct')
    $proxyDoublePath=[string[]]@('maximum_no_answer_wait_seconds','proxy')
    Set-CachePolicyLeafValue -Policy $numericRoundTripPayload.payload.dns_policy.dns_provider_policy -Path $directDoublePath -Value ([decimal]5.3)
    Set-CachePolicyLeafValue -Policy $numericRoundTripPayload.payload.dns_policy.dns_provider_policy -Path $proxyDoublePath -Value ([int]7)
    $numericRoundTripProvider=$numericRoundTripPayload.payload.dns_policy.dns_provider_policy
    Assert-CacheTest ($numericRoundTripProvider.maximum_no_answer_wait_seconds.direct -is [decimal] -and $numericRoundTripProvider.maximum_no_answer_wait_seconds.proxy -is [int]) 'Decimal and integral-number cache fixtures were not prepared with their intended input types.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $numericRoundTripPayload.payload
    $numericRoundTripHit=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $numericRoundTripHit.Hit 'Decimal and integral JSON numbers did not round-trip through a double schema leaf.'
    $numericRoundTripOutput=Join-Path $fixtureRoot 'numeric-roundtrip-output'
    [IO.Directory]::CreateDirectory($numericRoundTripOutput) | Out-Null
    $numericRoundTripRestored=Restore-OpenWrtAdapterCachePayload -Payload $numericRoundTripHit.Payload -OutputDirectory $numericRoundTripOutput
    $restoredDirectDouble=$numericRoundTripRestored.DnsPolicy.dns_provider_policy.maximum_no_answer_wait_seconds.direct
    $restoredProxyDouble=$numericRoundTripRestored.DnsPolicy.dns_provider_policy.maximum_no_answer_wait_seconds.proxy
    Assert-CacheTest ($restoredDirectDouble -is [double] -and $restoredProxyDouble -is [double] -and $restoredDirectDouble -eq [double]5.3 -and $restoredProxyDouble -eq [double]7.0) 'Numeric provider-policy leaves did not restore as source-schema doubles.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $nestedPolicyLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -MinimumDepth 2
    if ($null -eq $nestedPolicyLeaf) { $nestedPolicyLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -MinimumDepth 1 }
    Assert-CacheTest ($null -ne $nestedPolicyLeaf) 'Source provider policy has no digestable leaf field.'
    $nestedTamperEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $nestedTamperParent=Get-CachePolicyPathParent -Policy $nestedTamperEnvelope.payload.dns_policy.dns_provider_policy -Path $nestedPolicyLeaf.Path
    $nestedTamperProperty=$nestedTamperParent.PSObject.Properties[$nestedPolicyLeaf.Path[-1]]
    if ($nestedPolicyLeaf.Value -is [string]) { $nestedTamperProperty.Value=$nestedPolicyLeaf.Value+'-changed' }
    elseif ($nestedPolicyLeaf.Value -is [bool]) { $nestedTamperProperty.Value=(-not $nestedPolicyLeaf.Value) }
    elseif (Test-OpenWrtAdapterCacheInteger -Value $nestedPolicyLeaf.Value -AllowZero) { $nestedTamperProperty.Value=([int64]$nestedPolicyLeaf.Value+1) }
    else { $nestedTamperProperty.Value=([double]$nestedPolicyLeaf.Value+0.1) }
    $nestedChangedDigest=Get-OpenWrtAdapterCachePayloadDigest -Payload $nestedTamperEnvelope.payload
    Assert-CacheTest ($nestedChangedDigest -cne $nestedTamperEnvelope.payload_sha256) 'A nested DNS provider-policy field was omitted from the payload digest.'
    [IO.File]::WriteAllText($cacheFile,($nestedTamperEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
    $nestedDigestMiss=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $nestedDigestMiss.Hit -and $nestedDigestMiss.Reason -match 'digest') 'A nested provider-policy edit with the old digest was accepted.'
    $nestedTamperEnvelope.payload_sha256=$nestedChangedDigest
    [IO.File]::WriteAllText($cacheFile,($nestedTamperEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
    $nestedSemanticMiss=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $nestedSemanticMiss.Hit -and $nestedSemanticMiss.Reason -match 'provider policy') 'A changed provider policy with a recomputed digest was accepted.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload

    $missingProviderEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $missingProviderName=[string]@($providerPolicy.Keys | ForEach-Object { [string]$_ })[0]
    [void]$missingProviderEnvelope.payload.dns_policy.dns_provider_policy.PSObject.Properties.Remove($missingProviderName)
    [IO.File]::WriteAllText($cacheFile,($missingProviderEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
    $missingProvider=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $missingProvider.Hit -and $missingProvider.Reason -match 'schema') 'A provider policy with a missing required field was accepted.'

    if ($nestedPolicyLeaf.Path.Count -gt 1) {
        $missingNestedEnvelope=ConvertFrom-StrictJson -Text $validCacheText
        $missingNestedParent=Get-CachePolicyPathParent -Policy $missingNestedEnvelope.payload.dns_policy.dns_provider_policy -Path $nestedPolicyLeaf.Path
        [void]$missingNestedParent.PSObject.Properties.Remove($nestedPolicyLeaf.Path[-1])
        [IO.File]::WriteAllText($cacheFile,($missingNestedEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
        $missingNested=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
        Assert-CacheTest (-not $missingNested.Hit) 'A nested provider policy with a missing required field was accepted.'
    }

    $extraProviderEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $extraProviderEnvelope.payload.dns_policy.dns_provider_policy | Add-Member -NotePropertyName unowned -NotePropertyValue 'unknown'
    [IO.File]::WriteAllText($cacheFile,($extraProviderEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
    $extraProvider=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $extraProvider.Hit -and $extraProvider.Reason -match 'schema') 'A provider policy with an extra field was accepted.'

    if ($nestedPolicyLeaf.Path.Count -gt 1) {
        $extraNestedEnvelope=ConvertFrom-StrictJson -Text $validCacheText
        $extraNestedParent=Get-CachePolicyPathParent -Policy $extraNestedEnvelope.payload.dns_policy.dns_provider_policy -Path $nestedPolicyLeaf.Path
        $extraNestedParent | Add-Member -NotePropertyName unowned -NotePropertyValue 'unknown'
        [IO.File]::WriteAllText($cacheFile,($extraNestedEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
        $extraNested=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
        Assert-CacheTest (-not $extraNested.Hit) 'A nested provider policy with an extra field was accepted.'
    }

    $wrongProviderEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $providerStringLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -TypeName string
    if ($null -ne $providerStringLeaf) {
        $wrongProviderParent=Get-CachePolicyPathParent -Policy $wrongProviderEnvelope.payload.dns_policy.dns_provider_policy -Path $providerStringLeaf.Path
        $wrongProviderParent.PSObject.Properties[$providerStringLeaf.Path[-1]].Value='wrong-provider-order'
        $wrongProviderEnvelope.payload_sha256=Get-OpenWrtAdapterCachePayloadDigest -Payload $wrongProviderEnvelope.payload
        [IO.File]::WriteAllText($cacheFile,($wrongProviderEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
        $wrongProvider=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
        Assert-CacheTest (-not $wrongProvider.Hit -and $wrongProvider.Reason -match 'provider policy') 'A provider-order change with a valid digest was accepted.'
    }

    $wrongDeadlineEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $deadlineLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -TypeName double
    if ($null -eq $deadlineLeaf) { $deadlineLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -TypeName integer }
    if ($null -ne $deadlineLeaf) {
        $deadlineParent=Get-CachePolicyPathParent -Policy $wrongDeadlineEnvelope.payload.dns_policy.dns_provider_policy -Path $deadlineLeaf.Path
        $deadlineProperty=$deadlineParent.PSObject.Properties[$deadlineLeaf.Path[-1]]
        if ($deadlineLeaf.Value -is [double]) { $deadlineProperty.Value=([double]$deadlineLeaf.Value+0.1) }
        else { $deadlineProperty.Value=([int64]$deadlineLeaf.Value+1) }
        $wrongDeadlineEnvelope.payload_sha256=Get-OpenWrtAdapterCachePayloadDigest -Payload $wrongDeadlineEnvelope.payload
        [IO.File]::WriteAllText($cacheFile,($wrongDeadlineEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
        $wrongDeadline=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
        Assert-CacheTest (-not $wrongDeadline.Hit -and $wrongDeadline.Reason -match 'provider policy') 'A timeout change with a valid digest was accepted.'
    }
    $integerPolicyLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -TypeName integer
    if ($null -ne $integerPolicyLeaf) {
        $preTypeFailureHash=(Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash
        $booleanPolicyEnvelope=ConvertFrom-StrictJson -Text $validCacheText
        Set-CachePolicyLeafValue -Policy $booleanPolicyEnvelope.payload.dns_policy.dns_provider_policy -Path $integerPolicyLeaf.Path -Value $true
        $booleanPolicyRejected=$false
        try { Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $booleanPolicyEnvelope.payload }
        catch { $booleanPolicyRejected=$true }
        Assert-CacheTest ($booleanPolicyRejected -and (Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash -ceq $preTypeFailureHash) 'A boolean provider-policy timeout was written or replaced the valid cache.'
        $fractionPolicyEnvelope=ConvertFrom-StrictJson -Text $validCacheText
        Set-CachePolicyLeafValue -Policy $fractionPolicyEnvelope.payload.dns_policy.dns_provider_policy -Path $integerPolicyLeaf.Path -Value ([decimal]1.5)
        $fractionPolicyRejected=$false
        try { Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $fractionPolicyEnvelope.payload }
        catch { $fractionPolicyRejected=$true }
        Assert-CacheTest ($fractionPolicyRejected -and (Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash -ceq $preTypeFailureHash) 'A fractional provider-policy timeout was written or replaced the valid cache.'
    }
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $doublePolicyLeaf=Find-CachePolicyLeaf -Schema $providerPolicy -TypeName double
    if ($null -ne $doublePolicyLeaf) {
        $preDoubleFailureHash=(Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash
        $invalidDoubleValues=[object[]]@([bool]$true,[string]'5.3',[double]::NaN,[double]::PositiveInfinity,[double]::NegativeInfinity)
        foreach ($invalidDoubleValue in $invalidDoubleValues) {
            $invalidDoubleEnvelope=ConvertFrom-StrictJson -Text $validCacheText
            Set-CachePolicyLeafValue -Policy $invalidDoubleEnvelope.payload.dns_policy.dns_provider_policy -Path $doublePolicyLeaf.Path -Value $invalidDoubleValue
            $invalidDoubleRejected=$false
            try { Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $invalidDoubleEnvelope.payload }
            catch { $invalidDoubleRejected=$true }
            Assert-CacheTest ($invalidDoubleRejected -and (Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash -ceq $preDoubleFailureHash) 'A non-finite or nonnumeric provider-policy double replaced the valid cache.'
        }
    }
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload

    $oldSchemaEnvelope=ConvertFrom-StrictJson -Text $validCacheText
    $oldSchemaEnvelope.payload.version=1
    [IO.File]::WriteAllText($cacheFile,($oldSchemaEnvelope | ConvertTo-Json -Depth 100 -Compress),(New-Object Text.UTF8Encoding($false)))
    $oldSchema=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $oldSchema.Hit -and $oldSchema.Reason -match 'schema') 'A payload from the prior cache schema was accepted.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload

    $unknownCacheText=$validCacheText.Replace('"payload": {','"payload": {"unowned":true,')
    Assert-CacheTest ($unknownCacheText -cne $validCacheText) 'Could not prepare an unknown-member cache fixture.'
    [IO.File]::WriteAllText($cacheFile,$unknownCacheText,(New-Object Text.UTF8Encoding($false)))
    $unknownPayload=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $unknownPayload.Hit -and $unknownPayload.Reason -match 'schema') 'An unknown cache payload member was accepted.'
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload

    $savedSourceHashes=@($cachePayload.dns_policy.source_hashes)
    $cachePayload.dns_policy.source_hashes=@($savedSourceHashes[0],[pscustomobject][ordered]@{tag='routing-direct-domain';sha256=('b'*64)})
    $unsupportedSourceShapeRejected=$false
    try { Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload }
    catch { $unsupportedSourceShapeRejected=$_.Exception.Message -match 'source hash has an unsupported object shape' }
    Assert-CacheTest $unsupportedSourceShapeRejected 'A source tag without its predicate-count metadata was written to cache.'
    $cachePayload.dns_policy.source_hashes=$savedSourceHashes

    $corruptText=[IO.File]::ReadAllText($cacheFile).Replace('full:example.test','full:changed.example')
    [IO.File]::WriteAllText($cacheFile,$corruptText,(New-Object Text.UTF8Encoding($false)))
    $corrupt=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $corrupt.Hit -and $corrupt.Reason -match 'digest') 'A payload with a broken content digest was accepted.'

    [IO.File]::WriteAllText($cacheFile,'{"version":1,"version":1}',(New-Object Text.UTF8Encoding($false)))
    $duplicate=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $duplicate.Hit -and $duplicate.Reason -match 'invalid JSON') 'Duplicate JSON member names in the cache were accepted.'

    $cachePayload.files.dns_direct_domains="full:example.test`n"
    $cachePayload.numeric.numeric_predicates=$true
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $booleanCount=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $booleanCount.Hit -and $booleanCount.Reason -match 'numeric summary') 'A boolean value was accepted as a numeric count.'

    $cachePayload.numeric.numeric_predicates=1
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $validFractionFixtureText=[IO.File]::ReadAllText($cacheFile)
    $validFractionCache=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest $validFractionCache.Hit 'Could not prepare a valid persisted cache for the fractional-count reader case.'

    $cachePayload.numeric.numeric_predicates=1.5
    $fractionalWriterRejected=$false
    try { Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload }
    catch { $fractionalWriterRejected=$_.Exception.Message -match 'Unsupported cache digest field type: numeric.numeric_predicates' }
    Assert-CacheTest $fractionalWriterRejected 'The cache writer did not reject a fractional numeric summary before publication.'
    Assert-CacheTest ([IO.File]::ReadAllText($cacheFile) -ceq $validFractionFixtureText) 'A rejected fractional cache write changed the previously valid cache file.'

    $fractionalCacheText=$validFractionFixtureText.Replace('"numeric_predicates": 1,','"numeric_predicates": 1.5,')
    Assert-CacheTest ($fractionalCacheText -cne $validFractionFixtureText) 'Could not prepare a persisted fractional numeric summary.'
    [IO.File]::WriteAllText($cacheFile,$fractionalCacheText,(New-Object Text.UTF8Encoding($false)))
    $fractionalReaderThrew=$false
    try { $fractionalCount=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo }
    catch { $fractionalReaderThrew=$true }
    Assert-CacheTest (-not $fractionalReaderThrew) 'The cache reader threw instead of treating persisted fractional metadata as a cache miss.'
    Assert-CacheTest (-not $fractionalCount.Hit -and $fractionalCount.Reason -match 'invalid cache content|payload digest mismatch|invalid numeric summary') 'A persisted fractional value was accepted as an integer summary.'

    $cachePayload.numeric.numeric_predicates=1
    $cachePayload.dns_policy.domain_count=1
    Write-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Payload $cachePayload
    $countMismatch=Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo
    Assert-CacheTest (-not $countMismatch.Hit -and $countMismatch.Reason -match 'categorized totals') 'Inconsistent DNS category totals were accepted.'

    $unexpected=Join-Path $cacheDirectory 'unexpected.bin'
    [IO.File]::WriteAllText($unexpected,'unowned',(New-Object Text.UTF8Encoding($false)))
    $unexpectedRejected=$false
    try { Read-OpenWrtAdapterCache -CacheDirectory $cacheDirectory -Fingerprint $fingerprintTwo | Out-Null }
    catch { $unexpectedRejected=$_.Exception.Message -match 'unexpected entry' }
    Assert-CacheTest $unexpectedRejected 'Unexpected cache-directory contents were not rejected.'

    $output=Join-Path $fixtureRoot 'output'
    $support=Join-Path $fixtureRoot 'support'
    $formal=Join-Path $fixtureRoot 'formal'
    $aliasRejected=$false
    try {
        Assert-OpenWrtAdapterCacheTarget -CacheDirectory $support -OutputDirectory $output -BuildSupportDirectory $support -SourceRoot $sourceOne -SingBoxPath $SingBoxPath -FormalPackageDirectory $formal | Out-Null
    } catch { $aliasRejected=$_.Exception.Message -match 'protected source/archive/runtime directory' }
    Assert-CacheTest $aliasRejected 'Adapter cache path overlapping build support was not rejected.'
    Write-Output 'OpenWrt adapter cache checks passed: source-SRS and connection-cache-mode fingerprint isolation, valid hit, stale/corrupt misses, unexpected-entry rejection, and cache/support alias preflight.'
} finally {
    Assert-CacheFixtureTree -Root $fixtureRoot
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
