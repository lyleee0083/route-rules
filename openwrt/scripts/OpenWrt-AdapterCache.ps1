# Optional local cache for already validated DNS/nft adapter outputs. Bump the
# schema when this module's cache envelope or output meaning changes.
Set-StrictMode -Version 2.0

function Get-OpenWrtAdapterCacheDirectory {
    param([Parameter(Mandatory)][string]$BuildSupportDirectory)
    $fullPath = [IO.Path]::GetFullPath($BuildSupportDirectory)
    $parent = Split-Path -Parent $fullPath
    $leaf = Split-Path -Leaf $fullPath
    return Join-Path $parent ($leaf + '-adapter-cache')
}

function Get-OpenWrtAdapterCacheFilePath {
    param([Parameter(Mandatory)][string]$CacheDirectory)
    return Join-Path $CacheDirectory 'adapter-cache.json'
}

function Assert-OpenWrtAdapterCacheTarget {
    param(
        [Parameter(Mandatory)][string]$CacheDirectory,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$BuildSupportDirectory,
        [string]$SourceRoot,
        [string]$ArchivePath,
        [string]$SingBoxPath,
        [string[]]$RuntimePaths=@(),
        [string[]]$ProtectedPaths=@(),
        [Parameter(Mandatory)][string]$FormalPackageDirectory
    )
    $protected = @($ProtectedPaths) + @($OutputDirectory,$BuildSupportDirectory,$FormalPackageDirectory)
    Assert-OpenWrtOutputTarget -OutputDirectory $CacheDirectory -SourceRoot $SourceRoot -ArchivePath $ArchivePath -SingBoxPath $SingBoxPath -RuntimePaths $RuntimePaths -ProtectedPaths $protected
    $cachePaths = Get-BuildPaths $CacheDirectory
    $packagePaths = Get-BuildPaths $OutputDirectory
    $supportPaths = Get-BuildPaths $BuildSupportDirectory
    $coordinator = Get-OpenWrtArtifactCoordinatorPath -PackagePaths $packagePaths
    $comparison = [StringComparison]::Ordinal
    if ([IO.Path]::DirectorySeparatorChar -eq [char]'\') { $comparison = [StringComparison]::OrdinalIgnoreCase }
    $transactionPaths = @(
        $packagePaths.Destination,$packagePaths.Stage,$packagePaths.Backup,$packagePaths.Journal,($packagePaths.Journal+'.write'),$packagePaths.Lock,
        $supportPaths.Destination,$supportPaths.Stage,$supportPaths.Backup,$supportPaths.Journal,($supportPaths.Journal+'.write'),$supportPaths.Lock,
        $coordinator,($coordinator+'.write')
    )
    $cacheTransactionPaths = @(
        $cachePaths.Destination,$cachePaths.Stage,$cachePaths.Backup,$cachePaths.Journal,($cachePaths.Journal+'.write'),$cachePaths.Lock
    )
    foreach ($cachePath in $cacheTransactionPaths) {
        Assert-OpenWrtPathAncestors -Path $cachePath
        foreach ($transactionPath in $transactionPaths) {
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $transactionPath -Comparison $comparison) { throw 'Adapter cache overlaps a build transaction or coordinator path.' }
        }
        if (-not [string]::IsNullOrWhiteSpace($SourceRoot) -and (Test-OpenWrtPathOverlap -First $cachePath -Second $SourceRoot -Comparison $comparison)) { throw 'Adapter cache transaction path overlaps an input snapshot.' }
        if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
            $archiveDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($ArchivePath))
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $archiveDirectory -Comparison $comparison) { throw 'Adapter cache transaction path overlaps the source archive directory.' }
        }
        if (-not [string]::IsNullOrWhiteSpace($SingBoxPath)) {
            $decompilerDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($SingBoxPath))
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $decompilerDirectory -Comparison $comparison) { throw 'Adapter cache transaction path overlaps the official decompiler directory.' }
        }
        foreach ($runtimePath in $RuntimePaths) {
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $runtimePath -Comparison $comparison) { throw 'Adapter cache transaction path overlaps a runtime input.' }
        }
        foreach ($protectedPath in $ProtectedPaths) {
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $protectedPath -Comparison $comparison) { throw 'Adapter cache transaction path overlaps a protected project path.' }
        }
        foreach ($protectedRoot in @($OutputDirectory,$BuildSupportDirectory,$FormalPackageDirectory)) {
            if (Test-OpenWrtPathOverlap -First $cachePath -Second $protectedRoot -Comparison $comparison) { throw 'Adapter cache transaction path overlaps a delivery or support directory.' }
        }
        if (Test-Path -LiteralPath $cachePath) {
            $item = Get-Item -LiteralPath $cachePath -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Adapter cache transaction path is a reparse point: ' + $item.FullName) }
            if ($cachePath -ceq $cachePaths.Lock) {
                if ($item.PSIsContainer) { throw 'Adapter cache lock path is a directory.' }
            } elseif ($cachePath -ceq $cachePaths.Destination) {
                if (-not $item.PSIsContainer) { throw 'Adapter cache destination is not a directory.' }
            } else {
                throw ('Unexpected adapter cache transaction path already exists: ' + $item.FullName)
            }
        }
    }
    if (Test-OpenWrtPathOverlap -First $cachePaths.Destination -Second $cachePaths.Lock -Comparison $comparison) { throw 'Adapter cache destination overlaps its lock path.' }
    Assert-OpenWrtAdapterCacheTree -CacheDirectory $CacheDirectory
    return $cachePaths
}

function Get-OpenWrtAdapterCacheTextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
        return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Test-OpenWrtAdapterCacheInteger {
    param([Parameter(Mandatory)]$Value,[switch]$AllowZero)
    if ($null -eq $Value -or $Value -is [bool] -or $Value.GetType().FullName -notin @('System.Byte','System.SByte','System.Int16','System.UInt16','System.Int32','System.UInt32','System.Int64')) { return $false }
    $number = [int64]$Value
    if ($number -lt 0 -or $number -gt [int]::MaxValue) { return $false }
    if ($AllowZero) { return $true }
    return ($number -gt 0)
}

function ConvertTo-OpenWrtAdapterCachePolicyDoubleValue {
    param([Parameter(Mandatory)][AllowNull()]$Value)
    $numericTypes = @('System.Decimal','System.Double','System.Byte','System.SByte','System.Int16','System.UInt16','System.Int32','System.UInt32','System.Int64','System.UInt64')
    if ($null -eq $Value -or $Value -is [bool] -or $Value.GetType().FullName -notin $numericTypes) {
        throw 'DNS provider policy double value is not a JSON numeric type.'
    }
    $number = [double]$Value
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) { throw 'DNS provider policy double value must be finite.' }
    return $number
}

function Get-OpenWrtAdapterCacheObjectPropertyNames {
    param([Parameter(Mandatory)]$Object)
    if ($Object -is [System.Collections.IDictionary]) { return [string[]]@($Object.Keys | ForEach-Object { [string]$_ }) }
    return [string[]]@($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Get-OpenWrtAdapterCacheObjectValue {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string]$Name)
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) { if ([string]$key -ceq $Name) { return $Object[$key] } }
        return $null
    }
    foreach ($property in $Object.PSObject.Properties) { if ($property.Name -ceq $Name) { return $property.Value } }
    return $null
}

function Test-OpenWrtAdapterCacheObjectProperties {
    param([Parameter(Mandatory)][AllowNull()]$Object,[Parameter(Mandatory)][string[]]$ExpectedNames)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [array] -or $Object -is [ValueType]) { return $false }
    if (-not ($Object -is [System.Collections.IDictionary] -or $Object -is [System.Management.Automation.PSCustomObject])) { return $false }
    $actualNames = Get-OpenWrtAdapterCacheObjectPropertyNames -Object $Object
    if ($actualNames.Count -ne $ExpectedNames.Count) { return $false }
    $actualSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($name in $actualNames) { if (-not $actualSet.Add($name)) { return $false } }
    foreach ($name in $ExpectedNames) { if (-not $actualSet.Contains($name)) { return $false } }
    return $true
}

function Test-OpenWrtAdapterCacheTypedPolicyValue {
    param([Parameter(Mandatory)][AllowNull()]$Value,[Parameter(Mandatory)][AllowNull()]$Schema,[switch]$TypeOnly)
    if ($Schema -is [System.Collections.IDictionary]) {
        $expectedNames = [string[]]@($Schema.Keys | ForEach-Object { [string]$_ })
        if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $Value -ExpectedNames $expectedNames)) { return $false }
        foreach ($name in $expectedNames) {
            if (-not (Test-OpenWrtAdapterCacheTypedPolicyValue -Value (Get-OpenWrtAdapterCacheObjectValue -Object $Value -Name $name) -Schema $Schema[$name] -TypeOnly:$TypeOnly)) { return $false }
        }
        return $true
    }
    if ($Schema -is [string]) { return ($Value -is [string] -and ($TypeOnly -or $Value -ceq $Schema)) }
    if ($Schema -is [bool]) { return ($Value -is [bool] -and ($TypeOnly -or $Value -eq $Schema)) }
    if (Test-OpenWrtAdapterCacheInteger -Value $Schema -AllowZero) {
        return ((Test-OpenWrtAdapterCacheInteger -Value $Value -AllowZero) -and ($TypeOnly -or [int64]$Value -eq [int64]$Schema))
    }
    if ($Schema -is [double]) {
        try {
            $number = ConvertTo-OpenWrtAdapterCachePolicyDoubleValue -Value $Value
            $expected = ConvertTo-OpenWrtAdapterCachePolicyDoubleValue -Value $Schema
        } catch { return $false }
        return ($TypeOnly -or $number -eq $expected)
    }
    return $false
}

function ConvertTo-OpenWrtAdapterCacheTypedPolicyValue {
    param([Parameter(Mandatory)][AllowNull()]$Value,[Parameter(Mandatory)][AllowNull()]$Schema)
    if (-not (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $Value -Schema $Schema)) { throw 'DNS provider policy metadata does not match the source policy schema or values.' }
    if ($Schema -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($name in [string[]]@($Schema.Keys | ForEach-Object { [string]$_ })) {
            $copy[$name] = ConvertTo-OpenWrtAdapterCacheTypedPolicyValue -Value (Get-OpenWrtAdapterCacheObjectValue -Object $Value -Name $name) -Schema $Schema[$name]
        }
        return $copy
    }
    if ($Schema -is [string]) { return [string]$Value }
    if ($Schema -is [bool]) { return [bool]$Value }
    if (Test-OpenWrtAdapterCacheInteger -Value $Schema -AllowZero) {
        return [Convert]::ChangeType($Value,$Schema.GetType(),[Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Schema -is [double]) { return ConvertTo-OpenWrtAdapterCachePolicyDoubleValue -Value $Value }
    throw 'Unsupported source DNS provider policy schema type.'
}

function Add-OpenWrtAdapterCachePolicyDigestFields {
    param([Parameter(Mandatory)][Text.StringBuilder]$Builder,[Parameter(Mandatory)][string]$Prefix,[Parameter(Mandatory)][AllowNull()]$Value,[Parameter(Mandatory)][AllowNull()]$Schema)
    if ($Schema -is [System.Collections.IDictionary]) {
        foreach ($name in [string[]]@($Schema.Keys | ForEach-Object { [string]$_ })) {
            Add-OpenWrtAdapterCachePolicyDigestFields -Builder $Builder -Prefix ($Prefix + '.' + $name) -Value (Get-OpenWrtAdapterCacheObjectValue -Object $Value -Name $name) -Schema $Schema[$name]
        }
        return
    }
    if ($Schema -is [double]) {
        $number = ConvertTo-OpenWrtAdapterCachePolicyDoubleValue -Value $Value
        Add-OpenWrtAdapterCacheDigestField -Builder $Builder -Name $Prefix -Value $number -AllowDouble
        return
    }
    Add-OpenWrtAdapterCacheDigestField -Builder $Builder -Name $Prefix -Value $Value -AllowDouble
}

function Add-OpenWrtAdapterCacheDigestField {
    param([Parameter(Mandatory)][Text.StringBuilder]$Builder,[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)]$Value,[switch]$AllowDouble)
    if ($Value -is [string]) { $encoded = 's:' + $Value }
    elseif ($Value -is [bool]) { $encoded = 'b:' + $Value.ToString().ToLowerInvariant() }
    elseif (Test-OpenWrtAdapterCacheInteger -Value $Value -AllowZero) { $encoded = 'i:' + ([IFormattable]$Value).ToString($null,[Globalization.CultureInfo]::InvariantCulture) }
    elseif ($AllowDouble -and $Value -is [double] -and -not [double]::IsNaN($Value) -and -not [double]::IsInfinity($Value)) { $encoded = 'd:' + $Value.ToString('R',[Globalization.CultureInfo]::InvariantCulture) }
    else { throw ('Unsupported cache digest field type: ' + $Name) }
    [void]$Builder.Append($Name.Length).Append(':').Append($Name).Append($encoded.Length).Append(':').Append($encoded).Append(';')
}

function Get-OpenWrtAdapterCacheFingerprint {
    param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$SingBoxPath,[ValidateSet('off-v1','ctmark-v1')][string]$ConnectionCacheMode='off-v1')
    $openWrtRoot = Split-Path -Parent $PSScriptRoot
    $projectRoot = Split-Path -Parent $openWrtRoot
    $configPath = Join-Path $SourceRoot 'sing-box-openwrt.json'
    $ruleRoot = Join-Path $SourceRoot 'rule-set'
    $sourceFiles = New-Object 'System.Collections.Generic.List[object]'
    $sourceFiles.Add([pscustomobject][ordered]@{
        path = 'sing-box-openwrt.json'
        sha256 = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
    $ruleFiles = @(Get-ChildItem -LiteralPath $ruleRoot -File)
    if (-not $ruleFiles.Count) { throw 'Cannot fingerprint an empty OpenWrt rule-set snapshot.' }
    $ruleNames = [string[]]@($ruleFiles | ForEach-Object Name)
    [Array]::Sort($ruleNames,[StringComparer]::Ordinal)
    foreach ($ruleName in $ruleNames) {
        $item = Get-Item -LiteralPath (Join-Path $ruleRoot $ruleName) -Force -ErrorAction Stop
        if ($item.Name -cnotmatch '^[A-Za-z0-9_-]+\.srs$' -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Cannot fingerprint an unsafe OpenWrt rule-set input.'
        }
        $sourceFiles.Add([pscustomobject][ordered]@{
            path = 'rule-set/' + $ruleName
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    $converterPaths = @(
        (Join-Path $projectRoot 'scripts\Direct-RoutingPolicy.ps1'),
        (Join-Path $projectRoot 'scripts\Node-DnsPolicy.ps1'),
        (Join-Path $projectRoot 'scripts\SameTypeDirectPolicy.ps1'),
        (Join-Path $projectRoot 'src\SameTypeDirectCompiler.cs'),
        (Join-Path $projectRoot 'scripts\Json-Validation.ps1'),
        (Join-Path $projectRoot 'scripts\Generate-SingBoxConfig.ps1'),
        (Join-Path $projectRoot 'scripts\Build-Transaction.ps1'),
        (Join-Path $PSScriptRoot 'Build-OpenWrtPackage.ps1'),
        (Join-Path $PSScriptRoot 'Final-LinuxSnapshot.ps1'),
        (Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'scripts') 'Core-Assets.ps1'),
        (Join-Path $PSScriptRoot 'OpenWrt-Build.ps1'),
        (Join-Path $PSScriptRoot 'OpenWrt-AdapterCache.ps1'),
        (Join-Path $PSScriptRoot 'Nft-KernelPolicy.ps1'),
        (Join-Path $PSScriptRoot 'Numeric-KernelPolicy.ps1'),
        (Join-Path $PSScriptRoot 'Native-NumericPolicy.ps1'),
        (Join-Path $PSScriptRoot 'Mosdns-Policy.ps1'),
        (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/native/mosdns-policy.json'),
        (Join-Path (Join-Path $openWrtRoot 'src\native') 'policy.template.nft')
    )
    $converterFiles = New-Object 'System.Collections.Generic.List[object]'
    foreach ($path in $converterPaths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Adapter cache converter dependency is missing: ' + $path) }
        $resolved = [IO.Path]::GetFullPath($path)
        $separator = [IO.Path]::DirectorySeparatorChar
        $root = [IO.Path]::GetFullPath($projectRoot).TrimEnd($separator) + $separator
        $comparison = if ($separator -eq [char]'/') { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
        if (-not $resolved.StartsWith($root,$comparison)) { throw 'Adapter cache converter dependency escaped the project root.' }
        $relative = $resolved.Substring($root.Length).Replace('\','/')
        $converterFiles.Add([pscustomobject][ordered]@{
            path = $relative
            sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    $fingerprintInput = [ordered]@{
        schema_version = 3
        connection_cache_mode = $ConnectionCacheMode
        core_sha256 = (Get-FileHash -LiteralPath $SingBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()
        source_files = @($sourceFiles.ToArray())
        converter_files = @($converterFiles.ToArray())
    }
    return Get-OpenWrtAdapterCacheTextSha256 -Text ($fingerprintInput | ConvertTo-Json -Depth 20 -Compress)
}

function Assert-OpenWrtAdapterCacheTree {
    param([Parameter(Mandatory)][string]$CacheDirectory)
    Assert-OpenWrtPathAncestors -Path (Get-OpenWrtAdapterCacheFilePath -CacheDirectory $CacheDirectory)
    if (-not [IO.Directory]::Exists($CacheDirectory)) { return }
    $directory = Get-Item -LiteralPath $CacheDirectory -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Adapter cache path is not a regular directory.' }
    foreach ($item in @(Get-ChildItem -LiteralPath $CacheDirectory -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Adapter cache contains a reparse point: ' + $item.FullName) }
        if ($item.PSIsContainer -or ($item.Name -cne 'adapter-cache.json' -and $item.Name -cnotmatch '^adapter-cache\.[0-9a-f]{32}\.pending$')) {
            throw ('Adapter cache directory contains an unexpected entry: ' + $item.Name)
        }
    }
}

function Get-OpenWrtAdapterCachePayloadDigest {
    param([Parameter(Mandatory)]$Payload)
    $payloadNames = @('version','fingerprint','files','numeric','dns_policy')
    $fileNames = @('routing_policy_nft','dns_direct_domains','mosdns_json')
    $files = Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'files'
    if ((Get-OpenWrtAdapterCacheObjectPropertyNames -Object $files) -ccontains 'dns_reject_domains') { $fileNames += 'dns_reject_domains' }
    $numericNames = @('numeric_predicates','cidrs','ip_intervals','destination_intervals','source_intervals','decompiled_srs_count')
    $dnsNames = @('status','publication_ready','direct_rule_set_count','direct_domain_rule_count','full_count','domain_count','regexp_count','source_hashes','node_ttl_policy','dns_provider_policy')
    if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $Payload -ExpectedNames $payloadNames) -or
        -not (Test-OpenWrtAdapterCacheObjectProperties -Object (Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'files') -ExpectedNames $fileNames) -or
        -not (Test-OpenWrtAdapterCacheObjectProperties -Object (Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'numeric') -ExpectedNames $numericNames) -or
        -not (Test-OpenWrtAdapterCacheObjectProperties -Object (Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'dns_policy') -ExpectedNames $dnsNames)) {
        throw 'Adapter cache payload has an unexpected object schema.'
    }
    $dns = Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'dns_policy'
    $providerPolicy = Get-OpenWrtAdapterCacheObjectValue -Object $dns -Name 'dns_provider_policy'
    $providerSchema = Get-MosdnsDnsProviderPolicyMetadata
    if (-not (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $providerPolicy -Schema $providerSchema -TypeOnly)) {
        throw 'Adapter cache DNS provider policy has an unexpected schema, type, or value.'
    }
    $builder = New-Object Text.StringBuilder
    Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name 'version' -Value (Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'version')
    Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name 'fingerprint' -Value (Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'fingerprint')
    $files = Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'files'
    foreach ($name in $fileNames) { Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ('files.' + $name) -Value (Get-OpenWrtAdapterCacheObjectValue -Object $files -Name $name) }
    $numeric = Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'numeric'
    foreach ($name in $numericNames) { Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ('numeric.' + $name) -Value (Get-OpenWrtAdapterCacheObjectValue -Object $numeric -Name $name) }
    foreach ($name in @('status','publication_ready','direct_rule_set_count','direct_domain_rule_count','full_count','domain_count','regexp_count')) {
        Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ('dns_policy.' + $name) -Value (Get-OpenWrtAdapterCacheObjectValue -Object $dns -Name $name)
    }
    $sourceHashes = @(Get-OpenWrtAdapterCacheObjectValue -Object $dns -Name 'source_hashes')
    Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name 'dns_policy.source_hashes.count' -Value $sourceHashes.Count
    for ($index = 0; $index -lt $sourceHashes.Count; $index++) {
        $entry = $sourceHashes[$index]
        $prefix = 'dns_policy.source_hashes[' + $index + ']'
        $entryNames = Get-OpenWrtAdapterCacheObjectPropertyNames -Object $entry
        if ($entryNames.Count -eq 2 -and @($entryNames | Where-Object { $_ -ceq 'path' }).Count -eq 1 -and @($entryNames | Where-Object { $_ -ceq 'sha256' }).Count -eq 1) {
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.kind') -Value 'path'
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.path') -Value (Get-OpenWrtAdapterCacheObjectValue -Object $entry -Name 'path')
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.sha256') -Value (Get-OpenWrtAdapterCacheObjectValue -Object $entry -Name 'sha256')
        } elseif ($entryNames.Count -eq 3 -and @($entryNames | Where-Object { $_ -ceq 'tag' }).Count -eq 1 -and @($entryNames | Where-Object { $_ -ceq 'sha256' }).Count -eq 1 -and @($entryNames | Where-Object { $_ -ceq 'predicates' }).Count -eq 1) {
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.kind') -Value 'tag'
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.tag') -Value (Get-OpenWrtAdapterCacheObjectValue -Object $entry -Name 'tag')
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.sha256') -Value (Get-OpenWrtAdapterCacheObjectValue -Object $entry -Name 'sha256')
            Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name ($prefix + '.predicates') -Value (Get-OpenWrtAdapterCacheObjectValue -Object $entry -Name 'predicates')
        } else { throw 'Adapter cache source hash has an unsupported object shape.' }
    }
    Add-OpenWrtAdapterCacheDigestField -Builder $builder -Name 'dns_policy.node_ttl_policy' -Value (Get-OpenWrtAdapterCacheObjectValue -Object $dns -Name 'node_ttl_policy')
    Add-OpenWrtAdapterCachePolicyDigestFields -Builder $builder -Prefix 'dns_policy.dns_provider_policy' -Value $providerPolicy -Schema $providerSchema
    return Get-OpenWrtAdapterCacheTextSha256 -Text $builder.ToString()
}

function Read-OpenWrtAdapterCache {
    param([Parameter(Mandatory)][string]$CacheDirectory,[Parameter(Mandatory)][string]$Fingerprint)
    Assert-OpenWrtAdapterCacheTree -CacheDirectory $CacheDirectory
    $path = Get-OpenWrtAdapterCacheFilePath -CacheDirectory $CacheDirectory
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return [pscustomobject]@{ Hit=$false; Reason='missing' } }
    try {
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -le 0 -or $file.Length -gt 33554432) {
        return [pscustomobject]@{ Hit=$false; Reason='invalid file type or size' }
    }
    try { $envelope = ConvertFrom-StrictJson -Text ([IO.File]::ReadAllText($path)) }
    catch { return [pscustomobject]@{ Hit=$false; Reason='invalid JSON' } }
    if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $envelope -ExpectedNames @('version','payload_sha256','payload'))) { return [pscustomobject]@{ Hit=$false; Reason='invalid envelope' } }
    if (-not (Test-OpenWrtAdapterCacheInteger -Value $envelope.version) -or [int64]$envelope.version -ne 1 -or
        $envelope.payload_sha256 -isnot [string] -or $envelope.payload_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $null -eq $envelope.payload) {
        return [pscustomobject]@{ Hit=$false; Reason='invalid envelope' }
    }
    $payload = $envelope.payload
    if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $payload -ExpectedNames @('version','fingerprint','files','numeric','dns_policy'))) {
        return [pscustomobject]@{ Hit=$false; Reason='fingerprint or payload schema mismatch' }
    }
    $files = Get-OpenWrtAdapterCacheObjectValue -Object $payload -Name 'files'
    $numeric = Get-OpenWrtAdapterCacheObjectValue -Object $payload -Name 'numeric'
    $dns = Get-OpenWrtAdapterCacheObjectValue -Object $payload -Name 'dns_policy'
    $fileNames = @('routing_policy_nft','dns_direct_domains','mosdns_json')
    if ((Get-OpenWrtAdapterCacheObjectPropertyNames -Object $files) -ccontains 'dns_reject_domains') { $fileNames += 'dns_reject_domains' }
    if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $files -ExpectedNames $fileNames) -or
        -not (Test-OpenWrtAdapterCacheObjectProperties -Object $numeric -ExpectedNames @('numeric_predicates','cidrs','ip_intervals','destination_intervals','source_intervals','decompiled_srs_count')) -or
        -not (Test-OpenWrtAdapterCacheObjectProperties -Object $dns -ExpectedNames @('status','publication_ready','direct_rule_set_count','direct_domain_rule_count','full_count','domain_count','regexp_count','source_hashes','node_ttl_policy','dns_provider_policy'))) {
        return [pscustomobject]@{ Hit=$false; Reason='fingerprint or payload schema mismatch' }
    }
    $providerSchema = Get-MosdnsDnsProviderPolicyMetadata
    if (-not (Test-OpenWrtAdapterCacheObjectProperties -Object $dns.dns_provider_policy -ExpectedNames ([string[]]@($providerSchema.Keys | ForEach-Object { [string]$_ })))) {
        return [pscustomobject]@{ Hit=$false; Reason='fingerprint or payload schema mismatch' }
    }
    if (-not (Test-OpenWrtAdapterCacheInteger -Value $payload.version) -or [int64]$payload.version -ne 2 -or $payload.fingerprint -isnot [string] -or $payload.fingerprint -cne $Fingerprint) {
        return [pscustomobject]@{ Hit=$false; Reason='fingerprint or payload schema mismatch' }
    }
    $actualDigest = Get-OpenWrtAdapterCachePayloadDigest -Payload $payload
    if ($actualDigest -cne $envelope.payload_sha256) { return [pscustomobject]@{ Hit=$false; Reason='payload digest mismatch' } }
    if (-not (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $dns.dns_provider_policy -Schema $providerSchema)) {
        return [pscustomobject]@{ Hit=$false; Reason='invalid DNS provider policy metadata' }
    }
    foreach ($name in $fileNames) {
        $property = $payload.files.PSObject.Properties[$name]
        if (-not $property -or $null -eq $property.Value -or $property.Value -isnot [string] -or $property.Value.Length -eq 0 -or $property.Value -match "`r" -or -not $property.Value.EndsWith("`n",[StringComparison]::Ordinal)) {
            return [pscustomobject]@{ Hit=$false; Reason='invalid adapter output' }
        }
    }
    if (($files.mosdns_json.Contains('./dns-reject-domains.mdrs')) -ne ($fileNames -ccontains 'dns_reject_domains')) {
        return [pscustomobject]@{ Hit=$false; Reason='incomplete DNS reject payload' }
    }
    $numericNames = @('numeric_predicates','cidrs','ip_intervals','destination_intervals','source_intervals','decompiled_srs_count')
    foreach ($name in $numericNames) {
        $property = $payload.numeric.PSObject.Properties[$name]
        if (-not $property -or -not (Test-OpenWrtAdapterCacheInteger -Value $property.Value -AllowZero)) { return [pscustomobject]@{ Hit=$false; Reason='invalid numeric summary' } }
    }
    foreach ($name in @('direct_rule_set_count','direct_domain_rule_count')) {
        $property = $dns.PSObject.Properties[$name]
        if (-not $property -or -not (Test-OpenWrtAdapterCacheInteger -Value $property.Value)) { return [pscustomobject]@{ Hit=$false; Reason='invalid DNS summary' } }
    }
    $domainTotal = [int64]0
    foreach ($name in @('full_count','domain_count','regexp_count')) {
        $property = $dns.PSObject.Properties[$name]
        if (-not $property -or -not (Test-OpenWrtAdapterCacheInteger -Value $property.Value -AllowZero)) { return [pscustomobject]@{ Hit=$false; Reason='invalid DNS summary' } }
        $domainTotal += [int64]$property.Value
    }
    if ($domainTotal -ne [int64]$dns.direct_domain_rule_count) {
        return [pscustomobject]@{ Hit=$false; Reason='DNS domain count does not match categorized totals' }
    }
    if ($dns.status -isnot [string] -or $dns.status -cne 'written' -or $dns.publication_ready -isnot [bool] -or $dns.publication_ready -ne $true -or
        $dns.node_ttl_policy -isnot [string] -or [string]::IsNullOrWhiteSpace($dns.node_ttl_policy) -or -not $dns.source_hashes) {
        return [pscustomobject]@{ Hit=$false; Reason='invalid DNS policy metadata' }
    }
    if ($dns.source_hashes -isnot [array] -or $dns.source_hashes.Count -eq 0) { return [pscustomobject]@{ Hit=$false; Reason='invalid DNS source hash metadata' } }
    $sourceHashKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($hashEntry in $dns.source_hashes) {
        if (Test-OpenWrtAdapterCacheObjectProperties -Object $hashEntry -ExpectedNames @('path','sha256')) {
            $identity = 'path:' + [string]$hashEntry.path
            if ($hashEntry.path -isnot [string] -or [string]::IsNullOrWhiteSpace($hashEntry.path) -or $hashEntry.path -cnotmatch '^[A-Za-z0-9_.\-/]+$' -or
                $hashEntry.sha256 -isnot [string] -or $hashEntry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                return [pscustomobject]@{ Hit=$false; Reason='invalid DNS source hash metadata' }
            }
        } elseif (Test-OpenWrtAdapterCacheObjectProperties -Object $hashEntry -ExpectedNames @('tag','sha256','predicates')) {
            $identity = 'tag:' + [string]$hashEntry.tag
            if ($hashEntry.tag -isnot [string] -or [string]::IsNullOrWhiteSpace($hashEntry.tag) -or $hashEntry.tag -cnotmatch '^[A-Za-z0-9_-]+$' -or
                $hashEntry.sha256 -isnot [string] -or $hashEntry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                -not (Test-OpenWrtAdapterCacheInteger -Value $hashEntry.predicates)) {
                return [pscustomobject]@{ Hit=$false; Reason='invalid DNS source hash metadata' }
            }
        } else { return [pscustomobject]@{ Hit=$false; Reason='invalid DNS source hash metadata' } }
        if (-not $sourceHashKeys.Add($identity)) { return [pscustomobject]@{ Hit=$false; Reason='duplicate DNS source hash metadata' } }
    }
    return [pscustomobject]@{ Hit=$true; Reason='hit'; Payload=$payload }
    } catch {
        return [pscustomobject]@{ Hit=$false; Reason='invalid cache content' }
    }
}

function New-OpenWrtAdapterCachePayload {
    param([string]$Fingerprint,[string]$PayloadDirectory,$Numeric,$DnsPolicy)
    $files = [ordered]@{
        routing_policy_nft = [IO.File]::ReadAllText((Join-Path $PayloadDirectory 'routing-policy.nft'))
        dns_direct_domains = [IO.File]::ReadAllText((Join-Path $PayloadDirectory 'dns-direct-domains.txt'))
        mosdns_json = [IO.File]::ReadAllText((Join-Path $PayloadDirectory 'mosdns.json'))
    }
    $rejectPath = Join-Path $PayloadDirectory 'dns-reject-domains.txt'
    if ([IO.File]::Exists($rejectPath)) { $files['dns_reject_domains'] = [IO.File]::ReadAllText($rejectPath) }
    $dnsMetadata = [ordered]@{
        status = [string]$DnsPolicy.status
        publication_ready = [bool]$DnsPolicy.publication_ready
        direct_rule_set_count = [int]$DnsPolicy.direct_rule_set_count
        direct_domain_rule_count = [int]$DnsPolicy.direct_domain_rule_count
        full_count = [int]$DnsPolicy.full_count
        domain_count = [int]$DnsPolicy.domain_count
        regexp_count = [int]$DnsPolicy.regexp_count
        source_hashes = @($DnsPolicy.source_hashes)
        node_ttl_policy = [string]$DnsPolicy.node_ttl_policy
        dns_provider_policy = ConvertTo-OpenWrtAdapterCacheTypedPolicyValue -Value $DnsPolicy.dns_provider_policy -Schema (Get-MosdnsDnsProviderPolicyMetadata)
    }
    $numericMetadata = [ordered]@{
        numeric_predicates = [int]$Numeric.numeric_predicates
        cidrs = [int]$Numeric.cidrs
        ip_intervals = [int]$Numeric.ip_intervals
        destination_intervals = [int]$Numeric.destination_intervals
        source_intervals = [int]$Numeric.source_intervals
        decompiled_srs_count = [int]$Numeric.decompiled_srs_count
    }
    return [ordered]@{
        version = 2
        fingerprint = $Fingerprint
        files = $files
        numeric = $numericMetadata
        dns_policy = $dnsMetadata
    }
}

function Restore-OpenWrtAdapterCachePayload {
    param([Parameter(Mandatory)]$Payload,[Parameter(Mandatory)][string]$OutputDirectory)
    $files = [ordered]@{ 'routing-policy.nft'='routing_policy_nft'; 'dns-direct-domains.txt'='dns_direct_domains'; 'mosdns.json'='mosdns_json' }
    if ((Get-OpenWrtAdapterCacheObjectPropertyNames -Object $Payload.files) -ccontains 'dns_reject_domains') {
        $files['dns-reject-domains.txt'] = 'dns_reject_domains'
    }
    foreach ($name in $files.Keys) {
        $path = Join-Path $OutputDirectory $name
        if (Test-Path -LiteralPath $path) { throw ('Adapter output already exists in the staging directory: ' + $name) }
    }
    $encoding = New-Object Text.UTF8Encoding($false)
    foreach ($name in $files.Keys) {
        $value = Get-OpenWrtAdapterCacheObjectValue -Object $Payload.files -Name $files[$name]
        [IO.File]::WriteAllText((Join-Path $OutputDirectory $name),[string]$value,$encoding)
    }
    $numeric = [pscustomobject][ordered]@{
        numeric_predicates = [int]$Payload.numeric.numeric_predicates
        cidrs = [int]$Payload.numeric.cidrs
        ip_intervals = [int]$Payload.numeric.ip_intervals
        destination_intervals = [int]$Payload.numeric.destination_intervals
        source_intervals = [int]$Payload.numeric.source_intervals
        decompiled_srs_count = [int]$Payload.numeric.decompiled_srs_count
    }
    $sourceHashes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in @($Payload.dns_policy.source_hashes)) {
        if (Test-OpenWrtAdapterCacheObjectProperties -Object $entry -ExpectedNames @('path','sha256')) {
            $sourceHashes.Add([pscustomobject][ordered]@{path=[string]$entry.path;sha256=[string]$entry.sha256})
        } elseif (Test-OpenWrtAdapterCacheObjectProperties -Object $entry -ExpectedNames @('tag','sha256','predicates')) {
            $sourceHashes.Add([pscustomobject][ordered]@{tag=[string]$entry.tag;sha256=[string]$entry.sha256;predicates=[int]$entry.predicates})
        } else { throw 'Cannot restore unsupported DNS source hash metadata.' }
    }
    $dns = [pscustomobject][ordered]@{
        status = [string]$Payload.dns_policy.status
        publication_ready = [bool]$Payload.dns_policy.publication_ready
        paths = [pscustomobject][ordered]@{
            dns_direct_domains = Join-Path $OutputDirectory 'dns-direct-domains.txt'
            mosdns_json = Join-Path $OutputDirectory 'mosdns.json'
        }
        direct_rule_set_count = [int]$Payload.dns_policy.direct_rule_set_count
        direct_domain_rule_count = [int]$Payload.dns_policy.direct_domain_rule_count
        full_count = [int]$Payload.dns_policy.full_count
        domain_count = [int]$Payload.dns_policy.domain_count
        regexp_count = [int]$Payload.dns_policy.regexp_count
        node_ttl_policy = [string]$Payload.dns_policy.node_ttl_policy
        dns_provider_policy = ConvertTo-OpenWrtAdapterCacheTypedPolicyValue -Value $Payload.dns_policy.dns_provider_policy -Schema (Get-MosdnsDnsProviderPolicyMetadata)
        source_hashes = @($sourceHashes.ToArray())
    }
    return [pscustomobject][ordered]@{ Numeric=$numeric; DnsPolicy=$dns }
}

function Write-OpenWrtAdapterCache {
    param([Parameter(Mandatory)][string]$CacheDirectory,[Parameter(Mandatory)]$Payload)
    Assert-OpenWrtAdapterCacheTree -CacheDirectory $CacheDirectory
    $dnsPolicy = Get-OpenWrtAdapterCacheObjectValue -Object $Payload -Name 'dns_policy'
    $providerPolicy = Get-OpenWrtAdapterCacheObjectValue -Object $dnsPolicy -Name 'dns_provider_policy'
    if (-not (Test-OpenWrtAdapterCacheTypedPolicyValue -Value $providerPolicy -Schema (Get-MosdnsDnsProviderPolicyMetadata))) {
        throw 'Adapter cache DNS provider policy does not match the source policy.'
    }
    [IO.Directory]::CreateDirectory($CacheDirectory) | Out-Null
    Assert-OpenWrtAdapterCacheTree -CacheDirectory $CacheDirectory
    $path = Get-OpenWrtAdapterCacheFilePath -CacheDirectory $CacheDirectory
    $envelope = [ordered]@{
        version = 1
        payload_sha256 = Get-OpenWrtAdapterCachePayloadDigest -Payload $Payload
        payload = $Payload
    }
    $compactJson = $envelope | ConvertTo-Json -Depth 40 -Compress
    $json = (Format-JsonText -Text $compactJson).Replace("`r`n","`n").Replace("`r","`n").TrimEnd([char]10) + "`n"
    $encoding = New-Object Text.UTF8Encoding($false)
    $jsonBytes = $encoding.GetBytes($json)
    if ($jsonBytes.Length -gt 33554432) { throw 'Adapter cache payload exceeds the supported size.' }
    $pending = Join-Path $CacheDirectory ('adapter-cache.' + [guid]::NewGuid().ToString('N') + '.pending')
    $backup = Join-Path $CacheDirectory ('adapter-cache.' + [guid]::NewGuid().ToString('N') + '.pending')
    try {
        [IO.File]::WriteAllBytes($pending,$jsonBytes)
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            [IO.File]::Replace($pending,$path,$backup)
        } else {
            [IO.File]::Move($pending,$path)
        }
    } finally {
        foreach ($temporaryPath in @($pending,$backup)) {
            if (Test-Path -LiteralPath $temporaryPath) {
                $item = Get-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
                if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.DirectoryName -cne ([IO.Path]::GetFullPath($CacheDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar))) { throw 'Refusing unsafe adapter cache temporary cleanup.' }
                [IO.File]::Delete($temporaryPath)
            }
        }
    }
}

function Build-OpenWrtAdapterOutputs {
    param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$OutputDirectory,[Parameter(Mandatory)][string]$SingBoxPath,[Parameter(Mandatory)][string]$CacheDirectory,[ValidateSet('off-v1','ctmark-v1')][string]$ConnectionCacheMode='off-v1',[switch]$DisableCache)
    $fingerprint = $null
    $cacheStatus = 'disabled'
    $cacheReason = 'disabled by caller'
    if (-not $DisableCache) {
        $fingerprint = Get-OpenWrtAdapterCacheFingerprint -SourceRoot $SourceRoot -SingBoxPath $SingBoxPath -ConnectionCacheMode $ConnectionCacheMode
        $cache = Read-OpenWrtAdapterCache -CacheDirectory $CacheDirectory -Fingerprint $fingerprint
        if ($cache.Hit) {
            $restored = Restore-OpenWrtAdapterCachePayload -Payload $cache.Payload -OutputDirectory $OutputDirectory
            return [pscustomobject][ordered]@{ Numeric=$restored.Numeric; DnsPolicy=$restored.DnsPolicy; CacheStatus='hit'; CacheReason='validated fingerprint and payload checksum'; Fingerprint=$fingerprint; ConnectionCacheMode=$ConnectionCacheMode }
        }
        $cacheStatus = 'miss'
        $cacheReason = [string]$cache.Reason
    }
    $numeric = Write-NftAdapterFromSnapshot -SourceRoot $SourceRoot -OutputDirectory $OutputDirectory -SingBoxPath $SingBoxPath -ConnectionCacheMode $ConnectionCacheMode
    $dnsPolicy = Write-MosdnsAdapterFromSnapshot -SourceRoot $SourceRoot -OutputDirectory $OutputDirectory -SingBoxPath $SingBoxPath
    if (-not $DisableCache) {
        $payload = New-OpenWrtAdapterCachePayload -Fingerprint $fingerprint -PayloadDirectory $OutputDirectory -Numeric $numeric -DnsPolicy $dnsPolicy
        try {
            Write-OpenWrtAdapterCache -CacheDirectory $CacheDirectory -Payload $payload
            $cacheStatus = 'miss-stored'
        } catch {
            $cacheStatus = 'miss-not-stored'
            $cacheReason = 'cache write failed: ' + $_.Exception.Message
        }
    }
    return [pscustomobject][ordered]@{ Numeric=$numeric; DnsPolicy=$dnsPolicy; CacheStatus=$cacheStatus; CacheReason=$cacheReason; Fingerprint=$fingerprint; ConnectionCacheMode=$ConnectionCacheMode }
}
