[CmdletBinding()]
param(
    [string]$ManifestPath,
    [string]$OutputPath,
    [string]$CacheDirectory,
    [string]$ZstdLibraryPath,
    [switch]$Offline,
    [switch]$AllowSourceShrink,
    [ValidateRange(2,4)][int]$NetworkConcurrency = 4,
    [Parameter(DontShow=$true)][switch]$DefinitionsOnly,
    [ValidateRange(1,600)][int]$LockTimeoutSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Json-Validation.ps1')
$script:RemoteStates = @{}
$script:ValidatedSources = @{}
$script:ValidatedGeodata = @{}
$script:ParsedSources = @{}
$script:ParserFingerprint = $null

if (-not $ManifestPath) { $ManifestPath = Join-Path $script:ProjectRoot 'routing\routing-sources.json' }
if (-not $OutputPath) { $OutputPath = Join-Path $script:ProjectRoot 'routing\merged\merged-rules.json' }
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $script:ProjectRoot 'routing\cache' }

if (-not ('RoutingRuleItem' -as [type])) {
    $compileArguments = @{ Path=(Join-Path (Join-Path $script:ProjectRoot 'src') 'RoutingRuleCompiler.cs') }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $compileArguments.ReferencedAssemblies = @('System.dll','System.Core.dll',[System.Management.Automation.PSObject].Assembly.Location)
    }
    Add-Type @compileArguments
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "找不到 JSON 文件：$Path"
    }
    try {
        return Read-StrictJsonFile -Path $Path
    }
    catch {
        throw "JSON 文件无效：$Path`n$($_.Exception.Message)"
    }
}

function Format-JsonText {
    param(
        [Parameter(Mandatory)][string]$Text,
        [int]$IndentSize = 2
    )

    $builder = [System.Text.StringBuilder]::new()
    $indent = 0
    $inString = $false
    $escaping = $false
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($inString) {
            [void]$builder.Append($character)
            if ($escaping) { $escaping = $false }
            elseif ($character -eq '\') { $escaping = $true }
            elseif ($character -eq '"') { $inString = $false }
            continue
        }

        if ([char]::IsWhiteSpace($character)) { continue }
        if ($character -eq '"') {
            $inString = $true
            [void]$builder.Append($character)
            continue
        }
        if ($character -eq '{' -or $character -eq '[') {
            [void]$builder.Append($character)
            $next = $index + 1
            while ($next -lt $Text.Length -and [char]::IsWhiteSpace($Text[$next])) { $next++ }
            $closing = if ($character -eq '{') { '}' } else { ']' }
            if ($next -lt $Text.Length -and $Text[$next] -eq $closing) { continue }
            $indent++
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            continue
        }
        if ($character -eq '}' -or $character -eq ']') {
            $previous = $index - 1
            while ($previous -ge 0 -and [char]::IsWhiteSpace($Text[$previous])) { $previous-- }
            $opening = if ($character -eq '}') { '{' } else { '[' }
            if ($previous -ge 0 -and $Text[$previous] -eq $opening) {
                [void]$builder.Append($character)
                continue
            }
            $indent--
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            [void]$builder.Append($character)
            continue
        }
        if ($character -eq ',') {
            [void]$builder.Append($character)
            [void]$builder.Append("`n")
            [void]$builder.Append(''.PadLeft($indent * $IndentSize))
            continue
        }
        if ($character -eq ':') {
            [void]$builder.Append(': ')
            continue
        }
        [void]$builder.Append($character)
    }
    return $builder.ToString()
}

function Write-JsonAtomically {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = "$Path.$PID.tmp"
    try {
        $compactJson = $Value | ConvertTo-Json -Depth 100 -Compress
        $json = Format-JsonText -Text $compactJson
        [System.IO.File]::WriteAllText($temporaryPath, "$json`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Value)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-RoutingParserFingerprint {
    if ($script:ParserFingerprint) { return $script:ParserFingerprint }
    $updaterHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $validatorHash = (Get-FileHash -LiteralPath (Join-Path $script:ProjectRoot 'scripts\Json-Validation.ps1') -Algorithm SHA256).Hash
    $compilerHash = (Get-FileHash -LiteralPath (Join-Path $script:ProjectRoot 'src\RoutingRuleCompiler.cs') -Algorithm SHA256).Hash
    $domainCompilerHash = (Get-FileHash -LiteralPath (Join-Path $script:ProjectRoot 'src\SameTypeDirectCompiler.cs') -Algorithm SHA256).Hash
    $parts = @(
        'routing-parser-v2'
        $updaterHash
        $validatorHash
        $compilerHash
        $domainCompilerHash
        [string]$PSVersionTable.PSVersion
        [string][Globalization.CultureInfo]::CurrentCulture.Name
    )
    $script:ParserFingerprint = Get-Sha256Text ($parts -join ':')
    return $script:ParserFingerprint
}

function Save-ParsedSourceCache {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SourceHash,
        [Parameter(Mandatory)][string]$ParserFingerprint,
        [Parameter(Mandatory)][string]$Format,
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][object[]]$Items,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Ignored
    )
    try {
        [RoutingRuleBatch]::WriteParsedCache($Path, $SourceHash, $ParserFingerprint, $Format, $Tag, $Items, $Ignored)
    }
    catch {
        Write-Verbose "解析缓存未写入 '$Path'：$($_.Exception.Message)"
    }
}

function Test-StrictJsonInteger {
    param($Value, [long]$Minimum = 0, [long]$Maximum = 10000000)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
        $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return $false }
    $typeCode = [Type]::GetTypeCode($Value.GetType())
    if ($typeCode -notin @([TypeCode]::Byte,[TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::UInt16,[TypeCode]::Int32,[TypeCode]::UInt32,[TypeCode]::Int64,[TypeCode]::UInt64)) { return $false }
    try { $number = [long]$Value } catch { return $false }
    return $number -ge $Minimum -and $number -le $Maximum
}

function Test-RoutingMergeCachePayload {
    param([Parameter(Mandatory)]$Payload, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ManifestRules)
    if ($Payload -is [array] -or $null -eq $Payload) { return $false }
    $required = @('groups','extracted','retained','removed','interval_adjusted','interval_split_fragments','ignored','report_groups','removal_samples','ignored_items')
    foreach ($name in $required) { if (-not $Payload.PSObject.Properties[$name]) { return $false } }
    foreach ($name in @('groups','report_groups','removal_samples','ignored_items')) {
        if (-not ($Payload.$name -is [array])) { return $false }
    }
    foreach ($name in @('extracted','retained','removed','interval_adjusted','interval_split_fragments','ignored')) {
        if (-not (Test-StrictJsonInteger $Payload.$name)) { return $false }
    }
    if ($Payload.groups.Count -gt $ManifestRules.Count -or $Payload.report_groups.Count -ne $ManifestRules.Count -or
        $Payload.removal_samples.Count -gt 1000 -or $Payload.removal_samples.Count -gt [long]$Payload.removed -or
        $Payload.ignored_items.Count -ne [long]$Payload.ignored) { return $false }

    $sumExtracted = [long]0
    $sumRetained = [long]0
    $nonemptyReports = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $Payload.report_groups.Count; $index++) {
        $report = $Payload.report_groups[$index]
        $expected = $ManifestRules[$index]
        if (-not $report.PSObject.Properties['sequence'] -or -not (Test-StrictJsonInteger $report.sequence 1 10000000) -or
            [long]$report.sequence -ne ($index + 1) -or [string]$report.id -cne [string]$expected.id -or
            [string]$report.action -cne [string]$expected.action -or
            -not (Test-StrictJsonInteger $report.extracted) -or -not (Test-StrictJsonInteger $report.retained)) { return $false }
        $sumExtracted += [long]$report.extracted
        $sumRetained += [long]$report.retained
        if ([long]$report.retained -gt 0) { $nonemptyReports.Add($report) }
    }
    if ($sumExtracted -ne [long]$Payload.extracted -or $sumRetained -ne [long]$Payload.retained -or
        $nonemptyReports.Count -ne $Payload.groups.Count) { return $false }

    $seenTags = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $Payload.groups.Count; $index++) {
        $group = $Payload.groups[$index]
        $report = $nonemptyReports[$index]
        $expectedTag = 'routing-' + ([string]$report.id -replace '[^A-Za-z0-9_-]', '-')
        if (-not ($group.tag -is [string]) -or [string]$group.tag -cne $expectedTag -or -not $seenTags.Add([string]$group.tag) -or
            -not (Test-StrictJsonInteger $group.sequence 1 10000000) -or [long]$group.sequence -ne [long]$report.sequence -or
            -not ($group.id -is [string]) -or [string]$group.id -cne [string]$report.id -or
            -not ($group.action -is [string]) -or [string]$group.action -cne [string]$report.action -or -not ($group.has_domain -is [bool]) -or
            -not ($group.rules -is [array]) -or $group.rules.Count -lt 1 -or $group.rules.Count -gt 4) { return $false }
        $hasDomain = $false
        foreach ($rule in $group.rules) {
            if ($rule -is [array] -or $null -eq $rule) { return $false }
            $fields = @($rule.PSObject.Properties.Name)
            if ($fields.Count -lt 1) { return $false }
            foreach ($field in $fields) {
                if ($field -notin @('domain','domain_suffix','domain_regex','ip_cidr','port','port_range','source_port','source_port_range')) { return $false }
                $values = $rule.PSObject.Properties[$field].Value
                if (-not ($values -is [array]) -or $values.Count -lt 1) { return $false }
                if ($field -in @('domain','domain_suffix')) {
                    $hasDomain = $true
                    foreach ($value in $values) {
                        if (-not ($value -is [string]) -or $value -notmatch '^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$') { return $false }
                    }
                }
                elseif ($field -eq 'domain_regex') {
                    if ($group.action -cne 'reject') { return $false }
                    $hasDomain = $true
                    foreach ($value in $values) {
                        if ($value -isnot [string] -or $value -cnotmatch '^\(\?i\)\^.+\$$') { return $false }
                    }
                }
                elseif ($field -eq 'ip_cidr') {
                    foreach ($value in $values) {
                        if (-not ($value -is [string]) -or $value -notmatch '^([^/]+)/([0-9]{1,2})$') { return $false }
                        $address = $null
                        if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [int]$Matches[2] -gt 32) { return $false }
                    }
                }
                elseif ($field -in @('port','source_port')) {
                    foreach ($value in $values) { if (-not (Test-StrictJsonInteger $value 0 65535)) { return $false } }
                }
                else {
                    foreach ($value in $values) { if (-not ($value -is [string]) -or $value -notmatch '^(?:[0-9]{1,5}):(?:[0-9]{1,5})$') { return $false } }
                }
            }
        }
        if ([bool]$group.has_domain -ne $hasDomain) { return $false }
    }
    foreach ($item in $Payload.ignored_items) {
        if (-not $item.PSObject.Properties['Source'] -or -not $item.PSObject.Properties['Value'] -or -not $item.PSObject.Properties['Reason'] -or
            -not ($item.Source -is [string]) -or -not ($item.Value -is [string]) -or -not ($item.Reason -is [string])) { return $false }
        if ($item.PSObject.Properties['Line'] -and -not (Test-StrictJsonInteger $item.Line 1 100000000)) { return $false }
    }
    foreach ($sample in $Payload.removal_samples) {
        foreach ($name in @('Kind','Value','RemovedGroup','RemovedAction','KeptGroup','KeptAction','Reason')) {
            if (-not $sample.PSObject.Properties[$name] -or -not ($sample.$name -is [string])) { return $false }
        }
        if ($sample.Reason -notin @('duplicate','covered')) { return $false }
    }
    return $true
}

function Get-ResponseHeaderValue {
    param(
        $Response,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Response -or $null -eq $Response.Headers) { return '' }
    try {
        $value = $Response.Headers[$Name]
        if ($null -ne $value) {
            if (($value -is [System.Collections.IEnumerable]) -and -not ($value -is [string])) {
                return (@($value) -join ', ')
            }
            return [string]$value
        }
    }
    catch {
    }
    try {
        $values = $null
        if ($Response.Headers.TryGetValues($Name, [ref]$values)) {
            return (@($values) -join ', ')
        }
    }
    catch {
    }
    return ''
}

function Get-WebRequestTimeoutArguments {
    param([System.Collections.IDictionary]$Parameters = (Get-Command Invoke-WebRequest).Parameters)
    $arguments = @{ TimeoutSec = 180 }
    # In modern PowerShell TimeoutSec aliases only the connection timeout.
    if ($Parameters.Keys -contains 'OperationTimeoutSeconds') { $arguments['OperationTimeoutSeconds'] = 180 }
    return $arguments
}

function New-ValidatedRemoteResourcePlan {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources,
        [Parameter(Mandatory)][System.Collections.IDictionary]$SelectorsByResource,
        [Parameter(Mandatory)][string]$CacheRoot
    )
    $allowedFormats = @('plain','dnsmasq','adguard-dns','clash-yaml','mrs-domain','mrs-ipcidr','geosite-dat','geoip-dat')
    $seenTags = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenUrls = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenDestinations = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $plans = New-Object 'System.Collections.Generic.List[object]'
    foreach ($resource in $Resources) {
        $tag = [string]$resource.tag
        $format = [string]$resource.format
        $url = [string]$resource.url
        if ($tag -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$' -or -not $seenTags.Add($tag)) { throw "资源 tag 无效或重复：$tag" }
        if ([string]$resource.type -cne 'remote') { throw "资源 '$tag' 的 type 必须是 remote。" }
        if ($format -notin $allowedFormats) { throw "资源 '$tag' 使用了不支持的远程格式 '$format'。" }
        $uri = $null
        if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) {
            throw "资源 '$tag' URL 必须是无凭据的绝对 HTTP(S) 地址。"
        }
        if (-not $seenUrls.Add($uri.AbsoluteUri)) { throw "远程资源 URL 重复：$($uri.AbsoluteUri)" }
        $selectors = @()
        if ($SelectorsByResource.Contains($tag)) { $selectors = @($SelectorsByResource[$tag]) }
        if ($format -in @('geosite-dat','geoip-dat')) {
            if ($selectors.Count -eq 0) { throw "Geo 资源 '$tag' 没有选择器。" }
            $seenSelectors = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach ($selector in $selectors) {
                if ([string]$selector -notmatch '^[A-Za-z0-9_.@!-]+$' -or -not $seenSelectors.Add([string]$selector)) { throw "Geo 资源 '$tag' 选择器无效或重复。" }
            }
        }
        elseif ($selectors.Count -gt 0) { throw "非 Geo 资源 '$tag' 不得带选择器。" }
        $extension = [IO.Path]::GetExtension($uri.AbsolutePath)
        if (-not $extension) { $extension = '.bin' }
        $cachePath = Join-Path $CacheRoot ($tag + $extension.ToLowerInvariant())
        $metadataPath = Join-Path $CacheRoot ($tag + '.metadata.json')
        $destinationKey = [IO.Path]::GetFullPath($cachePath)
        if (-not $seenDestinations.Add($destinationKey)) { throw "远程资源缓存路径冲突：$destinationKey" }
        $plans.Add([PSCustomObject]@{
            Resource = $resource
            Tag = $tag
            Format = $format
            Url = $url
            Selectors = [string[]]$selectors
            CachePath = $cachePath
            MetadataPath = $metadataPath
        })
    }
    return $plans.ToArray()
}

function Remove-RoutingFetchStage {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$CacheRoot)
    if (-not [IO.Directory]::Exists($Path)) { return }
    $fullRoot = [IO.Path]::GetFullPath($CacheRoot).TrimEnd([char[]]'\/')
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
    if ((Split-Path -Parent $fullPath) -cne $fullRoot -or (Split-Path -Leaf $fullPath) -notlike '.routing-fetch-*') {
        throw "拒绝清理非本次远程暂存目录：$fullPath"
    }
    $items = @(Get-ChildItem -LiteralPath $fullPath -Recurse -Force -ErrorAction Stop)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) {
        throw "远程暂存目录含重解析点，拒绝递归清理：$fullPath"
    }
    Remove-Item -LiteralPath $fullPath -Recurse -Force
    if ([IO.Directory]::Exists($fullPath) -or [IO.File]::Exists($fullPath)) { throw "远程暂存目录清理后仍然存在：$fullPath" }
}

function Assert-SafeConditionalHeaderValue {
    param([AllowNull()][string]$Value,[Parameter(Mandatory)][string]$ResourceTag,[Parameter(Mandatory)][string]$HeaderName)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    if ($Value -match '[\x00-\x1F\x7F]') { throw "Cached conditional header '$HeaderName' for '$ResourceTag' contains a control character." }
    return $Value
}

function Write-CurlConditionalHeaderFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ResourceTag,
        [AllowNull()][string]$ETag,
        [AllowNull()][string]$LastModified
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $safeETag = Assert-SafeConditionalHeaderValue -Value $ETag -ResourceTag $ResourceTag -HeaderName 'If-None-Match'
    $safeLastModified = Assert-SafeConditionalHeaderValue -Value $LastModified -ResourceTag $ResourceTag -HeaderName 'If-Modified-Since'
    if ($safeETag) { $lines.Add('If-None-Match: ' + $safeETag) }
    if ($safeLastModified) { $lines.Add('If-Modified-Since: ' + $safeLastModified) }
    if ($lines.Count -eq 0) { return $false }
    [IO.File]::WriteAllLines($Path,$lines.ToArray(),[Text.UTF8Encoding]::new($false))
    return $true
}

function Assert-RoutingFetchPathsSupported {
    param([Parameter(Mandatory)][string]$CachePath,[Parameter(Mandatory)][int]$ResourceCount)
    if ($ResourceCount -lt 0) { throw 'Routing fetch resource count cannot be negative.' }
    if ($ResourceCount -eq 0) { return }
    if ($env:OS -ne 'Windows_NT' -or [int]$PSVersionTable.PSVersion.Major -gt 5) { return }

    # Windows PowerShell 5.1 may report ordinary MAX_PATH files as missing.
    # Check every future path before locks, stages, or network requests begin.
    try {
        $fullCachePath = [IO.Path]::GetFullPath($CachePath)
        $pathRoot = [IO.Path]::GetPathRoot($fullCachePath)
        if (-not [string]::Equals($fullCachePath, $pathRoot, [StringComparison]::OrdinalIgnoreCase)) {
            $fullCachePath = $fullCachePath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        }
    }
    catch { throw "Windows PowerShell 5.1 cannot normalize the routing fetch root before any transaction writes: $($_.Exception.Message)" }
    $fullCacheRoot = $fullCachePath + '.update.stage'
    $fetchRoot = Join-Path $fullCacheRoot ('.routing-fetch-' + ('0' * 32))
    if ($fetchRoot.Length -ge 248) {
        throw "Windows PowerShell 5.1 fetch directory exceeds the legacy path limit ($($fetchRoot.Length) characters): $fetchRoot"
    }
    for ($index = 0; $index -lt $ResourceCount; $index++) {
        $stem = 'r' + $index.ToString([Globalization.CultureInfo]::InvariantCulture)
        foreach ($suffix in @('.d','.h','.h.request')) {
            $candidate = [IO.Path]::GetFullPath((Join-Path $fetchRoot ($stem + $suffix)))
            if ($candidate.Length -ge 260) {
                throw "Windows PowerShell 5.1 fetch file exceeds MAX_PATH ($($candidate.Length) characters): $candidate"
            }
        }
    }
}

function Invoke-RoutingResourceFetches {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ResourcePlan,
        [Parameter(Mandatory)][int]$Concurrency,
        [Parameter(Mandatory)][string]$CacheRoot
    )
    if ($ResourcePlan.Count -eq 0) { return [PSCustomObject]@{ Root=''; Results=[object[]]@() } }
    $conditionalHeaders = New-Object 'object[]' $ResourcePlan.Count
    for ($index = 0; $index -lt $ResourcePlan.Count; $index++) {
        $resource = $ResourcePlan[$index]
        $etag = ''; $lastModified = ''
        if ((Test-Path -LiteralPath $resource.MetadataPath -PathType Leaf) -and (Test-Path -LiteralPath $resource.CachePath -PathType Leaf)) {
            $metadata = $null
            try { $metadata = Read-JsonFile $resource.MetadataPath } catch { $metadata = $null }
            if ($metadata -and $metadata.PSObject.Properties['url'] -and $metadata.PSObject.Properties['sha256'] -and
                [string]$metadata.url -ceq [string]$resource.Url -and [string]$metadata.sha256 -match '^[0-9a-fA-F]{64}$') {
                $etagProperty = $metadata.PSObject.Properties['etag']
                $lastModifiedProperty = $metadata.PSObject.Properties['last_modified']
                if ($etagProperty -and $etagProperty.Value -is [string]) {
                    $etag = Assert-SafeConditionalHeaderValue -Value ([string]$etagProperty.Value) -ResourceTag ([string]$resource.Tag) -HeaderName 'If-None-Match'
                }
                if ($lastModifiedProperty -and $lastModifiedProperty.Value -is [string]) {
                    $lastModified = Assert-SafeConditionalHeaderValue -Value ([string]$lastModifiedProperty.Value) -ResourceTag ([string]$resource.Tag) -HeaderName 'If-Modified-Since'
                }
            }
        }
        $conditionalHeaders[$index] = [PSCustomObject]@{ETag=$etag;LastModified=$lastModified}
    }
    $fetchRoot = Join-Path $CacheRoot ('.routing-fetch-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fetchRoot -Force | Out-Null
    $curlCommand = Get-Command 'curl.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $curlPath = if ($curlCommand) { $curlCommand.Source } else { '' }
    $worker = {
        param([string]$Url, [string]$DownloadPath, [string]$HeaderPath, [string]$CurlPath, [string]$ETag, [string]$LastModified)
        $ErrorActionPreference = 'Stop'
        if ($CurlPath) {
            try {
            $curlArgs = @('-sS','-L','--retry','3','--retry-delay','2','--max-time','180','--dump-header',$HeaderPath,'--output',$DownloadPath,'--write-out','%{http_code}')
            $requestHeaderPath = $HeaderPath + '.request'
            $requestHeaderLines = New-Object 'System.Collections.Generic.List[string]'
            if ($ETag) {
                if ($ETag -match '[\x00-\x1F\x7F]') { throw 'Cached If-None-Match header contains a control character.' }
                $requestHeaderLines.Add('If-None-Match: ' + $ETag)
            }
            if ($LastModified) {
                if ($LastModified -match '[\x00-\x1F\x7F]') { throw 'Cached If-Modified-Since header contains a control character.' }
                $requestHeaderLines.Add('If-Modified-Since: ' + $LastModified)
            }
            if ($requestHeaderLines.Count -gt 0) {
                [IO.File]::WriteAllLines($requestHeaderPath,$requestHeaderLines.ToArray(),[Text.UTF8Encoding]::new($false))
                $curlArgs += @('--header',('@' + $requestHeaderPath))
            }
            $curlArgs += $Url
            $curlOutput = @(& $CurlPath @curlArgs 2>&1)
            $curlExit = $LASTEXITCODE
            if ($curlExit -ne 0) { throw ('curl exit ' + $curlExit + ': ' + (($curlOutput | Out-String).Trim())) }
            $statusText = (($curlOutput | Out-String).Trim() -split '\s+')[-1]
            if ($statusText -notmatch '^\d{3}$') { throw ('curl returned no HTTP status: ' + (($curlOutput | Out-String).Trim())) }
            $statusCode = [int]$statusText
            $headers = @(Get-Content -LiteralPath $HeaderPath -ErrorAction SilentlyContinue)
            $etagResult = ''; $modifiedResult = ''
            foreach ($line in $headers) {
                if ($line -match '^ETag:\s*(.*)$') { $etagResult = $Matches[1].Trim() }
                elseif ($line -match '^Last-Modified:\s*(.*)$') { $modifiedResult = $Matches[1].Trim() }
            }
            if ($statusCode -notin @(200,304)) { throw ('HTTP ' + $statusCode) }
            return [PSCustomObject]@{ StatusCode=$statusCode; ETag=$etagResult; LastModified=$modifiedResult; DownloadPath=$DownloadPath; Error='' }
            }
            finally {
                if ([IO.File]::Exists($HeaderPath)) { [IO.File]::Delete($HeaderPath) }
                if ([IO.File]::Exists($HeaderPath + '.request')) { [IO.File]::Delete($HeaderPath + '.request') }
            }
        }

        $requestHeaders = @{}
        if ($ETag) { $requestHeaders['If-None-Match'] = $ETag }
        if ($LastModified) { $requestHeaders['If-Modified-Since'] = $LastModified }
        $statusCode = 0; $response = $null
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            $requestArguments = @{ Uri=$Url; OutFile=$DownloadPath; TimeoutSec=180; UseBasicParsing=$true; PassThru=$true }
            if ($requestHeaders.Count -gt 0) { $requestArguments['Headers'] = $requestHeaders }
            if ((Get-Command Invoke-WebRequest).Parameters.Keys -contains 'OperationTimeoutSeconds') { $requestArguments['OperationTimeoutSeconds'] = 180 }
            try {
                $response = Invoke-WebRequest @requestArguments
                $statusCode = [int]$response.StatusCode
                break
            }
            catch {
                $response = $null
                $responseProperty = $_.Exception.PSObject.Properties['Response']
                if ($responseProperty) { $response = $responseProperty.Value }
                if ($response) { try { $statusCode = [int]$response.StatusCode } catch { $statusCode = 0 } }
                if ($statusCode -eq 304) { break }
                $retryable = $statusCode -in @(0,408,429,500,502,503,504)
                if ($attempt -ge 4 -or -not $retryable) { throw }
                Start-Sleep -Seconds 2
            }
        }
        if ($statusCode -notin @(200,304)) { throw ('HTTP ' + $statusCode) }
        $etagResult = ''; $modifiedResult = ''
        if ($response -and $response.Headers) {
            try { $etagResult = [string]$response.Headers['ETag'] } catch { }
            try { $modifiedResult = [string]$response.Headers['Last-Modified'] } catch { }
        }
        return [PSCustomObject]@{ StatusCode=$statusCode; ETag=$etagResult; LastModified=$modifiedResult; DownloadPath=$DownloadPath; Error='' }
    }

    $pool = $null
    $pending = New-Object 'System.Collections.Generic.List[object]'
    $results = New-Object 'object[]' $ResourcePlan.Count
    $failures = New-Object 'System.Collections.Generic.List[string]'
    try {
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Concurrency)
        $pool.Open()
        for ($index = 0; $index -lt $ResourcePlan.Count; $index++) {
            $resource = $ResourcePlan[$index]
            $fileStem = 'r' + $index.ToString([Globalization.CultureInfo]::InvariantCulture)
            $downloadPath = Join-Path $fetchRoot ($fileStem + '.d')
            $headerPath = Join-Path $fetchRoot ($fileStem + '.h')
            $etag = [string]$conditionalHeaders[$index].ETag
            $lastModified = [string]$conditionalHeaders[$index].LastModified
            $powershell = [PowerShell]::Create()
            $powershell.RunspacePool = $pool
            $null = $powershell.AddScript($worker.ToString()).AddArgument([string]$resource.Url).AddArgument($downloadPath).AddArgument($headerPath).AddArgument($curlPath).AddArgument($etag).AddArgument($lastModified)
            $job = [PSCustomObject]@{ Index=$index; Tag=[string]$resource.Tag; PowerShell=$powershell; AsyncResult=$null }
            $pending.Add($job)
            $job.AsyncResult = $powershell.BeginInvoke()
        }
    }
    catch {
        $failures.Add(('scheduling: ' + $_.Exception.Message))
    }
    finally {
        # Observe every started pipeline before EndInvoke/disposal and before the
        # caller can remove the shared fetch stage.
        foreach ($job in $pending) {
            if ($null -eq $job.AsyncResult) { continue }
            try { [void]$job.AsyncResult.AsyncWaitHandle.WaitOne() }
            catch { $failures.Add(($job.Tag + ': worker completion wait: ' + $_.Exception.Message)) }
        }
        foreach ($job in $pending) {
            if ($null -eq $job.AsyncResult) {
                try {
                    if ($job.PowerShell.InvocationStateInfo.State -in @('Running','Stopping')) { $job.PowerShell.Stop() }
                }
                catch { $failures.Add(($job.Tag + ': stop unscheduled worker: ' + $_.Exception.Message)) }
                finally { $job.PowerShell.Dispose() }
                continue
            }
            try {
                $output = @($job.PowerShell.EndInvoke($job.AsyncResult))
                if (@($job.PowerShell.Streams.Error).Count -gt 0) {
                    $failures.Add(($job.Tag + ': ' + (($job.PowerShell.Streams.Error | ForEach-Object { $_.ToString() }) -join '; ')))
                }
                elseif ($output.Count -eq 1) { $results[$job.Index] = $output[0] }
                else { $failures.Add(($job.Tag + ': worker returned an invalid result count')) }
            }
            catch { $failures.Add(($job.Tag + ': ' + $_.Exception.Message)) }
            finally { $job.PowerShell.Dispose() }
        }
        if ($pool) { $pool.Close(); $pool.Dispose() }
    }
    if ($failures.Count -gt 0) {
        try { Remove-RoutingFetchStage -Path $fetchRoot -CacheRoot $CacheRoot } catch { $failures.Add(('fetch cleanup: ' + $_.Exception.Message)) }
        throw ('远程资源并发下载失败，未回退到旧缓存：' + ($failures -join ' | '))
    }
    return [PSCustomObject]@{ Root=$fetchRoot; Results=$results }
}

function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory)][hashtable]$Arguments,
        [int]$MaximumAttempts = 4,
        [int]$RetryDelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        try {
            return Invoke-WebRequest @Arguments
        }
        catch {
            $statusCode = 0
            $responseProperty = $_.Exception.PSObject.Properties['Response']
            if ($responseProperty -and $null -ne $responseProperty.Value) {
                try { $statusCode = [int]$responseProperty.Value.StatusCode } catch { $statusCode = 0 }
            }
            $retryableStatus = $statusCode -in @(0, 408, 429, 500, 502, 503, 504)
            if ($attempt -ge $MaximumAttempts -or -not $retryableStatus) { throw }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Assert-CachedSourceIntegrity {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$CachePath,
        $Metadata
    )

    if (-not (Test-Path -LiteralPath $CachePath -PathType Leaf)) {
        throw "规则资源 '$($Resource.tag)' 缓存文件不存在。"
    }
    if ($null -eq $Metadata -or [string]$Metadata.url -cne [string]$Resource.url -or [string]$Metadata.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw "规则资源 '$($Resource.tag)' 缓存缺少可信来源或哈希。"
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $CachePath).Hash
    if (-not [string]::Equals($actualHash, [string]$Metadata.sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "规则资源 '$($Resource.tag)' 本地缓存哈希与元数据不一致。"
    }
    return $actualHash
}

function Get-RemoteSource {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$CacheRoot,
        [string[]]$Selectors = @(),
        [string]$ZstdPath,
        [switch]$UseCacheOnly
    )

    New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
    $uri = [Uri][string]$Resource.url
    $extension = [System.IO.Path]::GetExtension($uri.AbsolutePath)
    if (-not $extension) { $extension = '.bin' }
    $cachePath = Join-Path $CacheRoot ([string]$Resource.tag + $extension.ToLowerInvariant())
    $metadataPath = Join-Path $CacheRoot ([string]$Resource.tag + '.metadata.json')

    if ($UseCacheOnly) {
        $metadata = if (Test-Path -LiteralPath $metadataPath -PathType Leaf) { Read-JsonFile $metadataPath } else { $null }
        $null = Assert-CachedSourceIntegrity -Resource $Resource -CachePath $cachePath -Metadata $metadata
        $script:RemoteStates[[string]$Resource.tag] = 'offline-cache'
    }
    else {
        $temporaryPath = "$cachePath.$PID.tmp"
        $headerPath = "$cachePath.$PID.headers.tmp"
        $requestHeaderPath = "$headerPath.request"
        try {
            $metadata = $null
            if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
                try { $metadata = Read-JsonFile $metadataPath } catch { $metadata = $null }
            }
            $canRequestConditionally = $metadata -and $metadata.url -eq $Resource.url -and (Test-Path -LiteralPath $cachePath -PathType Leaf)
            $curl = Get-Command 'curl.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($curl) {
                $arguments = @(
                    '-sS', '-L', '--retry', '3', '--retry-delay', '2', '--max-time', '180',
                    '--dump-header', $headerPath,
                    '--output', $temporaryPath,
                    '--write-out', '%{http_code}'
                )
                if ($canRequestConditionally) {
                    $etagProperty = $metadata.PSObject.Properties['etag']
                    $lastModifiedProperty = $metadata.PSObject.Properties['last_modified']
                    $conditionalETag = if ($etagProperty -and $etagProperty.Value -is [string]) { [string]$etagProperty.Value } else { '' }
                    $conditionalLastModified = if ($lastModifiedProperty -and $lastModifiedProperty.Value -is [string]) { [string]$lastModifiedProperty.Value } else { '' }
                    if (Write-CurlConditionalHeaderFile -Path $requestHeaderPath -ResourceTag ([string]$Resource.tag) -ETag $conditionalETag -LastModified $conditionalLastModified) {
                        $arguments += @('--header',('@' + $requestHeaderPath))
                    }
                }
                $arguments += [string]$Resource.url
                $httpCode = ((& $curl.Source @arguments) | Out-String).Trim()
                if ($LASTEXITCODE -ne 0) { throw "curl 退出码 $LASTEXITCODE" }

                if ($httpCode -eq '304') {
                    if (-not (Test-Path -LiteralPath $cachePath -PathType Leaf)) {
                        throw '服务器返回 304，但本地缓存不存在。'
                    }
                    $cacheHash = Assert-CachedSourceIntegrity -Resource $Resource -CachePath $cachePath -Metadata $metadata
                    $headerLines = @(Get-Content -LiteralPath $headerPath -ErrorAction SilentlyContinue)
                    $etagLine = $headerLines | Where-Object { $_ -match '^ETag:' } | Select-Object -Last 1
                    $modifiedLine = $headerLines | Where-Object { $_ -match '^Last-Modified:' } | Select-Object -Last 1
                    $newMetadata = [ordered]@{
                        url = [string]$Resource.url
                        etag = if ($etagLine) { ($etagLine -replace '^ETag:\s*', '').Trim() } elseif ($metadata) { [string]$metadata.etag } else { '' }
                        last_modified = if ($modifiedLine) { ($modifiedLine -replace '^Last-Modified:\s*', '').Trim() } elseif ($metadata) { [string]$metadata.last_modified } else { '' }
                        sha256 = $cacheHash
                        checked_at = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-JsonAtomically -Value $newMetadata -Path $metadataPath
                    $script:RemoteStates[[string]$Resource.tag] = 'unchanged'
                }
                elseif ($httpCode -eq '200') {
                    if ((Get-Item -LiteralPath $temporaryPath).Length -eq 0) {
                        throw '服务器返回了空文件。'
                    }
                    Assert-RemoteSource -Resource $Resource -Path $temporaryPath -Selectors $Selectors -ZstdPath $ZstdPath
                    Assert-SourceCountChange -Resource $Resource -NewPath $temporaryPath -OldPath $cachePath -Selectors $Selectors -ZstdPath $ZstdPath
                    Move-Item -LiteralPath $temporaryPath -Destination $cachePath -Force
                    $headerLines = @(Get-Content -LiteralPath $headerPath -ErrorAction SilentlyContinue)
                    $etagLine = $headerLines | Where-Object { $_ -match '^ETag:' } | Select-Object -Last 1
                    $modifiedLine = $headerLines | Where-Object { $_ -match '^Last-Modified:' } | Select-Object -Last 1
                    $newMetadata = [ordered]@{
                        url = [string]$Resource.url
                        etag = if ($etagLine) { ($etagLine -replace '^ETag:\s*', '').Trim() } else { '' }
                        last_modified = if ($modifiedLine) { ($modifiedLine -replace '^Last-Modified:\s*', '').Trim() } else { '' }
                        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $cachePath).Hash
                        checked_at = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-JsonAtomically -Value $newMetadata -Path $metadataPath
                    $script:RemoteStates[[string]$Resource.tag] = 'updated'
                }
                else {
                    throw "服务器返回 HTTP $httpCode"
                }
            }
            else {
                $requestHeaders = @{}
                if ($canRequestConditionally) {
                    if ($metadata.etag) { $requestHeaders['If-None-Match'] = [string]$metadata.etag }
                    if ($metadata.last_modified) { $requestHeaders['If-Modified-Since'] = [string]$metadata.last_modified }
                }
                $invokeArguments = @{
                    Uri = [string]$Resource.url
                    OutFile = $temporaryPath
                    TimeoutSec = 180
                    UseBasicParsing = $true
                    PassThru = $true
                }
                foreach ($timeout in (Get-WebRequestTimeoutArguments).GetEnumerator()) { $invokeArguments[$timeout.Key] = $timeout.Value }
                if ($requestHeaders.Count -gt 0) { $invokeArguments['Headers'] = $requestHeaders }

                $response = $null
                $httpCode = 0
                try {
                    $response = Invoke-WebRequestWithRetry -Arguments $invokeArguments
                    $httpCode = [int]$response.StatusCode
                }
                catch {
                    $errorResponse = $null
                    $responseProperty = $_.Exception.PSObject.Properties['Response']
                    if ($responseProperty) { $errorResponse = $responseProperty.Value }
                    if ($null -ne $errorResponse) {
                        try { $httpCode = [int]$errorResponse.StatusCode } catch { $httpCode = 0 }
                    }
                    if ($httpCode -ne 304) { throw }
                    $response = $errorResponse
                }

                if ($httpCode -eq 304) {
                    if (-not (Test-Path -LiteralPath $cachePath -PathType Leaf)) {
                        throw '服务器返回 304，但本地缓存不存在。'
                    }
                    $cacheHash = Assert-CachedSourceIntegrity -Resource $Resource -CachePath $cachePath -Metadata $metadata
                    $etag = Get-ResponseHeaderValue -Response $response -Name 'ETag'
                    $lastModified = Get-ResponseHeaderValue -Response $response -Name 'Last-Modified'
                    $newMetadata = [ordered]@{
                        url = [string]$Resource.url
                        etag = if ($etag) { $etag } else { [string]$metadata.etag }
                        last_modified = if ($lastModified) { $lastModified } else { [string]$metadata.last_modified }
                        sha256 = $cacheHash
                        checked_at = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-JsonAtomically -Value $newMetadata -Path $metadataPath
                    $script:RemoteStates[[string]$Resource.tag] = 'unchanged'
                }
                elseif ($httpCode -eq 200) {
                    if (-not (Test-Path -LiteralPath $temporaryPath -PathType Leaf) -or (Get-Item -LiteralPath $temporaryPath).Length -eq 0) {
                        throw '服务器返回了空文件。'
                    }
                    Assert-RemoteSource -Resource $Resource -Path $temporaryPath -Selectors $Selectors -ZstdPath $ZstdPath
                    Assert-SourceCountChange -Resource $Resource -NewPath $temporaryPath -OldPath $cachePath -Selectors $Selectors -ZstdPath $ZstdPath
                    Move-Item -LiteralPath $temporaryPath -Destination $cachePath -Force
                    $newMetadata = [ordered]@{
                        url = [string]$Resource.url
                        etag = Get-ResponseHeaderValue -Response $response -Name 'ETag'
                        last_modified = Get-ResponseHeaderValue -Response $response -Name 'Last-Modified'
                        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $cachePath).Hash
                        checked_at = [DateTime]::UtcNow.ToString('o')
                    }
                    Write-JsonAtomically -Value $newMetadata -Path $metadataPath
                    $script:RemoteStates[[string]$Resource.tag] = 'updated'
                }
                else {
                    throw "服务器返回 HTTP $httpCode"
                }
            }
        }
        catch {
            throw "更新规则资源 '$($Resource.tag)' 失败，已停止生成且未使用旧缓存：$($_.Exception.Message) 如需明确使用现有缓存，请指定 -Offline。"
        }
        finally {
            if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
            if (Test-Path -LiteralPath $headerPath) { Remove-Item -LiteralPath $headerPath -Force }
            if (Test-Path -LiteralPath $requestHeaderPath) { Remove-Item -LiteralPath $requestHeaderPath -Force }
        }
    }

    if (-not (Test-Path -LiteralPath $cachePath -PathType Leaf)) {
        throw "规则资源 '$($Resource.tag)' 没有可用缓存；请取消 -Offline 后重试。"
    }
    Assert-RemoteSource -Resource $Resource -Path $cachePath -Selectors $Selectors -ZstdPath $ZstdPath
    return $cachePath
}

function Get-RemoteResourceCachePath {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$CacheRoot
    )
    $uri = [Uri][string]$Resource.url
    $extension = [System.IO.Path]::GetExtension($uri.AbsolutePath)
    if (-not $extension) { $extension = '.bin' }
    return (Join-Path $CacheRoot ([string]$Resource.tag + $extension.ToLowerInvariant()))
}

function Resolve-ZstdLibrary {
    param([string]$RequestedPath)

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($RequestedPath) { $candidates.Add($RequestedPath) }
    $candidates.Add((Join-Path $script:ProjectRoot 'tools\libzstd.dll'))
    $candidates.Add('C:\Program Files\Git\mingw64\bin\libzstd.dll')
    $candidates.Add('C:\Program Files (x86)\Git\mingw64\bin\libzstd.dll')
    if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Git\mingw64\bin\libzstd.dll')) }
    $git = Get-Command 'git' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($git) {
        $gitRoot = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $git.Source) '..'))
        $candidates.Add((Join-Path $gitRoot 'mingw64\bin\libzstd.dll'))
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw '解析 MRS 需要 libzstd.dll。请安装 Git for Windows，或使用 -ZstdLibraryPath 指定该文件。'
}

function Initialize-MrsReader {
    if ('RoutingMrsReader' -as [type]) { return }

    $source = @'
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

public static class RoutingMrsReader {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong GetSize(IntPtr src, UIntPtr size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate ulong DecompressBoundFn(IntPtr src, UIntPtr size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate UIntPtr DecompressFn(IntPtr dst, UIntPtr capacity, IntPtr src, UIntPtr size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint IsErrorFn(UIntPtr code);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string fileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr module);

    private static IntPtr GetRequiredExport(IntPtr library, string name) {
        IntPtr address = GetProcAddress(library, name);
        if (address == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "找不到 Zstandard 导出函数：" + name);
        return address;
    }

    private static byte[] Decompress(string libraryPath, byte[] data) {
        IntPtr library = LoadLibraryW(libraryPath);
        if (library == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法加载 Zstandard 动态库：" + libraryPath);
        IntPtr source = IntPtr.Zero;
        IntPtr destination = IntPtr.Zero;
        try {
            var getSize = (GetSize)Marshal.GetDelegateForFunctionPointer(GetRequiredExport(library, "ZSTD_getFrameContentSize"), typeof(GetSize));
            var getBound = (DecompressBoundFn)Marshal.GetDelegateForFunctionPointer(GetRequiredExport(library, "ZSTD_decompressBound"), typeof(DecompressBoundFn));
            var decompress = (DecompressFn)Marshal.GetDelegateForFunctionPointer(GetRequiredExport(library, "ZSTD_decompress"), typeof(DecompressFn));
            var isError = (IsErrorFn)Marshal.GetDelegateForFunctionPointer(GetRequiredExport(library, "ZSTD_isError"), typeof(IsErrorFn));
            source = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, source, data.Length);
            ulong size = getSize(source, (UIntPtr)(uint)data.Length);
            if (size == ulong.MaxValue) size = getBound(source, (UIntPtr)(uint)data.Length);
            if (size == 0 || size == ulong.MaxValue || size == ulong.MaxValue - 1 || size > int.MaxValue) throw new InvalidOperationException("MRS Zstandard 内容长度无效。");
            destination = Marshal.AllocHGlobal((int)size);
            UIntPtr result = decompress(destination, (UIntPtr)size, source, (UIntPtr)(uint)data.Length);
            if (isError(result) != 0) throw new InvalidOperationException("MRS Zstandard 解压失败。");
            byte[] output = new byte[(int)result.ToUInt64()];
            Marshal.Copy(destination, output, 0, output.Length);
            return output;
        }
        finally {
            if (source != IntPtr.Zero) Marshal.FreeHGlobal(source);
            if (destination != IntPtr.Zero) Marshal.FreeHGlobal(destination);
            if (library != IntPtr.Zero) FreeLibrary(library);
        }
    }

    private static ulong ReadUInt64(byte[] data, ref int offset) {
        if (offset < 0 || offset + 8 > data.Length) throw new InvalidOperationException("MRS 数据提前结束。");
        ulong value = 0;
        for (int i = 0; i < 8; i++) value = (value << 8) | data[offset++];
        return value;
    }

    private static void ReadHeader(byte[] data, byte expectedBehavior, ref int offset, out int count) {
        if (data.Length < 21 || data[0] != (byte)'M' || data[1] != (byte)'R' || data[2] != (byte)'S' || data[3] != 1) throw new InvalidOperationException("MRS v1 文件头无效。");
        if (data[4] != expectedBehavior) throw new InvalidOperationException("MRS behavior 与资源声明不一致。");
        offset = 5;
        ulong rawCount = ReadUInt64(data, ref offset);
        if (rawCount > int.MaxValue) throw new InvalidOperationException("MRS 规则数量过大。");
        count = (int)rawCount;
        ulong extraLength = ReadUInt64(data, ref offset);
        if (extraLength > int.MaxValue || offset + (int)extraLength > data.Length) throw new InvalidOperationException("MRS extra 长度无效。");
        offset += (int)extraLength;
    }

    private static bool GetBit(ulong[] words, int index) {
        return (words[index >> 6] & (1UL << (index & 63))) != 0;
    }

    private static string ReverseTextElements(string value) {
        var elements = new List<string>();
        var enumerator = StringInfo.GetTextElementEnumerator(value);
        while (enumerator.MoveNext()) elements.Add((string)enumerator.Current);
        elements.Reverse();
        return string.Concat(elements);
    }

    public static string[] ReadDomains(string libraryPath, byte[] compressed) {
        byte[] data = Decompress(libraryPath, compressed);
        int offset = 0;
        int declaredCount;
        ReadHeader(data, 0, ref offset, out declaredCount);
        if (offset >= data.Length || data[offset++] != 1) throw new InvalidOperationException("MRS DomainSet 版本无效。");
        int leavesLength = checked((int)ReadUInt64(data, ref offset));
        if (leavesLength < 1) throw new InvalidOperationException("MRS leaves 为空。");
        ulong[] leaves = new ulong[leavesLength];
        for (int i = 0; i < leaves.Length; i++) leaves[i] = ReadUInt64(data, ref offset);
        int bitmapLength = checked((int)ReadUInt64(data, ref offset));
        if (bitmapLength < 1) throw new InvalidOperationException("MRS label bitmap 为空。");
        ulong[] bitmap = new ulong[bitmapLength];
        for (int i = 0; i < bitmap.Length; i++) bitmap[i] = ReadUInt64(data, ref offset);
        int labelsLength = checked((int)ReadUInt64(data, ref offset));
        if (labelsLength < 1 || offset + labelsLength > data.Length) throw new InvalidOperationException("MRS labels 长度无效。");
        byte[] labels = new byte[labelsLength];
        Buffer.BlockCopy(data, offset, labels, 0, labelsLength);

        int usedBits = checked(labelsLength * 2 + 1);
        var ones = new List<int>();
        int[] zerosBefore = new int[usedBits + 1];
        for (int i = 0; i < usedBits; i++) {
            bool bit = GetBit(bitmap, i);
            if (bit) ones.Add(i);
            zerosBefore[i + 1] = zerosBefore[i] + (bit ? 0 : 1);
        }
        if (ones.Count != labelsLength + 1) throw new InvalidOperationException("MRS LOUDS bitmap 结构无效。");

        var keys = new List<string>();
        var current = new List<byte>();
        Action<int, int> walk = null;
        walk = (nodeId, bitmapIndex) => {
            if (GetBit(leaves, nodeId)) keys.Add(ReverseTextElements(Encoding.UTF8.GetString(current.ToArray())));
            for (int i = bitmapIndex; ; i++) {
                if (GetBit(bitmap, i)) return;
                int labelIndex = i - nodeId;
                if (labelIndex < 0 || labelIndex >= labels.Length) throw new InvalidOperationException("MRS label 索引越界。");
                current.Add(labels[labelIndex]);
                int nextNodeId = zerosBefore[i + 1];
                int nextBitmapIndex = ones[nextNodeId - 1] + 1;
                walk(nextNodeId, nextBitmapIndex);
                current.RemoveAt(current.Count - 1);
            }
        };
        walk(0, 0);

        var set = new HashSet<string>(keys, StringComparer.Ordinal);
        var output = keys.Where(key => !set.Contains("+." + key)).Distinct(StringComparer.Ordinal).OrderBy(key => key, StringComparer.Ordinal).ToArray();
        if (output.Length > declaredCount) throw new InvalidOperationException("MRS 域名数量超过声明值。");
        return output;
    }

    private static uint ReadIPv4Mapped(byte[] data, ref int offset, out bool isIPv4) {
        if (offset + 16 > data.Length) throw new InvalidOperationException("MRS IP 数据提前结束。");
        isIPv4 = true;
        for (int i = 0; i < 10; i++) if (data[offset + i] != 0) isIPv4 = false;
        if (data[offset + 10] != 0xFF || data[offset + 11] != 0xFF) isIPv4 = false;
        uint value = ((uint)data[offset + 12] << 24) | ((uint)data[offset + 13] << 16) | ((uint)data[offset + 14] << 8) | data[offset + 15];
        offset += 16;
        return value;
    }

    private static int TrailingZeros(uint value) {
        if (value == 0) return 32;
        int count = 0;
        while ((value & 1) == 0) { value >>= 1; count++; }
        return count;
    }

    private static int FloorLog2(ulong value) {
        int result = -1;
        while (value > 0) { value >>= 1; result++; }
        return result;
    }

    private static string FormatIPv4(ulong value, int prefix) {
        return string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}/{4}", (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255, prefix);
    }

    public static string[] ReadIPv4Cidrs(string libraryPath, byte[] compressed) {
        byte[] data = Decompress(libraryPath, compressed);
        int offset = 0;
        int declaredCount;
        ReadHeader(data, 1, ref offset, out declaredCount);
        if (offset >= data.Length || data[offset++] != 1) throw new InvalidOperationException("MRS IP set 版本无效。");
        int rangeCount = checked((int)ReadUInt64(data, ref offset));
        if (rangeCount < 1) throw new InvalidOperationException("MRS IP range 为空。");
        var output = new List<string>();
        for (int i = 0; i < rangeCount; i++) {
            bool fromIPv4, toIPv4;
            uint from = ReadIPv4Mapped(data, ref offset, out fromIPv4);
            uint to = ReadIPv4Mapped(data, ref offset, out toIPv4);
            if (!fromIPv4 || !toIPv4) continue;
            ulong start = from;
            ulong end = to;
            if (start > end) throw new InvalidOperationException("MRS IPv4 range 反向。");
            while (start <= end) {
                int alignment = TrailingZeros((uint)start);
                int span = FloorLog2(end - start + 1);
                int hostBits = Math.Min(alignment, span);
                output.Add(FormatIPv4(start, 32 - hostBits));
                start += 1UL << hostBits;
            }
        }
        return output.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }
}
'@
    Add-Type -TypeDefinition $source -Language CSharp
}

function Initialize-GeoDataReader {
    if ('RoutingGeoDataReader' -as [type]) { return }

    $source = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

public static class RoutingGeoDataReader {
    private sealed class GeoSelector {
        public readonly string Selector;
        public readonly string Code;
        public readonly string Attribute;
        public GeoSelector(string selector, string code, string attribute) { Selector = selector; Code = code; Attribute = attribute; }
    }

    private static ulong ReadVarint(byte[] data, ref int offset, int end) {
        ulong value = 0;
        int shift = 0;
        while (offset < end && shift < 70) {
            byte current = data[offset++];
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return value;
            shift += 7;
        }
        throw new InvalidOperationException("GeoData varint 无效。");
    }

    private static void ReadSegment(byte[] data, ref int offset, int end, out int start, out int length) {
        ulong rawLength = ReadVarint(data, ref offset, end);
        if (rawLength > int.MaxValue || offset + (int)rawLength > end) throw new InvalidOperationException("GeoData 字段长度无效。");
        start = offset;
        length = (int)rawLength;
        offset += length;
    }

    private static void Skip(byte[] data, ref int offset, int end, int wire) {
        switch (wire) {
            case 0: ReadVarint(data, ref offset, end); return;
            case 1: if (offset + 8 > end) throw new InvalidOperationException("GeoData fixed64 越界。"); offset += 8; return;
            case 2: int start, length; ReadSegment(data, ref offset, end, out start, out length); return;
            case 5: if (offset + 4 > end) throw new InvalidOperationException("GeoData fixed32 越界。"); offset += 4; return;
            default: throw new InvalidOperationException("GeoData wire type 不受支持：" + wire.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static string ReadString(byte[] data, int start, int length) {
        return Encoding.UTF8.GetString(data, start, length);
    }

    private static string ParseAttribute(byte[] data, int start, int length, out bool enabled) {
        int offset = start;
        int end = start + length;
        string key = "";
        enabled = true;
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                key = ReadString(data, valueStart, valueLength);
            }
            else if (field == 2 && wire == 0) enabled = ReadVarint(data, ref offset, end) != 0;
            else Skip(data, ref offset, end, wire);
        }
        return key;
    }

    private static string ParseDomain(byte[] data, int start, int length, string requiredAttribute) {
        int offset = start;
        int end = start + length;
        int type = 0;
        string value = "";
        bool attributeMatched = string.IsNullOrEmpty(requiredAttribute);
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 0) type = checked((int)ReadVarint(data, ref offset, end));
            else if (field == 2 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                value = ReadString(data, valueStart, valueLength);
            }
            else if (field == 3 && wire == 2) {
                int attributeStart, attributeLength;
                ReadSegment(data, ref offset, end, out attributeStart, out attributeLength);
                bool enabled;
                string key = ParseAttribute(data, attributeStart, attributeLength, out enabled);
                if (enabled && string.Equals(key, requiredAttribute, StringComparison.OrdinalIgnoreCase)) attributeMatched = true;
            }
            else Skip(data, ref offset, end, wire);
        }
        if (!attributeMatched || string.IsNullOrWhiteSpace(value)) return null;
        string kind;
        switch (type) {
            case 0: kind = "domain_keyword"; break;
            case 1: kind = "domain_regex"; break;
            case 2: kind = "domain_suffix"; break;
            case 3: kind = "domain"; break;
            default: throw new InvalidOperationException("未知 GeoSite 域名类型：" + type.ToString(CultureInfo.InvariantCulture));
        }
        return kind + "\t" + value;
    }

    private static void ParseGeoSite(byte[] data, int start, int length, string wantedCode, string requiredAttribute, List<string> output) {
        int offset = start;
        int end = start + length;
        string countryCode = "";
        string code = "";
        var domains = new List<Tuple<int, int>>();
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if ((field == 1 || field == 4) && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                if (field == 1) countryCode = ReadString(data, valueStart, valueLength);
                else code = ReadString(data, valueStart, valueLength);
            }
            else if (field == 2 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                domains.Add(Tuple.Create(valueStart, valueLength));
            }
            else Skip(data, ref offset, end, wire);
        }
        string actual = string.IsNullOrEmpty(code) ? countryCode : code;
        if (!string.Equals(actual, wantedCode, StringComparison.OrdinalIgnoreCase)) return;
        foreach (var domain in domains) {
            string parsed = ParseDomain(data, domain.Item1, domain.Item2, requiredAttribute);
            if (parsed != null) output.Add(parsed);
        }
    }

    private static string ParseDomainWithAttributes(byte[] data, int start, int length, out HashSet<string> attributes) {
        int offset = start;
        int end = start + length;
        int type = 0;
        string value = "";
        attributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 0) type = checked((int)ReadVarint(data, ref offset, end));
            else if (field == 2 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                value = ReadString(data, valueStart, valueLength);
            }
            else if (field == 3 && wire == 2) {
                int attributeStart, attributeLength;
                ReadSegment(data, ref offset, end, out attributeStart, out attributeLength);
                bool enabled;
                string key = ParseAttribute(data, attributeStart, attributeLength, out enabled);
                if (enabled) attributes.Add(key);
            }
            else Skip(data, ref offset, end, wire);
        }
        if (String.IsNullOrWhiteSpace(value)) return null;
        string kind;
        switch (type) {
            case 0: kind = "domain_keyword"; break;
            case 1: kind = "domain_regex"; break;
            case 2: kind = "domain_suffix"; break;
            case 3: kind = "domain"; break;
            default: throw new InvalidOperationException("未知 GeoSite 域名类型：" + type.ToString(CultureInfo.InvariantCulture));
        }
        return kind + "\t" + value;
    }

    private static void ReadGeoSiteRecordIdentityAndDomains(byte[] data, int start, int length, out string actualCode, out List<Tuple<int, int>> domains) {
        int offset = start;
        int end = start + length;
        string countryCode = "";
        string code = "";
        domains = new List<Tuple<int, int>>();
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if ((field == 1 || field == 4) && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                if (field == 1) countryCode = ReadString(data, valueStart, valueLength);
                else code = ReadString(data, valueStart, valueLength);
            }
            else if (field == 2 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                domains.Add(Tuple.Create(valueStart, valueLength));
            }
            else Skip(data, ref offset, end, wire);
        }
        actualCode = String.IsNullOrEmpty(code) ? countryCode : code;
    }

    public static string[] ReadGeoSite(byte[] data, string selector) {
        string code = selector;
        string attribute = "";
        int attributeIndex = selector.LastIndexOf('@');
        if (attributeIndex > 0) {
            code = selector.Substring(0, attributeIndex);
            attribute = selector.Substring(attributeIndex + 1);
        }
        var output = new List<string>();
        int offset = 0;
        while (offset < data.Length) {
            ulong tag = ReadVarint(data, ref offset, data.Length);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 2) {
                int start, length;
                ReadSegment(data, ref offset, data.Length, out start, out length);
                ParseGeoSite(data, start, length, code, attribute, output);
            }
            else Skip(data, ref offset, data.Length, wire);
        }
        if (output.Count == 0) throw new InvalidOperationException("GeoSite 标签不存在或为空：" + selector);
        return output.Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    public static Dictionary<string, string[]> ReadGeoSiteMany(byte[] data, string[] selectors) {
        Dictionary<string, List<GeoSelector>> requestsByCode = new Dictionary<string, List<GeoSelector>>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, List<string>> outputBySelector = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (string selector in selectors) {
            string code = selector;
            string attribute = "";
            int attributeIndex = selector.LastIndexOf('@');
            if (attributeIndex > 0) {
                code = selector.Substring(0, attributeIndex);
                attribute = selector.Substring(attributeIndex + 1);
            }
            GeoSelector request = new GeoSelector(selector, code, attribute);
            List<GeoSelector> byCode;
            if (!requestsByCode.TryGetValue(code, out byCode)) {
                byCode = new List<GeoSelector>();
                requestsByCode.Add(code, byCode);
            }
            byCode.Add(request);
            if (!outputBySelector.ContainsKey(selector)) outputBySelector.Add(selector, new List<string>());
        }
        int offset = 0;
        while (offset < data.Length) {
            ulong tag = ReadVarint(data, ref offset, data.Length);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 2) {
                int start, length;
                ReadSegment(data, ref offset, data.Length, out start, out length);
                string code;
                List<Tuple<int, int>> domains;
                ReadGeoSiteRecordIdentityAndDomains(data, start, length, out code, out domains);
                List<GeoSelector> requests;
                if (requestsByCode.TryGetValue(code, out requests)) {
                    foreach (Tuple<int, int> domain in domains) {
                        HashSet<string> attributes;
                        string encoded = ParseDomainWithAttributes(data, domain.Item1, domain.Item2, out attributes);
                        if (encoded == null) continue;
                        foreach (GeoSelector request in requests) {
                            if (request.Attribute.Length == 0 || attributes.Contains(request.Attribute)) outputBySelector[request.Selector].Add(encoded);
                        }
                    }
                }
            }
            else Skip(data, ref offset, data.Length, wire);
        }
        Dictionary<string, string[]> result = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (string selector in selectors) {
            List<string> values = outputBySelector[selector];
            if (values.Count == 0) throw new InvalidOperationException("GeoSite 标签不存在或为空：" + selector);
            result[selector] = values.Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal).ToArray();
        }
        return result;
    }

    private static string ParseCidr(byte[] data, int start, int length) {
        int offset = start;
        int end = start + length;
        byte[] address = null;
        int prefix = -1;
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                address = new byte[valueLength];
                Buffer.BlockCopy(data, valueStart, address, 0, valueLength);
            }
            else if (field == 2 && wire == 0) prefix = checked((int)ReadVarint(data, ref offset, end));
            else Skip(data, ref offset, end, wire);
        }
        if (address == null || address.Length != 4 || prefix < 0 || prefix > 32) return null;
        return string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}/{4}", address[0], address[1], address[2], address[3], prefix);
    }

    private static void ParseGeoIp(byte[] data, int start, int length, string wantedCode, List<string> output) {
        int offset = start;
        int end = start + length;
        string countryCode = "";
        string code = "";
        var cidrs = new List<Tuple<int, int>>();
        while (offset < end) {
            ulong tag = ReadVarint(data, ref offset, end);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if ((field == 1 || field == 5) && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                if (field == 1) countryCode = ReadString(data, valueStart, valueLength);
                else code = ReadString(data, valueStart, valueLength);
            }
            else if (field == 2 && wire == 2) {
                int valueStart, valueLength;
                ReadSegment(data, ref offset, end, out valueStart, out valueLength);
                cidrs.Add(Tuple.Create(valueStart, valueLength));
            }
            else Skip(data, ref offset, end, wire);
        }
        string actual = string.IsNullOrEmpty(code) ? countryCode : code;
        if (!string.Equals(actual, wantedCode, StringComparison.OrdinalIgnoreCase)) return;
        foreach (var cidr in cidrs) {
            string parsed = ParseCidr(data, cidr.Item1, cidr.Item2);
            if (parsed != null) output.Add(parsed);
        }
    }

    public static string[] ReadGeoIp(byte[] data, string selector) {
        var output = new List<string>();
        int offset = 0;
        while (offset < data.Length) {
            ulong tag = ReadVarint(data, ref offset, data.Length);
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (field == 1 && wire == 2) {
                int start, length;
                ReadSegment(data, ref offset, data.Length, out start, out length);
                ParseGeoIp(data, start, length, selector, output);
            }
            else Skip(data, ref offset, data.Length, wire);
        }
        if (output.Count == 0) throw new InvalidOperationException("GeoIP 标签不存在、为空或仅含 IPv6：" + selector);
        return output.Distinct(StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }
}
'@
    Add-Type -TypeDefinition $source -Language CSharp
}

function ConvertTo-IPv4Cidr {
    param([Parameter(Mandatory)][string]$Token)

    $parts = $Token.Split('/', 2)
    if ($parts[0] -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$') { return $null }
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address)) { return $null }
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $prefixLength = if ($parts.Count -eq 2) { 0 } else { 32 }
    if ($parts.Count -eq 2 -and ($parts[1] -notmatch '^[0-9]+$' -or -not [int]::TryParse($parts[1], [ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt 32)) { return $null }
    $bytes = $address.GetAddressBytes()
    $value = ([uint64]$bytes[0] -shl 24) -bor ([uint64]$bytes[1] -shl 16) -bor ([uint64]$bytes[2] -shl 8) -bor [uint64]$bytes[3]
    $mask = if ($prefixLength -eq 0) { [uint64]0 } else { ([uint64]4294967295 -shr (32 - $prefixLength)) -shl (32 - $prefixLength) }
    $network = $value -band $mask
    $normalized = '{0}.{1}.{2}.{3}/{4}' -f (($network -shr 24) -band 255), (($network -shr 16) -band 255), (($network -shr 8) -band 255), ($network -band 255), $prefixLength
    return [PSCustomObject]@{ Value=$normalized; Network=$network; Prefix=$prefixLength; Mask=$mask }
}

function New-RuleItem {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)]$Parsed,
        [Parameter(Mandatory)]$Context
    )

    $value = if ($Parsed -is [string]) { $Parsed } else { $Parsed.Value }
    if ($Kind -eq 'ip_cidr') {
        return [RoutingRuleItem]::new($Kind, $value, [int]$Context.Sequence, [string]$Context.Group, [string]$Context.Action, [string]$Context.Source, [uint64]$Parsed.Network, [int]$Parsed.Prefix, [uint64]$Parsed.Mask)
    }
    return [RoutingRuleItem]::new($Kind, $value, [int]$Context.Sequence, [string]$Context.Group, [string]$Context.Action, [string]$Context.Source, [uint64]0, 0, [uint64]0)
}

function Add-TextRuleValues {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IEnumerable]$RawValues,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Ignored
    )

    $batch = [RoutingRuleBatch]::ParseTextValues(
        $Kind,
        [string[]]$RawValues,
        [int]$Context.Sequence,
        [string]$Context.Group,
        [string]$Context.Action,
        [string]$Context.Source
    )
    $Items.AddRange([object[]]$batch.Items)
    $Ignored.AddRange([object[]]$batch.Ignored)
}

function Add-TextRuleValue {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$RawValue,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Ignored
    )

    $singleValue = @($RawValue)
    Add-TextRuleValues -Kind $Kind -RawValues $singleValue -Context $Context -Items $Items -Ignored $Ignored
}

function Convert-MrsDomainKey {
    param([Parameter(Mandatory)][string]$Key)

    if ($Key.StartsWith('+.')) {
        return [PSCustomObject]@{Kind='domain_suffix';Value=$Key.Substring(2)}
    }
    if ($Key.Contains('*')) {
        $segments = $Key.Split('.') | ForEach-Object { if ($_ -eq '*') { '[^.]+' } else { [regex]::Escape($_) } }
        return [PSCustomObject]@{Kind='domain_regex';Value=('^' + ($segments -join '\.') + '$')}
    }
    return [PSCustomObject]@{Kind='domain';Value=$Key}
}

function Add-DocumentRules {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rules,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Ignored
    )

    foreach ($rule in @($Rules)) {
        foreach ($kind in @('domain','domain_suffix','ip_cidr','port','port_range','source_port','source_port_range')) {
            $property = $rule.PSObject.Properties[$kind]
            if (-not $property) { continue }
            $rawValues = @($property.Value)
            Add-TextRuleValues -Kind $kind -RawValues $rawValues -Context $Context -Items $Items -Ignored $Ignored
        }
    }
}

function Add-ResourceItems {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Ignored,
        [string]$ZstdPath
    )

    $destinationItems = $Items
    $destinationIgnored = $Ignored
    $Items = [System.Collections.Generic.List[object]]::new()
    $Ignored = [System.Collections.Generic.List[object]]::new()
    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    $parseKey = $sourceHash + ':' + [string]$Resource.tag + ':' + [string]$Resource.format + ':' + [string]$Context.Source
    if ($script:ParsedSources.ContainsKey($parseKey)) {
        $cached = $script:ParsedSources[$parseKey]
        $contextualized = [RoutingRuleBatch]::Recontextualize(
            [object[]]$cached.Items,
            [int]$Context.Sequence,
            [string]$Context.Group,
            [string]$Context.Action,
            [string]$Context.Source
        )
        $destinationItems.AddRange([object[]]$contextualized)
        $destinationIgnored.AddRange([object[]]$cached.Ignored)
        return
    }

    switch ([string]$Resource.format) {
        'plain' {
            $lines = [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)
            $batch = [RoutingRuleBatch]::ParsePlainLines($lines, [int]$Context.Sequence, [string]$Context.Group, [string]$Context.Action, [string]$Context.Source)
            $Items.AddRange([object[]]$batch.Items)
            $Ignored.AddRange([object[]]$batch.Ignored)
        }
        'adguard-dns' {
            . (Join-Path $PSScriptRoot 'SameTypeDirectPolicy.ps1')
            $lines = [IO.File]::ReadAllLines($Path, [Text.UTF8Encoding]::new($false, $true))
            $exceptions = [RoutingRuleBatch]::ReadAdGuardDnsExceptions($lines)
            $exceptionMatcher = New-Object SingBoxSameType.DomainCompiler
            foreach ($exception in $exceptions) { $exceptionMatcher.Block($exception, $true) }
            $remainingSuffix = [Func[string,string]]{ param($domain) $exceptionMatcher.SuffixPattern($domain) }
            $batch = [RoutingRuleBatch]::ParseAdGuardDnsLines($lines, $exceptions, $remainingSuffix, [int]$Context.Sequence, [string]$Context.Group, [string]$Context.Action, [string]$Context.Source)
            $Items.AddRange([object[]]$batch.Items)
            $Ignored.AddRange([object[]]$batch.Ignored)
        }
        'dnsmasq' {
            $lines = [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)
            $batch = [RoutingRuleBatch]::ParseDnsmasqLines($lines, [int]$Context.Sequence, [string]$Context.Group, [string]$Context.Action, [string]$Context.Source)
            $Items.AddRange([object[]]$batch.Items)
            $Ignored.AddRange([object[]]$batch.Ignored)
        }
        'mrs-domain' {
            Initialize-MrsReader
            [byte[]]$bytes = [System.IO.File]::ReadAllBytes($Path)
            $valuesByKind = @{
                domain = [System.Collections.Generic.List[string]]::new()
                domain_suffix = [System.Collections.Generic.List[string]]::new()
                domain_regex = [System.Collections.Generic.List[string]]::new()
            }
            foreach ($key in [RoutingMrsReader]::ReadDomains($ZstdPath, $bytes)) {
                $converted = Convert-MrsDomainKey $key
                $valuesByKind[[string]$converted.Kind].Add([string]$converted.Value)
            }
            foreach ($kind in @('domain','domain_suffix','domain_regex')) {
                $rawValues = $valuesByKind[$kind].ToArray()
                Add-TextRuleValues -Kind $kind -RawValues $rawValues -Context $Context -Items $Items -Ignored $Ignored
            }
        }
        'mrs-ipcidr' {
            Initialize-MrsReader
            [byte[]]$bytes = [System.IO.File]::ReadAllBytes($Path)
            $cidrs = [RoutingMrsReader]::ReadIPv4Cidrs($ZstdPath, $bytes)
            Add-TextRuleValues -Kind 'ip_cidr' -RawValues $cidrs -Context $Context -Items $Items -Ignored $Ignored
        }
        'clash-yaml' {
            $lineNumber = 0
            $payloadSeen = $false
            foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
                $lineNumber++
                $token = $line.Trim().TrimStart([char]0xFEFF)
                if (-not $token -or $token.StartsWith('#') -or $token -eq '---' -or $token -eq '...') { continue }
                if ($token -match '^payload:\s*(?:#.*)?$' -and -not $payloadSeen) { $payloadSeen = $true; continue }
                if (-not $payloadSeen -or $token -notmatch '^-\s+(.+)$') {
                    $Ignored.Add([PSCustomObject]@{Source=$Context.Source;Line=$lineNumber;Value=$token;Reason='invalid-clash-line'})
                    continue
                }
                $token = ($Matches[1] -replace '\s+#.*$', '').Trim()
                if ($token -match '^"([^"\r\n]*)"$' -or $token -match "^'([^'\r\n]*)'$") { $token = $Matches[1] }
                elseif ($token -match '["'']') {
                    $Ignored.Add([PSCustomObject]@{Source=$Context.Source;Line=$lineNumber;Value=$token;Reason='invalid-clash-quoting'})
                    continue
                }
                $parts = $token.Split(',')
                if ($parts.Count -lt 2 -or -not $parts[1].Trim() -or
                    ($parts.Count -gt 2 -and -not ($parts.Count -eq 3 -and $parts[0].Trim() -in @('IP-CIDR','IP-CIDR6') -and $parts[2].Trim() -eq 'no-resolve'))) {
                    $Ignored.Add([PSCustomObject]@{Source=$Context.Source;Line=$lineNumber;Value=$token;Reason='invalid-clash-fields'})
                    continue
                }
                $kind = $parts[0].Trim().ToUpperInvariant()
                $value = $parts[1].Trim()
                switch ($kind) {
                    'DOMAIN' { Add-TextRuleValue -Kind 'domain' -RawValue $value -Context $Context -Items $Items -Ignored $Ignored }
                    'DOMAIN-SUFFIX' { Add-TextRuleValue -Kind 'domain_suffix' -RawValue $value -Context $Context -Items $Items -Ignored $Ignored }
                    'DOMAIN-KEYWORD' { Add-TextRuleValue -Kind 'domain_keyword' -RawValue $value -Context $Context -Items $Items -Ignored $Ignored }
                    'DOMAIN-REGEX' { Add-TextRuleValue -Kind 'domain_regex' -RawValue $value -Context $Context -Items $Items -Ignored $Ignored }
                    'IP-CIDR' { Add-TextRuleValue -Kind 'ip_cidr' -RawValue $value -Context $Context -Items $Items -Ignored $Ignored }
                    'IP-CIDR6' { $Ignored.Add([PSCustomObject]@{Source=$Context.Source;Line=$lineNumber;Value=$token;Reason='ipv6-rejected-by-core'}) }
                    'DST-PORT' {
                        $targetKind = if ($value -match '[:-]') { 'port_range' } else { 'port' }
                        Add-TextRuleValue -Kind $targetKind -RawValue $value -Context $Context -Items $Items -Ignored $Ignored
                    }
                    'SRC-PORT' {
                        $targetKind = if ($value -match '[:-]') { 'source_port_range' } else { 'source_port' }
                        Add-TextRuleValue -Kind $targetKind -RawValue $value -Context $Context -Items $Items -Ignored $Ignored
                    }
                    default { $Ignored.Add([PSCustomObject]@{Source=$Context.Source;Line=$lineNumber;Value=$token;Reason='unsupported-clash-rule'}) }
                }
            }
        }
        'source' {
            $document = Read-JsonFile $Path
            Add-DocumentRules -Rules $document.rules -Context $Context -Items $Items -Ignored $Ignored
        }
        default { throw "规则资源 '$($Resource.tag)' 使用了不支持的格式 '$($Resource.format)'。" }
    }
    $script:ParsedSources[$parseKey] = [PSCustomObject]@{Items=$Items.ToArray();Ignored=$Ignored.ToArray()}
    $contextualizedItems = [RoutingRuleBatch]::Recontextualize(
        [object[]]$Items.ToArray(),
        [int]$Context.Sequence,
        [string]$Context.Group,
        [string]$Context.Action,
        [string]$Context.Source
    )
    $destinationItems.AddRange([object[]]$contextualizedItems)
    $destinationIgnored.AddRange([object[]]$Ignored.ToArray())
}

function Assert-RemoteSource {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Selectors = @(),
        [string]$ZstdPath
    )

    try {
        $sourceHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        $validationKey = $sourceHash + ':' + [string]$Resource.tag + ':' + [string]$Resource.format + ':' + (($Selectors | Sort-Object -Unique) -join ',')
        $parseKey = $sourceHash + ':' + [string]$Resource.tag + ':' + [string]$Resource.format + ':' + [string]$Resource.tag
        $isGeoData = $Resource.format -in @('geosite-dat','geoip-dat')
        $cacheRoot = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path))
        $parsedCachePath = Join-Path $cacheRoot ([string]$Resource.tag + '.parsed.bin')
        $stableResourcePath = $false
        if (-not $isGeoData) {
            $expectedResourcePath = [System.IO.Path]::GetFullPath((Get-RemoteResourceCachePath -Resource $Resource -CacheRoot $cacheRoot))
            $stableResourcePath = [System.IO.Path]::GetFullPath($Path).Equals($expectedResourcePath, [System.StringComparison]::OrdinalIgnoreCase)
        }
        $parserFingerprint = if ($isGeoData) { $null } else { Get-RoutingParserFingerprint }
        if ($script:ValidatedSources.ContainsKey($validationKey)) {
            if ($stableResourcePath -and $script:ParsedSources.ContainsKey($parseKey)) {
                $existingCache = [RoutingRuleBatch]::ReadParsedCache($parsedCachePath, $sourceHash, $parserFingerprint, [string]$Resource.format, [string]$Resource.tag)
                if ($null -eq $existingCache) {
                    $parsed = $script:ParsedSources[$parseKey]
                    Save-ParsedSourceCache -Path $parsedCachePath -SourceHash $sourceHash -ParserFingerprint $parserFingerprint -Format ([string]$Resource.format) -Tag ([string]$Resource.tag) -Items ([object[]]$parsed.Items) -Ignored ([object[]]$parsed.Ignored)
                }
            }
            return
        }
        if ($Resource.format -in @('geosite-dat','geoip-dat')) {
            if ($Selectors.Count -eq 0) {
                throw '没有配置任何需要提取的标签。'
            }
            $validationRoot = New-RoutingSourceValidationDirectory -CacheRoot $cacheRoot
            try {
                Assert-RoutingSourceValidationDirectory -Path $validationRoot -CacheRoot $cacheRoot
                $validated = Get-GeodataCache -Resource $Resource -ResourcePath $Path -Selectors $Selectors -CacheRoot $validationRoot
                Assert-RoutingSourceValidationDirectory -Path $validationRoot -CacheRoot $cacheRoot
                if (@($validated.categories.PSObject.Properties).Count -ne $Selectors.Count) {
                    throw '提取后的标签数量与请求数量不一致。'
                }
                $count = 0
                foreach ($category in $validated.categories.PSObject.Properties) {
                    foreach ($rule in @($category.Value)) {
                        foreach ($field in $rule.PSObject.Properties) { $count += @($field.Value).Count }
                    }
                }
                if ($count -eq 0) { throw '提取后的标签没有可用规则。' }
                $script:ValidatedSources[$validationKey] = $count
            }
            finally {
                if ([System.IO.Directory]::Exists($validationRoot)) {
                    Remove-RoutingSourceValidationDirectory -Path $validationRoot -CacheRoot $cacheRoot
                }
            }
            return
        }

        $parsedCache = [RoutingRuleBatch]::ReadParsedCache($parsedCachePath, $sourceHash, $parserFingerprint, [string]$Resource.format, [string]$Resource.tag)
        if ($null -ne $parsedCache -and $parsedCache.Items.Count -gt 0) {
            $invalidCached = @($parsedCache.Ignored | Where-Object { $_.Reason -ne 'ipv6-rejected-by-core' })
            if ($invalidCached.Count -eq 0) {
                $script:ParsedSources[$parseKey] = [PSCustomObject]@{Items=[object[]]$parsedCache.Items;Ignored=[object[]]$parsedCache.Ignored}
                $script:ValidatedSources[$validationKey] = $parsedCache.Items.Count
                return
            }
        }

        $items = [System.Collections.Generic.List[object]]::new()
        $ignored = [System.Collections.Generic.List[object]]::new()
        $context = [PSCustomObject]@{Sequence=0;Group='validation';Action='direct';Source=[string]$Resource.tag}
        Add-ResourceItems -Resource $Resource -Path $Path -Context $context -Items $items -Ignored $ignored -ZstdPath $ZstdPath
        if ($items.Count -eq 0) {
            throw '没有解析出任何可用规则。'
        }
        $invalid = @($ignored | Where-Object { $_.Reason -ne 'ipv6-rejected-by-core' })
        if ($invalid.Count -gt 0) { throw "包含 $($invalid.Count) 条无效规则：$($invalid[0].Reason)" }
        $script:ValidatedSources[$validationKey] = $items.Count
        if ($stableResourcePath) {
            $parsed = $script:ParsedSources[$parseKey]
            Save-ParsedSourceCache -Path $parsedCachePath -SourceHash $sourceHash -ParserFingerprint $parserFingerprint -Format ([string]$Resource.format) -Tag ([string]$Resource.tag) -Items ([object[]]$parsed.Items) -Ignored ([object[]]$parsed.Ignored)
        }
    }
    catch {
        throw "规则资源 '$($Resource.tag)' 内容校验失败：$($_.Exception.Message)"
    }
}

function New-RoutingSourceValidationDirectory {
    param([Parameter(Mandatory)][string]$CacheRoot)

    $parent = Get-NormalizedRoutingPath $CacheRoot
    Assert-RoutingPathHasNoReparsePoint $parent
    if (-not [System.IO.Directory]::Exists($parent)) { throw "GeoData source cache directory is missing: $parent" }
    $name = '.source-validation-' + [guid]::NewGuid().ToString('N')
    $path = Get-NormalizedRoutingPath (Join-Path $parent $name)
    if (-not [string]::Equals([System.IO.Directory]::GetParent($path).FullName, $parent, [System.StringComparison]::OrdinalIgnoreCase) -or
        $name -notmatch '^\.source-validation-[0-9a-f]{32}$') { throw 'Invalid GeoData validation directory path.' }
    Assert-RoutingPathHasNoReparsePoint $path
    if ([System.IO.Directory]::Exists($path) -or [System.IO.File]::Exists($path)) { throw "GeoData validation path already exists: $path" }
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    Assert-RoutingSourceValidationDirectory -Path $path -CacheRoot $parent
    return $path
}

function Assert-RoutingSourceValidationDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CacheRoot
    )

    $parent = Get-NormalizedRoutingPath $CacheRoot
    $target = Get-NormalizedRoutingPath $Path
    if (-not [string]::Equals([System.IO.Directory]::GetParent($target).FullName, $parent, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($target) -notmatch '^\.source-validation-[0-9a-f]{32}$' -or
        -not [System.IO.Directory]::Exists($target)) { throw "Refusing a non-owned GeoData validation directory: $target" }
    Assert-RoutingPathHasNoReparsePoint $target
    Assert-RoutingPathTreeHasNoReparsePoint $target
}

function Remove-RoutingSourceValidationDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$CacheRoot
    )

    Assert-RoutingSourceValidationDirectory -Path $Path -CacheRoot $CacheRoot
    $target = Get-NormalizedRoutingPath $Path
    [System.IO.Directory]::Delete($target, $true)
    if ([System.IO.Directory]::Exists($target) -or [System.IO.File]::Exists($target)) {
        throw "GeoData validation directory remained after cleanup: $target"
    }
}

function Assert-SourceCountChange {
    param($Resource, [string]$NewPath, [string]$OldPath, [string[]]$Selectors, [string]$ZstdPath)
    if ($AllowSourceShrink -or -not (Test-Path -LiteralPath $OldPath -PathType Leaf)) { return }
    Assert-RemoteSource -Resource $Resource -Path $OldPath -Selectors $Selectors -ZstdPath $ZstdPath
    $suffix = ':' + [string]$Resource.tag + ':' + [string]$Resource.format + ':' + (($Selectors | Sort-Object -Unique) -join ',')
    $oldCount = $script:ValidatedSources[(Get-FileHash -LiteralPath $OldPath -Algorithm SHA256).Hash + $suffix]
    $newCount = $script:ValidatedSources[(Get-FileHash -LiteralPath $NewPath -Algorithm SHA256).Hash + $suffix]
    if ($oldCount -gt 0 -and $newCount -lt $oldCount * 0.5) { throw "规则数量异常下降超过 50%：$oldCount -> $newCount；核实上游后可显式使用 -AllowSourceShrink。" }
}

function Get-GeodataCache {
    param(
        [Parameter(Mandatory)]$Resource,
        [Parameter(Mandatory)][string]$ResourcePath,
        [Parameter(Mandatory)][string[]]$Selectors,
        [Parameter(Mandatory)][string]$CacheRoot
    )

    $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ResourcePath).Hash
    $selectorSignature = Get-Sha256Text (($Selectors | Sort-Object -Unique) -join "`n")
    $cachePath = Join-Path $CacheRoot ([string]$Resource.tag + '.extracted.json')
    $memoryKey = $sourceHash + ':' + $selectorSignature + ':' + [string]$Resource.format
    if ($script:ValidatedGeodata.ContainsKey($memoryKey)) {
        $result = $script:ValidatedGeodata[$memoryKey]
        Write-JsonAtomically -Value $result -Path $cachePath
        return $result
    }
    if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
        try {
            $cached = Read-JsonFile $cachePath
            if ([int]$cached.version -eq 3 -and $cached.source_sha256 -eq $sourceHash -and $cached.selector_signature -eq $selectorSignature -and $cached.content_sha256 -eq (Get-Sha256Text ($cached.categories | ConvertTo-Json -Depth 100 -Compress))) {
                $script:ValidatedGeodata[$memoryKey] = $cached
                return $cached
            }
        }
        catch { }
    }

    Initialize-GeoDataReader
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($ResourcePath)
    $geoSiteValuesBySelector = $null
    if ($Resource.format -eq 'geosite-dat') {
        $geoSiteValuesBySelector = [RoutingGeoDataReader]::ReadGeoSiteMany($bytes, [string[]]$Selectors)
    }
    $categories = [ordered]@{}
    foreach ($selector in $Selectors) {
        try {
            $rule = [ordered]@{}
            if ($Resource.format -eq 'geosite-dat') {
                $valuesByKind = @{}
                foreach ($encoded in $geoSiteValuesBySelector[$selector]) {
                    $separator = $encoded.IndexOf("`t", [StringComparison]::Ordinal)
                    if ($separator -lt 1) { throw "标签 '$selector' 返回了无效域名记录。" }
                    $kind = $encoded.Substring(0, $separator)
                    $value = $encoded.Substring($separator + 1)
                    if (-not $valuesByKind.ContainsKey($kind)) { $valuesByKind[$kind] = [System.Collections.Generic.List[string]]::new() }
                    $valuesByKind[$kind].Add($value)
                }
                foreach ($kind in @('domain','domain_suffix')) {
                    if ($valuesByKind.ContainsKey($kind) -and $valuesByKind[$kind].Count -gt 0) { $rule[$kind] = @($valuesByKind[$kind]) }
                }
            }
            elseif ($Resource.format -eq 'geoip-dat') {
                $rule['ip_cidr'] = @([RoutingGeoDataReader]::ReadGeoIp($bytes, $selector))
            }
            else { throw "不是 Geo 数据资源：$($Resource.tag)" }
            if ($rule.Count -eq 0) { throw "标签 '$selector' 没有可用规则。" }
            $categories[$selector] = @($rule)
        }
        catch {
            throw "从 '$($Resource.tag)' 提取标签 '$selector' 失败：$($_.Exception.Message)"
        }
    }
    $result = [ordered]@{
        version = 3
        source_sha256 = $sourceHash
        selector_signature = $selectorSignature
        generated_at = [DateTime]::UtcNow.ToString('o')
        categories = $categories
        content_sha256 = Get-Sha256Text ($categories | ConvertTo-Json -Depth 100 -Compress)
    }
    Write-JsonAtomically -Value $result -Path $cachePath
    $script:ValidatedGeodata[$memoryKey] = Read-JsonFile $cachePath
    return $script:ValidatedGeodata[$memoryKey]
}

function Get-SortedUniqueRuleStrings {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Items,
        [Parameter(Mandatory)][string]$Kind
    )

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $Items) {
        if ($item.Kind -eq $Kind) { $set.Add([string]$item.Value) | Out-Null }
    }
    [string[]]$values = @($set)
    [Array]::Sort($values, [System.StringComparer]::Ordinal)
    return $values
}

function Get-NormalizedRoutingPath {
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { throw '规则事务路径不能为空。' }
    try { $fullPath = [System.IO.Path]::GetFullPath($Path) }
    catch { throw "规则事务路径无效：$Path" }
    if ($fullPath.StartsWith('\\?\', [System.StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith('\\.\', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "规则事务路径不接受设备命名空间：$Path"
    }
    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if (-not [string]::Equals($fullPath, $pathRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        $fullPath = $fullPath.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    }
    return $fullPath
}

function Test-RoutingPathOverlap {
    param(
        [Parameter(Mandatory)][string]$LeftPath,
        [Parameter(Mandatory)][string]$RightPath
    )

    $left = Get-NormalizedRoutingPath $LeftPath
    $right = Get-NormalizedRoutingPath $RightPath
    if ([string]::Equals($left, $right, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    $leftPrefix = if ($left.EndsWith($separator, [System.StringComparison]::OrdinalIgnoreCase)) { $left } else { $left + $separator }
    $rightPrefix = if ($right.EndsWith($separator, [System.StringComparison]::OrdinalIgnoreCase)) { $right } else { $right + $separator }
    return $right.StartsWith($leftPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $left.StartsWith($rightPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-RoutingPathHasNoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)

    $currentPath = Get-NormalizedRoutingPath $Path
    $pathRoot = [System.IO.Path]::GetPathRoot($currentPath)
    while ($true) {
        $attributes = $null
        try {
            $attributes = [System.IO.File]::GetAttributes($currentPath)
        }
        catch [System.IO.FileNotFoundException] {
        }
        catch [System.IO.DirectoryNotFoundException] {
        }
        catch {
            throw "无法安全检查规则事务路径：$currentPath`n$($_.Exception.Message)"
        }
        if ($null -ne $attributes -and ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "规则事务路径经过重解析点，拒绝操作：$currentPath"
        }
        if ([string]::Equals($currentPath, $pathRoot, [System.StringComparison]::OrdinalIgnoreCase)) { break }
        $parent = [System.IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) { throw "无法确定规则事务路径祖先：$currentPath" }
        $currentPath = $parent.FullName
    }
}

function Assert-RoutingPathTreeHasNoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)

    $rootPath = Get-NormalizedRoutingPath $Path
    Assert-RoutingPathHasNoReparsePoint $rootPath
    if (-not [System.IO.Directory]::Exists($rootPath)) { return }
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($rootPath)
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        foreach ($childPath in [System.IO.Directory]::EnumerateFileSystemEntries($directoryPath)) {
            try { $attributes = [System.IO.File]::GetAttributes($childPath) }
            catch { throw "无法安全检查事务清理对象：$childPath`n$($_.Exception.Message)" }
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "事务清理对象包含重解析点，拒绝递归删除：$childPath"
            }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { $pending.Push($childPath) }
        }
    }
}

function Get-RoutingPlanRegistry {
    $registryVariable = Get-Variable -Name RoutingTransactionPlanRegistry -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $registryVariable) {
        $registryVariable = @{}
        Set-Variable -Name RoutingTransactionPlanRegistry -Scope Script -Value $registryVariable
    }
    return $registryVariable
}

function Assert-RoutingTransactionPathSet {
    param(
        [Parameter(Mandatory)][string[]]$TransactionPaths,
        [string[]]$ProtectedPaths = @(),
        [string[]]$ProtectedRoots = @()
    )

    $normalizedPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $TransactionPaths) {
        $normalized = Get-NormalizedRoutingPath $path
        Assert-RoutingPathHasNoReparsePoint $normalized
        foreach ($existing in $normalizedPaths) {
            if (Test-RoutingPathOverlap -LeftPath $normalized -RightPath $existing) {
                throw "规则事务路径相等或互为祖先，拒绝继续：$normalized`n$existing"
            }
        }
        $normalizedPaths.Add($normalized)
    }

    $normalizedProtectedPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $ProtectedPaths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $normalized = Get-NormalizedRoutingPath $path
        Assert-RoutingPathHasNoReparsePoint $normalized
        $normalizedProtectedPaths.Add($normalized)
    }
    $normalizedProtectedRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $ProtectedRoots) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $normalized = Get-NormalizedRoutingPath $path
        Assert-RoutingPathHasNoReparsePoint $normalized
        $normalizedProtectedRoots.Add($normalized)
    }

    foreach ($transactionPath in $normalizedPaths) {
        foreach ($protectedPath in $normalizedProtectedPaths) {
            if (Test-RoutingPathOverlap -LeftPath $transactionPath -RightPath $protectedPath) {
                throw "规则事务路径与清单或静态输入重叠，拒绝继续：$transactionPath`n$protectedPath"
            }
        }
        foreach ($protectedRoot in $normalizedProtectedRoots) {
            if (Test-RoutingPathOverlap -LeftPath $transactionPath -RightPath $protectedRoot) {
                throw "规则事务路径与维护源码保护目录重叠，拒绝继续：$transactionPath`n$protectedRoot"
            }
        }
    }

    return [PSCustomObject]@{
        TransactionPaths = [string[]]$normalizedPaths.ToArray()
        ProtectedPaths = [string[]]$normalizedProtectedPaths.ToArray()
        ProtectedRoots = [string[]]$normalizedProtectedRoots.ToArray()
    }
}

function Assert-RoutingTransactionPaths {
    param([Parameter(Mandatory)]$Paths)

    if ($null -eq $Paths.PSObject.Properties['PlanId']) { throw '规则事务路径未经过隔离校验。' }
    $registry = Get-RoutingPlanRegistry
    $planId = [string]$Paths.PlanId
    if (-not $registry.ContainsKey($planId)) { throw '规则事务路径校验凭据无效。' }
    $registration = $registry[$planId]
    foreach ($propertyName in $registration.PathValues.Keys) {
        if ($null -eq $Paths.PSObject.Properties[$propertyName] -or
            -not [string]::Equals([string]$Paths.$propertyName, [string]$registration.PathValues[$propertyName], [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "规则事务路径在校验后被修改：$propertyName"
        }
    }
    foreach ($propertyName in @('ProtectedPaths','ProtectedRoots')) {
        $actual = @($Paths.$propertyName)
        $expected = @($registration.$propertyName)
        if ($actual.Count -ne $expected.Count) { throw "规则事务保护路径在校验后被修改：$propertyName" }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if (-not [string]::Equals([string]$actual[$index], [string]$expected[$index], [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "规则事务保护路径在校验后被修改：$propertyName"
            }
        }
    }

    $transactionPathNames = @('CachePath','CacheStagePath','CacheBackupPath','CacheLockPath','OutputPath','OutputStagePath','OutputBackupPath','OutputLockPath','JournalPath','JournalWritePath','JournalReplaceBackupPath')
    $transactionPathValues = [string[]]@($transactionPathNames | ForEach-Object { [string]$Paths.$_ })
    $pathSet = Assert-RoutingTransactionPathSet -TransactionPaths $transactionPathValues -ProtectedPaths ([string[]]$registration.ProtectedPaths) -ProtectedRoots ([string[]]$registration.ProtectedRoots)
    foreach ($path in $pathSet.TransactionPaths) { Assert-RoutingPathHasNoReparsePoint $path }
    foreach ($path in $pathSet.ProtectedPaths) { Assert-RoutingPathHasNoReparsePoint $path }
    foreach ($path in $pathSet.ProtectedRoots) { Assert-RoutingPathHasNoReparsePoint $path }

    foreach ($name in @('CachePath','CacheStagePath','CacheBackupPath')) {
        $path = [string]$Paths.$name
        if ([System.IO.File]::Exists($path)) { throw "缓存事务目录路径被文件占用：$path" }
        Assert-RoutingPathTreeHasNoReparsePoint $path
    }
    foreach ($name in @('OutputPath','OutputStagePath','OutputBackupPath','CacheLockPath','OutputLockPath','JournalPath','JournalWritePath','JournalReplaceBackupPath')) {
        $path = [string]$Paths.$name
        if ([System.IO.Directory]::Exists($path)) { throw "规则事务文件路径被目录占用：$path" }
        Assert-RoutingPathHasNoReparsePoint $path
    }
}

function Remove-RoutingTransactionPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Paths
    )

    Assert-RoutingTransactionPaths -Paths $Paths
    $registry = Get-RoutingPlanRegistry
    $registration = $registry[[string]$Paths.PlanId]
    $allowed = $false
    foreach ($allowedPath in $registration.RemovalPaths) {
        if ([string]::Equals($Path, [string]$allowedPath, [System.StringComparison]::OrdinalIgnoreCase)) { $allowed = $true; break }
    }
    if (-not $allowed) { throw "拒绝清理未列入本事务的路径：$Path" }

    $directoryPaths = @($Paths.CachePath, $Paths.CacheStagePath, $Paths.CacheBackupPath)
    $expectsDirectory = $false
    foreach ($directoryPath in $directoryPaths) {
        if ([string]::Equals($Path, [string]$directoryPath, [System.StringComparison]::OrdinalIgnoreCase)) { $expectsDirectory = $true; break }
    }
    if ($expectsDirectory) {
        if ([System.IO.File]::Exists($Path)) { throw "缓存事务目录被文件占用，拒绝清理：$Path" }
        Assert-RoutingPathTreeHasNoReparsePoint $Path
        if ([System.IO.Directory]::Exists($Path)) { [System.IO.Directory]::Delete($Path, $true) }
        return
    }

    if ([System.IO.Directory]::Exists($Path)) { throw "规则事务文件被目录占用，拒绝清理：$Path" }
    Assert-RoutingPathHasNoReparsePoint $Path
    if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
}

function Get-RoutingTransactionPaths {
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$ManifestPath,
        [string[]]$ProtectedPaths = @(),
        [string[]]$ProtectedRoots = @()
    )

    $resolvedCachePath = Get-NormalizedRoutingPath $CachePath
    $resolvedOutputPath = Get-NormalizedRoutingPath $OutputPath
    $resolvedManifestPath = if ([string]::IsNullOrWhiteSpace($ManifestPath)) { '' } else { Get-NormalizedRoutingPath $ManifestPath }
    $allPaths = [ordered]@{
        CachePath = $resolvedCachePath
        CacheStagePath = "$resolvedCachePath.update.stage"
        CacheBackupPath = "$resolvedCachePath.update.backup"
        CacheLockPath = "$resolvedCachePath.update.lock"
        OutputPath = $resolvedOutputPath
        OutputStagePath = "$resolvedOutputPath.update.stage"
        OutputBackupPath = "$resolvedOutputPath.update.backup"
        OutputLockPath = "$resolvedOutputPath.update.lock"
        JournalPath = "$resolvedOutputPath.update.transaction.json"
        JournalWritePath = "$resolvedOutputPath.update.transaction.write.tmp"
        JournalReplaceBackupPath = "$resolvedOutputPath.update.transaction.replace.backup"
    }
    $protectionList = [System.Collections.Generic.List[string]]::new()
    if ($resolvedManifestPath) { $protectionList.Add($resolvedManifestPath) }
    foreach ($path in $ProtectedPaths) {
        if (-not [string]::IsNullOrWhiteSpace($path)) { $protectionList.Add((Get-NormalizedRoutingPath $path)) }
    }
    $pathSet = Assert-RoutingTransactionPathSet -TransactionPaths ([string[]]@($allPaths.Values)) -ProtectedPaths ([string[]]$protectionList.ToArray()) -ProtectedRoots $ProtectedRoots
    foreach ($name in @('CachePath','CacheStagePath','CacheBackupPath','CacheLockPath','OutputPath','OutputStagePath','OutputBackupPath','OutputLockPath','JournalPath','JournalWritePath','JournalReplaceBackupPath')) {
        $allPaths[$name] = Get-NormalizedRoutingPath ([string]$allPaths[$name])
    }
    $planId = [guid]::NewGuid().ToString('N')
    $plan = [ordered]@{}
    foreach ($name in $allPaths.Keys) { $plan[$name] = [string]$allPaths[$name] }
    $plan['ManifestPath'] = $resolvedManifestPath
    $plan['ProtectedPaths'] = [string[]]$pathSet.ProtectedPaths
    $plan['ProtectedRoots'] = [string[]]$pathSet.ProtectedRoots
    $plan['PlanId'] = $planId
    $result = [PSCustomObject]$plan

    $pathValues = [ordered]@{}
    foreach ($name in $allPaths.Keys) { $pathValues[$name] = [string]$allPaths[$name] }
    $pathValues['ManifestPath'] = $resolvedManifestPath
    $removalPaths = [string[]]@($allPaths.CachePath, $allPaths.CacheStagePath, $allPaths.CacheBackupPath, $allPaths.OutputPath, $allPaths.OutputStagePath, $allPaths.OutputBackupPath, $allPaths.JournalPath, $allPaths.JournalWritePath, $allPaths.JournalReplaceBackupPath)
    $registration = [PSCustomObject]@{
        PathValues = $pathValues
        ProtectedPaths = [string[]]$pathSet.ProtectedPaths
        ProtectedRoots = [string[]]$pathSet.ProtectedRoots
        RemovalPaths = $removalPaths
    }
    $registry = Get-RoutingPlanRegistry
    $registry[$planId] = $registration
    Assert-RoutingTransactionPaths -Paths $result
    return $result
}

function Resolve-RoutingInputFilePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )

    $normalized = Get-NormalizedRoutingPath $Path
    Assert-RoutingPathHasNoReparsePoint $normalized
    if (-not [System.IO.File]::Exists($normalized) -or [System.IO.Directory]::Exists($normalized)) {
        throw "$Label 必须是现存的普通文件：$normalized"
    }
    try { $resolved = (Resolve-Path -LiteralPath $normalized -ErrorAction Stop).ProviderPath }
    catch { throw "无法解析$Label：$normalized`n$($_.Exception.Message)" }
    $resolved = Get-NormalizedRoutingPath ([string]$resolved)
    Assert-RoutingPathHasNoReparsePoint $resolved
    return $resolved
}

function Get-RoutingManifestLocalSourcePaths {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$ManifestDirectory
    )

    $sources = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in @($Manifest.rules)) {
        foreach ($input in @($rule.inputs)) {
            if ($null -eq $input -or $null -eq $input.PSObject.Properties['type'] -or [string]$input.type -ne 'local') { continue }
            if ($null -eq $input.PSObject.Properties['path'] -or [string]::IsNullOrWhiteSpace([string]$input.path)) {
                throw '本地规则输入缺少有效 path 字段。'
            }
            $candidate = Join-Path $ManifestDirectory ([string]$input.path)
            $resolved = Resolve-RoutingInputFilePath -Path $candidate -Label '本地规则输入'
            if ($seen.Add($resolved)) { $sources.Add($resolved) }
        }
    }
    return [string[]]$sources.ToArray()
}

function Get-RoutingProtectedProjectRoots {
    param([Parameter(Mandatory)][string]$ProjectRoot)

    $root = Get-NormalizedRoutingPath $ProjectRoot
    return [string[]]@(
        (Join-Path $root 'scripts'),
        (Join-Path $root 'src'),
        (Join-Path $root 'tests'),
        (Join-Path $root 'config'),
        (Join-Path $root 'openwrt'),
        (Join-Path $root 'generated')
    )
}

function Enter-RoutingUpdateLocks {
    param(
        [Parameter(Mandatory)]$Paths,
        [int]$TimeoutSeconds = 30
    )

    Assert-RoutingTransactionPaths -Paths $Paths
    $candidatePaths = [string[]]@($Paths.CacheLockPath, $Paths.OutputLockPath)
    [Array]::Sort($candidatePaths, [System.StringComparer]::OrdinalIgnoreCase)
    $uniquePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($candidatePath in $candidatePaths) {
        if ($uniquePaths.Count -eq 0 -or -not [string]::Equals($uniquePaths[$uniquePaths.Count - 1], $candidatePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $uniquePaths.Add($candidatePath)
        }
    }

    $streams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    try {
        foreach ($lockPath in $uniquePaths) {
            Assert-RoutingTransactionPaths -Paths $Paths
            $parent = Split-Path -Parent $lockPath
            if (-not [System.IO.Directory]::Exists($parent)) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
            $stream = $null
            while ($null -eq $stream) {
                try {
                    Assert-RoutingTransactionPaths -Paths $Paths
                    $stream = [System.IO.FileStream]::new(
                        $lockPath,
                        [System.IO.FileMode]::OpenOrCreate,
                        [System.IO.FileAccess]::ReadWrite,
                        [System.IO.FileShare]::None
                    )
                }
                catch [System.IO.IOException] {
                    if ([DateTime]::UtcNow -ge $deadline) {
                        throw "等待规则更新锁超时，已有其他进程正在使用：$lockPath"
                    }
                    Start-Sleep -Milliseconds 200
                }
            }
            $streams.Add($stream)
            $lockBytes = [System.Text.Encoding]::ASCII.GetBytes("PID=$PID`n")
            $stream.SetLength(0)
            $stream.Write($lockBytes, 0, $lockBytes.Length)
            $stream.Flush($true)
        }
        return $streams.ToArray()
    }
    catch {
        foreach ($stream in $streams) {
            try {
                $stream.SetLength(0)
                $stream.Flush($true)
            }
            catch {
            }
            $stream.Dispose()
        }
        throw
    }
}

function Exit-RoutingUpdateLocks {
    param([AllowEmptyCollection()][System.IO.FileStream[]]$Streams)

    for ($index = @($Streams).Count - 1; $index -ge 0; $index--) {
        try {
            $Streams[$index].SetLength(0)
            $Streams[$index].Flush($true)
        }
        catch {
        }
        $Streams[$index].Dispose()
    }
}

function Write-RoutingTransactionJournal {
    param(
        [Parameter(Mandatory)]$Journal,
        [Parameter(Mandatory)]$Paths
    )

    Assert-RoutingTransactionPaths -Paths $Paths
    if ([System.IO.File]::Exists($Paths.JournalWritePath)) {
        throw '事务日志暂存文件已存在，拒绝覆盖未识别内容。'
    }
    if ([System.IO.File]::Exists($Paths.JournalReplaceBackupPath)) {
        throw '事务日志替换备份已存在，必须先完成恢复。'
    }
    $Journal.updated_at = [DateTime]::UtcNow.ToString('o')
    $compactJson = $Journal | ConvertTo-Json -Depth 10 -Compress
    $json = (Format-JsonText -Text $compactJson) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = $null
    try {
        $stream = [System.IO.FileStream]::new(
            $Paths.JournalWritePath,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }

    if ([System.IO.File]::Exists($Paths.JournalPath)) {
        Assert-RoutingTransactionPaths -Paths $Paths
        [System.IO.File]::Replace($Paths.JournalWritePath, $Paths.JournalPath, $Paths.JournalReplaceBackupPath)
        Remove-RoutingTransactionPath -Path $Paths.JournalReplaceBackupPath -Paths $Paths
    }
    else {
        [System.IO.File]::Move($Paths.JournalWritePath, $Paths.JournalPath)
    }
}

function Read-RoutingTransactionJournal {
    param([Parameter(Mandatory)]$Paths)

    Assert-RoutingTransactionPaths -Paths $Paths
    $journal = Read-JsonFile $Paths.JournalPath
    if ([int]$journal.version -ne 1) { throw '规则更新事务日志版本无效。' }
    if ([string]$journal.phase -notin @('prepared', 'committed')) { throw "规则更新事务阶段无效：$($journal.phase)" }
    foreach ($propertyName in @('cache_path','cache_stage_path','cache_backup_path','output_path','output_stage_path','output_backup_path')) {
        if ($null -eq $journal.PSObject.Properties[$propertyName]) { throw "规则更新事务日志缺少字段：$propertyName" }
    }
    foreach ($propertyName in @('cache_existed','output_existed')) {
        if ($null -eq $journal.PSObject.Properties[$propertyName]) { throw "规则更新事务日志缺少字段：$propertyName" }
    }

    $expectedPaths = [ordered]@{
        cache_path = $Paths.CachePath
        cache_stage_path = $Paths.CacheStagePath
        cache_backup_path = $Paths.CacheBackupPath
        output_path = $Paths.OutputPath
        output_stage_path = $Paths.OutputStagePath
        output_backup_path = $Paths.OutputBackupPath
    }
    foreach ($propertyName in $expectedPaths.Keys) {
        $recordedPath = [System.IO.Path]::GetFullPath([string]$journal.$propertyName)
        if (-not [string]::Equals($recordedPath, [string]$expectedPaths[$propertyName], [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "规则更新事务日志路径不匹配：$propertyName"
        }
    }
    return $journal
}

function Complete-RoutingCommittedTransaction {
    param([Parameter(Mandatory)]$Paths)

    Assert-RoutingTransactionPaths -Paths $Paths
    if ([System.IO.File]::Exists($Paths.CachePath)) { throw '缓存路径被文件占用，拒绝清理事务。' }
    if ([System.IO.Directory]::Exists($Paths.OutputPath)) { throw '规则输出路径被目录占用，拒绝清理事务。' }
    if (-not [System.IO.Directory]::Exists($Paths.CachePath)) { throw '已提交事务缺少发布后的缓存目录。' }
    if (-not [System.IO.File]::Exists($Paths.OutputPath)) { throw '已提交事务缺少发布后的规则输出。' }
    Remove-RoutingTransactionPath -Path $Paths.CacheStagePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.OutputStagePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.CacheBackupPath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.OutputBackupPath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalWritePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalReplaceBackupPath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalPath -Paths $Paths
}

function Rollback-RoutingPreparedTransaction {
    param(
        [Parameter(Mandatory)]$Journal,
        [Parameter(Mandatory)]$Paths
    )

    Assert-RoutingTransactionPaths -Paths $Paths
    if ([System.IO.File]::Exists($Paths.CachePath)) { throw '缓存路径被文件占用，拒绝自动回滚。' }
    if ([System.IO.Directory]::Exists($Paths.OutputPath)) { throw '规则输出路径被目录占用，拒绝自动回滚。' }
    if ([bool]$Journal.output_existed) {
        if ([System.IO.File]::Exists($Paths.OutputBackupPath)) {
            Remove-RoutingTransactionPath -Path $Paths.OutputPath -Paths $Paths
            [System.IO.File]::Move($Paths.OutputBackupPath, $Paths.OutputPath)
        }
        elseif (-not [System.IO.File]::Exists($Paths.OutputPath)) {
            throw '未提交事务无法恢复原规则输出：输出和备份都不存在。'
        }
    }
    else {
        if ([System.IO.File]::Exists($Paths.OutputBackupPath)) { throw '未提交事务发现不应存在的规则输出备份。' }
        Remove-RoutingTransactionPath -Path $Paths.OutputPath -Paths $Paths
    }

    if ([bool]$Journal.cache_existed) {
        if ([System.IO.Directory]::Exists($Paths.CacheBackupPath)) {
            Remove-RoutingTransactionPath -Path $Paths.CachePath -Paths $Paths
            [System.IO.Directory]::Move($Paths.CacheBackupPath, $Paths.CachePath)
        }
        elseif (-not [System.IO.Directory]::Exists($Paths.CachePath)) {
            throw '未提交事务无法恢复原缓存：缓存和备份都不存在。'
        }
    }
    else {
        if ([System.IO.Directory]::Exists($Paths.CacheBackupPath)) { throw '未提交事务发现不应存在的缓存备份。' }
        Remove-RoutingTransactionPath -Path $Paths.CachePath -Paths $Paths
    }

    Remove-RoutingTransactionPath -Path $Paths.OutputStagePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.CacheStagePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalWritePath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalReplaceBackupPath -Paths $Paths
    Remove-RoutingTransactionPath -Path $Paths.JournalPath -Paths $Paths
}

function Invoke-RoutingTransactionRecovery {
    param([Parameter(Mandatory)]$Paths)

    Assert-RoutingTransactionPaths -Paths $Paths
    if (-not [System.IO.File]::Exists($Paths.JournalPath) -and [System.IO.File]::Exists($Paths.JournalReplaceBackupPath)) {
        [System.IO.File]::Move($Paths.JournalReplaceBackupPath, $Paths.JournalPath)
    }
    if (-not [System.IO.File]::Exists($Paths.JournalPath)) {
        if ([System.IO.Directory]::Exists($Paths.CacheBackupPath) -or [System.IO.File]::Exists($Paths.OutputBackupPath)) {
            throw '检测到没有事务日志的规则更新备份，拒绝自动处理。'
        }
        Remove-RoutingTransactionPath -Path $Paths.CacheStagePath -Paths $Paths
        Remove-RoutingTransactionPath -Path $Paths.OutputStagePath -Paths $Paths
        Remove-RoutingTransactionPath -Path $Paths.JournalWritePath -Paths $Paths
        Remove-RoutingTransactionPath -Path $Paths.JournalReplaceBackupPath -Paths $Paths
        return
    }

    $journal = Read-RoutingTransactionJournal -Paths $Paths
    if ([string]$journal.phase -eq 'committed') {
        Write-Warning '检测到已提交但未清理的规则更新事务，正在完成清理。'
        Complete-RoutingCommittedTransaction -Paths $Paths
    }
    else {
        Write-Warning '检测到未提交的规则更新事务，正在恢复旧缓存和旧输出。'
        Rollback-RoutingPreparedTransaction -Journal $journal -Paths $Paths
    }
}

function Publish-RoutingTransaction {
    param([Parameter(Mandatory)]$Paths)

    Assert-RoutingTransactionPaths -Paths $Paths
    if ([System.IO.File]::Exists($Paths.CachePath)) { throw '缓存路径被文件占用，拒绝发布。' }
    if ([System.IO.Directory]::Exists($Paths.OutputPath)) { throw '规则输出路径被目录占用，拒绝发布。' }
    if (-not [System.IO.Directory]::Exists($Paths.CacheStagePath)) { throw '规则缓存暂存目录不存在。' }
    if (-not [System.IO.File]::Exists($Paths.OutputStagePath)) { throw '规则输出暂存文件不存在。' }
    if ([System.IO.File]::Exists($Paths.JournalPath) -or [System.IO.Directory]::Exists($Paths.CacheBackupPath) -or [System.IO.File]::Exists($Paths.OutputBackupPath)) {
        throw '检测到未恢复的规则更新事务，拒绝开始新发布。'
    }

    $journal = [ordered]@{
        version = 1
        phase = 'prepared'
        cache_path = $Paths.CachePath
        cache_stage_path = $Paths.CacheStagePath
        cache_backup_path = $Paths.CacheBackupPath
        cache_existed = [System.IO.Directory]::Exists($Paths.CachePath)
        output_path = $Paths.OutputPath
        output_stage_path = $Paths.OutputStagePath
        output_backup_path = $Paths.OutputBackupPath
        output_existed = [System.IO.File]::Exists($Paths.OutputPath)
        created_at = [DateTime]::UtcNow.ToString('o')
        updated_at = ''
    }
    Write-RoutingTransactionJournal -Journal $journal -Paths $Paths

    try {
        Assert-RoutingTransactionPaths -Paths $Paths
        if ([bool]$journal.cache_existed) { [System.IO.Directory]::Move($Paths.CachePath, $Paths.CacheBackupPath) }
        Assert-RoutingTransactionPaths -Paths $Paths
        [System.IO.Directory]::Move($Paths.CacheStagePath, $Paths.CachePath)
        if ([bool]$journal.output_existed) {
            Assert-RoutingTransactionPaths -Paths $Paths
            [System.IO.File]::Move($Paths.OutputPath, $Paths.OutputBackupPath)
        }
        Assert-RoutingTransactionPaths -Paths $Paths
        [System.IO.File]::Move($Paths.OutputStagePath, $Paths.OutputPath)
        $journal.phase = 'committed'
        Write-RoutingTransactionJournal -Journal $journal -Paths $Paths
    }
    catch {
        $publishError = $_
        try {
            Invoke-RoutingTransactionRecovery -Paths $Paths
        }
        catch {
            throw "规则更新事务提交失败：$($publishError.Exception.Message)；自动恢复失败：$($_.Exception.Message)"
        }
        throw $publishError
    }

    try {
        Complete-RoutingCommittedTransaction -Paths $Paths
    }
    catch {
        Write-Warning "规则更新已提交，但事务清理未完成；下次运行将自动恢复：$($_.Exception.Message)"
    }
}

if ($DefinitionsOnly) { return }
$resolvedManifestPath = Resolve-RoutingInputFilePath -Path $ManifestPath -Label '规则清单'
$manifestDirectory = Split-Path -Parent $resolvedManifestPath
$manifest = Read-JsonFile $resolvedManifestPath
if ([int]$manifest.version -ne 2) { throw 'routing-sources.json 必须使用 version 2 顺序格式。' }
$nonRejectSeen = $false
$remoteRejectSeen = $false
$adGuardTags = @($manifest.resources | Where-Object { $_.format -ceq 'adguard-dns' } | ForEach-Object { [string]$_.tag })
foreach ($rule in @($manifest.rules)) {
    if ($rule.action -cnotin @('direct','proxy','reject')) { throw "规则 '$($rule.id)' action 无效。" }
    foreach ($input in @($rule.inputs)) {
        $isLocal = $input.PSObject.Properties['type'] -and $input.type -ceq 'local'
        if ($rule.action -ceq 'reject') {
            if ($nonRejectSeen -or ($isLocal -and $remoteRejectSeen)) { throw 'Rules must order static rejects, then remote rejects, before direct/proxy groups.' }
            if (-not $isLocal) { $remoteRejectSeen = $true }
        } elseif (-not $isLocal -and [string]$input.resource -cin $adGuardTags) {
            throw 'AdGuard DNS sources require action reject.'
        }
    }
    if ($rule.action -cne 'reject') { $nonRejectSeen = $true }
}
$localSourcePaths = @(Get-RoutingManifestLocalSourcePaths -Manifest $manifest -ManifestDirectory $manifestDirectory)
$protectedPaths = [System.Collections.Generic.List[string]]::new()
foreach ($path in $localSourcePaths) { $protectedPaths.Add([string]$path) }
foreach ($path in @(
    (Join-Path $PSScriptRoot 'Update-RoutingRules.ps1'),
    (Join-Path $PSScriptRoot 'Json-Validation.ps1'),
    (Join-Path (Join-Path $script:ProjectRoot 'src') 'RoutingRuleCompiler.cs'),
    (Join-Path $PSScriptRoot 'SameTypeDirectPolicy.ps1'),
    (Join-Path (Join-Path $script:ProjectRoot 'src') 'SameTypeDirectCompiler.cs')
)) {
    $protectedPaths.Add((Get-NormalizedRoutingPath $path))
}
$resolvedZstdInputPath = ''
if (-not [string]::IsNullOrWhiteSpace($ZstdLibraryPath)) {
    $resolvedZstdInputPath = Get-NormalizedRoutingPath $ZstdLibraryPath
    Assert-RoutingPathHasNoReparsePoint $resolvedZstdInputPath
    if ([System.IO.File]::Exists($resolvedZstdInputPath)) {
        $resolvedZstdInputPath = Resolve-RoutingInputFilePath -Path $resolvedZstdInputPath -Label 'Zstandard 输入'
    }
    $protectedPaths.Add($resolvedZstdInputPath)
}
$protectedProjectRoots = Get-RoutingProtectedProjectRoots -ProjectRoot $script:ProjectRoot
if (-not $Offline) {
    Assert-RoutingFetchPathsSupported -CachePath $CacheDirectory -ResourceCount (@($manifest.resources).Count)
}
$transactionPaths = Get-RoutingTransactionPaths -CachePath $CacheDirectory -OutputPath $OutputPath -ManifestPath $resolvedManifestPath -ProtectedPaths ([string[]]$protectedPaths.ToArray()) -ProtectedRoots $protectedProjectRoots
$publishedCacheDirectory = $transactionPaths.CachePath
$publishedOutputPath = $transactionPaths.OutputPath
$transactionEnabled = -not $Offline
$workingCacheDirectory = $publishedCacheDirectory
$workingOutputPath = $publishedOutputPath
$transactionCommitted = $false
$routingLockStreams = @()
$ownsRoutingStage = $false

try {
$routingLockStreams = @(Enter-RoutingUpdateLocks -Paths $transactionPaths -TimeoutSeconds $LockTimeoutSeconds)
Assert-RoutingTransactionPaths -Paths $transactionPaths
Invoke-RoutingTransactionRecovery -Paths $transactionPaths
if ([System.IO.File]::Exists($transactionPaths.CachePath)) { throw '缓存路径被文件占用。' }
if ([System.IO.Directory]::Exists($transactionPaths.OutputPath)) { throw '规则输出路径被目录占用。' }
if ($transactionEnabled) {
    $ownsRoutingStage = $true
    $cacheParent = Split-Path -Parent $publishedCacheDirectory
    if (-not [System.IO.Directory]::Exists($cacheParent)) { [System.IO.Directory]::CreateDirectory($cacheParent) | Out-Null }
    Assert-RoutingTransactionPaths -Paths $transactionPaths
    if ([System.IO.Directory]::Exists($publishedCacheDirectory)) {
        Assert-RoutingPathTreeHasNoReparsePoint $publishedCacheDirectory
        Copy-Item -LiteralPath $publishedCacheDirectory -Destination $transactionPaths.CacheStagePath -Recurse
    }
    else {
        [System.IO.Directory]::CreateDirectory($transactionPaths.CacheStagePath) | Out-Null
    }
    Assert-RoutingTransactionPaths -Paths $transactionPaths
    $workingCacheDirectory = $transactionPaths.CacheStagePath
    $workingOutputPath = $transactionPaths.OutputStagePath
}

$selectorsByResource = @{}
foreach ($rule in @($manifest.rules)) {
    foreach ($input in @($rule.inputs)) {
        if (-not $input.PSObject.Properties['resource'] -or -not $input.PSObject.Properties['selector']) { continue }
        $tag = [string]$input.resource
        if (-not $selectorsByResource.ContainsKey($tag)) { $selectorsByResource[$tag] = [System.Collections.Generic.List[string]]::new() }
        if (-not $selectorsByResource[$tag].Contains([string]$input.selector)) { $selectorsByResource[$tag].Add([string]$input.selector) }
    }
}

$resourcePlan = @(New-ValidatedRemoteResourcePlan -Resources @($manifest.resources) -SelectorsByResource $selectorsByResource -CacheRoot $workingCacheDirectory)
$requiresMrs = @($resourcePlan | Where-Object { $_.Format -in @('mrs-domain','mrs-ipcidr') }).Count -gt 0
$requestedZstdPath = if ($resolvedZstdInputPath) { $resolvedZstdInputPath } else { $ZstdLibraryPath }
$zstdPath = if ($requiresMrs) { Resolve-ZstdLibrary $requestedZstdPath } else { $null }

$resourceByTag = @{}
$resourcePathByTag = @{}
$resourceStats = [System.Collections.Generic.List[object]]::new()
foreach ($entry in $resourcePlan) { $resourceByTag[[string]$entry.Tag] = $entry.Resource }
$fetchBatch = $null
if (-not $Offline) { $fetchBatch = Invoke-RoutingResourceFetches -ResourcePlan $resourcePlan -Concurrency $NetworkConcurrency -CacheRoot $workingCacheDirectory }
try {
    for ($resourceIndex = 0; $resourceIndex -lt $resourcePlan.Count; $resourceIndex++) {
        $entry = $resourcePlan[$resourceIndex]
        $resource = $entry.Resource
        $tag = [string]$entry.Tag
        $resourceSelectors = [string[]]$entry.Selectors
        if ($Offline) {
            $path = Get-RemoteSource -Resource $resource -CacheRoot $workingCacheDirectory -Selectors $resourceSelectors -ZstdPath $zstdPath -UseCacheOnly
        }
        else {
            $fetch = $fetchBatch.Results[$resourceIndex]
            if ($null -eq $fetch -or $fetch.StatusCode -notin @(200,304)) { throw "规则资源 '$tag' 下载结果无效。" }
            $metadata = $null
            if (Test-Path -LiteralPath $entry.MetadataPath -PathType Leaf) {
                try { $metadata = Read-JsonFile $entry.MetadataPath } catch { $metadata = $null }
            }
            if ($fetch.StatusCode -eq 304) {
                if (-not (Test-Path -LiteralPath $entry.CachePath -PathType Leaf)) { throw "规则资源 '$tag' 返回 304，但缓存不存在。" }
                $cacheHash = Assert-CachedSourceIntegrity -Resource $resource -CachePath $entry.CachePath -Metadata $metadata
                $newMetadata = [ordered]@{
                    url = [string]$resource.url
                    etag = if ($fetch.ETag) { [string]$fetch.ETag } elseif ($metadata) { [string]$metadata.etag } else { '' }
                    last_modified = if ($fetch.LastModified) { [string]$fetch.LastModified } elseif ($metadata) { [string]$metadata.last_modified } else { '' }
                    sha256 = $cacheHash
                    checked_at = [DateTime]::UtcNow.ToString('o')
                }
                Write-JsonAtomically -Value $newMetadata -Path $entry.MetadataPath
                $script:RemoteStates[$tag] = 'unchanged'
            }
            else {
                if (-not (Test-Path -LiteralPath $fetch.DownloadPath -PathType Leaf) -or (Get-Item -LiteralPath $fetch.DownloadPath).Length -eq 0) {
                    throw "规则资源 '$tag' 返回了空文件。"
                }
                Assert-RemoteSource -Resource $resource -Path $fetch.DownloadPath -Selectors $resourceSelectors -ZstdPath $zstdPath
                Assert-SourceCountChange -Resource $resource -NewPath $fetch.DownloadPath -OldPath $entry.CachePath -Selectors $resourceSelectors -ZstdPath $zstdPath
                Move-Item -LiteralPath $fetch.DownloadPath -Destination $entry.CachePath -Force
                $newMetadata = [ordered]@{
                    url = [string]$resource.url
                    etag = [string]$fetch.ETag
                    last_modified = [string]$fetch.LastModified
                    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.CachePath).Hash
                    checked_at = [DateTime]::UtcNow.ToString('o')
                }
                Write-JsonAtomically -Value $newMetadata -Path $entry.MetadataPath
                $script:RemoteStates[$tag] = 'updated'
            }
            $state = [string]$script:RemoteStates[$tag]
            $path = Get-RemoteSource -Resource $resource -CacheRoot $workingCacheDirectory -Selectors $resourceSelectors -ZstdPath $zstdPath -UseCacheOnly
            $script:RemoteStates[$tag] = $state
        }
        $resourcePathByTag[$tag] = $path
        $resourceStats.Add([PSCustomObject]@{
            Tag = $tag
            Format = [string]$resource.format
            State = $script:RemoteStates[$tag]
            Bytes = (Get-Item -LiteralPath $path).Length
            Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
        })
    }
}
finally {
    if ($fetchBatch -and $fetchBatch.Root) { Remove-RoutingFetchStage -Path $fetchBatch.Root -CacheRoot $workingCacheDirectory }
}

$localFingerprints = [System.Collections.Generic.List[object]]::new()
$ruleSequence = 0
foreach ($rule in @($manifest.rules)) {
    $ruleSequence++
    $inputIndex = 0
    foreach ($input in @($rule.inputs)) {
        $inputIndex++
        if (-not ($input.PSObject.Properties['type'] -and $input.type -eq 'local')) { continue }
        $localPath = Join-Path $manifestDirectory ([string]$input.path)
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) { throw "找不到本地规则输入：$localPath" }
        $localFingerprints.Add([ordered]@{
            Rule = [string]$rule.id
            Sequence = $ruleSequence
            Input = $inputIndex
            Path = [string]$input.path
            Format = [string]$input.format
            Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $localPath).Hash
        })
    }
}
$resourceFingerprints = [System.Collections.Generic.List[object]]::new()
foreach ($resource in @($manifest.resources)) {
    $resourceTag = [string]$resource.tag
    $resourceStat = @($resourceStats | Where-Object { $_.Tag -eq $resourceTag })[0]
    $resourceSelectors = if ($selectorsByResource.ContainsKey($resourceTag)) { @($selectorsByResource[$resourceTag]) } else { @() }
    $resourceFingerprints.Add([ordered]@{
        Tag = $resourceTag
        Format = [string]$resource.format
        Url = [string]$resource.url
        Selectors = $resourceSelectors
        Sha256 = [string]$resourceStat.Sha256
    })
}
$parserFingerprint = Get-RoutingParserFingerprint
$manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedManifestPath).Hash
$inputDescriptor = [ordered]@{
    Version = 1
    ManifestSha256 = $manifestHash
    ParserFingerprint = $parserFingerprint
    Sources = @($resourceFingerprints) + @($localFingerprints)
}
$mergeFingerprint = Get-Sha256Text ($inputDescriptor | ConvertTo-Json -Depth 100 -Compress)
$mergeCachePath = Join-Path $workingCacheDirectory 'merged-result.cache.json'
$mergePayload = $null
$mergeCacheHit = $false
if (Test-Path -LiteralPath $mergeCachePath -PathType Leaf) {
    try {
        $candidateCache = Read-JsonFile $mergeCachePath
        if ((Test-StrictJsonInteger $candidateCache.version 2 2) -and
            $candidateCache.fingerprint -is [string] -and $candidateCache.fingerprint -ceq $mergeFingerprint -and
            $candidateCache.content_sha256 -is [string] -and $candidateCache.content_sha256 -match '^[0-9A-Fa-f]{64}$' -and
            $candidateCache.PSObject.Properties['payload']) {
            $candidatePayload = $candidateCache.payload
            $candidatePayloadHash = Get-Sha256Text ($candidatePayload | ConvertTo-Json -Depth 100 -Compress)
            if ($candidatePayloadHash -ceq $candidateCache.content_sha256 -and
                (Test-RoutingMergeCachePayload -Payload $candidatePayload -ManifestRules @($manifest.rules))) {
                $mergePayload = $candidatePayload
                $mergeCacheHit = $true
            }
        }
    }
    catch {
        $mergeCacheHit = $false
        $mergePayload = $null
    }
}

if (-not $mergeCacheHit) {
    $geodataByTag = @{}
    foreach ($tag in $selectorsByResource.Keys) {
        $resource = $resourceByTag[$tag]
        if ($resource.format -notin @('geosite-dat','geoip-dat')) { continue }
        $geodataByTag[$tag] = Get-GeodataCache -Resource $resource -ResourcePath $resourcePathByTag[$tag] -Selectors @($selectorsByResource[$tag]) -CacheRoot $workingCacheDirectory
    }

    $ignored = [System.Collections.Generic.List[object]]::new()
    $groupInputs = [System.Collections.Generic.List[RoutingRuleGroupInput]]::new()
    $sequence = 0
    foreach ($rule in @($manifest.rules)) {
        $sequence++
        $groupItems = [System.Collections.Generic.List[object]]::new()
        foreach ($input in @($rule.inputs)) {
            if ($input.PSObject.Properties['type'] -and $input.type -eq 'local') {
                $localPath = Join-Path $manifestDirectory ([string]$input.path)
                $context = [PSCustomObject]@{Sequence=$sequence;Group=[string]$rule.id;Action=[string]$rule.action;Source=[string]$rule.id}
                $localResource = [PSCustomObject]@{tag=[string]$rule.id;format=[string]$input.format}
                Add-ResourceItems -Resource $localResource -Path $localPath -Context $context -Items $groupItems -Ignored $ignored -ZstdPath $zstdPath
                continue
            }

            $resourceTag = [string]$input.resource
            if (-not $resourceByTag.ContainsKey($resourceTag)) { throw "规则 '$($rule.id)' 引用了未知资源 '$resourceTag'。" }
            $resource = $resourceByTag[$resourceTag]
            $context = [PSCustomObject]@{Sequence=$sequence;Group=[string]$rule.id;Action=[string]$rule.action;Source=$resourceTag}
            if ($input.PSObject.Properties['selector']) {
                $selector = [string]$input.selector
                $category = $geodataByTag[$resourceTag].categories.PSObject.Properties[$selector]
                if (-not $category) { throw "资源 '$resourceTag' 缺少已导出的标签 '$selector'。" }
                Add-DocumentRules -Rules $category.Value -Context $context -Items $groupItems -Ignored $ignored
            }
            else {
                Add-ResourceItems -Resource $resource -Path $resourcePathByTag[$resourceTag] -Context $context -Items $groupItems -Ignored $ignored -ZstdPath $zstdPath
            }
        }
        $groupInputs.Add([RoutingRuleGroupInput]::new($sequence, [string]$rule.id, [string]$rule.action, $groupItems.Count, $groupItems.ToArray()))
    }

    $sampleLimit = 1000
    $mergeOutput = [RoutingRuleMergeEngine]::Merge($groupInputs.ToArray(), $sampleLimit)
    $removedSamples = [object[]]$mergeOutput.RemovedSamples
    $mergePayload = [ordered]@{
        groups = @($mergeOutput.Groups)
        extracted = [int]$mergeOutput.Extracted
        retained = [int]$mergeOutput.Retained
        removed = [int]$mergeOutput.Removed
        interval_adjusted = [int]$mergeOutput.IntervalAdjusted
        interval_split_fragments = [int]$mergeOutput.IntervalSplitFragments
        ignored = [int]$ignored.Count
        report_groups = @($mergeOutput.ReportGroups)
        removal_samples = @($removedSamples)
        ignored_items = @($ignored)
    }
    $payloadHash = Get-Sha256Text ($mergePayload | ConvertTo-Json -Depth 100 -Compress)
    $cacheRecord = [ordered]@{
        version = 2
        fingerprint = $mergeFingerprint
        content_sha256 = $payloadHash
        payload = $mergePayload
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    Write-JsonAtomically -Value $cacheRecord -Path $mergeCachePath
    Write-Host 'Validated merge cache rebuilt.'
}
else {
    Write-Host 'Validated merge cache reused.'
}

$sampleLimit = 1000
$extractedCount = [int]$mergePayload.extracted
$retainedCount = [int]$mergePayload.retained
$removedCount = [int]$mergePayload.removed
$intervalAdjustedCount = [int]$mergePayload.interval_adjusted
$intervalSplitFragments = [int]$mergePayload.interval_split_fragments
$removedSamples = @($mergePayload.removal_samples)
$groups = @($mergePayload.groups)
$result = [ordered]@{
    version = 2
    generated_at = [DateTime]::UtcNow.ToString('o')
    conflict_policy = [ordered]@{earlier_rule='wins';later_overlap='ordered-first-match'}
    groups = $groups
    report = [ordered]@{
        extracted = $extractedCount
        retained = $retainedCount
        removed = $removedCount
        interval_adjusted = $intervalAdjustedCount
        interval_split_fragments = $intervalSplitFragments
        ignored = [int]$mergePayload.ignored
        resources = @($resourceStats)
        groups = @($mergePayload.report_groups)
        removal_sample_limit = $sampleLimit
        removals_truncated = ($removedCount -gt $removedSamples.Count)
        removal_samples = $removedSamples
        ignored_items = @($mergePayload.ignored_items)
    }
}
Write-JsonAtomically -Value $result -Path $workingOutputPath
if ($transactionEnabled) {
    Publish-RoutingTransaction -Paths $transactionPaths
    $transactionCommitted = $true
}
$result.report.resources | Format-Table -AutoSize
Write-Host "顺序规则合并完成：提取 $extractedCount，保留 $retainedCount，删除 $removedCount，忽略 $($mergePayload.ignored)。"
Write-Host "输出：$publishedOutputPath"
}
finally {
    if ($ownsRoutingStage -and $routingLockStreams.Count -gt 0 -and -not $transactionCommitted -and -not [System.IO.File]::Exists($transactionPaths.JournalPath)) {
        try { Remove-RoutingTransactionPath -Path $transactionPaths.OutputStagePath -Paths $transactionPaths } catch { Write-Warning "清理规则输出暂存失败：$($_.Exception.Message)" }
        try { Remove-RoutingTransactionPath -Path $transactionPaths.CacheStagePath -Paths $transactionPaths } catch { Write-Warning "清理规则缓存暂存失败：$($_.Exception.Message)" }
        try { Remove-RoutingTransactionPath -Path $transactionPaths.JournalWritePath -Paths $transactionPaths } catch { Write-Warning "清理事务日志暂存失败：$($_.Exception.Message)" }
        try { Remove-RoutingTransactionPath -Path $transactionPaths.JournalReplaceBackupPath -Paths $transactionPaths } catch { Write-Warning "清理事务日志替换备份失败：$($_.Exception.Message)" }
    }
    Exit-RoutingUpdateLocks -Streams $routingLockStreams
}
