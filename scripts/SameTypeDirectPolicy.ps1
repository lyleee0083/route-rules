# Resolve only within domain/IP/port families. PS 5.1 and 7 compatible.
if (-not ('SingBoxSameType.DomainCompiler' -as [type])) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $compileArguments = @{ Path=(Join-Path (Join-Path $projectRoot 'src') 'SameTypeDirectCompiler.cs') }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $compileArguments.ReferencedAssemblies = @('System.dll','System.Core.dll','System.Numerics.dll')
    }
    Add-Type @compileArguments
}
function Get-SameTypeValues {
    param($Rule, [string]$Field)
    if ($null -eq $Rule) { throw "Null rule object is not allowed while reading field '$Field'." }
    $values = $null
    if ($Rule -is [System.Collections.IDictionary]) {
        if (-not $Rule.Contains($Field)) { return }
        $values = $Rule[$Field]
    }
    else {
        $property = $Rule.PSObject.Properties[$Field]
        if ($null -eq $property) { return }
        $values = $property.Value
    }
    if ($null -eq $values) { throw "Null rule value is not allowed for field '$Field'." }
    if ($values -is [array]) {
        foreach ($value in $values) {
            if ($null -eq $value) { throw "Null rule value is not allowed for field '$Field'." }
        }
        return @($values)
    }
    return @($values)
}
function Test-SameTypeHasField {
    param($Rule, [string]$Field)
    if ($Rule -is [System.Collections.IDictionary]) { return $Rule.Contains($Field) }
    return $null -ne $Rule.PSObject.Properties[$Field]
}
function Get-SameTypePortRanges {
    param([object[]]$Rules, [string]$Family)
    $ranges = New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
    foreach ($rule in $Rules) {
        foreach ($port in (Get-SameTypeValues $rule $Family)) {
            if ($null -eq $port -or $port -is [bool] -or $port -is [string] -or $port -is [double] -or $port -is [decimal] -or [long]$port -lt 0 -or [long]$port -gt 65535) { throw 'Invalid integer port.' }
            $ranges.Add([SingBoxSameType.Ranges]::Port([int]$port,[int]$port))
        }
        foreach ($range in (Get-SameTypeValues $rule ($Family + '_range'))) {
            if ([string]$range -notmatch '^(\d*):(\d*)$') { throw 'Invalid port range.' }
            $start=0; $end=65535
            if ($Matches[1]) { $start=[int]$Matches[1] }
            if ($Matches[2]) { $end=[int]$Matches[2] }
            $ranges.Add([SingBoxSameType.Ranges]::Port($start,$end))
        }
    }
    return ,$ranges.ToArray()
}

function Get-SameTypeSourceProvenance {
    param([Parameter(Mandatory)][object[]]$Items)
    $bySequence = New-Object 'System.Collections.Generic.SortedDictionary[int,string]'
    foreach ($item in $Items) {
        $groups = @($item.SourceGroups)
        $sequences = @($item.SourceSequences)
        if ($groups.Count -ne $sequences.Count) { throw 'Source group and sequence provenance lengths differ.' }
        for ($index = 0; $index -lt $groups.Count; $index++) {
            $sequence = [int]$sequences[$index]
            $group = [string]$groups[$index]
            if ($bySequence.ContainsKey($sequence) -and $bySequence[$sequence] -cne $group) {
                throw ('Conflicting source provenance sequence: ' + $sequence)
            }
            $bySequence[$sequence] = $group
        }
    }
    return [pscustomobject]@{
        Sequences = [int[]]@($bySequence.Keys)
        Groups = [string[]]@($bySequence.Values)
    }
}

function Join-SameTypeDirectFamilyPlan {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Plan)
    $families = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $Plan) {
        if (-not $families.Contains([string]$item.Kind)) { $families.Add([string]$item.Kind) }
    }
    $joined = New-Object 'System.Collections.Generic.List[object]'
    foreach ($family in $families) {
        $items = @($Plan | Where-Object { $_.Kind -ceq $family })
        if ($items.Count -eq 0) { continue }
        $provenance = Get-SameTypeSourceProvenance -Items $items
        $rules = New-Object 'System.Collections.Generic.List[object]'
        if ($family -eq 'domain') {
            $combined = [ordered]@{}
            foreach ($field in @('domain','domain_suffix','domain_regex')) {
                $values = New-Object 'System.Collections.Generic.List[string]'
                foreach ($item in $items) {
                    foreach ($rule in @($item.Rules)) {
                        foreach ($value in (Get-SameTypeValues $rule $field)) { $values.Add([string]$value) }
                    }
                }
                if ($values.Count -gt 0) { $combined[$field] = [string[]]$values.ToArray() }
            }
            if ($combined.Count -gt 0) { $rules.Add($combined) }
        }
        elseif ($family -eq 'ip') {
            $ranges = New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
            foreach ($item in $items) {
                foreach ($rule in @($item.Rules)) {
                    foreach ($cidr in (Get-SameTypeValues $rule 'ip_cidr')) {
                        $range = [SingBoxSameType.Ranges]::IP([string]$cidr)
                        if ($range.Bits -ne 32) { throw 'IPv6 reached final effective direct family aggregation.' }
                        $ranges.Add($range)
                    }
                }
            }
            $cidrs = [SingBoxSameType.Ranges]::CIDRs([SingBoxSameType.Ranges]::Merge($ranges.ToArray()))
            if ($cidrs.Count -gt 0) { $rules.Add([ordered]@{ ip_cidr = [string[]]$cidrs }) }
        }
        elseif ($family -eq 'port') {
            foreach ($portFamily in @('port','source_port')) {
                $allRanges = New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
                foreach ($item in $items) {
                    foreach ($rule in @($item.Rules)) {
                        $hasFamily = $false
                        foreach ($field in @('port','port_range','source_port','source_port_range')) {
                            if ((Test-SameTypeHasField -Rule $rule -Field $field) -and
                                (($portFamily -eq 'port' -and $field -in @('port','port_range')) -or
                                 ($portFamily -eq 'source_port' -and $field -in @('source_port','source_port_range')))) { $hasFamily = $true }
                        }
                        if ($hasFamily) {
                            foreach ($range in (Get-SameTypePortRanges -Rules @($rule) -Family $portFamily)) { $allRanges.Add($range) }
                        }
                    }
                }
                if ($allRanges.Count -eq 0) { continue }
                $match = [ordered]@{}
                $ports = New-Object 'System.Collections.Generic.List[int]'
                $portRanges = New-Object 'System.Collections.Generic.List[string]'
                foreach ($range in [SingBoxSameType.Ranges]::Merge($allRanges.ToArray())) {
                    if ($range.Start -eq $range.End) { $ports.Add([int]$range.Start) }
                    else { $portRanges.Add(([string]$range.Start + ':' + [string]$range.End)) }
                }
                if ($ports.Count -gt 0) { $match[$portFamily] = [int[]]$ports.ToArray() }
                if ($portRanges.Count -gt 0) { $match[$portFamily + '_range'] = [string[]]$portRanges.ToArray() }
                if ($match.Count -gt 0) { $rules.Add($match) }
            }
        }
        else { throw ('Unexpected final direct family: ' + $family) }
        if ($rules.Count -eq 0) { continue }
        $action = [string]$items[0].Action
        $tag = 'routing-' + $action + '-' + $family
        $joined.Add([pscustomobject][ordered]@{
            Sequence = [int]$provenance.Sequences[0]
            Tag = $tag
            Action = $action
            HasDomain = ($family -eq 'domain')
            Kind = $family
            Rules = $rules.ToArray()
            SourceGroups = $provenance.Groups
            SourceSequences = $provenance.Sequences
        })
    }
    return ,$joined.ToArray()
}

function Optimize-SameTypeDirectDomainUnion {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Plan)
    $domainItems = @($Plan | Where-Object { $_.Kind -eq 'domain' })
    if ($domainItems.Count -eq 0) {
        $script:SameTypeDomainCompactionSummary = [pscustomobject]@{ NativeBefore=0; NativeAfter=0; Removed=0; RegexBefore=0; RegexAfter=0; GroupsBefore=0; GroupsAfter=0; FamilyFilesBefore=$Plan.Count; FamilyFilesAfter=@((Join-SameTypeDirectFamilyPlan -Plan $Plan) | Where-Object { $_.Kind -eq 'domain' }).Count }
        return ,(Join-SameTypeDirectFamilyPlan -Plan $Plan)
    }

    $details = New-Object 'System.Collections.Generic.List[object]'
    $exactValues = New-Object 'System.Collections.Generic.List[string]'
    $suffixValues = New-Object 'System.Collections.Generic.List[string]'
    $nativeBefore = 0
    $regexBefore = 0
    foreach ($item in $domainItems) {
        $rule = @($item.Rules)[0]
        $exact = [string[]]@(Get-SameTypeValues $rule 'domain')
        $suffix = [string[]]@(Get-SameTypeValues $rule 'domain_suffix')
        $regex = [string[]]@(Get-SameTypeValues $rule 'domain_regex')
        $nativeBefore += $exact.Count + $suffix.Count
        $regexBefore += $regex.Count
        foreach ($value in $exact) { $exactValues.Add($value) }
        foreach ($value in $suffix) { $suffixValues.Add($value) }
        $details.Add([pscustomobject]@{ Item=$item; Exact=$exact; Suffix=$suffix; Regex=$regex; SourceGroups=[string[]]@($item.SourceGroups); SourceSequences=[int[]]@($item.SourceSequences) })
    }

    $compacted = [SingBoxSameType.PositiveDomainCompactor]::Compact($exactValues.ToArray(),$suffixValues.ToArray())
    $keptExact = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $keptSuffix = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($value in $compacted[0]) { [void]$keptExact.Add([string]$value) }
    foreach ($value in $compacted[1]) { [void]$keptSuffix.Add([string]$value) }
    $assignedExact = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $assignedSuffix = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $exactOwners = @{}
    $suffixOwners = @{}
    $removedValues = New-Object 'System.Collections.Generic.List[object]'
    $regexAfter = 0
    foreach ($detail in $details) {
        $rule = [ordered]@{}
        $remainingExact = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in $detail.Exact) {
            if ($keptExact.Contains($value) -and $assignedExact.Add($value)) {
                $remainingExact.Add($value)
                $exactOwners[$value] = $detail.Item
            }
            else { $removedValues.Add([pscustomobject]@{ Field='domain'; Value=$value; Item=$detail.Item; SourceGroups=$detail.SourceGroups; SourceSequences=$detail.SourceSequences }) }
        }
        $remainingSuffix = New-Object 'System.Collections.Generic.List[string]'
        foreach ($value in $detail.Suffix) {
            if ($keptSuffix.Contains($value) -and $assignedSuffix.Add($value)) {
                $remainingSuffix.Add($value)
                $suffixOwners[$value] = $detail.Item
            }
            else { $removedValues.Add([pscustomobject]@{ Field='domain_suffix'; Value=$value; Item=$detail.Item; SourceGroups=$detail.SourceGroups; SourceSequences=$detail.SourceSequences }) }
        }
        if ($remainingExact.Count -gt 0) { $rule['domain'] = [string[]]$remainingExact.ToArray() }
        if ($remainingSuffix.Count -gt 0) { $rule['domain_suffix'] = [string[]]$remainingSuffix.ToArray() }
        if ($detail.Regex.Count -gt 0) {
            $rule['domain_regex'] = [string[]]$detail.Regex
            $regexAfter += $detail.Regex.Count
        }
        if ($rule.Count -gt 0) { $detail.Item.Rules = @($rule) }
        else { $detail.Item.Rules = [object[]]@() }
    }

    foreach ($removed in $removedValues) {
        $owner = $null
        if ($removed.Field -eq 'domain' -and $exactOwners.ContainsKey([string]$removed.Value)) {
            $owner = $exactOwners[[string]$removed.Value]
        }
        if ($null -eq $owner) {
            $candidate = [string]$removed.Value
            while ($candidate) {
                if ($suffixOwners.ContainsKey($candidate)) {
                    $owner = $suffixOwners[$candidate]
                    break
                }
                $dot = $candidate.IndexOf('.')
                if ($dot -lt 0) { break }
                $candidate = $candidate.Substring($dot + 1)
            }
        }
        if ($null -eq $owner) { throw ('Unable to preserve source provenance for compacted domain predicate: ' + [string]$removed.Value) }
        $sourceGroups = New-Object 'System.Collections.Generic.List[string]'
        $sourceSequences = New-Object 'System.Collections.Generic.List[int]'
        $seenSources = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        $sourcePairs = New-Object 'System.Collections.Generic.SortedDictionary[int,string]'
        $ownerGroups = @($owner.SourceGroups)
        $ownerSequences = @($owner.SourceSequences)
        $removedGroups = @($removed.SourceGroups)
        $removedSequences = @($removed.SourceSequences)
        if ($ownerGroups.Count -ne $ownerSequences.Count -or $removedGroups.Count -ne $removedSequences.Count) { throw 'Source group and sequence provenance lengths differ.' }
        for ($index = 0; $index -lt $ownerGroups.Count; $index++) { $sourcePairs[[int]$ownerSequences[$index]] = [string]$ownerGroups[$index] }
        for ($index = 0; $index -lt $removedGroups.Count; $index++) { $sourcePairs[[int]$removedSequences[$index]] = [string]$removedGroups[$index] }
        foreach ($sequence in $sourcePairs.Keys) {
            $sourceGroup = $sourcePairs[$sequence]
            if ($seenSources.Add([string]$sourceGroup)) { $sourceGroups.Add([string]$sourceGroup); $sourceSequences.Add([int]$sequence) }
        }
        $owner.SourceGroups = [string[]]$sourceGroups.ToArray()
        $owner.SourceSequences = [int[]]$sourceSequences.ToArray()
    }

    $optimized = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $Plan) {
        if ($item.Kind -eq 'domain' -and @($item.Rules).Count -eq 0) { continue }
        $optimized.Add($item)
    }
    $nativeAfter = $keptExact.Count + $keptSuffix.Count
    $hasDomainOutput = ($nativeAfter -gt 0 -or $regexAfter -gt 0)
    $script:SameTypeDomainCompactionSummary = [pscustomobject]@{
        NativeBefore=$nativeBefore; NativeAfter=$nativeAfter; Removed=($nativeBefore - $nativeAfter)
        RegexBefore=$regexBefore; RegexAfter=$regexAfter; GroupsBefore=$domainItems.Count
        GroupsAfter=[int]$hasDomainOutput; FamilyFilesBefore=$Plan.Count
        FamilyFilesAfter=@(Join-SameTypeDirectFamilyPlan -Plan $optimized.ToArray()).Count
    }
    return ,(Join-SameTypeDirectFamilyPlan -Plan $optimized.ToArray())
}

function Get-SameTypeDirectPlan {
    param([Parameter(Mandatory)][object]$Document)
    $doc = ConvertTo-Json -InputObject $Document -Depth 100 -Compress | ConvertFrom-Json
    if ($doc.version -ne 2) { throw 'Expected ordered merged document version 2.' }
    $groups = @($doc.groups | Sort-Object sequence)
    if (@($groups.sequence | Select-Object -Unique).Count -ne $groups.Count) { throw 'Duplicate source sequence.' }
    $rejectGroups = @($groups | Where-Object { $_.action -ceq 'reject' })
    $directInputs = New-Object 'System.Collections.Generic.List[object]'
    $ordinaryStarted = $false
    foreach ($group in $groups) {
        if ($group.action -cne 'reject') {
            $ordinaryStarted = $true
            $directInputs.Add($group)
            continue
        }
        if ($ordinaryStarted) { throw 'Reject source groups must precede direct/proxy groups.' }
        $numeric = @($group.rules | Where-Object { $_.PSObject.Properties.Name -match '^(ip_cidr|port|port_range|source_port|source_port_range)$' })
        if ($numeric.Count) {
            $directInputs.Add([pscustomobject]@{ sequence=$group.sequence; id=$group.id; action='proxy'; rules=$numeric; rejection_input=$true })
        }
    }
    $denyPlan = @()
    if ($rejectGroups.Count) { $denyPlan = Resolve-SameTypeFamilyPlan -Groups $rejectGroups -Action 'reject' }
    $directPlan = Resolve-SameTypeFamilyPlan -Groups $directInputs.ToArray() -Action 'direct'
    return ,@($denyPlan + $directPlan)
}

function Resolve-SameTypeFamilyPlan {
    param([object[]]$Groups, [ValidateSet('reject','direct')][string]$Action)
    $typeOrder = New-Object 'System.Collections.Generic.List[string]'
    $plan = New-Object 'System.Collections.Generic.List[object]'
    $domains = New-Object SingBoxSameType.DomainCompiler
    $blockedIP = [SingBoxSameType.Interval[]]@()
    $blockedPorts = @{ port=[SingBoxSameType.Interval[]]@(); source_port=[SingBoxSameType.Interval[]]@() }
    foreach ($group in $Groups) {
        if ($group.action -cnotin @($Action,'proxy')) { throw 'Unsupported source action.' }
        $families = [ordered]@{}
        foreach ($rule in @($group.rules)) {
            $family=''
            foreach ($field in @($rule.PSObject.Properties.Name)) {
                $next=''
                if ($field -in @('domain','domain_suffix') -or ($field -eq 'domain_regex' -and $Action -eq 'reject')) { $next='domain' }
                elseif ($field -eq 'ip_cidr') { $next='ip' }
                elseif ($field -in @('port','port_range')) { $next='port' }
                elseif ($field -in @('source_port','source_port_range')) { $next='source_port' }
                else { throw ('Unsupported same-type input field: ' + $field) }
                if ($family -and $family -ne $next) { throw 'Mixed-type AND inputs cannot be silently flattened into independent families.' }
                $family=$next
            }
            if (-not $family) { throw 'Empty source predicate.' }
            $type=$family
            if ($family -eq 'source_port') { $type='port' }
            if (-not $group.PSObject.Properties['rejection_input'] -and -not $typeOrder.Contains($type)) { $typeOrder.Add($type) }
            if (-not $families.Contains($family)) { $families[$family]=New-Object 'System.Collections.Generic.List[object]' }
            $families[$family].Add($rule)
        }
        foreach ($family in $families.Keys) {
            $rules=@($families[$family].ToArray())
            $match=[ordered]@{}
            if ($family -eq 'domain') {
                if ($group.action -eq 'proxy') {
                    foreach ($rule in $rules) {
                        foreach ($value in (Get-SameTypeValues $rule domain)) { $domains.Block([string]$value,$false) }
                        foreach ($value in (Get-SameTypeValues $rule domain_suffix)) { $domains.Block([string]$value,$true) }
                    }
                    continue
                }
                $exact=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                $suffix=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                $patterns=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                foreach ($rule in $rules) {
                    foreach ($value in (Get-SameTypeValues $rule domain_regex)) {
                        if (-not [SingBoxSameType.DomainCompiler]::IsGeneratedPositiveRegex([string]$value)) { throw 'Invalid compiled rejection domain predicate.' }
                        [void]$patterns.Add([string]$value)
                    }
                    foreach ($value in (Get-SameTypeValues $rule domain)) {
                        $normalized=[SingBoxSameType.DomainCompiler]::Normalize([string]$value)
                        if ($domains.ExactAllowed($normalized)) { [void]$exact.Add($normalized) }
                    }
                    foreach ($value in (Get-SameTypeValues $rule domain_suffix)) {
                        $normalized=[SingBoxSameType.DomainCompiler]::Normalize([string]$value)
                        $pattern=$domains.SuffixPattern($normalized)
                        if ($null -eq $pattern) { continue }
                        if ($pattern -eq '') { [void]$suffix.Add($normalized) } else { [void]$patterns.Add($pattern) }
                    }
                }
                $compactedDomains = [SingBoxSameType.PositiveDomainCompactor]::Compact([string[]]@($exact), [string[]]@($suffix))
                $exact = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                $suffix = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                foreach ($value in $compactedDomains[0]) { [void]$exact.Add([string]$value) }
                foreach ($value in $compactedDomains[1]) { [void]$suffix.Add([string]$value) }
                foreach ($pair in @(@('domain',$exact),@('domain_suffix',$suffix),@('domain_regex',$patterns))) {
                    if ($pair[1].Count) { $values=[string[]]@($pair[1]); [Array]::Sort($values,[StringComparer]::Ordinal); $match[$pair[0]]=$values }
                }
            } elseif ($family -eq 'ip') {
                $ranges=New-Object 'System.Collections.Generic.List[SingBoxSameType.Interval]'
                foreach ($rule in $rules) {
                    foreach ($value in (Get-SameTypeValues $rule ip_cidr)) {
                        $range=[SingBoxSameType.Ranges]::IP([string]$value)
                        # IPv6 is rejected first; it must not exist in final SRS.
                        if ($range.Bits -eq 32) { $ranges.Add($range) }
                    }
                }
                if ($group.action -eq 'proxy') { $blockedIP=[SingBoxSameType.Ranges]::Merge([SingBoxSameType.Interval[]]@($blockedIP + $ranges.ToArray())); continue }
                $remaining=[SingBoxSameType.Ranges]::Subtract($ranges.ToArray(),$blockedIP)
                $cidrs=[SingBoxSameType.Ranges]::CIDRs($remaining)
                if ($cidrs.Count) { $match.ip_cidr=$cidrs }
            } else {
                $ranges=Get-SameTypePortRanges $rules $family
                if ($group.action -eq 'proxy') { $blockedPorts[$family]=[SingBoxSameType.Ranges]::Merge([SingBoxSameType.Interval[]]@($blockedPorts[$family] + $ranges)); continue }
                $remaining=[SingBoxSameType.Ranges]::Subtract($ranges,$blockedPorts[$family])
                $ports=@(); $intervals=@()
                foreach ($range in $remaining) {
                    if ($range.Start -eq $range.End) { $ports += [int]$range.Start }
                    else { $intervals += ([string]$range.Start + ':' + [string]$range.End) }
                }
                if ($ports.Count) { $match[$family]=$ports }
                if ($intervals.Count) { $match[$family + '_range']=$intervals }
            }
            if ($match.Count) {
                $type=$family; if ($family -eq 'source_port') { $type='port' }
                $plan.Add([pscustomobject][ordered]@{ Sequence=[int]$group.sequence; Tag=('routing-{0}-{1:D2}-{2}' -f $Action,[int]$group.sequence,$family);
                    Action=$Action; HasDomain=($family -eq 'domain'); Kind=$type; Rules=@($match); SourceGroups=@([string]$group.id); SourceSequences=@([int]$group.sequence) })
            }
        }
    }
    $ordered=New-Object 'System.Collections.Generic.List[object]'
    foreach ($type in $typeOrder) { foreach ($item in $plan) { if ($item.Kind -eq $type) { $ordered.Add($item) } } }
    $optimized = Optimize-SameTypeDirectDomainUnion -Plan $ordered.ToArray()
    return ,$optimized
}
