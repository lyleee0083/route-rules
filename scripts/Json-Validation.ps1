Add-Type -AssemblyName System.Runtime.Serialization

function Assert-StrictJsonText {
    param([Parameter(Mandatory)][string]$Text)
    # JSON member names are case-sensitive, unlike PSCustomObject properties.
    # Keep Linux file-name evidence intact while rejecting exact duplicate keys.
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $reader = [System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
        $bytes, [Xml.XmlDictionaryReaderQuotas]::Max)
    $objects = @{}
    try {
        while ($reader.Read()) {
            $depth = $reader.Depth
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                [void]$objects.Remove($depth)
                if ($depth -gt 0 -and $objects.ContainsKey($depth - 1)) {
                    $key = $reader.GetAttribute('item')
                    if ($null -eq $key) { $key = $reader.LocalName }
                    if (-not $objects[$depth - 1].Add($key)) {
                        throw ('Duplicate JSON member name: ' + $key)
                    }
                }
                if ($reader.GetAttribute('type') -eq 'object' -and -not $reader.IsEmptyElement) {
                    $objects[$depth] = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                }
            } elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) {
                [void]$objects.Remove($depth)
            }
        }
    } finally { $reader.Dispose() }
}

function ConvertFrom-StrictJson {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    # Validate before ConvertFrom-Json can silently replace duplicate members.
    Assert-StrictJsonText -Text $Text
    return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
}

function Read-StrictJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
        return ConvertFrom-StrictJson -Text $text
    } catch {
        throw ('Invalid JSON file: ' + $Path + "`n" + $_.Exception.Message)
    }
}

function Get-ClientNormalizedFullPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A filesystem path is required.' }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) { throw "Filesystem path has no absolute root: $Path" }
    if ($full.Length -gt $root.Length) { $full = $full.TrimEnd([char[]]'\/') }
    if ([string]::IsNullOrEmpty($full)) { $full = $root }
    return $full
}

function Assert-ClientPlainPathTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('Any','Directory','File')][string]$LeafType = 'Any',
        [switch]$Required,
        [switch]$IncludeDescendants
    )

    $full = Get-ClientNormalizedFullPath -Path $Path
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) { throw "Filesystem path has no absolute root: $full" }
    $chain = [Collections.Generic.List[string]]::new()
    $cursor = $full
    while ($true) {
        $chain.Add($cursor)
        if ($cursor.TrimEnd([char[]]'\/') -ieq $root.TrimEnd([char[]]'\/')) { break }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -ieq $cursor) { break }
        $cursor = $parent
    }

    $leafExists = $false
    $missingAncestor = $false
    for ($index = $chain.Count - 1; $index -ge 0; $index--) {
        $component = $chain[$index]
        $attributes = $null
        try { $attributes = [IO.File]::GetAttributes($component) }
        catch [IO.FileNotFoundException] {
            $missingAncestor = $true
            continue
        }
        catch [IO.DirectoryNotFoundException] {
            $missingAncestor = $true
            continue
        }

        if ($missingAncestor) { throw "Path component exists below a missing ancestor: $component" }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing filesystem path through a reparse point: $component"
        }
        $isDirectory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
        if ($index -gt 0 -and -not $isDirectory) { throw "Filesystem path ancestor is not a directory: $component" }
        if ($index -eq 0) {
            $leafExists = $true
            if ($LeafType -ceq 'Directory' -and -not $isDirectory) { throw "Filesystem path is not a directory: $full" }
            if ($LeafType -ceq 'File' -and $isDirectory) { throw "Filesystem path is not a file: $full" }
        }
    }

    if ($Required -and -not $leafExists) { throw "Required filesystem path is missing: $full" }
    if ($IncludeDescendants -and $leafExists -and $LeafType -ceq 'Directory') {
        $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
        $pending.Push([IO.DirectoryInfo]::new($full))
        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            foreach ($child in $directory.GetFileSystemInfos()) {
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Refusing filesystem tree containing a reparse point: $($child.FullName)"
                }
                if ($child -is [IO.DirectoryInfo]) { $pending.Push([IO.DirectoryInfo]$child) }
                elseif ($child -isnot [IO.FileInfo]) { throw "Unsupported filesystem object in path tree: $($child.FullName)" }
            }
        }
    }
    return $full
}
