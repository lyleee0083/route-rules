Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'Json-Validation.ps1')
$valid = @(
    '{"/lib/xt_DSCP.ko":1,"/lib/xt_dscp.ko":2}',
    '{"A":1,"a":2}',
    '{"":1,"item":2,"nested":{"A":1,"a":2}}',
    '[{"key":1},{"key":2}]',
    '{"empty":{},"array":[{},1,null,true],"after":{"x":1}}'
)
foreach ($value in $valid) { Assert-StrictJsonText $value }
$invalid = @(
    '{"same":1,"same":2}',
    '{"/lib/xt_DSCP.ko":1,"/lib/xt_DSCP.ko":2}',
    '{"same":1,"\u0073ame":2}',
    '{"nested":{"key":1,"key":2}}',
    '[{"key":1,"key":2}]',
    '{"":1,"":2}',
    '{"broken":',
    'not-json'
)
foreach ($value in $invalid) {
    $rejected = $false
    try { Assert-StrictJsonText $value } catch { $rejected = $true }
    if (-not $rejected) { throw ('Invalid JSON accepted: ' + $value) }
    $rejected = $false
    try { $null = ConvertFrom-StrictJson -Text $value } catch { $rejected = $true }
    if (-not $rejected) { throw ('Production JSON conversion accepted invalid input: ' + $value) }
}
$converted = ConvertFrom-StrictJson -Text '{"name":"production","nested":{"value":1}}'
if ($converted.name -ne 'production' -or $converted.nested.value -ne 1) {
    throw 'Production JSON conversion changed valid input.'
}
Write-Output ('Case-sensitive JSON validation passed: ' + $valid.Count + ' valid fixtures and ' + $invalid.Count + ' duplicate/malformed fixtures.')
