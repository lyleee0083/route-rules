[CmdletBinding()]
param(
    [string]$Client,
    [switch]$All,
    [switch]$Offline,
    [switch]$AllowSourceShrink,
    [switch]$Force,
    [switch]$LinuxRouteExcludeAddressSets,
    [string]$TunAddress,
    [string]$OutputDirectory,
    [string]$SupportDirectory,
    [string]$SingBoxPath,
    [string]$ZstdLibraryPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$generateScript = Join-Path $PSScriptRoot 'Generate-SingBoxConfig.ps1'

$arguments = @{
    Force = $Force
    Offline = $Offline
    AllowSourceShrink = $AllowSourceShrink
}
if ($Client) { $arguments['Client'] = $Client }
if ($All) { $arguments['All'] = $true }
if ($PSBoundParameters.ContainsKey('LinuxRouteExcludeAddressSets')) { $arguments['LinuxRouteExcludeAddressSets'] = $LinuxRouteExcludeAddressSets.IsPresent }
if ($TunAddress) { $arguments['TunAddress'] = $TunAddress }
if ($OutputDirectory) { $arguments['OutputDirectory'] = $OutputDirectory }
if ($SupportDirectory) { $arguments['SupportDirectory'] = $SupportDirectory }
if ($SingBoxPath) { $arguments['SingBoxPath'] = $SingBoxPath }
if ($ZstdLibraryPath) { $arguments['ZstdLibraryPath'] = $ZstdLibraryPath }

& $generateScript @arguments
