# Run as a normal user. Only public, verified upstream files enter the export.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bundle,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'
$sourceDir = (Resolve-Path -LiteralPath $Bundle).Path
$exportDir = [System.IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $exportDir) { throw "Destination must be a new folder." }
$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'zapret-files.json') | ConvertFrom-Json
foreach ($item in $manifest.PSObject.Properties) {
    $path = Join-Path $sourceDir $item.Name
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $item.Value) {
        throw "Upstream file failed verification: $($item.Name)"
    }
}
[void][IO.Directory]::CreateDirectory($exportDir)
foreach ($item in $manifest.PSObject.Properties) {
    $target = Join-Path $exportDir $item.Name
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    [IO.File]::Copy((Join-Path $sourceDir $item.Name),$target,$false)
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $item.Value) {
        throw "The copy failed verification. Discard this export."
    }
}
Write-Output "Verified export: $exportDir"
Write-Output "Copy this whole folder as engine under Program Files\FLURUX\Security using Explorer."
