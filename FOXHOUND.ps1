param (
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$ProjectRoot
)

$ModulePath = Join-Path $PSScriptRoot "foxhound.psm1"
Import-Module $ModulePath -Force

Write-Host "FOXHOUND starting manifest $Manifest"
Invoke-Manifest -ManifestPath $Manifest -ProjectRoot $ProjectRoot
Write-Host "FOXHOUND finished."
