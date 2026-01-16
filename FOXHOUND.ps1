# Invoke-FOXHOUND.ps1
param (
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$ProjectRoot
)

# Import central module
$ModulePath = Join-Path $PSScriptRoot "foxhound.psm1"
Import-Module $ModulePath -Force

# Optional: Write startup message
Write-Host "FOXHOUND starting manifest $Manifest"

# Invoke manifest
Invoke-FoxhoundManifest -ManifestPath $Manifest -ProjectRoot $ProjectRoot

Write-Host "FOXHOUND finished."
