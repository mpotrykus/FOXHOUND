param (
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$false)][string]$ProjectRoot
)

$ModulePath = Join-Path $PSScriptRoot "foxhound.psm1"
Import-Module $ModulePath -Force

# If ProjectRoot wasn't supplied, derive it from the Manifest's folder.
if (-not $ProjectRoot) {
    try {
        $manifestFull = (Resolve-Path -Path $Manifest -ErrorAction Stop).ProviderPath
    } catch {
        # Resolve-Path failed (manifest may be a non-existent relative path); use the raw value
        $manifestFull = $Manifest
    }

    try {
        $derived = Split-Path -Path $manifestFull -Parent
    } catch {
        $derived = $null
    }

    if ($derived) {
        $ProjectRoot = $derived
    } else {
        # Fallback to the script folder if we couldn't determine the manifest folder
        $ProjectRoot = $PSScriptRoot
    }
}

Write-Host "FOXHOUND starting manifest $Manifest"
Invoke-Manifest -ManifestPath $Manifest -ProjectRoot $ProjectRoot
Write-Host "FOXHOUND finished."
