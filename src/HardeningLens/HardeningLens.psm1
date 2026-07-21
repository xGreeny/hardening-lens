Set-StrictMode -Version 2.0

$script:HLModuleRoot = $PSScriptRoot
$script:HLDataRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Data'
$script:HLSchemaRoot = Join-Path -Path $PSScriptRoot -ChildPath 'Schema'
$script:HLControlCatalogCache = $null
$script:HLProbeRegistryCache = $null
$script:HLAuditNativeLoaded = $false

$privateFunctions = Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Private') -Filter '*.ps1' -File | Sort-Object Name
$publicFunctions = Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1' -File | Sort-Object Name

foreach ($file in @($privateFunctions + $publicFunctions)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load Hardening Lens function file '$($file.FullName)': $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Invoke-HardeningLens',
    'Invoke-HardeningLensFleet',
    'Export-HardeningLensReport',
    'Export-HardeningLensFleetReport',
    'Compare-HardeningLensResult',
    'Get-HardeningLensBaseline',
    'Get-HardeningLensControl',
    'Test-HardeningLensBaseline',
    'Test-HardeningLensPolicy',
    'Test-HardeningLensExceptionFile',
    'New-HardeningLensExceptionFile',
    'Set-HardeningLensException'
)
