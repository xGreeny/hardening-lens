@{
    RootModule           = 'HardeningLens.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = '1b1d694c-40f9-4db4-a7ad-b6ca5ad934af'
    Author               = 'xGreeny'
    CompanyName          = 'xGreeny'
    Copyright            = '(c) 2026 xGreeny. Released under the MIT License.'
    Description          = 'Read-only Windows security posture, baseline, exception, and configuration drift assessment.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @(
        'Invoke-HardeningLens',
        'Invoke-HardeningLensFleet',
        'Export-HardeningLensReport',
        'Compare-HardeningLensResult',
        'Get-HardeningLensBaseline',
        'Get-HardeningLensControl',
        'Test-HardeningLensBaseline',
        'Test-HardeningLensPolicy',
        'Test-HardeningLensExceptionFile',
        'New-HardeningLensExceptionFile',
        'Set-HardeningLensException'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Windows', 'Security', 'Hardening', 'Audit', 'PowerShell', 'Baseline', 'Drift', 'SecOps')
            LicenseUri   = 'https://github.com/xGreeny/hardening-lens/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/xGreeny/hardening-lens'
            ReleaseNotes = 'Operational release with collection provenance and caching, explainable drift, first-class fleet orchestration, policy gates, baseline validation, and governed exception lifecycle updates.'
        }
    }
}
