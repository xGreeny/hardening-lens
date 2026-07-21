@{
    RootModule           = 'HardeningLens.psm1'
    ModuleVersion        = '1.2.1'
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

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Windows', 'Security', 'Hardening', 'Audit', 'PowerShell', 'Baseline', 'Drift', 'SecOps')
            LicenseUri   = 'https://github.com/xGreeny/hardening-lens/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/xGreeny/hardening-lens'
            ReleaseNotes = 'Maintenance release: one cached optional-feature listing per scan, role-aware Guest account evaluation on domain controllers, truthful BitLocker and firewall results, and retry-hardened fleet run publication.'
        }
    }
}
