BeforeAll {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Live Windows assessment' -Tag WindowsLive {
    It 'returns a schema-versioned result for safe representative controls' -Skip:($env:HARDENINGLENS_LIVE_TESTS -ne '1') {
        [Environment]::OSVersion.Platform | Should -Be ([PlatformID]::Win32NT)
        $result = Invoke-HardeningLens `
            -Baseline MemberServer `
            -ControlId HL-UAC-001, HL-SMB-003, HL-AUD-001 `
            -AllowPartial `
            -NoConsole

        $result.schemaVersion | Should -Be '1.1'
        $result.provenance.catalogDigest | Should -Match '^[0-9a-f]{64}$'
        $result.provenance.baselineDigest | Should -Match '^[0-9a-f]{64}$'
        $result.scan.readOnly | Should -BeTrue
        @($result.results).Count | Should -Be 3
    }

    It 'collects the full member-server baseline without errors in robust probe classes' -Skip:($env:HARDENINGLENS_LIVE_TESTS -ne '1') {
        # Robust probes query registry, native APIs, and in-box providers that
        # exist on every supported Windows SKU. An Error status there is a
        # product defect, not runner variance. Hardware- and licensing-bound
        # probes (Defender, BitLocker, Secure Boot, VBS, LAPS) stay excluded.
        $robustProbes = @(
            'RegistryValue', 'AuditPolicy', 'Service', 'WinRM', 'EventLog',
            'PowerShellModuleLogging', 'AutoRun', 'LocalGuestAccount',
            'SmbServer', 'SmbClient', 'WindowsOptionalFeature', 'FirewallProfiles'
        )

        $result = Invoke-HardeningLens -Baseline MemberServer -AllowPartial -NoConsole
        @($result.results).Count | Should -Be 54

        $robustErrors = @($result.results | Where-Object { $_.probe -in $robustProbes -and $_.status -eq 'Error' })
        if ($robustErrors.Count -gt 0) {
            $detail = @($robustErrors | ForEach-Object { '{0}: {1}' -f $_.controlId, $_.message }) -join ' | '
            throw "Robust probes returned Error status: $detail"
        }

        $auditErrors = @($result.results | Where-Object { $_.probe -eq 'AuditPolicy' -and $_.status -in @('Error') })
        $auditErrors | Should -BeNullOrEmpty
    }
}
