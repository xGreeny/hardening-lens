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

        $result.schemaVersion | Should -Be '1.0'
        $result.scan.readOnly | Should -BeTrue
        @($result.results).Count | Should -Be 3
    }
}
