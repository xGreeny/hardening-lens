BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Control catalog contract' {
    It 'contains exactly 58 unique controls' {
        $controls = @(Get-HardeningLensControl)
        $controls.Count | Should -Be 58
        @($controls.id | Sort-Object -Unique).Count | Should -Be 58
    }

    It 'uses stable IDs, supported severities, and first-party references' {
        foreach ($control in @(Get-HardeningLensControl)) {
            $control.id | Should -Match '^HL-[A-Z]+-[0-9]{3}$'
            $control.severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Informational')
            @($control.references).Count | Should -BeGreaterThan 0
            foreach ($reference in @($control.references)) {
                $reference | Should -Match '^https://learn\.microsoft\.com/'
            }
        }
    }

    It 'supports wildcard and category queries' {
        @(Get-HardeningLensControl -Id 'HL-SMB-*').Count | Should -Be 5
        @(Get-HardeningLensControl -Category 'Credential Protection').Count | Should -Be 7
        @(Get-HardeningLensControl -Tag 'laps').Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'Built-in baseline contract' {
    It 'ships the four documented role profiles' {
        $baselines = @(Get-HardeningLensBaseline)
        $actualNames = @($baselines.Name | Sort-Object) -join ','
        $expectedNames = @('AVDSessionHost', 'DomainController', 'MemberServer', 'Workstation') -join ','
        $actualNames | Should -Be $expectedNames
    }

    It 'resolves every profile to its documented control count' -ForEach @(
        @{ Name = 'Workstation'; Count = 54 }
        @{ Name = 'MemberServer'; Count = 53 }
        @{ Name = 'DomainController'; Count = 55 }
        @{ Name = 'AVDSessionHost'; Count = 53 }
    ) {
        $baseline = Get-HardeningLensBaseline -Name $Name -IncludeControls
        $baseline.controlCount | Should -Be $Count
        @($baseline.controls).Count | Should -Be $Count
        @($baseline.controls.id | Sort-Object -Unique).Count | Should -Be $Count
    }

    It 'contains domain-controller-specific controls only in the domain controller profile' {
        $dc = Get-HardeningLensBaseline -Name DomainController -IncludeControls
        $member = Get-HardeningLensBaseline -Name MemberServer -IncludeControls
        @($dc.controls.id) | Should -Contain 'HL-DC-001'
        @($member.controls.id) | Should -Not -Contain 'HL-DC-001'
    }
}

Describe 'Custom baseline resolution' {
    It 'inherits, excludes, and overrides catalog controls deterministically' {
        $path = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/custom-baseline.json'
        $baseline = Get-HardeningLensBaseline -Path $path -IncludeControls

        $baseline.name | Should -Be 'NorthstarMemberServer'
        @($baseline.controls.id) | Should -Not -Contain 'HL-BIT-001'
        $logControl = $baseline.controls | Where-Object id -eq 'HL-LOG-001'
        [int64]$logControl.parameters.minimumSizeBytes | Should -Be 2147483648
        $serviceControl = $baseline.controls | Where-Object id -eq 'HL-SVC-001'
        $serviceControl.severity | Should -Be 'Low'
    }
}
