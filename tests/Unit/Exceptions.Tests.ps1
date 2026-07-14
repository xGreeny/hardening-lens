BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
}

Describe 'Exception register validation' {
    It 'accepts the committed governed exception example' {
        $result = Test-HardeningLensExceptionFile -Path (Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/exceptions.json')
        $result.IsValid | Should -BeTrue
        $result.ExceptionCount | Should -Be 2
        @($result.Errors).Count | Should -Be 0
    }

    It 'rejects Approved exceptions without approval metadata or compensating controls' {
        $document = [ordered]@{
            schemaVersion = '1.0'
            exceptions = @(
                [ordered]@{
                    id = 'EXC-BROKEN'
                    controlId = 'HL-SMB-003'
                    status = 'Approved'
                    owner = 'Infrastructure'
                    reason = 'Temporary application compatibility requirement.'
                    ticket = 'RISK-100'
                    expires = (Get-Date).AddDays(30).ToString('yyyy-MM-dd')
                    targets = @('SRV-APP-*')
                }
            )
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'invalid-exceptions.json'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8

        $result = Test-HardeningLensExceptionFile -Path $path
        $result.IsValid | Should -BeFalse
        @($result.Errors -join ' ') | Should -Match 'approvedBy'
        @($result.Errors -join ' ') | Should -Match 'compensatingControls'
    }

    It 'warns about a global target scope' {
        $document = [ordered]@{
            schemaVersion = '1.0'
            exceptions = @(
                [ordered]@{
                    id = 'EXC-GLOBAL-DRAFT'
                    controlId = 'HL-SMB-003'
                    status = 'Draft'
                    owner = 'Infrastructure'
                    reason = 'Draft scope review for a shared platform policy.'
                    ticket = 'RISK-101'
                    expires = (Get-Date).AddDays(30).ToString('yyyy-MM-dd')
                    targets = @('*')
                    compensatingControls = @()
                }
            )
        }
        $path = Join-Path -Path $TestDrive -ChildPath 'global-exception.json'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8

        $result = Test-HardeningLensExceptionFile -Path $path
        $result.IsValid | Should -BeTrue
        @($result.Warnings -join ' ') | Should -Match 'every host'
    }

    It 'requires compensating controls when creating an Approved entry' {
        $parameters = @{
            Path       = (Join-Path -Path $TestDrive -ChildPath 'new-exception.json')
            ControlId  = 'HL-RA-001'
            Target     = 'AVD-PILOT-*'
            Status     = 'Approved'
            Owner      = 'Workplace Engineering'
            Reason     = 'Approved support workflow requires Remote Assistance.'
            Ticket     = 'SEC-1842'
            Expires    = (Get-Date).AddDays(30)
            ApprovedBy = 'Security Engineering'
        }
        { New-HardeningLensExceptionFile @parameters } | Should -Throw '*CompensatingControl*'
    }

    It 'creates a valid Approved exception entry' {
        $path = Join-Path -Path $TestDrive -ChildPath 'approved-exception.json'
        $null = New-HardeningLensExceptionFile `
            -Path $path `
            -ControlId HL-RA-001 `
            -Target 'AVD-PILOT-*' `
            -Baseline AVDSessionHost `
            -Status Approved `
            -Owner 'Workplace Engineering' `
            -Reason 'Approved support workflow requires Remote Assistance.' `
            -Ticket 'SEC-1842' `
            -Expires (Get-Date).AddDays(30) `
            -ApprovedBy 'Security Engineering' `
            -CompensatingControl 'Access is restricted to the support group.'

        $result = Test-HardeningLensExceptionFile -Path $path
        $result.IsValid | Should -BeTrue
        $result.ExceptionCount | Should -Be 1
    }
}

Describe 'Exception matching' {
    InModuleScope HardeningLens {
        It 'applies only Approved, unexpired, scoped exceptions' {
            $exceptions = @(
                [pscustomobject]@{
                    id = 'EXC-MATCH'
                    controlId = 'HL-SMB-003'
                    status = 'Approved'
                    owner = 'Infrastructure'
                    reason = 'Temporary compatibility requirement with compensating monitoring.'
                    ticket = 'RISK-102'
                    expires = (Get-Date).AddDays(30).ToString('yyyy-MM-dd')
                    targets = @('SRV-APP-*')
                    baselines = @('MemberServer')
                    approvedBy = 'Security Engineering'
                    approvedOn = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
                    compensatingControls = @('SMB traffic is restricted by host firewall.')
                }
            )

            $match = Get-HLApplicableException -Exceptions $exceptions -ControlId 'HL-SMB-003' -ComputerName 'SRV-APP-01' -BaselineName 'MemberServer'
            $match.id | Should -Be 'EXC-MATCH'

            $wrongHost = Get-HLApplicableException -Exceptions $exceptions -ControlId 'HL-SMB-003' -ComputerName 'SRV-DB-01' -BaselineName 'MemberServer'
            $wrongHost | Should -BeNullOrEmpty
        }
    }
}
