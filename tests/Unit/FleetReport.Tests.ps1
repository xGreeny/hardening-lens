BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'Fleet report export' {
    BeforeAll {
        function New-TestHostAssessment {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory test fixture only.')]
            param(
                [string]$ComputerName,
                [object[]]$Results,
                [double]$Score
            )

            [pscustomobject]@{
                summary  = [pscustomobject]@{
                    Pass                = @($Results | Where-Object status -eq 'Pass').Count
                    Fail                = @($Results | Where-Object status -eq 'Fail').Count
                    Warning             = @($Results | Where-Object status -eq 'Warning').Count
                    Excepted            = @($Results | Where-Object status -eq 'Excepted').Count
                    Unknown             = @($Results | Where-Object status -eq 'Unknown').Count
                    Error               = @($Results | Where-Object status -eq 'Error').Count
                    HardeningScore      = $Score
                    EvidenceCoverage    = 96.0
                    HighestOpenSeverity = 'High'
                }
                baseline = [pscustomobject]@{ name = 'MemberServer'; version = '1.1.0' }
                system   = [pscustomobject]@{ ComputerName = $ComputerName }
                results  = $Results
            }
        }

        function New-TestResult {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Builds an in-memory test fixture only.')]
            param([string]$ControlId, [string]$Status, [string]$Severity = 'High')

            [pscustomobject]@{
                controlId = $ControlId
                title     = "Title for $ControlId"
                category  = 'Network Protection'
                severity  = $Severity
                status    = $Status
            }
        }

        $script:fleetResult = [pscustomobject]@{
            schemaVersion = '1.1'
            run           = [pscustomobject]@{
                id                = '11111111-2222-3333-4444-555555555555'
                startedAt         = '2026-07-21T08:00:00.0000000Z'
                completedAt       = '2026-07-21T08:05:00.0000000Z'
                moduleVersion     = '1.2.0'
                baselineSelection = 'MemberServer'
                redacted          = $false
            }
            summary       = [pscustomobject]@{
                requestedCount          = 3
                succeededCount          = 2
                failedCount             = 1
                averageHardeningScore   = 71.25
                averageEvidenceCoverage = 96.0
            }
            hosts         = @(
                [pscustomobject]@{
                    ordinal               = 1
                    requestedComputerName = 'srv-app-01'
                    status                = 'Succeeded'
                    error                 = $null
                    assessment            = (New-TestHostAssessment -ComputerName 'srv-app-01' -Score 68.5 -Results @(
                        (New-TestResult -ControlId 'HL-SMB-003' -Status 'Fail'),
                        (New-TestResult -ControlId 'HL-NET-001' -Status 'Fail' -Severity 'Medium'),
                        (New-TestResult -ControlId 'HL-UAC-001' -Status 'Pass' -Severity 'Critical')
                    ))
                },
                [pscustomobject]@{
                    ordinal               = 2
                    requestedComputerName = 'srv-app-02<script>alert(1)</script>'
                    status                = 'Succeeded'
                    error                 = $null
                    assessment            = (New-TestHostAssessment -ComputerName 'srv-app-02' -Score 74.0 -Results @(
                        (New-TestResult -ControlId 'HL-SMB-003' -Status 'Fail'),
                        (New-TestResult -ControlId 'HL-UAC-001' -Status 'Pass' -Severity 'Critical')
                    ))
                },
                [pscustomobject]@{
                    ordinal               = 3
                    requestedComputerName = 'srv-app-03'
                    status                = 'Failed'
                    error                 = [pscustomobject]@{ message = 'WinRM cannot complete the operation.' }
                    assessment            = $null
                }
            )
        }
    }

    It 'writes one self-contained HTML report with a restrictive CSP' {
        $written = Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive
        $written.Format | Should -Be 'Html'
        $written.Path | Should -Exist
        $html = Get-Content -LiteralPath $written.Path -Raw
        $html | Should -Match 'Content-Security-Policy'
        $html | Should -Match "default-src 'none'"
        $html | Should -Not -Match 'https?://(?!learn\.microsoft\.com)'
        $html | Should -Match 'srv-app-01'
        $html | Should -Match 'WinRM cannot complete the operation'
    }

    It 'encodes hostile host names instead of rendering them' {
        $written = Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive -FileNamePrefix 'encode-check' -Force
        $html = Get-Content -LiteralPath $written.Path -Raw
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match 'srv-app-02&lt;script&gt;'
    }

    It 'aggregates the controls affecting the most hosts' {
        $written = Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive -FileNamePrefix 'aggregate-check' -Force
        $html = Get-Content -LiteralPath $written.Path -Raw
        $html | Should -Match 'Most affected controls'
        $html | Should -Match 'HL-SMB-003'
        $html | Should -Match '2 / 2'
        $html | Should -Match 'HL-NET-001'
    }

    It 'does not overwrite an existing report without Force' {
        $first = Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive -FileNamePrefix 'clobber-check'
        $first.Path | Should -Exist
        { Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive -FileNamePrefix 'clobber-check' } | Should -Throw '*already exists*'
        { Export-HardeningLensFleetReport -InputObject $script:fleetResult -OutputDirectory $TestDrive -FileNamePrefix 'clobber-check' -Force } | Should -Not -Throw
    }

    It 'accepts a fleet-result JSON file through the Path parameter set' {
        $jsonPath = Join-Path -Path $TestDrive -ChildPath 'fleet-result.json'
        $script:fleetResult | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        $written = Export-HardeningLensFleetReport -Path $jsonPath -OutputDirectory $TestDrive -FileNamePrefix 'from-json' -Force
        (Get-Content -LiteralPath $written.Path -Raw) | Should -Match 'HL-SMB-003'
    }

    It 'rejects malformed fleet results before writing anything' {
        { Export-HardeningLensFleetReport -InputObject ([pscustomobject]@{ schemaVersion = '1.1' }) -OutputDirectory $TestDrive } |
            Should -Throw "*required property 'run'*"
        $wrongVersion = [pscustomobject]@{
            schemaVersion = '9.9'
            run           = $script:fleetResult.run
            summary       = $script:fleetResult.summary
            hosts         = $script:fleetResult.hosts
        }
        { Export-HardeningLensFleetReport -InputObject $wrongVersion -OutputDirectory $TestDrive } |
            Should -Throw '*Unsupported fleet result schema version*'
    }
}
