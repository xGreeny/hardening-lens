BeforeDiscovery {
    $repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
}

Describe 'First-class fleet assessment API' {
    InModuleScope HardeningLens {
        BeforeAll {
            function Get-HLFleetApiTestScan {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory)]
                    [string]$RequestedComputerName,

                    [Parameter(Mandatory)]
                    [string]$ComputerName,

                    [string]$Domain = 'CONTOSO',

                    [double]$Score = 100.0
                )

                $timestamp = '2026-07-14T08:00:00.0000000Z'
                $scan = [pscustomobject][ordered]@{
                    schemaVersion = '1.1'
                    scan = [pscustomobject][ordered]@{
                        id                    = [guid]::NewGuid().ToString()
                        collectedAt           = $timestamp
                        moduleVersion         = Get-HLModuleVersion
                        redacted              = $false
                        readOnly              = $true
                        elevated              = $true
                        partialCollection     = $false
                        exceptionRegisterUsed = $false
                        selectedControlCount  = 1
                        collectionDurationMs  = 10
                    }
                    system = [pscustomobject][ordered]@{
                        ComputerName     = $ComputerName
                        Domain           = $Domain
                        DomainJoined     = $true
                        DetectedRole     = 'MemberServer'
                        ProductType      = 3
                        OSCaption        = 'Windows Server'
                        OSVersion        = '10.0'
                        BuildNumber      = '26100'
                        OSArchitecture   = '64-bit'
                        Manufacturer     = 'Contoso'
                        Model            = 'Virtual Machine'
                        PowerShellVersion = '5.1'
                        PowerShellEdition = 'Desktop'
                        CurrentUser      = 'CONTOSO\Operator'
                        IsElevated       = $true
                    }
                    baseline = [pscustomobject][ordered]@{
                        name           = 'MemberServer'
                        displayName    = 'Member Server'
                        version        = '1.0.0'
                        description    = 'Fleet API test baseline.'
                        source         = 'BuiltIn'
                        sourceBasis    = @('Test')
                        supportedRoles = @('MemberServer')
                        controlCount   = 1
                        notes          = @()
                    }
                    provenance = [pscustomobject][ordered]@{
                        catalogVersion = '1.1.0'
                        catalogDigest  = '0000000000000000000000000000000000000000000000000000000000000000'
                        baselineDigest = '1111111111111111111111111111111111111111111111111111111111111111'
                        capabilities   = @()
                    }
                    summary = [pscustomobject][ordered]@{
                        Total               = 1
                        Applicable          = 1
                        Pass                = 1
                        Fail                = 0
                        Warning             = 0
                        Excepted            = 0
                        Unknown             = 0
                        Error               = 0
                        NotApplicable       = 0
                        HardeningScore      = $Score
                        EvidenceCoverage    = 100.0
                        HighestOpenSeverity = 'None'
                        ScoringModel        = 'Fleet API test model.'
                    }
                    results = @(
                        [pscustomobject][ordered]@{
                            controlId      = 'HL-TEST-001'
                            title          = 'Fleet API test control'
                            category       = 'Test'
                            severity       = 'Medium'
                            status         = 'Pass'
                            originalStatus = $null
                            expected       = $true
                            actual         = $true
                            message        = 'Test evidence passed.'
                            evidence       = [pscustomobject]@{ source = 'Pester' }
                            rationale      = 'Test rationale.'
                            remediation    = 'No remediation required.'
                            references     = @('https://learn.microsoft.com/')
                            tags           = @('test')
                            probe          = 'Test'
                            exception      = $null
                            collectedAt    = $timestamp
                            probeDurationMs = 5
                        }
                    )
                }
                $scan | Add-Member -NotePropertyName PSComputerName -NotePropertyValue $RequestedComputerName
                $scan | Add-Member -NotePropertyName RunspaceId -NotePropertyValue ([guid]::NewGuid())
                $scan | Add-Member -NotePropertyName PSShowComputerName -NotePropertyValue $true
                return $scan
            }
        }

        It 'exposes pipeline input and separate built-in and custom baseline parameter sets' {
            $command = Get-Command -Name Invoke-HardeningLensFleet
            @($command.ParameterSets.Name) | Should -Contain 'BuiltIn'
            @($command.ParameterSets.Name) | Should -Contain 'Custom'
            @($command.Parameters.ComputerName.Aliases) | Should -Contain 'DNSHostName'
            @($command.Parameters.ComputerName.Attributes | Where-Object {
                $_ -is [Management.Automation.ParameterAttribute] -and $_.ValueFromPipeline
            }).Count | Should -BeGreaterThan 0
            @($command.Parameters.ComputerName.Attributes | Where-Object {
                $_ -is [Management.Automation.ParameterAttribute] -and $_.ValueFromPipelineByPropertyName
            }).Count | Should -BeGreaterThan 0
        }

        It 'never treats different fully qualified names as the same host' {
            (Test-HLFleetHostNameMatch -Requested 'node.corp-a.test' -Candidate 'node.corp-b.test') | Should -BeFalse
            (Test-HLFleetHostNameMatch -Requested 'node.corp-a.test' -Candidate 'NODE') | Should -BeFalse
            (Test-HLFleetHostNameMatch -Requested 'node.corp-a.test' -Candidate 'NODE' -AllowShortName) | Should -BeTrue
        }

        It 'correlates reversed remoting results by exact FQDN before considering short names' {
            Mock Invoke-Command {
                @(
                    Get-HLFleetApiTestScan -RequestedComputerName 'node.corp-b.test' -ComputerName 'NODE' -Domain 'CORP-B'
                    Get-HLFleetApiTestScan -RequestedComputerName 'node.corp-a.test' -ComputerName 'NODE' -Domain 'CORP-A'
                )
            }

            $output = Join-Path -Path $TestDrive -ChildPath 'reversed-fqdn'
            $fleet = Invoke-HardeningLensFleet -ComputerName 'node.corp-a.test','node.corp-b.test' -OutputDirectory $output

            $fleet.summary.succeededCount | Should -Be 2
            (@($fleet.hosts.assessment.system.Domain) -join ',') | Should -Be 'CORP-A,CORP-B'
        }

        It 'uses short-name fallback only when the request and result are unambiguous' {
            Mock Invoke-Command {
                Get-HLFleetApiTestScan -RequestedComputerName 'unique-node' -ComputerName 'UNIQUE-NODE'
            }
            $uniqueOutput = Join-Path -Path $TestDrive -ChildPath 'unique-short-name'
            $unique = Invoke-HardeningLensFleet -ComputerName 'unique-node.corp.test' -OutputDirectory $uniqueOutput
            $unique.summary.succeededCount | Should -Be 1

            Mock Invoke-Command {
                @(
                    Get-HLFleetApiTestScan -RequestedComputerName 'shared-node' -ComputerName 'SHARED-NODE' -Domain 'CORP-A'
                    Get-HLFleetApiTestScan -RequestedComputerName 'shared-node' -ComputerName 'SHARED-NODE' -Domain 'CORP-B'
                )
            }
            $ambiguousOutput = Join-Path -Path $TestDrive -ChildPath 'ambiguous-short-name'
            $ambiguous = Invoke-HardeningLensFleet `
                -ComputerName 'shared-node.corp-a.test','shared-node.corp-b.test' `
                -OutputDirectory $ambiguousOutput `
                -WarningAction SilentlyContinue
            $ambiguous.summary.succeededCount | Should -Be 0
            $ambiguous.summary.failedCount | Should -Be 2
            @($ambiguous.hosts | Where-Object status -eq 'Failed').Count | Should -Be 2
        }

        It 'preserves requested pipeline order and writes one schema-versioned outcome per host' {
            Mock Invoke-Command {
                @(
                    Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[1] -ComputerName 'SRV-A' -Score 90
                    Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[0] -ComputerName 'SRV-B' -Score 70
                )
            }

            $output = Join-Path -Path $TestDrive -ChildPath 'ordered'
            $fleet = 'srv-b.contoso.test','srv-a.contoso.test' |
                Invoke-HardeningLensFleet -Baseline Auto -OutputDirectory $output

            $fleet.schemaVersion | Should -Be '1.1'
            @($fleet.hosts).Count | Should -Be 2
            (@($fleet.hosts.requestedComputerName) -join ',') | Should -Be 'srv-b.contoso.test,srv-a.contoso.test'
            (@($fleet.hosts.ordinal) -join ',') | Should -Be '1,2'
            @($fleet.hosts | Where-Object status -eq 'Succeeded').Count | Should -Be 2
            $fleet.summary.requestedCount | Should -Be 2
            $fleet.summary.succeededCount | Should -Be 2
            $fleet.summary.failedCount | Should -Be 0
            $fleet.summary.averageHardeningScore | Should -Be 80
            Test-Path -LiteralPath $fleet.artifacts.summaryPath -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $fleet.artifacts.resultPath -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $fleet.artifacts.manifestPath -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $fleet.artifacts.commitMarkerPath -PathType Leaf | Should -BeTrue
            @(Get-ChildItem -LiteralPath $output -Directory -Force -Filter '*.staging-*').Count | Should -Be 0
            foreach ($hostResult in $fleet.hosts) {
                Test-Path -LiteralPath $hostResult.artifactPath -PathType Leaf | Should -BeTrue
                $hostResult.error | Should -BeNullOrEmpty
                $hostResult.assessment.PSObject.Properties['PSComputerName'] | Should -BeNullOrEmpty
            }

            $saved = Get-Content -LiteralPath $fleet.artifacts.resultPath -Raw | ConvertFrom-Json
            $saved.run.id | Should -Be $fleet.run.id
            @($saved.hosts).Count | Should -Be 2
        }

        It 'forwards custom baseline, control, exception, credential, partial, and redaction settings to remoting' {
            Mock Invoke-Command {
                $script:CapturedFleetArguments = @($ArgumentList)
                $script:CapturedFleetScriptBlock = $ScriptBlock
                $script:CapturedFleetThrottle = $ThrottleLimit
                $script:CapturedFleetCredential = $Credential
                Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[0] -ComputerName 'SRV-CUSTOM'
            }

            $customPath = Join-Path -Path $TestDrive -ChildPath 'custom.json'
            $exceptionPath = Join-Path -Path $TestDrive -ChildPath 'exceptions.json'
            [IO.File]::WriteAllText($customPath, '{"name":"custom"}')
            [IO.File]::WriteAllText($exceptionPath, '{"exceptions":[]}')
            $secure = ConvertTo-SecureString -String 'not-a-real-password' -AsPlainText -Force
            $credential = New-Object pscredential('CONTOSO\FleetUser', $secure)
            $output = Join-Path -Path $TestDrive -ChildPath 'forwarding'

            $null = Invoke-HardeningLensFleet -ComputerName 'srv-custom' `
                -CustomBaselinePath $customPath `
                -ControlId 'HL-TEST-001','HL-TEST-002' `
                -ExceptionPath $exceptionPath `
                -Credential $credential `
                -ThrottleLimit 7 `
                -AllowPartial `
                -Redact `
                -OutputDirectory $output

            [string]$script:CapturedFleetArguments[2] | Should -Be '{"name":"custom"}'
            (@($script:CapturedFleetArguments[3]) -join ',') | Should -Be 'HL-TEST-001,HL-TEST-002'
            [string]$script:CapturedFleetArguments[4] | Should -Be '{"exceptions":[]}'
            [bool]$script:CapturedFleetArguments[5] | Should -BeTrue
            [bool]$script:CapturedFleetArguments[6] | Should -BeTrue
            $script:CapturedFleetThrottle | Should -Be 7
            $script:CapturedFleetCredential.UserName | Should -Be 'CONTOSO\FleetUser'
            $script:CapturedFleetScriptBlock.ToString() | Should -Match 'Import-Module'
            $script:CapturedFleetScriptBlock.ToString() | Should -Match 'Invoke-HardeningLens @parameters'
        }

        It 'imports the transferred module and invokes the local assessment with remote file paths' {
            Mock Import-Module {}
            Mock Invoke-HardeningLens {
                [pscustomobject]@{
                    BaselinePathExists  = Test-Path -LiteralPath $BaselinePath
                    ExceptionsPathExists = Test-Path -LiteralPath $ExceptionsPath
                    ControlIds          = @($ControlId)
                    AllowPartial        = [bool]$AllowPartial
                    Redact              = [bool]$Redact
                    NoConsole           = [bool]$NoConsole
                }
            }

            $emptyContent = [Convert]::ToBase64String([byte[]]@())
            $files = @([pscustomobject]@{ RelativePath = 'HardeningLens.psd1'; Content = $emptyContent })
            $remoteScript = Get-HLFleetRemoteScriptBlock
            $remoteResult = & $remoteScript `
                $files `
                'Auto' `
                '{"schemaVersion":"1.0"}' `
                @('HL-TEST-001') `
                '{"exceptions":[]}' `
                $true `
                $true

            $remoteResult.BaselinePathExists | Should -BeTrue
            $remoteResult.ExceptionsPathExists | Should -BeTrue
            (@($remoteResult.ControlIds) -join ',') | Should -Be 'HL-TEST-001'
            $remoteResult.AllowPartial | Should -BeTrue
            $remoteResult.Redact | Should -BeTrue
            $remoteResult.NoConsole | Should -BeTrue
        }

        It 'records missing hosts as failures and can throw only after artifacts are written' {
            Mock Invoke-Command {
                Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[0] -ComputerName 'SRV-A'
            }

            $output = Join-Path -Path $TestDrive -ChildPath 'partial'
            $fleet = Invoke-HardeningLensFleet -ComputerName 'srv-a','srv-b' -OutputDirectory $output -WarningAction SilentlyContinue
            @($fleet.hosts).Count | Should -Be 2
            $fleet.summary.succeededCount | Should -Be 1
            $fleet.summary.failedCount | Should -Be 1
            $failed = @($fleet.hosts | Where-Object status -eq 'Failed')[0]
            $failed.requestedComputerName | Should -Be 'srv-b'
            $failed.error.message | Should -Not -BeNullOrEmpty
            $failed.error.category | Should -Be 'RemoteResultMissing'
            Test-Path -LiteralPath $failed.artifactPath -PathType Leaf | Should -BeTrue

            $throwOutput = Join-Path -Path $TestDrive -ChildPath 'terminating'
            { Invoke-HardeningLensFleet -ComputerName 'srv-a','srv-b' -OutputDirectory $throwOutput -FailOnHostError -WarningAction SilentlyContinue | Out-Null } |
                Should -Throw '*failed on 1 of 2 requested host*'
            $runDirectories = @(Get-ChildItem -LiteralPath $throwOutput -Directory -Filter 'fleet-run-*')
            $runDirectories.Count | Should -Be 1
            Test-Path -LiteralPath (Join-Path -Path $runDirectories[0].FullName -ChildPath 'fleet-result.json') -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath (Join-Path -Path $runDirectories[0].FullName -ChildPath 'manifest.json') -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath (Join-Path -Path $runDirectories[0].FullName -ChildPath 'commit.json') -PathType Leaf | Should -BeTrue
        }

        It 'never overwrites a colliding run unless Force is explicit' {
            Mock Get-HLFleetUtcNow { [datetime]'2026-07-14T08:30:00Z' }
            Mock Get-HLFleetRunId { '11111111-2222-3333-4444-555555555555' }
            Mock Invoke-Command {
                Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[0] -ComputerName 'SRV-A'
            }

            $output = Join-Path -Path $TestDrive -ChildPath 'collision'
            $first = Invoke-HardeningLensFleet -ComputerName 'srv-a' -OutputDirectory $output
            { Invoke-HardeningLensFleet -ComputerName 'srv-a' -OutputDirectory $output | Out-Null } |
                Should -Throw '*already exists*Use -Force*'

            $forced = Invoke-HardeningLensFleet -ComputerName 'srv-a' -OutputDirectory $output -Force
            $forced.run.id | Should -Be $first.run.id
            @(Get-ChildItem -LiteralPath $output -Directory -Filter 'fleet-run-*').Count | Should -Be 1
            Test-Path -LiteralPath $forced.artifacts.resultPath -PathType Leaf | Should -BeTrue
            Test-Path -LiteralPath $forced.artifacts.commitMarkerPath -PathType Leaf | Should -BeTrue
            @(Get-ChildItem -LiteralPath $output -Directory -Force -Filter '*.staging-*').Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $output -Directory -Force -Filter '*.backup-*').Count | Should -Be 0
        }

        It 'preserves the previous committed run when forced staging fails' {
            Mock Get-HLFleetUtcNow { [datetime]'2026-07-14T09:00:00Z' }
            Mock Get-HLFleetRunId { '22222222-3333-4444-5555-666666666666' }
            Mock Invoke-Command {
                Get-HLFleetApiTestScan -RequestedComputerName $ComputerName[0] -ComputerName 'SRV-A'
            }

            $output = Join-Path -Path $TestDrive -ChildPath 'transaction-rollback'
            $first = Invoke-HardeningLensFleet -ComputerName 'srv-a' -OutputDirectory $output
            $originalResult = Get-Content -LiteralPath $first.artifacts.resultPath -Raw
            Test-Path -LiteralPath $first.artifacts.commitMarkerPath -PathType Leaf | Should -BeTrue

            Mock Get-HLFleetModulePayload { throw 'Injected staging failure.' }
            { Invoke-HardeningLensFleet -ComputerName 'srv-a' -OutputDirectory $output -Force | Out-Null } |
                Should -Throw '*Injected staging failure*'

            (Get-Content -LiteralPath $first.artifacts.resultPath -Raw) | Should -BeExactly $originalResult
            Test-Path -LiteralPath $first.artifacts.commitMarkerPath -PathType Leaf | Should -BeTrue
            @(Get-ChildItem -LiteralPath $output -Directory -Force -Filter '*.staging-*').Count | Should -Be 0
            @(Get-ChildItem -LiteralPath $output -Directory -Force -Filter '*.backup-*').Count | Should -Be 0
        }
    }
}
