BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:FleetScript = Join-Path -Path $script:RepositoryRoot -ChildPath 'scripts/Invoke-FleetAssessment.ps1'
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Legacy fleet assessment wrapper' {
    It 'keeps summary-row output and the fleet-summary.csv compatibility artifact' {
        Mock Invoke-HardeningLensFleet -ModuleName HardeningLens {
            [pscustomobject][ordered]@{
                run = [pscustomobject]@{ id = '11111111-2222-3333-4444-555555555555' }
                summary = [pscustomobject]@{ requestedCount = 2; succeededCount = 2; failedCount = 0 }
                hosts = @(
                    [pscustomobject][ordered]@{
                        requestedComputerName = 'srv-a'
                        computerName = 'SRV-A'
                        status = 'Succeeded'
                        error = $null
                        artifactPath = 'srv-a.json'
                        assessment = [pscustomobject]@{
                            baseline = [pscustomobject]@{ name = 'MemberServer' }
                            summary = [pscustomobject]@{
                                HardeningScore = 90; EvidenceCoverage = 100; Fail = 1; Warning = 0
                                Excepted = 0; Unknown = 0; Error = 0
                            }
                        }
                    }
                    [pscustomobject][ordered]@{
                        requestedComputerName = 'srv-b'
                        computerName = 'SRV-B'
                        status = 'Succeeded'
                        error = $null
                        artifactPath = 'srv-b.json'
                        assessment = [pscustomobject]@{
                            baseline = [pscustomobject]@{ name = 'MemberServer' }
                            summary = [pscustomobject]@{
                                HardeningScore = 80; EvidenceCoverage = 95; Fail = 2; Warning = 1
                                Excepted = 0; Unknown = 0; Error = 0
                            }
                        }
                    }
                )
            }
        }

        $output = Join-Path -Path $TestDrive -ChildPath 'success'
        [void](New-Item -Path $output -ItemType Directory -Force)
        $summary = @(& $script:FleetScript -ComputerName 'srv-a','srv-b' -OutputDirectory $output)

        $summary.Count | Should -Be 2
        @($summary | Where-Object Status -eq 'Succeeded').Count | Should -Be 2
        (@($summary.RequestedComputerName) -join ',') | Should -Be 'srv-a,srv-b'
        $summary[0].Score | Should -Be 90
        Test-Path -LiteralPath (Join-Path -Path $output -ChildPath 'fleet-summary.csv') -PathType Leaf | Should -BeTrue
    }

    It 'preserves failed host details and throws after writing the compatibility summary when requested' {
        Mock Invoke-HardeningLensFleet -ModuleName HardeningLens {
            [pscustomobject][ordered]@{
                run = [pscustomobject]@{ id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
                summary = [pscustomobject]@{ requestedCount = 1; succeededCount = 0; failedCount = 1 }
                hosts = @(
                    [pscustomobject][ordered]@{
                        requestedComputerName = 'srv-failed'
                        computerName = 'srv-failed'
                        status = 'Failed'
                        error = [pscustomobject]@{
                            message = 'WinRM connection failed.'
                            category = 'OpenError'
                        }
                        artifactPath = 'srv-failed.error.json'
                        assessment = $null
                    }
                )
            }
        }

        $output = Join-Path -Path $TestDrive -ChildPath 'failed'
        [void](New-Item -Path $output -ItemType Directory -Force)
        { & $script:FleetScript -ComputerName 'srv-failed' -OutputDirectory $output -FailOnHostError | Out-Null } |
            Should -Throw '*failed on 1 of 1 requested host*'

        $summaryPath = Join-Path -Path $output -ChildPath 'fleet-summary.csv'
        Test-Path -LiteralPath $summaryPath -PathType Leaf | Should -BeTrue
        $saved = @(Import-Csv -LiteralPath $summaryPath)
        $saved.Count | Should -Be 1
        $saved[0].Status | Should -Be 'Failed'
        $saved[0].Error | Should -Be 'WinRM connection failed.'
        $saved[0].ErrorCategory | Should -Be 'OpenError'
    }

    It 'requires Force before replacing the compatibility summary' {
        Mock Invoke-HardeningLensFleet -ModuleName HardeningLens {
            [pscustomobject][ordered]@{
                run = [pscustomobject]@{ id = '99999999-8888-7777-6666-555555555555' }
                summary = [pscustomobject]@{ requestedCount = 1; succeededCount = 1; failedCount = 0 }
                hosts = @(
                    [pscustomobject][ordered]@{
                        requestedComputerName = 'srv-a'
                        computerName = 'SRV-A'
                        status = 'Succeeded'
                        error = $null
                        artifactPath = 'srv-a.json'
                        assessment = [pscustomobject]@{
                            baseline = [pscustomobject]@{ name = 'MemberServer' }
                            summary = [pscustomobject]@{
                                HardeningScore = 100; EvidenceCoverage = 100; Fail = 0; Warning = 0
                                Excepted = 0; Unknown = 0; Error = 0
                            }
                        }
                    }
                )
            }
        }

        $output = Join-Path -Path $TestDrive -ChildPath 'force'
        [void](New-Item -Path $output -ItemType Directory -Force)
        [IO.File]::WriteAllText((Join-Path -Path $output -ChildPath 'fleet-summary.csv'), 'existing')

        { & $script:FleetScript -ComputerName 'srv-a' -OutputDirectory $output | Out-Null } |
            Should -Throw '*already exists*Use -Force*'
        $summary = @(& $script:FleetScript -ComputerName 'srv-a' -OutputDirectory $output -Force)
        $summary.Count | Should -Be 1
        $summary[0].Status | Should -Be 'Succeeded'
        $summaryPath = Join-Path -Path $output -ChildPath 'fleet-summary.csv'
        $committedSummary = Get-Content -LiteralPath $summaryPath -Raw
        $committedSummary | Should -Match '99999999-8888-7777-6666-555555555555'
        @(Get-ChildItem -LiteralPath $output -File -Force | Where-Object Name -Match '\.(tmp|bak)$').Count | Should -Be 0

        Mock Write-HLAtomicUtf8File -ModuleName HardeningLens { throw 'Injected legacy summary write failure.' }
        { & $script:FleetScript -ComputerName 'srv-a' -OutputDirectory $output -Force | Out-Null } |
            Should -Throw '*Injected legacy summary write failure*'
        (Get-Content -LiteralPath $summaryPath -Raw) | Should -BeExactly $committedSummary
    }

    It 'uses the atomic no-clobber boundary for a new compatibility summary' {
        Mock Invoke-HardeningLensFleet -ModuleName HardeningLens {
            [pscustomobject][ordered]@{
                run = [pscustomobject]@{ id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
                summary = [pscustomobject]@{ requestedCount = 1; succeededCount = 1; failedCount = 0 }
                hosts = @(
                    [pscustomobject][ordered]@{
                        requestedComputerName = 'srv-a'; computerName = 'SRV-A'; status = 'Succeeded'
                        error = $null; artifactPath = 'srv-a.json'
                        assessment = [pscustomobject]@{
                            baseline = [pscustomobject]@{ name = 'MemberServer' }
                            summary = [pscustomobject]@{
                                HardeningScore = 100; EvidenceCoverage = 100; Fail = 0; Warning = 0
                                Excepted = 0; Unknown = 0; Error = 0
                            }
                        }
                    }
                )
            }
        }
        Mock Write-HLAtomicUtf8File -ModuleName HardeningLens { }

        $output = Join-Path -Path $TestDrive -ChildPath 'no-clobber'
        $null = & $script:FleetScript -ComputerName 'srv-a' -OutputDirectory $output

        Should -Invoke Write-HLAtomicUtf8File -ModuleName HardeningLens -Times 1 -Exactly -ParameterFilter { $NoClobber }
    }
}

Describe 'Fleet publish move retry' {
    BeforeDiscovery {
        $script:IsWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    }

    BeforeAll {
        $script:MoveFleetDirectory = {
            param($Source, $Target, $Attempts, $DelayMs)
            & (Get-Module HardeningLens) {
                param($s, $t, $a, $d)
                Move-HLFleetDirectory -Path $s -Destination $t -MaximumAttempts $a -RetryDelayMilliseconds $d
            } $Source $Target $Attempts $DelayMs
        }
    }

    BeforeEach {
        $script:parent = Join-Path -Path $TestDrive -ChildPath ([guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $script:parent -ItemType Directory -Force)
        $script:staging = Join-Path -Path $script:parent -ChildPath 'staging'
        $script:destination = Join-Path -Path $script:parent -ChildPath 'committed'
        [void](New-Item -Path $script:staging -ItemType Directory -Force)
        Set-Content -LiteralPath (Join-Path -Path $script:staging -ChildPath 'artifact.json') -Value '{}' -Encoding Ascii
    }

    It 'moves a staged directory without any lock' {
        & $script:MoveFleetDirectory $script:staging $script:destination 5 50
        Test-Path -LiteralPath $script:destination -PathType Container | Should -BeTrue
        Test-Path -LiteralPath $script:staging | Should -BeFalse
    }

    It 'fails fast when the source directory is missing' {
        $missing = Join-Path -Path $script:parent -ChildPath 'does-not-exist'
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        { & $script:MoveFleetDirectory $missing $script:destination 5 500 } | Should -Throw
        $stopwatch.Stop()
        $stopwatch.ElapsedMilliseconds | Should -BeLessThan 1500
    }

    It 'rethrows after bounded attempts while the lock persists' -Skip:(-not $IsWindowsPlatform) {
        $lockFile = Join-Path -Path $script:staging -ChildPath 'artifact.json'
        $stream = [IO.File]::Open($lockFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try {
            { & $script:MoveFleetDirectory $script:staging $script:destination 2 50 } | Should -Throw
            Test-Path -LiteralPath $script:staging -PathType Container | Should -BeTrue
            Test-Path -LiteralPath $script:destination | Should -BeFalse
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'recovers when a transient lock is released during the retry window' -Skip:(-not $IsWindowsPlatform) {
        $lockFile = Join-Path -Path $script:staging -ChildPath 'artifact.json'
        $stream = [IO.File]::Open($lockFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        $job = Start-Job -ScriptBlock {
            param($module, $source, $target)
            Import-Module -Name $module -Force
            & (Get-Module HardeningLens) {
                param($s, $t)
                Move-HLFleetDirectory -Path $s -Destination $t -MaximumAttempts 20 -RetryDelayMilliseconds 250
            } $source $target
        } -ArgumentList $script:ModulePath, $script:staging, $script:destination
        try {
            Start-Sleep -Milliseconds 1500
            $stream.Dispose()
            $null = $job | Wait-Job -Timeout 60
            $job.State | Should -Be 'Completed'
            Receive-Job -Job $job -ErrorAction Stop
            Test-Path -LiteralPath $script:destination -PathType Container | Should -BeTrue
            Test-Path -LiteralPath $script:staging | Should -BeFalse
        }
        finally {
            if (-not $stream.SafeFileHandle.IsClosed) { $stream.Dispose() }
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }
}
