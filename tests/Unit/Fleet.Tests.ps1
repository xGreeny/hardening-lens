BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:FleetScript = Join-Path -Path $script:RepositoryRoot -ChildPath 'scripts/Invoke-FleetAssessment.ps1'

    function Get-HLFleetTestResult {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$RequestedComputerName,

            [Parameter(Mandatory)]
            [string]$ComputerName
        )

        $result = [pscustomobject][ordered]@{
            schemaVersion = '1.0'
            scan = [pscustomobject]@{
                id          = [guid]::NewGuid().ToString()
                collectedAt = (Get-Date).ToUniversalTime().ToString('o')
            }
            system = [pscustomobject]@{
                ComputerName = $ComputerName
            }
            baseline = [pscustomobject]@{
                name = 'MemberServer'
            }
            summary = [pscustomobject]@{
                HardeningScore   = 90.0
                EvidenceCoverage = 100.0
                Fail             = 1
                Warning          = 0
                Excepted         = 0
                Unknown          = 0
                Error            = 0
            }
            results = @()
        }
        $result | Add-Member -NotePropertyName PSComputerName -NotePropertyValue $RequestedComputerName
        $result | Add-Member -NotePropertyName RunspaceId -NotePropertyValue ([guid]::NewGuid())
        $result | Add-Member -NotePropertyName PSShowComputerName -NotePropertyValue $true
        return $result
    }
}

Describe 'Fleet assessment orchestration' {
    It 'returns exactly one successful summary row per requested host and writes run-scoped artifacts' {
        Mock Invoke-Command {
            @(
                Get-HLFleetTestResult -RequestedComputerName 'srv-a.contoso.test' -ComputerName 'SRV-A'
                Get-HLFleetTestResult -RequestedComputerName 'srv-b.contoso.test' -ComputerName 'SRV-B'
            )
        }

        $output = Join-Path -Path $TestDrive -ChildPath 'success'
        $summary = @(& $script:FleetScript -ComputerName 'srv-a.contoso.test','srv-b.contoso.test' -OutputDirectory $output)

        $summary.Count | Should -Be 2
        @($summary | Where-Object Status -eq 'Succeeded').Count | Should -Be 2
        @($summary | Select-Object -ExpandProperty RequestedComputerName | Sort-Object) | Should -Be @('srv-a.contoso.test','srv-b.contoso.test')
        @($summary | Select-Object -ExpandProperty RunId | Sort-Object -Unique).Count | Should -Be 1
        foreach ($row in $summary) {
            $row.Error | Should -BeNullOrEmpty
            Test-Path -LiteralPath $row.ArtifactPath -PathType Leaf | Should -BeTrue
            (Split-Path -Path $row.ArtifactPath -Leaf) | Should -Match '^fleet-\d{8}T\d{9}Z-'
        }

        $manifestPath = @(Get-ChildItem -LiteralPath $output -Filter 'fleet-run-*.json').FullName
        @($manifestPath).Count | Should -Be 1
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.requestedCount | Should -Be 2
        $manifest.succeededCount | Should -Be 2
        $manifest.failedCount | Should -Be 0
        Test-Path -LiteralPath (Join-Path -Path $output -ChildPath 'fleet-summary.csv') -PathType Leaf | Should -BeTrue
        @(Get-ChildItem -LiteralPath $output -Filter 'fleet-summary-*.csv').Count | Should -Be 1
    }

    It 'creates a failed summary row and machine-readable failure artifact when a host returns nothing' {
        Mock Invoke-Command {
            Get-HLFleetTestResult -RequestedComputerName 'srv-a' -ComputerName 'SRV-A'
        }

        $output = Join-Path -Path $TestDrive -ChildPath 'partial'
        $warnings = @()
        $summary = @(& $script:FleetScript -ComputerName 'srv-a','srv-b' -OutputDirectory $output -WarningVariable warnings)

        $summary.Count | Should -Be 2
        @($summary | Where-Object Status -eq 'Succeeded').Count | Should -Be 1
        $failed = @($summary | Where-Object Status -eq 'Failed')
        $failed.Count | Should -Be 1
        $failed[0].RequestedComputerName | Should -Be 'srv-b'
        $failed[0].ErrorCategory | Should -Be 'RemoteResultMissing'
        $failed[0].Error | Should -Not -BeNullOrEmpty
        $warnings.Count | Should -Be 1

        $failureArtifact = Get-Content -LiteralPath $failed[0].ArtifactPath -Raw | ConvertFrom-Json
        $failureArtifact.artifactType | Should -Be 'HardeningLens.FleetHostFailure'
        $failureArtifact.status | Should -Be 'Failed'
        $failureArtifact.requestedComputerName | Should -Be 'srv-b'
        $failureArtifact.error.message | Should -Not -BeNullOrEmpty

        $manifestPath = @(Get-ChildItem -LiteralPath $output -Filter 'fleet-run-*.json').FullName
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.requestedCount | Should -Be 2
        $manifest.succeededCount | Should -Be 1
        $manifest.failedCount | Should -Be 1
    }

    It 'can turn host failures into a terminating automation error after writing artifacts' {
        Mock Invoke-Command { @() }

        $output = Join-Path -Path $TestDrive -ChildPath 'fail-fast'
        { & $script:FleetScript -ComputerName 'srv-a' -OutputDirectory $output -FailOnHostError -WarningAction SilentlyContinue | Out-Null } |
            Should -Throw '*failed on 1 of 1 requested host*'

        @(Get-ChildItem -LiteralPath $output -Filter '*.error.json').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $output -Filter 'fleet-run-*.json').Count | Should -Be 1
    }
}
