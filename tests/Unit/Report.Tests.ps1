BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:SamplePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json'

    function Get-HLTestScanResult {
        return Get-Content -LiteralPath $script:SamplePath -Raw | ConvertFrom-Json
    }
}

Describe 'Report export' {
    It 'writes self-contained HTML, JSON, and CSV' {
        $files = @(Export-HardeningLensReport -Path $script:SamplePath -Format Html, Json, Csv -OutputDirectory $TestDrive -FileNamePrefix 'assessment')
        $files.Count | Should -Be 3

        foreach ($format in @('Html', 'Json', 'Csv')) {
            $file = $files | Where-Object Format -eq $format
            $file | Should -Not -BeNullOrEmpty
            Test-Path -LiteralPath $file.Path | Should -BeTrue
            $file.Bytes | Should -BeGreaterThan 0
        }
    }

    It 'encodes findings and includes a restrictive report policy' {
        $null = Export-HardeningLensReport -Path $script:SamplePath -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'report'
        $content = Get-Content -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'report.html') -Raw

        $content | Should -Match 'Content-Security-Policy'
        $content | Should -Match 'default-src ''none'''
        $content | Should -Match "script-src 'sha256-[A-Za-z0-9+/=]+'"
        $content | Should -Not -Match "script-src 'unsafe-inline'"
        $content | Should -Match 'HL-SMB-003'
        $content | Should -Match 'Prioritized findings'
        $content | Should -Match 'Assessment provenance'
        $content | Should -Match 'ee4f598239afe802f2a85018ad261c93faecc681e47fc8bcab6811f515be3d81'
        $content | Should -Match 'report schema 1\.1'
        $content | Should -Not -Match '<script[^>]+src='
        $content | Should -Not -Match '<link[^>]+stylesheet'

        $policyHash = [regex]::Match($content, "script-src 'sha256-([^']+)'").Groups[1].Value
        $scriptBody = [regex]::Match($content, '<script>(.*?)</script>', [Text.RegularExpressions.RegexOptions]::Singleline).Groups[1].Value
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $actualHash = [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($scriptBody)))
        }
        finally {
            $sha256.Dispose()
        }
        $policyHash | Should -BeExactly $actualHash
    }

    It 'preserves every result in JSON and CSV' {
        $null = Export-HardeningLensReport -Path $script:SamplePath -Format Json, Csv -OutputDirectory $TestDrive -FileNamePrefix 'portable'
        $json = Get-Content -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'portable.json') -Raw | ConvertFrom-Json
        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'portable.csv'))

        @($json.results).Count | Should -Be 53
        $csv.Count | Should -Be 53
        @($csv | Where-Object ControlId -eq 'HL-SMB-003').Status | Should -Be 'Fail'
    }

    It 'rejects malformed scan structures before creating report files' {
        $scan = Get-HLTestScanResult
        $scan.PSObject.Properties.Remove('summary')
        $invalidPath = Join-Path -Path $TestDrive -ChildPath 'invalid-result.json'
        [IO.File]::WriteAllText($invalidPath, ($scan | ConvertTo-Json -Depth 40), (New-Object Text.UTF8Encoding($false)))

        { Export-HardeningLensReport -Path $invalidPath -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'invalid' } |
            Should -Throw '*summary: required property is missing*'
        Test-Path -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'invalid.html') | Should -BeFalse
    }

    It 'rejects unsupported result enums and duplicate control IDs' {
        $badSeverity = Get-HLTestScanResult
        $badSeverity.results[0].severity = 'High" onclick="alert(1)'
        { Export-HardeningLensReport -InputObject $badSeverity -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'bad-severity' } |
            Should -Throw '*severity: must be one of*'

        $badStatus = Get-HLTestScanResult
        $badStatus.results[0].status = 'Compromised'
        { Export-HardeningLensReport -InputObject $badStatus -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'bad-status' } |
            Should -Throw '*status: must be one of*'

        $duplicate = Get-HLTestScanResult
        $duplicate.results[1].controlId = $duplicate.results[0].controlId
        { Export-HardeningLensReport -InputObject $duplicate -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'duplicate' } |
            Should -Throw '*duplicate controlId*'
    }

    It 'encodes report data and only links allowlisted Microsoft guidance' {
        $scan = Get-HLTestScanResult
        $result = $scan.results | Where-Object status -eq 'Fail' | Select-Object -First 1
        $result.title = '<img src=x onerror=alert(1)>'
        $result.references = @(
            'javascript:alert(1)',
            'https://learn.microsoft.com.evil.example/security',
            'https://learn.microsoft.com/windows/security/'
        )

        $null = Export-HardeningLensReport -InputObject $scan -Format Html -OutputDirectory $TestDrive -FileNamePrefix 'safe-html'
        $content = Get-Content -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'safe-html.html') -Raw

        $content | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
        $content | Should -Not -Match '<img src=x'
        $content | Should -Not -Match 'javascript:'
        $content | Should -Not -Match 'learn\.microsoft\.com\.evil'
        $content | Should -Match 'href="https://learn\.microsoft\.com/windows/security/"'
    }

    It 'neutralizes spreadsheet formulas in every CSV field' {
        $scan = Get-HLTestScanResult
        $result = $scan.results[0]
        $result.title = '=1+1'
        $result.category = '+SUM(A1:A2)'
        $result.expected = '-2'
        $result.actual = '@SUM(A1:A2)'
        $result.message = "`tformula"
        $result.remediation = "`rcarriage"

        $null = Export-HardeningLensReport -InputObject $scan -Format Csv -OutputDirectory $TestDrive -FileNamePrefix 'safe-csv'
        $row = Import-Csv -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'safe-csv.csv') | Select-Object -First 1

        $row.Title | Should -BeExactly "'=1+1"
        $row.Category | Should -BeExactly "'+SUM(A1:A2)"
        $row.Expected | Should -BeExactly "'-2"
        $row.Actual | Should -BeExactly "'@SUM(A1:A2)"
        $row.Message | Should -BeExactly "'`tformula"
        $row.Remediation | Should -BeExactly "'`rcarriage"
    }

    It 'uses a unique prefix for every pipeline input' {
        $inputs = @((Get-HLTestScanResult), (Get-HLTestScanResult))
        $files = @($inputs | Export-HardeningLensReport -Format Json -OutputDirectory $TestDrive -FileNamePrefix 'batch')

        $files.Count | Should -Be 2
        Test-Path -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'batch.json') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'batch-2.json') | Should -BeTrue
    }

    It 'does not overwrite existing files unless Force is specified' {
        $target = Join-Path -Path $TestDrive -ChildPath 'protected.json'
        [IO.File]::WriteAllText($target, 'sentinel')

        { Export-HardeningLensReport -Path $script:SamplePath -Format Json -OutputDirectory $TestDrive -FileNamePrefix 'protected' } |
            Should -Throw '*already exists*Use -Force*'
        [IO.File]::ReadAllText($target) | Should -BeExactly 'sentinel'

        $null = Export-HardeningLensReport -Path $script:SamplePath -Format Json -OutputDirectory $TestDrive -FileNamePrefix 'protected' -Force
        (Get-Content -LiteralPath $target -Raw | ConvertFrom-Json).schemaVersion | Should -Be '1.1'
    }
}
