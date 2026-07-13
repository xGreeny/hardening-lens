BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:SamplePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'examples/sample-result.json'
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
        $content | Should -Match 'HL-SMB-003'
        $content | Should -Match 'Prioritized findings'
        $content | Should -Not -Match '<script[^>]+src='
        $content | Should -Not -Match '<link[^>]+stylesheet'
    }

    It 'preserves every result in JSON and CSV' {
        $null = Export-HardeningLensReport -Path $script:SamplePath -Format Json, Csv -OutputDirectory $TestDrive -FileNamePrefix 'portable'
        $json = Get-Content -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'portable.json') -Raw | ConvertFrom-Json
        $csv = @(Import-Csv -LiteralPath (Join-Path -Path $TestDrive -ChildPath 'portable.csv'))

        @($json.results).Count | Should -Be 53
        $csv.Count | Should -Be 53
        @($csv | Where-Object ControlId -eq 'HL-SMB-003').Status | Should -Be 'Fail'
    }
}
