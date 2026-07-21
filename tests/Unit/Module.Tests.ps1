BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Module manifest and public surface' {
    It 'loads as version 1.2.0 on the current PowerShell edition' {
        $manifest = Test-ModuleManifest -Path $script:ModulePath
        $manifest.Version.ToString() | Should -Be '1.2.0'
        $manifest.PowerShellVersion | Should -Be ([version]'5.1')
    }

    It 'exports only the documented commands' {
        $expected = @(
            'Compare-HardeningLensResult'
            'Export-HardeningLensFleetReport'
            'Export-HardeningLensReport'
            'Get-HardeningLensBaseline'
            'Get-HardeningLensControl'
            'Invoke-HardeningLens'
            'Invoke-HardeningLensFleet'
            'New-HardeningLensExceptionFile'
            'Set-HardeningLensException'
            'Test-HardeningLensBaseline'
            'Test-HardeningLensExceptionFile'
            'Test-HardeningLensPolicy'
        ) | Sort-Object
        $actual = @(Get-Command -Module HardeningLens -CommandType Function | Select-Object -ExpandProperty Name | Sort-Object)
        ($actual -join ',') | Should -Be ($expected -join ',')
    }

    It 'provides synopsis help for every exported command' {
        foreach ($command in @(Get-Command -Module HardeningLens -CommandType Function)) {
            (Get-Help -Name $command.Name).Synopsis | Should -Not -BeNullOrEmpty
        }
    }

    It 'keeps PowerShell source ASCII-safe for Windows PowerShell 5.1' {
        $sourceFiles = @(Get-ChildItem -Path $script:RepositoryRoot -Include *.ps1, *.psm1, *.psd1 -File -Recurse | Where-Object {
            $_.FullName -notmatch '[\\/]dist[\\/]|[\\/]artifacts[\\/]'
        })
        foreach ($file in $sourceFiles) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because $file.FullName
        }
    }

    It 'rejects live collection on non-Windows platforms' {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
            { Invoke-HardeningLens -Baseline MemberServer -AllowPartial -NoConsole } | Should -Throw '*requires Windows*'
        }
        else {
            Set-ItResult -Skipped -Because 'The live collection path is covered by the opt-in Windows integration test.'
        }
    }
}
