BeforeDiscovery {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    $script:ModulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
    Import-Module -Name $script:ModulePath -Force
}

Describe 'Collection context and probe registry' {
    InModuleScope HardeningLens {
        It 'caches shared provider snapshots for the duration of one collection' {
            $script:providerCalls = 0
            $context = New-HLCollectionContext
            $factory = {
                $script:providerCalls++
                [pscustomobject]@{ Value = 42 }
            }

            $first = Get-HLProviderSnapshot -CollectionContext $context -Name 'SharedProvider' -Factory $factory
            $second = Get-HLProviderSnapshot -CollectionContext $context -Name 'SharedProvider' -Factory $factory

            $script:providerCalls | Should -Be 1
            $first.Value | Should -Be 42
            $second.Value | Should -Be 42
            $context.ProviderMetrics.Count | Should -Be 1
            $context.ProviderMetrics[0].CacheHits | Should -Be 1
        }

        It 'registers every catalog probe exactly once' {
            $registry = Get-HLProbeRegistry
            $catalogProbes = @((Get-HLControlCatalog).controls | ForEach-Object { [string]$_.probe } | Sort-Object -Unique)
            $registeredProbes = @($registry.Keys | Sort-Object)

            ($registeredProbes -join ',') | Should -Be ($catalogProbes -join ',')
        }

        It 'produces stable content digests independent of object property order' {
            $first = [pscustomobject][ordered]@{ Beta = @(1, 2); Alpha = [pscustomobject][ordered]@{ Y = $true; X = 'value' } }
            $second = [pscustomobject][ordered]@{ Alpha = [pscustomobject][ordered]@{ X = 'value'; Y = $true }; Beta = @(1, 2) }
            $reorderedArray = [pscustomobject][ordered]@{ Alpha = [pscustomobject][ordered]@{ X = 'value'; Y = $true }; Beta = @(2, 1) }

            (Get-HLContentDigest -InputObject $first) | Should -Be (Get-HLContentDigest -InputObject $second)
            (Get-HLContentDigest -InputObject $first) | Should -Not -Be (Get-HLContentDigest -InputObject $reorderedArray)
        }

        It 'returns sorted capability provenance for selected probes' {
            $controls = @(
                [pscustomobject]@{ probe = 'DefenderStatus' },
                [pscustomobject]@{ probe = 'AutoRun' },
                [pscustomobject]@{ probe = 'AutoRun' }
            )

            $capabilities = @(Get-HLProbeCapability -Controls $controls)
            @($capabilities.name) | Should -Be @('AutoRun', 'DefenderStatus')
            foreach ($capability in $capabilities) {
                $capability.available | Should -BeOfType ([bool])
                $capability.PSObject.Properties.Name | Should -Contain 'detail'
            }
        }

        It 'dispatches through the registry and records probe duration' {
            Mock Invoke-HLAutoRunProbe {
                Get-HLProbeResult -Status Pass -Expected 'Disabled' -Actual 'Disabled'
            }
            $control = [pscustomobject]@{ id = 'HL-TEST-001'; probe = 'AutoRun'; parameters = [pscustomobject]@{} }
            $system = [pscustomobject]@{ BuildNumber = '0' }

            $result = Invoke-HLProbe -Control $control -SystemContext $system -CollectionContext (New-HLCollectionContext)

            $result.Status | Should -Be 'Pass'
            $result.DurationMs | Should -BeGreaterOrEqual 0
            Should -Invoke Invoke-HLAutoRunProbe -Times 1 -Exactly
        }

        It 'rejects unsupported probe parameters before collection' {
            Mock Invoke-HLAutoRunProbe {
                throw 'This handler must not run.'
            }
            $control = [pscustomobject]@{ id = 'HL-TEST-002'; probe = 'AutoRun'; parameters = [pscustomobject]@{ injected = $true } }
            $system = [pscustomobject]@{ BuildNumber = '0' }

            $result = Invoke-HLProbe -Control $control -SystemContext $system

            $result.Status | Should -Be 'Error'
            $result.Message | Should -Match 'unsupported parameter'
            Should -Invoke Invoke-HLAutoRunProbe -Times 0 -Exactly
        }
    }
}
