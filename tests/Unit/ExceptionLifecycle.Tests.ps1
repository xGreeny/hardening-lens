BeforeAll {
    $script:RepositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    Import-Module -Name (Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1') -Force
    $script:Module = Get-Module HardeningLens

    function Initialize-HLLifecycleRegister {
        param([Parameter(Mandatory)][string]$Path)

        $null = New-HardeningLensExceptionFile -Path $Path
        return $Path
    }
}

Describe 'Exception lifecycle governance' {
    It 'adds a unique Draft and requires Force before replacing it' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'draft.json')
        $parameters = @{
            Path       = $path
            Add        = $true
            Id         = 'EXC-LIFECYCLE-DRAFT'
            ControlId  = 'HL-RA-001'
            Owner      = 'Workplace Engineering'
            Reason     = 'A governed lifecycle test requires a draft exception.'
            Ticket     = 'SEC-500'
            Expires    = (Get-Date).AddDays(30)
            Target     = @('AVD-PILOT-*')
        }

        $added = & $script:Module { param($Arguments) Set-HardeningLensException @Arguments } $parameters
        $added.Status | Should -Be 'Draft'
        $added.Changed | Should -BeTrue

        { & $script:Module { param($Arguments) Set-HardeningLensException @Arguments } $parameters } |
            Should -Throw '*already exists*Use -Force*'

        $parameters.Reason = 'The replacement draft has explicitly reviewed metadata.'
        $parameters.Force = $true
        $replaced = & $script:Module { param($Arguments) Set-HardeningLensException @Arguments } $parameters
        $replaced.PreviousStatus | Should -Be 'Draft'
        $replaced.Changed | Should -BeTrue
        $replaced.Exception.reason | Should -Be $parameters.Reason
    }

    It 'enforces approval metadata and forward-only transitions' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'approval.json')
        $draft = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Add -Id EXC-LIFECYCLE-APPROVAL -ControlId HL-RA-001 -Owner 'Workplace Engineering' -Reason 'A governed approval transition is being tested.' -Ticket SEC-501 -Expires (Get-Date).AddDays(30) -Target 'AVD-*'
        } $path
        $draft.Status | Should -Be 'Draft'

        { & $script:Module {
                param($InputPath)
                Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-APPROVAL -Status Approved -ApprovedBy 'Security Engineering'
            } $path } | Should -Throw '*compensatingControls*'

        $approved = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-APPROVAL -Status Approved -ApprovedBy 'Security Engineering' -CompensatingControl 'Access is restricted to the approved support group.'
        } $path
        $approved.PreviousStatus | Should -Be 'Draft'
        $approved.Status | Should -Be 'Approved'

        { & $script:Module {
                param($InputPath)
                Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-APPROVAL -Status Draft
            } $path } | Should -Throw '*Unsupported exception transition*'

        $revoked = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-APPROVAL -Revoke
        } $path
        $revoked.PreviousStatus | Should -Be 'Approved'
        $revoked.Status | Should -Be 'Revoked'

        { & $script:Module {
                param($InputPath)
                Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-APPROVAL -Status Approved
            } $path } | Should -Throw '*Unsupported exception transition*'
    }

    It 'reports natural expiry without persisting an unsupported status' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'expired.json')
        $null = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Add -Id EXC-LIFECYCLE-EXPIRED -ControlId HL-RA-001 -Owner 'Workplace Engineering' -Reason 'An expired approval state is being tested safely.' -Ticket SEC-502 -Expires (Get-Date).AddDays(-1) -Target 'AVD-*' -CompensatingControl 'Access remains restricted while the record is reviewed.'
        } $path
        $expired = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-EXPIRED -Status Approved -ApprovedBy 'Security Engineering' -ApprovedOn (Get-Date).AddDays(-2)
        } $path

        $expired.Status | Should -Be 'Approved'
        $expired.EffectiveStatus | Should -Be 'Expired'
        (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).exceptions[0].status | Should -Be 'Approved'
    }

    It 'resets changed Approved terms to Draft and requires a separate re-approval' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'reapproval.json')
        $null = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Add -Id EXC-LIFECYCLE-REAPPROVAL -ControlId HL-RA-001 -Owner 'Workplace Engineering' -Reason 'A narrowly scoped approved support exception is being tested.' -Ticket SEC-504 -Expires (Get-Date).AddDays(30) -Target 'AVD-PILOT-*' -Baseline AVDSessionHost -CompensatingControl 'Access is restricted to the approved support group.'
        } $path
        $approved = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-REAPPROVAL -Status Approved -ApprovedBy 'Security Engineering'
        } $path
        $approved.Status | Should -Be 'Approved'
        $approved.ApprovalReset | Should -BeFalse

        $changed = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-REAPPROVAL -Target 'AVD-*' -Expires (Get-Date).AddDays(60) -ApprovedBy 'Replacement approver'
        } $path
        $changed.PreviousStatus | Should -Be 'Approved'
        $changed.Status | Should -Be 'Draft'
        $changed.ApprovalReset | Should -BeTrue
        $changed.Exception.targets | Should -Be @('AVD-*')
        $changed.Exception.PSObject.Properties['approvedBy'] | Should -BeNullOrEmpty
        $changed.Exception.PSObject.Properties['approvedOn'] | Should -BeNullOrEmpty

        $persisted = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $persisted.exceptions[0].status | Should -Be 'Draft'
        $persisted.exceptions[0].PSObject.Properties['approvedBy'] | Should -BeNullOrEmpty
        $persisted.exceptions[0].PSObject.Properties['approvedOn'] | Should -BeNullOrEmpty
        (Test-HardeningLensExceptionFile -Path $path).IsValid | Should -BeTrue

        $reapproved = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-REAPPROVAL -Status Approved -ApprovedBy 'Security Architecture'
        } $path
        $reapproved.Status | Should -Be 'Approved'
        $reapproved.ApprovalReset | Should -BeFalse
        $reapproved.Exception.approvedBy | Should -Be 'Security Architecture'
        $reapproved.Exception.approvedOn | Should -Not -BeNullOrEmpty
    }

    It 'keeps an unchanged Approved entry approved' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'unchanged-approval.json')
        $null = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Add -Id EXC-LIFECYCLE-UNCHANGED -ControlId HL-RA-001 -Owner 'Workplace Engineering' -Reason 'An unchanged approved exception is being tested safely.' -Ticket SEC-505 -Expires (Get-Date).AddDays(30) -Target 'AVD-*' -CompensatingControl 'Access is restricted to the approved support group.'
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-UNCHANGED -Status Approved -ApprovedBy 'Security Engineering'
        } $path

        $unchanged = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-UNCHANGED -Status Approved
        } $path
        $unchanged.Status | Should -Be 'Approved'
        $unchanged.ApprovalReset | Should -BeFalse
        $unchanged.WouldChange | Should -BeFalse
        $unchanged.Changed | Should -BeFalse
    }

    It 'updates atomically, honors WhatIf, and leaves a valid register' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'atomic.json')
        $null = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Add -Id EXC-LIFECYCLE-ATOMIC -ControlId HL-RA-001 -Owner 'Workplace Engineering' -Reason 'Atomic lifecycle persistence is being verified.' -Ticket SEC-503 -Expires (Get-Date).AddDays(30) -Target 'AVD-*'
        } $path
        $before = [IO.File]::ReadAllText($path)

        $preview = & $script:Module {
            param($InputPath)
            Set-HardeningLensException -Path $InputPath -Id EXC-LIFECYCLE-ATOMIC -Owner 'Changed only in preview' -WhatIf
        } $path
        $preview.WouldChange | Should -BeTrue
        $preview.Changed | Should -BeFalse
        [IO.File]::ReadAllText($path) | Should -BeExactly $before

        $result = Test-HardeningLensExceptionFile -Path $path
        $result.IsValid | Should -BeTrue
        @(Get-ChildItem -LiteralPath $TestDrive -Force | Where-Object Name -Match '\.(tmp|bak)$').Count | Should -Be 0
    }

    It 'uses a bounded cross-process lock timeout' {
        $path = Join-Path -Path $TestDrive -ChildPath 'lock-timeout.json'
        $readyPath = Join-Path -Path $TestDrive -ChildPath 'lock-ready'
        $modulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
        $job = Start-Job -ScriptBlock {
            param($ImportedModulePath, $LockedPath, $ReadyFile)
            $module = Import-Module -Name $ImportedModulePath -Force -PassThru
            & $module {
                param($TargetPath, $SignalPath)
                $lock = Enter-HLFileLock -Path $TargetPath
                try {
                    [IO.File]::WriteAllText($SignalPath, 'ready')
                    Start-Sleep -Seconds 2
                }
                finally {
                    Exit-HLFileLock -Lock $lock
                }
            } $LockedPath $ReadyFile
        } -ArgumentList $modulePath, $path, $readyPath

        try {
            $deadline = (Get-Date).AddSeconds(30)
            while (-not (Test-Path -LiteralPath $readyPath)) {
                if ((Get-Date) -gt $deadline) {
                    throw 'The lock-holder process did not become ready.'
                }
                Start-Sleep -Milliseconds 50
            }

            {
                & $script:Module {
                    param($TargetPath)
                    $lock = Enter-HLFileLock -Path $TargetPath -TimeoutMilliseconds 150
                    try { }
                    finally { Exit-HLFileLock -Lock $lock }
                } $path
            } | Should -Throw '*Timed out*waiting for the file lock*'
        }
        finally {
            $null = Wait-Job -Job $job -Timeout 10
            if ($job.State -eq 'Running') {
                $job | Stop-Job
            }
            $null = $job | Receive-Job -ErrorAction SilentlyContinue
            $job | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }

    It 'preserves every concurrent cross-process addition' {
        $path = Initialize-HLLifecycleRegister -Path (Join-Path -Path $TestDrive -ChildPath 'parallel.json')
        $gatePath = Join-Path -Path $TestDrive -ChildPath 'parallel-go'
        $modulePath = Join-Path -Path $script:RepositoryRoot -ChildPath 'src/HardeningLens/HardeningLens.psd1'
        $jobs = @()
        $readyPaths = @(1..4 | ForEach-Object { Join-Path -Path $TestDrive -ChildPath ("parallel-ready-$_") })
        try {
            for ($worker = 1; $worker -le 4; $worker++) {
                $jobs += Start-Job -ScriptBlock {
                    param($ImportedModulePath, $RegisterPath, $WorkerNumber, $ReadyFile, $GateFile)
                    Import-Module -Name $ImportedModulePath -Force
                    [IO.File]::WriteAllText($ReadyFile, 'ready')
                    while (-not (Test-Path -LiteralPath $GateFile)) {
                        Start-Sleep -Milliseconds 10
                    }
                    $null = Set-HardeningLensException -Path $RegisterPath -Add -Id ("EXC-PARALLEL-$WorkerNumber") -ControlId HL-RA-001 -Owner 'Parallel Worker' -Reason ("Parallel governed exception number $WorkerNumber is being added.") -Ticket ("SEC-60$WorkerNumber") -Expires (Get-Date).AddDays(30) -Target ("HOST-$WorkerNumber")
                } -ArgumentList $modulePath, $path, $worker, $readyPaths[$worker - 1], $gatePath
            }

            $deadline = (Get-Date).AddSeconds(45)
            while (@($readyPaths | Where-Object { Test-Path -LiteralPath $_ }).Count -ne $readyPaths.Count) {
                if ((Get-Date) -gt $deadline) {
                    throw 'The parallel worker processes did not become ready.'
                }
                Start-Sleep -Milliseconds 50
            }
            [IO.File]::WriteAllText($gatePath, 'go')
            $null = Wait-Job -Job $jobs -Timeout 60
            @($jobs | Where-Object State -ne 'Completed').Count | Should -Be 0

            $jobErrors = @()
            $null = $jobs | Receive-Job -ErrorAction SilentlyContinue -ErrorVariable +jobErrors
            @($jobErrors).Count | Should -Be 0

            $persisted = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            @($persisted.exceptions).Count | Should -Be 4
            @($persisted.exceptions.id | Sort-Object) | Should -Be @(
                'EXC-PARALLEL-1',
                'EXC-PARALLEL-2',
                'EXC-PARALLEL-3',
                'EXC-PARALLEL-4'
            )
            (Test-HardeningLensExceptionFile -Path $path).IsValid | Should -BeTrue
        }
        finally {
            @($jobs | Where-Object State -eq 'Running') | Stop-Job -ErrorAction SilentlyContinue
            @($jobs) | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }
}
