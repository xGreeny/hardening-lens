#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'examples')
)

$root = Join-Path -Path $PSScriptRoot -ChildPath '..'
Import-Module -Name (Join-Path -Path (Join-Path -Path $root -ChildPath 'src/HardeningLens') -ChildPath 'HardeningLens.psd1') -Force
Export-HardeningLensReport -Path (Join-Path -Path $root -ChildPath 'examples/sample-result.json') -Format Html,Csv -OutputDirectory $OutputDirectory -FileNamePrefix 'sample-report'
