#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$source = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'src/HardeningLens'
$manifest = Test-ModuleManifest -Path (Join-Path -Path $source -ChildPath 'HardeningLens.psd1') -ErrorAction Stop
$edition = if ($null -ne $PSVersionTable.PSObject.Properties['PSEdition']) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
$moduleFolder = if ($edition -eq 'Core') { 'PowerShell/Modules' } else { 'WindowsPowerShell/Modules' }

if ($Scope -eq 'AllUsers') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'AllUsers installation requires an elevated PowerShell session.'
    }
    $base = Join-Path -Path $env:ProgramFiles -ChildPath $moduleFolder
}
else {
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($documents)) {
        $documents = Join-Path -Path $HOME -ChildPath 'Documents'
    }
    $base = Join-Path -Path $documents -ChildPath $moduleFolder
}

$destination = Join-Path -Path (Join-Path -Path $base -ChildPath 'HardeningLens') -ChildPath $manifest.Version.ToString()
if ((Test-Path -LiteralPath $destination) -and -not $Force) {
    throw "Module version already exists at $destination. Use -Force to replace it."
}

if ($PSCmdlet.ShouldProcess($destination, "Install HardeningLens $($manifest.Version) for $Scope")) {
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    [void](New-Item -Path $destination -ItemType Directory -Force)
    Copy-Item -Path (Join-Path -Path $source -ChildPath '*') -Destination $destination -Recurse -Force
    Get-Item -LiteralPath $destination
}
