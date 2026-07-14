function Get-HLFileLockName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $pathKey = [IO.Path]::GetFullPath($Path)
    $isWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if ($isWindows) {
        $pathKey = $pathKey.ToUpperInvariant()
    }

    $encoding = New-Object Text.UTF8Encoding($false)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash($encoding.GetBytes($pathKey))
    }
    finally {
        $hasher.Dispose()
    }
    $digestText = -join @($digest | ForEach-Object { $_.ToString('x2') })
    $prefix = if ($isWindows) { 'Global\HardeningLens.File.' } else { 'HardeningLens.File.' }
    return $prefix + $digestText
}

function Enter-HLFileLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateRange(1, 300000)]
        [int]$TimeoutMilliseconds = 15000
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $mutexName = Get-HLFileLockName -Path $fullPath
    $mutex = New-Object System.Threading.Mutex($false, $mutexName)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne($TimeoutMilliseconds)
        }
        catch [System.Threading.AbandonedMutexException] {
            # The previous owner terminated without releasing the mutex. Ownership is
            # transferred to this thread, so the protected operation can proceed.
            $acquired = $true
        }

        if (-not $acquired) {
            throw (New-Object System.TimeoutException("Timed out after $TimeoutMilliseconds ms waiting for the file lock for '$fullPath'."))
        }
        return $mutex
    }
    catch {
        if (-not $acquired) {
            $mutex.Dispose()
        }
        throw
    }
}

function Exit-HLFileLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Threading.Mutex]$Lock
    )

    try {
        $Lock.ReleaseMutex()
    }
    finally {
        $Lock.Dispose()
    }
}

function Write-HLAtomicUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content,

        [switch]$NoClobber
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Path $fullPath -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Parent directory does not exist: $parent"
    }

    $temporaryPath = Join-Path -Path $parent -ChildPath ('.{0}.{1}.tmp' -f [IO.Path]::GetFileName($fullPath), [guid]::NewGuid().ToString('N'))
    $backupPath = Join-Path -Path $parent -ChildPath ('.{0}.{1}.bak' -f [IO.Path]::GetFileName($fullPath), [guid]::NewGuid().ToString('N'))
    $encoding = New-Object Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Content)
    $stream = [IO.File]::Open($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    try {
        if ($NoClobber) {
            # File.Move is atomic on the same volume and fails when the destination
            # appears concurrently, closing the final no-clobber check/write race.
            [IO.File]::Move($temporaryPath, $fullPath)
        }
        elseif (Test-Path -LiteralPath $fullPath) {
            [IO.File]::Replace($temporaryPath, $fullPath, $backupPath)
        }
        else {
            [IO.File]::Move($temporaryPath, $fullPath)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if (Test-Path -LiteralPath $backupPath) {
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}
