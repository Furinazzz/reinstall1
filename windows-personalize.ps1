param(
    [ValidateSet('Run', 'Check')][string] $Mode = 'Run',
    [string] $InstallerDirectory,
    [switch] $UseExistingInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-ReinstallRuntimeDirectory {
    return Join-Path $env:ProgramData 'ReinstallPersonalization'
}

function Assert-ReinstallLocalPath {
    param([Parameter(Mandatory)][string] $Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.TrimEnd('\') -eq [IO.Path]::GetPathRoot($full).TrimEnd('\')) {
        throw "Expected a local directory below a drive root: $Path"
    }
    # Never traverse a junction, including an ancestor, from an elevated script.
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse points are not allowed: $cursor" }
        }
        $parent = Split-Path -Path $cursor -Parent
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full.TrimEnd('\')
}

function Get-ReinstallDownloadsDirectory {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $value = (Get-ItemProperty -LiteralPath $key -Name '{374DE290-123F-4565-9164-39C4925E467B}').'{374DE290-123F-4565-9164-39C4925E467B}'
    return Assert-ReinstallLocalPath ([Environment]::ExpandEnvironmentVariables($value))
}

function Test-ReinstallSupportedWindows {
    $os = Get-CimInstance Win32_OperatingSystem
    return $os.ProductType -eq 1 -and [int]$os.BuildNumber -ge 10240
}

function Test-ReinstallWindowsActivated {
    $products = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL")
    return @($products | Where-Object { $_.LicenseStatus -eq 1 -and -not $_.LicenseDependsOn }).Count -gt 0
}

function Receive-ReinstallFile {
    param([string] $Uri, [string] $Destination, [string] $Sha256)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $partial = "$Destination.partial"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $partial -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop
            if ($Sha256 -and (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $Sha256) {
                throw 'Downloaded file does not match its pinned SHA256.'
            }
            Move-Item -LiteralPath $partial -Destination $Destination -Force
            return
        }
        catch {
            if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 3
        }
    }
}

function Invoke-ReinstallActivation {
    param([string] $WorkingDirectory)
    $file = Join-Path $WorkingDirectory 'MAS_AIO.cmd'
    $timeoutMarker = Join-Path $WorkingDirectory 'activation-timeout.txt'
    if (Test-Path -LiteralPath $timeoutMarker) { throw 'An earlier TSforge process timed out. Inspect it and remove activation-timeout.txt before retrying.' }
    if (Test-ReinstallWindowsActivated) {
        Write-Host 'Windows is already activated; skipping TSforge.'
        return
    }
    Receive-ReinstallFile -Uri 'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/05c4f881efec946c0040cdd552d1afa9a519704b/MAS/All-In-One-Version-KL/MAS_AIO.cmd' -Destination $file -Sha256 '850F979665FB93999ACAE93F4790C1FF8ED2041532060B7966A121C2D29A0BFA'
    $finished = $false
    try {
        # Equivalent to TSforge > Activate Windows. Elevated native-bitness CMD
        # avoids MAS's asynchronous elevation/Terminal relaunch. No SendKeys.
        $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $cmd
        $start.Arguments = '/d /s /c ""' + $file + '" /Z-Windows -el"'
        $start.WorkingDirectory = $WorkingDirectory
        $start.UseShellExecute = $false
        $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
        $process = [Diagnostics.Process]::Start($start)
        try {
            if (-not $process.WaitForExit(900000)) {
                "TSforge process $($process.Id) timed out at $(Get-Date -Format o). Its script was retained because it may still be running." | Set-Content -LiteralPath $timeoutMarker -Encoding UTF8
                throw 'TSforge exceeded 15 minutes. Inspect its process before manually retrying; later steps were not started.'
            }
            $finished = $true
        }
        finally { $process.Dispose() }
        # MAS may return zero even when activation fails. Query Windows itself.
        if (-not (Test-ReinstallWindowsActivated)) { throw 'Windows activation was not verified. Software installation has been stopped.' }
    }
    finally {
        if ($finished -and (Test-Path -LiteralPath $file)) { Remove-Item -LiteralPath $file -Force }
    }
}

function Initialize-ReinstallBundle {
    param([string] $Directory)
    # Downloads may not exist yet at the first logon.
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $archive = Join-Path (Split-Path $directory -Parent) 'install.zip'
    foreach ($path in @($archive, "$archive.partial")) {
        [void](Assert-ReinstallLocalPath $path)
        if (Test-Path -LiteralPath $path -PathType Container) { throw "Expected a download file path: $path" }
    }
    Receive-ReinstallFile -Uri 'https://dl-b2.r18.zip/install.zip' -Destination $archive
    Expand-Archive -LiteralPath $archive -DestinationPath $directory -Force
}

function Initialize-ReinstallRuntime {
    $directory = Assert-ReinstallLocalPath (Get-ReinstallRuntimeDirectory)
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if (Test-Path -LiteralPath $directory) {
        $existingAcl = Get-Acl -LiteralPath $directory
        if ($existingAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
            throw 'Existing runtime directory has an untrusted owner. Inspect it before running elevated code.'
        }
        $writeRights = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        foreach ($rule in $existingAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and ($rule.FileSystemRights -band $writeRights)) {
                throw 'Existing runtime directory is writable by an untrusted identity.'
            }
        }
        if (@(Get-ChildItem -LiteralPath $directory -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
            throw 'Existing runtime directory contains a reparse point.'
        }
    }
    else { New-Item -ItemType Directory -Path $directory | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in $trusted) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    return $directory
}

function Invoke-ReinstallPersonalization {
    param([string] $Directory, [switch] $UseExisting, [switch] $CheckOnly)
    if (-not (Test-ReinstallSupportedWindows)) { Write-Host 'Automatic personalization requires Windows 10 or 11 client; skipped.'; return }
    if (-not [Environment]::Is64BitProcess) { throw 'Run this script using native 64-bit PowerShell.' }
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'This personalization workflow supports x64 Windows only.' }
    # The DNS helper enables native DoH when available. Its absence on stable
    # Windows 10 must not prevent DNS configuration or the remaining workflow.
    if (-not $Directory) { $Directory = Join-Path (Get-ReinstallDownloadsDirectory) 'install' }
    $Directory = Assert-ReinstallLocalPath $Directory
    if ((Split-Path $Directory -Leaf) -ne 'install') { throw 'The installer directory must be named install.' }
    if ($CheckOnly) {
        Write-Host "Installer directory: $Directory. Windows activated: $(Test-ReinstallWindowsActivated)."
        return
    }
    if (-not (Test-ReinstallAdministrator)) { throw 'Run this script as administrator.' }
    $mutex = New-Object Threading.Mutex($false, 'Global\ReinstallPersonalization')
    $acquired = $false
    $transcript = $false
    try {
        try { $acquired = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Another personalization process is already running.' }
        $runtime = Initialize-ReinstallRuntime
        Start-Transcript -LiteralPath (Join-Path $runtime 'personalization.log') -Append | Out-Null
        $transcript = $true
        $statePath = Join-Path $runtime 'state.json'
        $steps = @()
        $hasState = Test-Path -LiteralPath $statePath
        if ($hasState) {
            $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($state.Directory -ne $Directory) { throw 'A prior run used a different install directory. Inspect its state before retrying.' }
            $steps = @($state.Steps)
        }
        if ($steps -contains 'DefenderStarted') { throw 'Defender removal was previously dispatched or its launch failed. Inspect removal status before retrying.' }
        if ((Test-Path -LiteralPath $Directory) -and -not ($UseExisting -or $hasState)) {
            throw "Existing directory will not be overwritten. Use -UseExistingInstall after checking it: $Directory"
        }
        Set-ReinstallJapanTimeZone
        Set-ReinstallJapanHomeLocation
        Invoke-CloudflareDns
        Invoke-ReinstallActivation -WorkingDirectory $runtime
        # Record the chosen directory before downloading so an interrupted
        # download can resume without accepting an unrelated existing directory.
        @{ Directory = $Directory; Steps = $steps } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
        $bundleExists = Test-Path -LiteralPath $Directory -PathType Container
        if (-not $bundleExists -or ($steps -notcontains 'BundleExpanded' -and -not $UseExisting)) {
            Initialize-ReinstallBundle -Directory $Directory
        }
        if ($steps -notcontains 'BundleExpanded') {
            $steps += 'BundleExpanded'
            @{ Directory = $Directory; Steps = $steps } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
        }
        # Keep the layout from the ZIP and locate the installers in either supported layout.
        $installerPath = $Directory
        $wrappedPath = Join-Path $Directory 'install'
        if (Test-Path -LiteralPath (Join-Path $wrappedPath 'Remove-EdgeWeb.exe') -PathType Leaf) {
            $installerPath = Assert-ReinstallLocalPath $wrappedPath
        }
        foreach ($step in @('Edge', 'LocalSoftware', 'DefenderStarted')) {
            if ($steps -contains $step) { continue }
            switch ($step) {
                'Edge' { Invoke-ReinstallEdgeRemoval -InstallerDirectory $installerPath -WorkingDirectory $runtime }
                'LocalSoftware' { Install-ReinstallSoftware -InstallerDirectory $installerPath -WorkingDirectory $runtime }
            }
            if ($steps -notcontains $step) { $steps += $step }
            @{ Directory = $Directory; Steps = $steps } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
            if ($step -eq 'DefenderStarted') {
                Invoke-ReinstallDefenderRemoval -InstallerDirectory $installerPath -WorkingDirectory $runtime
            }
        }
        Write-Host 'All steps dispatched. DefenderRemover schedules the restart. Downloaded installation files are kept.'
    }
    finally {
        if ($transcript) { Stop-Transcript | Out-Null }
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        . (Join-Path $PSScriptRoot 'windows-install-software.ps1')
        . (Join-Path $PSScriptRoot 'windows-remove-components.ps1')
        $dns = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'windows-cloudflare-japan.bat') -Raw -Encoding UTF8
        $marker = '#==PS_PAYLOAD_START=='
        $payload = $dns.Substring($dns.LastIndexOf($marker) + $marker.Length)
        $payload = $payload -replace '(?m)^exit \(Invoke-ReinstallConfiguration\)\s*$', ''
        . ([scriptblock]::Create($payload))
        Invoke-ReinstallPersonalization -Directory $InstallerDirectory -UseExisting:$UseExistingInstall -CheckOnly:($Mode -eq 'Check')
        exit 0
    }
    catch { Write-Error $_ -ErrorAction Continue; exit 1 }
}
