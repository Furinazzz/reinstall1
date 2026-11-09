$ErrorActionPreference = 'Stop'

# Functions only. Install local bundle files; read MSI identity at runtime.
function Get-ReinstallMsiPackage {
    param([string]$Path, [string]$ProductPattern)

    # Read package identity without installing it or querying Win32_Product.
    $installer = $database = $view = $record = $null
    $properties = @{}
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Path, 0)
        $view = $database.OpenView('SELECT `Property`, `Value` FROM `Property`')
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            try { $properties[$record.StringData(1)] = $record.StringData(2) }
            finally {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
                $record = $null
            }
        }
    }
    finally {
        if ($null -ne $view) { [void]$view.Close() }
        foreach ($item in @($record, $view, $database, $installer)) {
            if ($null -ne $item) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item) }
        }
    }
    $version = $null
    if (-not $properties['ProductCode'] -or
        -not [version]::TryParse([string]$properties['ProductVersion'], [ref]$version)) {
        throw "Cannot read ProductCode and ProductVersion from $Path."
    }
    return [pscustomobject]@{
        Name = [IO.Path]::GetFileName($Path)
        ProductCode = [string]$properties['ProductCode']
        Version = $version
        ProductPattern = $ProductPattern
    }
}

function Get-ReinstallRegistryValue {
    param([string]$SubKey, [string]$Name, [Microsoft.Win32.RegistryView]$View)

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $View)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey($SubKey, $false)
        if ($null -ne $key) { return $key.GetValue($Name, $null) }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $baseKey.Dispose()
    }
}

function Get-ReinstallWebViewVersion {
    $path = 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    # Evergreen per-machine registration uses the 32-bit registry view even on x64.
    $raw = Get-ReinstallRegistryValue -SubKey $path -Name 'pv' -View Registry32
    $version = $null
    if ([version]::TryParse([string]$raw, [ref]$version) -and $version -gt [version]'0.0.0.0') {
        foreach ($root in @($env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
            if (-not $root) { continue }
            $file = Join-Path $root ("Microsoft\EdgeWebView\Application\{0}\msedgewebview2.exe" -f $version)
            if (Test-Path -LiteralPath $file -PathType Leaf) { return $version }
        }
    }
}

function Get-ReinstallInstalledPrograms {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $uninstall = $null
        try {
            $uninstall = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $false)
            if ($null -eq $uninstall) { continue }
            foreach ($name in $uninstall.GetSubKeyNames()) {
                $key = $uninstall.OpenSubKey($name, $false)
                if ($null -eq $key) { continue }
                try {
                    [pscustomobject]@{
                        ProductCode = $name
                        DisplayName = [string]$key.GetValue('DisplayName', '')
                        DisplayVersion = [string]$key.GetValue('DisplayVersion', '')
                        RegistryView = $view
                    }
                }
                finally { $key.Dispose() }
            }
        }
        finally {
            if ($null -ne $uninstall) { $uninstall.Dispose() }
            $baseKey.Dispose()
        }
    }
}

function Test-ReinstallMsiInstalled {
    param([Parameter(Mandatory = $true)]$Package, [switch]$ExactProductCode)

    foreach ($program in Get-ReinstallInstalledPrograms) {
        if ($program.RegistryView -ne [Microsoft.Win32.RegistryView]::Registry64) { continue }
        if ($ExactProductCode) {
            if ($program.ProductCode -ne $Package.ProductCode) { continue }
        }
        elseif ($program.DisplayName -notmatch $Package.ProductPattern) { continue }
        $version = $null
        if ([version]::TryParse($program.DisplayVersion, [ref]$version) -and
            $version -ge [version]$Package.Version) { return $true }
    }
    return $false
}

function ConvertTo-ReinstallQuotedArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -match '["\r\n]' -or $Value.EndsWith('\')) { throw 'Unsafe process argument.' }
    return '"' + $Value + '"'
}

function Invoke-ReinstallInstallerProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 900
    )

    $marker = Join-Path $WorkingDirectory 'software-install-timeout.txt'
    if (Test-Path -LiteralPath $marker) {
        throw 'An earlier installer timed out. Inspect its process and remove software-install-timeout.txt before retrying.'
    }
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden -PassThru -ErrorAction Stop
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # Do not kill Windows Installer mid-transaction. The caller stops and
            # keeps diagnostics; later removal/reboot stages must not run.
            $message = "Installer timed out after $TimeoutSeconds seconds: $FilePath (PID $($process.Id)). Its process may still be running."
            $message | Set-Content -LiteralPath $marker -Encoding UTF8
            throw $message
        }
        $process.Refresh()
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

function Wait-ReinstallWebView {
    param([ValidateRange(0, 600)][int]$TimeoutSeconds = 120)

    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $version = Get-ReinstallWebViewVersion
        if ($null -ne $version) { return }
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
        Start-Sleep -Milliseconds 500
    } while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    throw 'WebView2 did not register a valid per-machine runtime before the timeout.'
}

function Install-ReinstallSoftware {
    param(
        [Parameter(Mandatory = $true)][string]$InstallerDirectory,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    if (-not [Environment]::Is64BitProcess) { throw 'Run software installation from native 64-bit PowerShell.' }
    $InstallerDirectory = Assert-ReinstallLocalPath $InstallerDirectory
    $WorkingDirectory = Assert-ReinstallLocalPath $WorkingDirectory
    New-Item -ItemType Directory -Path $WorkingDirectory -Force -ErrorAction Stop | Out-Null
    if (Test-Path -LiteralPath (Join-Path $WorkingDirectory 'software-install-timeout.txt')) {
        throw 'An earlier installer timed out. Inspect its process and remove software-install-timeout.txt before retrying.'
    }

    # The standalone installer's own file version is not a reliable Runtime
    # version. Keep a healthy registered Runtime; repair missing registrations.
    if ($null -eq (Get-ReinstallWebViewVersion)) {
        Write-Host 'Installing WebView2 from webview2.exe...'
        $path = Join-Path $InstallerDirectory 'webview2.exe'
        $code = Invoke-ReinstallInstallerProcess -FilePath $path -Arguments '/silent /install' -WorkingDirectory $WorkingDirectory
        if ($code -notin @(0, 3010)) { throw "WebView2 installer failed with exit code $code." }
        Wait-ReinstallWebView
        Write-Host 'Verified installation: WebView2.'
    }
    else { Write-Host 'A registered WebView2 runtime is already installed.' }

    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $path = Join-Path $InstallerDirectory 'notepad.msi'
    $package = Get-ReinstallMsiPackage -Path $path -ProductPattern '^Notepad\+\+(?:\s|$)'
    if (Test-ReinstallMsiInstalled -Package $package) {
        Write-Host "$($package.Name): this version or a newer x64 version is already installed."
    }
    else {
        Write-Host "Installing $($package.Name)..."
        $log = Join-Path $WorkingDirectory ($package.Name + '.log')
        $arguments = '/i {0} /qn /norestart ALLUSERS=1 /L*v {1}' -f
            (ConvertTo-ReinstallQuotedArgument $path), (ConvertTo-ReinstallQuotedArgument $log)
        $code = Invoke-ReinstallInstallerProcess -FilePath $msiexec -Arguments $arguments -WorkingDirectory $WorkingDirectory
        if ($code -notin @(0, 3010)) { throw "$($package.Name) failed with exit code $code (log: $log)." }
        if (-not (Test-ReinstallMsiInstalled -Package $package -ExactProductCode)) {
            throw "$($package.Name) returned success but its x64 MSI product registration could not be verified."
        }
        Write-Host "Verified installation: $($package.Name)."
    }

    Write-Host 'Installing 7-Zip from 7z.exe...'
    $path = Join-Path $InstallerDirectory '7z.exe'
    $code = Invoke-ReinstallInstallerProcess -FilePath $path -Arguments '/S' -WorkingDirectory $WorkingDirectory
    if ($code -notin @(0, 3010)) { throw "7-Zip installer failed with exit code $code." }
    if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles '7-Zip\7z.exe') -PathType Leaf)) {
        throw '7-Zip installer returned success but 7z.exe is missing from the default installation directory.'
    }
    Write-Host 'Verified installation: 7-Zip.'
}
