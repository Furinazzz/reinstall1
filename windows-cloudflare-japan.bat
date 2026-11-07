@echo off
setlocal DisableDelayedExpansion
rem Manual use: right-click this file and choose Run as administrator.
rem --auto suppresses the final pause for SetupComplete and FirstLogonCommands.
set "REINSTALL_AUTO="
if /i "%~1"=="--auto" set "REINSTALL_AUTO=1"
set "REINSTALL_SELF=%~f0"
set "REINSTALL_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "REINSTALL_POWERSHELL=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%REINSTALL_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$raw=[IO.File]::ReadAllText($env:REINSTALL_SELF); $marker='#==PS_PAYLOAD_START=='; $start=$raw.LastIndexOf($marker); if ($start -lt 0) { exit 1 }; & ([scriptblock]::Create($raw.Substring($start+$marker.Length)))"
set "REINSTALL_RESULT=%errorlevel%"
if not "%REINSTALL_RESULT%"=="0" echo Configuration failed. See the error and log path above.
if not defined REINSTALL_AUTO pause
exit /b %REINSTALL_RESULT%
#==PS_PAYLOAD_START==
# Windows PowerShell 5.1 payload. This file is intentionally ASCII / CRLF.
# DNS overrides DHCP-provided DNS only. IP addresses, routes, DHCP, and adapter
# bindings are left intact. No adapters are disabled, restarted, or enabled.

function Test-ReinstallAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ReinstallSystem {
    return [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

function ConvertTo-CanonicalDnsList {
    param([string[]] $Addresses)
    return @($Addresses | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() })
}

function Invoke-CloudflareDns {
    param(
        [ValidateRange(0, 300)][int] $TimeoutSeconds = 75,
        [ValidateRange(0, 30)][int] $RetryDelaySeconds = 5
    )

    $families = @(
        @{ Name = 'IPv4'; Binding = 'ms_tcpip'; Servers = @('1.1.1.1', '1.0.0.1') },
        @{ Name = 'IPv6'; Binding = 'ms_tcpip6'; Servers = @('2606:4700:4700::1111', '2606:4700:4700::1001') }
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $originalDns = @{}
    $attempt = 0

    do {
        $attempt++
        $failures = New-Object 'System.Collections.Generic.List[string]'
        try {
            # Include VM/synthetic and disconnected enabled adapters. Get-NetAdapter
            # omits hidden adapters by default; IANA types 24/131 are loopback/tunnel.
            $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object {
                $_.AdminStatus -eq 'Up' -and $_.InterfaceType -notin @(24, 131)
            })
            if ($adapters.Count -eq 0) {
                throw 'No enabled, non-loopback, non-tunnel network adapters are available yet.'
            }
            # Enumerate once, then compare exact names: adapter aliases can contain
            # wildcard characters, so do not pass an alias as a wildcard selector.
            $bindings = @(Get-NetAdapterBinding -Name '*' -ComponentID ms_tcpip, ms_tcpip6 -ErrorAction Stop)
            foreach ($adapter in $adapters) {
                foreach ($family in $families) {
                    try {
                        $binding = @($bindings | Where-Object {
                            $_.Name -eq $adapter.Name -and $_.ComponentID -eq $family.Binding
                        })
                        if ($binding.Count -ne 1 -or -not $binding[0].Enabled) {
                            throw "$($family.Name) is unavailable or its binding is disabled; it will not be enabled by this script."
                        }
                        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family.Name -ErrorAction Stop)
                        if ($dns.Count -ne 1) {
                            throw "Expected one $($family.Name) DNS configuration, found $($dns.Count)."
                        }

                        $key = "$($adapter.ifIndex)/$($family.Name)"
                        if (-not $originalDns.ContainsKey($key)) {
                            $previous = @($dns[0].ServerAddresses) -join ', '
                            if ([string]::IsNullOrEmpty($previous)) { $previous = '(none)' }
                            Write-Host "Previous DNS: '$($adapter.Name)' (index $($adapter.ifIndex)) $($family.Name): $previous"
                            $originalDns[$key] = $true
                        }

                        $expected = @(ConvertTo-CanonicalDnsList $family.Servers)
                        $actual = @(ConvertTo-CanonicalDnsList $dns[0].ServerAddresses)
                        if (($actual -join ',') -ne ($expected -join ',')) {
                            # InputObject confines this write to this interface AND
                            # address family; the other family is not overwritten.
                            Set-DnsClientServerAddress -InputObject $dns[0] -ServerAddresses $family.Servers -ErrorAction Stop
                        }
                        $verified = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family.Name -ErrorAction Stop)
                        if ($verified.Count -ne 1) { throw 'DNS readback did not return exactly one configuration.' }
                        $actual = @(ConvertTo-CanonicalDnsList $verified[0].ServerAddresses)
                        if (($actual -join ',') -ne ($expected -join ',')) {
                            throw "DNS verification failed: expected $($expected -join ', '); received $($actual -join ', ')."
                        }
                        Write-Host "Verified: '$($adapter.Name)' $($family.Name): $($actual -join ', ')"
                    }
                    catch {
                        $failures.Add("'$($adapter.Name)' $($family.Name): $($_.Exception.Message)")
                    }
                }
            }
        }
        catch {
            $failures.Add($_.Exception.Message)
        }

        if ($failures.Count -eq 0) {
            Write-Host "Cloudflare DNS configured and verified on $($adapters.Count) adapter(s)."
            return
        }
        foreach ($failure in $failures) { Write-Host "Attempt $attempt : $failure" }
        $remaining = ($deadline - [DateTime]::UtcNow).TotalSeconds
        if ($remaining -le 0) { break }
        Write-Host 'Waiting for network initialization before retrying...'
        Start-Sleep -Milliseconds ([int]([Math]::Min($RetryDelaySeconds, $remaining) * 1000))
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "DNS configuration remains incomplete after $attempt attempt(s): $($failures -join '; ')"
}

function Set-ReinstallJapanTimeZone {
    $tzutil = Join-Path $env:SystemRoot 'System32\tzutil.exe'
    & $tzutil /s 'Tokyo Standard Time'
    if ($LASTEXITCODE -ne 0) { throw "tzutil /s failed with exit code $LASTEXITCODE." }
    $actual = (& $tzutil /g | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne 'Tokyo Standard Time') {
        throw "Time zone verification failed: '$actual'."
    }
    Write-Host 'Verified time zone: Tokyo Standard Time (Japan, UTC+09:00).'
}

function Set-ReinstallJapanHomeLocation {
    if (Test-ReinstallSystem) {
        Write-Host 'Japan home location is a per-user setting; deferred to FirstLogonCommands for the signed-in administrator.'
        return
    }
    Set-WinHomeLocation -GeoId 122 -ErrorAction Stop
    if ((Get-WinHomeLocation -ErrorAction Stop).GeoId -ne 122) {
        throw 'Japan home location verification failed.'
    }
    Write-Host 'Verified current-user home location: Japan (GeoId 122).'
}

function Invoke-ReinstallConfiguration {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $transcriptStarted = $false
    $exitCode = 1
    try {
        if (-not (Test-ReinstallAdministrator)) {
            throw 'Administrator privileges are required. Right-click this BAT file and choose Run as administrator.'
        }
        $logRoot = Join-Path $env:ProgramData 'Reinstall'
        try {
            New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
            $logPath = Join-Path $logRoot 'cloudflare-japan.log'
            Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
        }
        catch {
            $logPath = Join-Path $env:TEMP 'reinstall-cloudflare-japan.log'
            Write-Host "ProgramData logging is unavailable; using $logPath"
            Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
        }
        $transcriptStarted = $true
        Write-Host "Log: $logPath"
        Write-Host "Starting Cloudflare DNS / Japan configuration at $(Get-Date -Format o)"
        Write-Host 'DNS server addresses are static; IP address assignment and DHCP remain unchanged.'
        Write-Host 'Previous DNS addresses below may have been supplied by DHCP; they are logged for recovery.'

        $failures = New-Object 'System.Collections.Generic.List[string]'
        # Apply independent settings even if another step fails.
        try { Set-ReinstallJapanTimeZone } catch { $failures.Add("Time zone: $($_.Exception.Message)") }
        try { Set-ReinstallJapanHomeLocation } catch { $failures.Add("Home location: $($_.Exception.Message)") }
        try { Invoke-CloudflareDns } catch { $failures.Add($_.Exception.Message) }
        if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }

        Write-Host 'SUCCESS: All settings for this execution context were verified.' -ForegroundColor Green
        $exitCode = 0
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'After installation, run this BAT as administrator to retry and review the log.'
    }
    finally {
        if ($transcriptStarted) {
            try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { Write-Host "Could not stop transcript: $($_.Exception.Message)" }
        }
    }
    return $exitCode
}

exit (Invoke-ReinstallConfiguration)
