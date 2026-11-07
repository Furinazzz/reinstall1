$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$path = Join-Path (Split-Path $PSScriptRoot -Parent) 'windows-cloudflare-japan.bat'
$raw = [IO.File]::ReadAllText($path)
$marker = '#==PS_PAYLOAD_START=='
$payload = $raw.Substring($raw.LastIndexOf($marker) + $marker.Length)
$tokens = $null
$parseErrors = $null
[void][Management.Automation.Language.Parser]::ParseInput($payload, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
$definitions = $payload -replace '(?m)^exit \(Invoke-ReinstallConfiguration\)\s*$', ''
if ($definitions -eq $payload) { throw 'Could not safely remove entry point.' }
. ([scriptblock]::Create($definitions))

# Every mutating OS command used by the payload is replaced by an in-memory mock.
# The BAT entry point is never invoked, and tzutil is never executed.
function Get-NetAdapter {
    [CmdletBinding()]param()
    $script:AdapterReads++
    if ($script:AdapterReads -le $script:MissingReads) { return }
    return $script:Adapters
}
function Get-NetAdapterBinding {
    [CmdletBinding()]param($Name, $ComponentID)
    return $script:Bindings
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]param($InterfaceIndex, $AddressFamily)
    $key = "$InterfaceIndex/$AddressFamily"
    $servers = @($script:Dns[$key])
    if ($script:WrongReadback -and $AddressFamily -eq 'IPv6') { $servers = @('::1') }
    return [pscustomobject]@{ InterfaceIndex = $InterfaceIndex; Family = $AddressFamily; ServerAddresses = $servers }
}
function Set-DnsClientServerAddress {
    [CmdletBinding()]param($InputObject, [string[]] $ServerAddresses)
    $key = "$($InputObject.InterfaceIndex)/$($InputObject.Family)"
    $script:Writes.Add($key)
    if ($InputObject.Family -eq 'IPv6' -and $script:TransientFailures -gt 0) {
        $script:TransientFailures--
        throw 'Simulated transient IPv6 failure.'
    }
    $script:Dns[$key] = @($ServerAddresses)
}
function Start-Sleep { param($Milliseconds) }
function Test-ReinstallAdministrator { return $script:IsAdministrator }
function Test-ReinstallSystem { return $script:IsSystem }
function Set-ReinstallJapanTimeZone {
    $script:TimeZoneCalls++
    if ($script:FailTimeZone) { throw 'Simulated timezone failure.' }
}
function Set-WinHomeLocation {
    [CmdletBinding()]param($GeoId)
    $script:GeoCalls++
    $script:GeoId = $GeoId
}
function Get-WinHomeLocation {
    [CmdletBinding()]param()
    return [pscustomobject]@{ GeoId = $script:GeoId }
}
function New-Item { [CmdletBinding()]param($ItemType, [switch]$Force, $Path) }
function Start-Transcript { [CmdletBinding()]param($Path, [switch]$Append) }
function Stop-Transcript { [CmdletBinding()]param() }

function Assert($Condition, $Message) { if (-not $Condition) { throw "ASSERT: $Message" } }
function Assert-Fails([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action } catch { $failed = $true }
    Assert $failed $Message
}
function Reset-Mocks {
    $script:Adapters = @(
        [pscustomobject]@{ Name = 'Ethernet [VM]'; ifIndex = 3; AdminStatus = 'Up'; InterfaceType = 6; Status = 'Up' },
        [pscustomobject]@{ Name = 'Disconnected'; ifIndex = 4; AdminStatus = 'Up'; InterfaceType = 6; Status = 'Disconnected' },
        [pscustomobject]@{ Name = 'Disabled'; ifIndex = 5; AdminStatus = 'Down'; InterfaceType = 6; Status = 'Disabled' },
        [pscustomobject]@{ Name = 'Loopback'; ifIndex = 6; AdminStatus = 'Up'; InterfaceType = 24; Status = 'Up' },
        [pscustomobject]@{ Name = 'Tunnel'; ifIndex = 7; AdminStatus = 'Up'; InterfaceType = 131; Status = 'Up' }
    )
    $script:Bindings = @(
        foreach ($name in @('Ethernet [VM]', 'Disconnected')) {
            [pscustomobject]@{ Name = $name; ComponentID = 'ms_tcpip'; Enabled = $true }
            [pscustomobject]@{ Name = $name; ComponentID = 'ms_tcpip6'; Enabled = $true }
        }
    )
    $script:Dns = @{
        '3/IPv4' = @('192.0.2.53'); '3/IPv6' = @('2001:db8::53')
        '4/IPv4' = @(); '4/IPv6' = @()
    }
    $script:Writes = New-Object 'System.Collections.Generic.List[string]'
    $script:AdapterReads = 0
    $script:MissingReads = 0
    $script:TransientFailures = 0
    $script:WrongReadback = $false
    $script:IsAdministrator = $true
    $script:IsSystem = $false
    $script:TimeZoneCalls = 0
    $script:FailTimeZone = $false
    $script:GeoCalls = 0
    $script:GeoId = 0
}

Reset-Mocks
Invoke-CloudflareDns -TimeoutSeconds 0
Assert ($script:Writes.Count -eq 4) 'Both families on both enabled adapters must be configured.'
Assert (($script:Dns['3/IPv4'] -join ',') -eq '1.1.1.1,1.0.0.1') 'IPv4 ordering must be exact.'
Assert (($script:Dns['4/IPv6'] -join ',') -eq '2606:4700:4700::1111,2606:4700:4700::1001') 'Disconnected adapter IPv6 ordering must be exact.'
Invoke-CloudflareDns -TimeoutSeconds 0
Assert ($script:Writes.Count -eq 4) 'Already-correct DNS must not be rewritten.'

Reset-Mocks
$script:Bindings[1].Enabled = $false
Assert-Fails { Invoke-CloudflareDns -TimeoutSeconds 0 } 'Disabled IPv6 must report failure.'
Assert ($script:Writes.Contains('3/IPv4')) 'IPv4 must still be configured when IPv6 is disabled.'
Assert (-not $script:Writes.Contains('3/IPv6')) 'Disabled IPv6 must not be changed.'

Reset-Mocks
$script:Adapters = @()
Assert-Fails { Invoke-CloudflareDns -TimeoutSeconds 0 } 'No adapters must report failure.'
Reset-Mocks
$script:MissingReads = 1
Invoke-CloudflareDns -TimeoutSeconds 1 -RetryDelaySeconds 0
Assert ($script:AdapterReads -eq 2) 'Adapters must be rediscovered after initialization delay.'

Reset-Mocks
$script:TransientFailures = 1
Invoke-CloudflareDns -TimeoutSeconds 1 -RetryDelaySeconds 0
Assert ($script:AdapterReads -eq 2) 'A transient DNS failure must be retried.'
Assert (@($script:Writes | Where-Object { $_ -eq '3/IPv4' }).Count -eq 1) 'A successful family must not be rewritten on retry.'

Reset-Mocks
$script:WrongReadback = $true
Assert-Fails { Invoke-CloudflareDns -TimeoutSeconds 0 } 'Incorrect DNS readback must report failure.'

Reset-Mocks
$script:IsSystem = $true
Set-ReinstallJapanHomeLocation
Assert ($script:GeoCalls -eq 0) 'SYSTEM must not set its own home location.'
$script:IsSystem = $false
Set-ReinstallJapanHomeLocation
Assert ($script:GeoCalls -eq 1 -and $script:GeoId -eq 122) 'An administrator must get Japan GeoId 122.'

Reset-Mocks
$result = Invoke-ReinstallConfiguration
Assert ($result -eq 0) 'Successful configuration must return exit code zero.'
Assert ($script:TimeZoneCalls -eq 1 -and $script:GeoCalls -eq 1 -and $script:Writes.Count -eq 4) 'Main entry must apply all three settings.'

Reset-Mocks
$script:IsAdministrator = $false
$result = Invoke-ReinstallConfiguration
Assert ($result -eq 1 -and $script:TimeZoneCalls -eq 0 -and $script:GeoCalls -eq 0 -and $script:Writes.Count -eq 0) 'Non-admin execution must fail without changing settings.'

Reset-Mocks
$script:FailTimeZone = $true
$result = Invoke-ReinstallConfiguration
Assert ($result -eq 1) 'A timezone failure must propagate a failing exit code.'
Assert ($script:GeoCalls -eq 1 -and $script:Writes.Count -eq 4) 'Other independent settings must still run after a timezone failure.'

Write-Host 'PASS: Windows PowerShell 5.1 parsing and isolated DNS/role/retry/readback/exit-code tests. No host settings changed.'
