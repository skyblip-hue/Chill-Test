<#
.SYNOPSIS
    Subnet Host Discovery Scanner
.DESCRIPTION
    A production-quality, multithreaded host discovery scanner for Windows PowerShell 5.1.
    Utilizes a bounded Runspace Pool job queue to limit memory footprint when scanning subnets.
    Performs ICMP Ping followed by TCP connection checks on standard discovery ports (21, 22, 23, 25, 80, 135, 139, 443, 445).
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Scan')]
    [string]$Subnet,

    [Parameter(ParameterSetName = 'Scan')]
    [int]$Threads = 100,

    [Parameter(ParameterSetName = 'Scan')]
    [int]$Timeout = 500,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$ShowTime,

    [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
    [switch]$Help
)

# -----------------------------------------------------------------------------
# Function: Show-Help
# -----------------------------------------------------------------------------
function Show-Help {
    Write-Host "HostDiscovery.ps1"
    Write-Host ""
    Write-Host "Subnet Host Discovery Scanner"
    Write-Host ""
    Write-Host "Usage"
    Write-Host ""
    Write-Host "HostDiscovery.ps1 -Subnet <Subnet|Range|IP>"
    Write-Host ""
    Write-Host "Options"
    Write-Host ""
    Write-Host "-Subnet"
    Write-Host "Target subnet (CIDR format e.g., 192.168.1.0/24, range 192.168.1.1-254)."
    Write-Host "Required."
    Write-Host ""
    Write-Host "-Threads"
    Write-Host "Number of concurrent threads."
    Write-Host "Default: 100"
    Write-Host ""
    Write-Host "-Timeout"
    Write-Host "ICMP/TCP probe timeout (milliseconds)."
    Write-Host "Default: 500"
    Write-Host ""
    Write-Host "-ShowTime"
    Write-Host "Display elapsed scan time."
    Write-Host ""
    Write-Host "-Help"
    Write-Host "Display this help."
    Write-Host ""
    Write-Host "Examples"
    Write-Host ""
    Write-Host "HostDiscovery.ps1 -Subnet 192.168.1.0/24"
    Write-Host "HostDiscovery.ps1 -Subnet 10.0.0.1-254 -Threads 150 -Timeout 300 -ShowTime"
    Write-Host "HostDiscovery.ps1 -Subnet 172.16.0.1-172.16.0.100 -ShowTime"
}

# -----------------------------------------------------------------------------
# Function: Get-ParsedIPs
# -----------------------------------------------------------------------------
function Get-ParsedIPs {
    param ([string]$SubnetString)

    $ipList = New-Object System.Collections.Generic.List[string]

    # CIDR Notation (e.g., 192.168.1.0/24)
    if ($SubnetString -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$') {
        $baseIpStr = $matches[1]
        $prefix = [int]$matches[2]

        if ($prefix -lt 1 -or $prefix -gt 30) {
            Write-Host "Error: CIDR prefix must be between /1 and /30."
            exit 1
        }

        try {
            $baseIp = [System.Net.IPAddress]::Parse($baseIpStr)
        } catch {
            Write-Host "Error: Invalid base IP address '$baseIpStr'."
            exit 1
        }

        $bytes = $baseIp.GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $uintIp = [BitConverter]::ToUInt32($bytes, 0)

        # Calculate network mask and boundary addresses using int64 math
        $hostBits = 32 - $prefix
        $mask = [uint32]([int64][Math]::Pow(2, 32) - [int64][Math]::Pow(2, $hostBits))
        $network = [uint32]($uintIp -band $mask)
        $wildcard = [uint32]([int64][Math]::Pow(2, $hostBits) - 1)
        $broadcast = [uint32]($network -bor $wildcard)

        for ($i = [int64]$network + 1; $i -lt [int64]$broadcast; $i++) {
            $b = [BitConverter]::GetBytes([uint32]$i)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
            $ipList.Add(([System.Net.IPAddress]::new($b)).IPAddressToString)
        }
    }
    # Short Range Notation (e.g., 192.168.1.1-254)
    elseif ($SubnetString -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$') {
        $prefixStr = $matches[1]
        $start = [int]$matches[2]
        $end = [int]$matches[3]

        if ($start -lt 1 -or $end -gt 254 -or $start -gt $end) {
            Write-Host "Error: Invalid octet range '$SubnetString'."
            exit 1
        }

        for ($i = $start; $i -le $end; $i++) {
            $ipList.Add("${prefixStr}${i}")
        }
    }
    # Full IP Range Notation (e.g., 192.168.1.1-192.168.1.100)
    elseif ($SubnetString -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        try {
            $startIp = [System.Net.IPAddress]::Parse($matches[1])
            $endIp = [System.Net.IPAddress]::Parse($matches[2])
        } catch {
            Write-Host "Error: Invalid IP range."
            exit 1
        }

        $bStart = $startIp.GetAddressBytes()
        $bEnd = $endIp.GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bStart); [Array]::Reverse($bEnd) }

        $uStart = [BitConverter]::ToUInt32($bStart, 0)
        $uEnd = [BitConverter]::ToUInt32($bEnd, 0)

        if ($uStart -gt $uEnd) {
            Write-Host "Error: Start IP must be less than or equal to End IP."
            exit 1
        }

        for ($i = [int64]$uStart; $i -le [int64]$uEnd; $i++) {
            $b = [BitConverter]::GetBytes([uint32]$i)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
            $ipList.Add(([System.Net.IPAddress]::new($b)).IPAddressToString)
        }
    }
    # Single IP
    elseif ($SubnetString -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $ipList.Add($SubnetString)
    }
    else {
        Write-Host "Error: Malformed subnet or IP expression '$SubnetString'."
        exit 1
    }

    return $ipList
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if ($Help) {
    Show-Help
    exit 0
}

if ($Threads -le 0) {
    Write-Host "Error: -Threads must be greater than zero."
    exit 1
}

if ($Timeout -le 0) {
    Write-Host "Error: -Timeout must be greater than zero."
    exit 1
}

# Parse and validate targets
$targetIPs = Get-ParsedIPs -SubnetString $Subnet
if ($targetIPs.Count -eq 0) {
    Write-Host "Error: No valid IP addresses to scan."
    exit 1
}

# -----------------------------------------------------------------------------
# Worker ScriptBlock (Executed in Runspaces)
# -----------------------------------------------------------------------------
$workerScript = {
    param(
        [string]$IP,
        [int]$Timeout
    )

    $result = [PSCustomObject]@{
        IP      = $IP
        IsAlive = $false
        Method  = $null
    }

    # Standard TCP fallback discovery ports
    $discoveryPorts = @(21, 22, 23, 25, 80, 135, 139, 443, 445)

    # Step 1: Test ICMP Ping
    $ping = $null
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IP, $Timeout)
        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $result.IsAlive = $true
            $result.Method  = "ICMP Ping"
            return $result
        }
    } catch {
        # Ignore ping exceptions and attempt TCP connect
    } finally {
        if ($null -ne $ping) {
            try { $ping.Dispose() } catch {}
        }
    }

    # Step 2: Fallback TCP Connect Probe
    foreach ($port in $discoveryPorts) {
        $tcpClient = $null
        $asyncResult = $null
        $waitHandle = $null

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($IP, $port, $null, $null)
            $waitHandle = $asyncResult.AsyncWaitHandle

            $success = $waitHandle.WaitOne($Timeout, $false)

            if ($success -and $tcpClient.Connected) {
                $result.IsAlive = $true
                $result.Method  = "TCP Port $port"
                break
            }
        } catch {
            # Ignore connection errors and try next port
        } finally {
            if ($null -ne $waitHandle) { try { $waitHandle.Dispose() } catch {} }
            if ($null -ne $tcpClient) {
                try { $tcpClient.Close() } catch {}
                try { $tcpClient.Dispose() } catch {}
            }
        }
    }

    return $result
}

# -----------------------------------------------------------------------------
# Runspace Pool Execution Engine (Bounded Queue)
# -----------------------------------------------------------------------------
$startTime = Get-Date

Write-Host "Target Subnet : $Subnet"
Write-Host "Total Targets : $($targetIPs.Count)"
Write-Host ""
Write-Host "Scanning..."
Write-Host ""

$initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $initialSessionState, $Host)
$pool.Open()

# Queue all IP targets
$ipQueue = New-Object System.Collections.Generic.Queue[string]
foreach ($ip in $targetIPs) {
    $ipQueue.Enqueue($ip)
}

$activeJobs = New-Object System.Collections.Generic.List[psobject]
$results = New-Object System.Collections.Generic.List[psobject]

# Producer-Consumer Execution Loop
while ($ipQueue.Count -gt 0 -or $activeJobs.Count -gt 0) {

    # Producer: Fill queue up to -Threads concurrency limit
    while ($activeJobs.Count -lt $Threads -and $ipQueue.Count -gt 0) {
        $ipToScan = $ipQueue.Dequeue()
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        [void]$ps.AddScript($workerScript)
        [void]$ps.AddArgument($ipToScan)
        [void]$ps.AddArgument($Timeout)

        $jobObj = [PSCustomObject]@{
            PowerShell = $ps
            Handle     = $ps.BeginInvoke()
        }
        $activeJobs.Add($jobObj)
    }

    # Consumer: Retrieve completed worker threads
    $jobsToRemove = New-Object System.Collections.Generic.List[psobject]
    foreach ($job in $activeJobs) {
        if ($job.Handle.IsCompleted) {
            try {
                $res = $job.PowerShell.EndInvoke($job.Handle)
                if ($res) {
                    foreach ($r in $res) {
                        $results.Add($r)
                    }
                }
            } catch {
                # Ignore thread execution exceptions
            } finally {
                if ($null -ne $job.PowerShell) {
                    $job.PowerShell.Dispose()
                }
            }
            $jobsToRemove.Add($job)
        }
    }

    # Clean active job list
    foreach ($job in $jobsToRemove) {
        [void]$activeJobs.Remove($job)
    }

    # Yield briefly to CPU while waiting for results
    if ($activeJobs.Count -ge $Threads -or ($ipQueue.Count -eq 0 -and $activeJobs.Count -gt 0)) {
        Start-Sleep -Milliseconds 10
    }
}

$pool.Close()
$pool.Dispose()

# -----------------------------------------------------------------------------
# Output Formatting
# -----------------------------------------------------------------------------
$aliveCount = 0
$sortedResults = $results | Where-Object { $_.IsAlive } | Sort-Object { [version]$_.IP }

foreach ($res in $sortedResults) {
    $aliveCount++
    $ipStr = $res.IP.PadRight(16)
    Write-Host "${ipStr} ALIVE    ($($res.Method))"
}

Write-Host ""
Write-Host "Completed."
Write-Host ""
Write-Host "Alive hosts : $aliveCount"

if ($ShowTime) {
    $endTime = Get-Date
    $elapsed = ($endTime - $startTime).TotalSeconds
    $formattedTime = "{0:N2}" -f $elapsed
    Write-Host ""
    Write-Host "Elapsed time : $formattedTime seconds"
}

exit 0
