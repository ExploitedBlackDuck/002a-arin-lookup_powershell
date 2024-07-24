# PowerShell Script Documentation: ARIN Lookup Script

## Purpose
This script performs an ARIN WHOIS lookup for a given IP address, retrieves relevant information about the IP address, and logs the details. It also checks if the IP address is an RFC1918 private address and handles logging and error reporting.

## Prerequisites
- PowerShell installed on the system.
- Internet connectivity to perform ARIN WHOIS lookups.

## Script Components

### Parameters
- `$ip`: The IP address to be processed.

### Logging Function
`Log-Message` function is defined to log messages with timestamps. It accepts two parameters:
- `message`: The message to log.
- `type`: The type of log message (default is "INFO").
```powershell
function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$type] $message"
    Write-Output $logMessage
}
```

### RFC1918 Address Check Function
`Is-RFC1918` function is defined to check if the provided IP address is an RFC1918 private address. It splits the IP address into octets and checks against the RFC1918 ranges:
- 10.0.0.0 - 10.255.255.255
- 172.16.0.0 - 172.31.255.255
- 192.168.0.0 - 192.168.255.255
```powershell
function Is-RFC1918 {
    param (
        [string]$ip
    )
    $octets = $ip -split '\.'
    if ($octets[0] -eq 10) { return $true }
    if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { return $true }
    if ($octets[0] -eq 192 -and $octets[1] -eq 168) { return $true }
    return $false
}
```

### ARIN WHOIS Lookup Function
`Get-ArinInfo` function is defined to perform an ARIN WHOIS lookup for the given IP address. It extracts relevant information such as the company name and performs a reverse DNS lookup to get the FQDN:
```powershell
function Get-ArinInfo {
    param (
        [string]$ip
    )
    try {
        # Perform ARIN WHOIS lookup
        $whoisResult = Invoke-RestMethod -Uri "https://whois.arin.net/rest/ip/$ip" -Method Get -Headers @{"Accept"="application/json"} -ErrorAction Stop

        # Log the raw ARIN response to help with debugging
        Log-Message ("Raw ARIN response for IP {0}: {1}" -f $ip, ($whoisResult | ConvertTo-Json -Depth 10)) "DEBUG"

        # Extract relevant information
        $company = $null

        if ($whoisResult.net -and $whoisResult.net.orgRef -and $whoisResult.net.orgRef.'@name') {
            $company = $whoisResult.net.orgRef.'@name'
        }

        # Perform reverse DNS lookup to get FQDN
        try {
            $fqdn = ([System.Net.Dns]::GetHostEntry($ip)).HostName
        } catch {
            $fqdn = "Not Available"
        }

        # Log details of the ARIN lookup result
        Log-Message ("ARIN lookup result for IP {0}: FQDN: {1}, Company: {2}" -f $ip, $fqdn, $company)
        return [PSCustomObject]@{
            FQDN    = $fqdn
            Company = if ($company) { $company } else { "Not Available" }
        }
    } catch {
        Log-Message ("Failed to retrieve ARIN info for IP {0}: {1}" -f $ip, $_) "ERROR"
        return [PSCustomObject]@{
            FQDN    = "Not Available"
            Company = "Not Available"
        }
    }
}
```

### RFC1918 Address Verification
The script first verifies if the provided IP address is an RFC1918 private address. If it is, the script outputs a message and exits:
```powershell
if (Is-RFC1918 -ip $ip) {
    Write-Output "The IP address $ip is an RFC1918 address and not publicly routable."
    exit
}
```

### ARIN Lookup and Output
The script performs the ARIN lookup using the `Get-ArinInfo` function and outputs the results:
```powershell
$result = Get-ArinInfo -ip $ip
Write-Output ("FQDN: {0}, Company: {1}" -f $result.FQDN, $result.Company)
```

## Usage Instructions
1. Ensure you have PowerShell installed.
2. Save the script to a `.ps1` file, for example, `arin_lookup_script.ps1`.
3. Run the script in PowerShell with the IP address as a parameter:
   ```powershell
   .\arin_lookup_script.ps1 -ip "8.8.8.8"
   ```
4. The script will output the FQDN and company name associated with the provided IP address.

## Example
**Command**
```powershell
.\arin_lookup_script.ps1 -ip "8.8.8.8"
```

**Output**
```
FQDN: dns.google, Company: Google LLC
```

---

This document outlines the purpose, functionality, and usage of the PowerShell script for performing ARIN WHOIS lookups and logging the details.
