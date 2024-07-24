param (
    [string]$ip
)

function Log-Message {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$type] $message"
    Write-Output $logMessage
}

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

# Verify that the IP address is not a RFC1918 address
if (Is-RFC1918 -ip $ip) {
    Write-Output "The IP address $ip is an RFC1918 address and not publicly routable."
    exit
}

# Perform the ARIN lookup and print the results
$result = Get-ArinInfo -ip $ip
Write-Output ("FQDN: {0}, Company: {1}" -f $result.FQDN, $result.Company)
