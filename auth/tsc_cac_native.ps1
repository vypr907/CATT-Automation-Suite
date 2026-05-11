<#
.SYNOPSIS
    tsc_cac_native.ps1
    Robust CAC/PIV certificate selector for Windows

.DESCRIPTION
    This script enumerates smart card certificates from the Windows certificate store,
    prompts the user to select one, and exports metadata (subject, issuer, thumbprint, EKUs).
    - Tries PowerShell’s Cert:\ provider first
    - Falls back to .NET X509Store API if provider access is restricted
    - Safe: private keys are never exported

.NOTES
    Author: Steven "vypr" Laszloffy
    Date:   8-18-2025
#>

param(
    [string]$ExportPath = "$env:TEMP\cac_cert_info.json"
)

# ========================
# Helper function: Get EKU
# ========================
function Get-EKUString {
    param([System.Security.Cryptography.OidCollection]$ekuCollection)
    if (-not $ekuCollection) { return @() }
    $ekuList = @()
    foreach ($eku in $ekuCollection) {
        $ekuList += if ($eku.FriendlyName) { $eku.FriendlyName } else { $eku.Value }
    }
    return $ekuList
}

# =======================================
# Try Method 1: PowerShell Certificate PSDrive
# =======================================
try {
    Write-Host "[*] Attempting to enumerate certificates via Cert:\ provider..."
    $certs = Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction Stop
    $certs += Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "[-] Cert:\ provider unavailable or restricted. Falling back to .NET API..."
    $certs = @()
}

# =======================================
# If no certs found, try Method 2: .NET API
# =======================================
if (-not $certs -or $certs.Count -eq 0) {
    $stores = @(
        @{Location="CurrentUser"; Name="My"},
        @{Location="LocalMachine"; Name="My"}
    )

    foreach ($storeInfo in $stores) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $storeInfo.Name,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::$($storeInfo.Location)
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $certs += $store.Certificates
            $store.Close()
        }
        catch {
            Write-Warning "Could not open $($storeInfo.Location)\$($storeInfo.Name)"
        }
    }
}

# ===============================
# Filter for Smart Card Certificates
# ===============================
if (-not $certs -or $certs.Count -eq 0) {
    throw "No certificates found in any accessible store."
}

# =====================================
# Filter for CAC/PIV certificates with Client Authentication EKU
# =====================================
$filteredCerts = $certs | Where-Object {
    # Must have private key + Client Authentication EKU
    $_.HasPrivateKey -and
    ($_.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Client Authentication" })
}

if (-not $filteredCerts -or $filteredCerts.Count -eq 0) {
    throw "No suitable CAC/PIV certificates with Client Authentication EKU found."
}

# ===================================
# Prompt user for selection
# ===================================
Write-Host "`nAvailable CAC/PIV Certificates:`n" -ForegroundColor Cyan
$i = 1
$certMap = @{}

foreach ($cert in $filteredCerts) {
    $ekuList = (Get-EKUString $cert.EnhancedKeyUsageList) -join ", "
    Write-Host "[$i] Subject: $($cert.Subject)"
    Write-Host "    Issuer : $($cert.Issuer)"
    Write-Host "    Thumb  : $($cert.Thumbprint)"
    Write-Host "    EKUs   : $ekuList`n"
    $certMap[$i] = $cert
    $i++
}

do {
    $choice = Read-Host "Enter the number of the certificate you want to use"
} until ($certMap.ContainsKey([int]$choice))

$selectedCert = $certMap[[int]$choice]

# ================================
# Export Metadata (no private key!)
# ================================
$exportData = @{
    Subject    = $selectedCert.Subject
    Issuer     = $selectedCert.Issuer
    Thumbprint = $selectedCert.Thumbprint
    NotBefore  = $selectedCert.NotBefore
    NotAfter   = $selectedCert.NotAfter
    EKUs       = ($selectedCert.EnhancedKeyUsageList | ForEach-Object {
        if ($_.FriendlyName){$_.FriendlyName} else { $_.Value}
    }) -join "; "
}

# Write to file
$exportData | ConvertTo-Json -Compress | Set-Content -Path $ExportPath -Encoding UTF8

Write-Host "`n[+] Certificate metadata exported to $outFile" -ForegroundColor Green
Write-Host "[+] Ready to use certificate (private key remains safely in the Windows store)" -ForegroundColor Green