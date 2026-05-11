<#
.SYNOPSIS
    cac_picker.ps1 - NOAA CATT Suite Certificate Selector
.DESCRIPTION
    1. Scans Windows Certificate Stores (CurrentUser and LocalMachine).
    2. Filters for valid CAC/PIV cards with "Client Authentication" capabilities.
    3. Provides a fallback to show all personal certs if no smart card is found.
    4. Exports the selection Thumbprint to a temp file for Python to use.
#>

param(
    # This path is where the Python script expects to find the selection data
    [string]$ExportPath = "$env:TEMP\cac_cert_info.json"
)

# --- STEP 1: DEFINE STORES ---
# We check both the current logged-in user and the local machine
$stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
$allCerts = @()

# --- STEP 2: ENUMERATE CERTIFICATES ---
# Attempt to find certificates using the standard PowerShell provider
foreach ($storePath in $stores) {
    try {
        $allCerts += Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
    } catch {
        # IT restrictions may block direct provider access; the .NET fallback in Python handles this
    }
}

# --- STEP 3: FILTER FOR CAC/PIV CARDS ---
# We look for certs that have a private key and "Client Authentication" EKUs
$filteredCerts = $allCerts | Where-Object {
    $_.HasPrivateKey -and (
        ($_.EnhancedKeyUsageList.FriendlyName -match 'Client|Smart|PIV|Authentication') -or 
        ($_.Subject -match 'PIV|Authentication')
    )
}

# --- STEP 4: FALLBACK SAFETY NET ---
# If no specific CAC is found, we show all personal certificates so the user isn't stuck
if (-not $filteredCerts) {
    Write-Host "---" -ForegroundColor Gray
    Write-Host "No explicit CAC/PIV found. Displaying all available personal certificates..." -ForegroundColor Yellow
    $displayCerts = $allCerts
} else {
    $displayCerts = $filteredCerts
}

# --- STEP 5: USER SELECTION UI ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   NOAA CATT CERTIFICATE SELECTION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "Select the certificate associated with your CAC/PIV card:`n"

$i = 1
$certMap = @{}
foreach ($cert in $displayCerts) {
    # Determine the store for the display
    $storeLoc = if ($cert.PSPath -like "*CurrentUser*") { "CurrentUser" } else { "LocalMachine" }
    
    Write-Host "[$i] Subject: $($cert.Subject)" -ForegroundColor White
    Write-Host "    Store:   $storeLoc" -ForegroundColor Gray
    Write-Host "    Expires: $($cert.NotAfter)" -ForegroundColor Gray
    Write-Host ""
    
    $certMap[$i] = $cert
    $i++
}

# Ensure the user enters a valid number from the list
$choice = 0
while ($choice -lt 1 -or $choice -ge $i) {
    $selection = Read-Host "Enter the number of the certificate to use"
    [int]::TryParse($selection, [ref]$choice) | Out-Null
}

$selectedCert = $certMap[$choice]

# --- STEP 6: EXPORT METADATA FOR PYTHON ---
# We only export non-sensitive metadata and the Thumbprint
$ekus = @()
foreach ($eku in $selectedCert.EnhancedKeyUsageList) {
    if ($eku.FriendlyName) { $ekus += $eku.FriendlyName }
}

$certInfo = @{
    Thumbprint = $selectedCert.Thumbprint
    Subject    = $selectedCert.Subject
    Issuer     = $selectedCert.Issuer
    NotAfter   = $selectedCert.NotAfter
    EKUs       = $ekus
    # Identifies if the cert is CurrentUser or LocalMachine
    Store      = if ($selectedCert.PSPath -like "*CurrentUser*") { "CurrentUser" } else { "LocalMachine" }
}

# Save to the temp path as JSON for the Python scripts to consume
$certInfo | ConvertTo-Json -Compress | Set-Content -Path $ExportPath -Encoding UTF8

Write-Host "`n[SUCCESS] Certificate Selected!" -ForegroundColor Green
Write-Host "Selection metadata saved to: $ExportPath" -ForegroundColor Cyan