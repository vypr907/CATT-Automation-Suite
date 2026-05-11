function Get-CACCertificate {
    [CmdletBinding()]
    param ()

    $stores = @(
        'Cert:\CurrentUser\My',
        'Cert:\LocalMachine\My'
    )

    $certs = @()

    foreach ($store in $stores) {
        $storeCerts = Get-ChildItem $store | Where-Object {
            $ekuNames = $_.EnhancedKeyUsageList | ForEach-Object {$_.FriendlyName} | Where-Object{$_}
            ($ekuNames -match 'Client|Smart|PIV|Authentication') -or ($_.Subject -match 'PIV|Authentication')
        } | Select-Object @{Name='Store';Expression={$store}},
        @{Name='CertObject';Expression={$_}},
        Subject, Thumbprint, NotAfter

        $certs += $storeCerts
    }

    if(-not $certs) {
        Write-Host "No matching CAC/PIV certificates found - showing all personal certs." -ForegroundColor Yellow
        foreach($store in $stores) {
            $storeCerts = Get-ChildItem $store | Select-Object @{Name='Store';Expression={$store}},
            @{Name='CertObject';Expression={$_}},
            Subject, Thumbprint, NotAfter

            $certs += $storeCerts
        }
    }

    Write-Host "`nCertificates available for selection:`n"
    $i = 1
    foreach($cert in $certs){
        Write-Host ("[{0}] Store: {1} | Subject: {2} | Exp: {3}" -f $i, $cert.Store, $cert.Subject, $cert.NotAfter)
        $i++
    }

    $selection = Read-Host "`nEnter the number of the certificate to use"

    if($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $certs.Count){
        $chosenCert = $certs[[int]$selection - 1].CertObject
        Write-Host "`nYou selected:" -ForegroundColor Green
        $chosenCert | Format-List Subject, Thumbprint, NotAfter
        return $chosenCert
    }
    else {
        Write-Host "Invalid selection." -ForegroundColor Red
        return $null
    }
}

# After the user selects a cert:
$CACCert = Get-CACCertificate
if ($CACCert) {
    $exportPath = Join-Path $env:TEMP "cac_cert_info.json"

    # Get EKU friendly names as an array of strings
    $ekus = @()
    foreach ($eku in $CACCert.EnhancedKeyUsageList) {
        if ($eku.FriendlyName) {
            $ekus += $eku.FriendlyName
        }
    }

    # Only export Thumbprint (and optional metadata)
    $certInfo = @{
        Thumbprint  = $CACCert.Thumbprint
        Store       = if ($CACCert.PSPath -like "*CurrentUser*"){"CurrentUser"} else {"LocalMachine"}
        Subject     = $CACCert.Subject
        EKU         = $ekus
        NotAfter    = $CACCert.NotAfter
    }

    $certInfo | ConvertTo-Json | Set-Content -Path $exportPath -Encoding UTF8
    Write-Host "Certificate exported to $exportPath" -ForegroundColor Cyan
}