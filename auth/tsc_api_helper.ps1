param(
    [Parameter(Mandatory=$true)][string]$BaseUrl,
    [Parameter(Mandatory=$true)][string]$Path,
    [ValidateSet("GET","POST","PUT","PATCH","DELETE")][string]$Method = "GET",
    [Parameter(Mandatory=$true)][string]$Thumbprint,
    [string]$BodyJson,
    [hashtable]$Query,
    [hashtable]$Headers,
    [switch]$IgnoreSslErrors,
    [string]$QueryJson,
    [string]$HeadersJson
)

# Build URL
if ($Path -like "/*") { $Path = $Path } else { $Path = "/$Path" }
$uri = "$($BaseUrl.TrimEnd('/'))$Path"

# Splat params for Invoke-RestMethod
$irParams = @{
    Uri                     = $uri
    Method                  = $Method
    UseBasicParsing         = $true
    CertificateThumbprint   = $Thumbprint
    ErrorAction             = 'Stop'
}

# Convert JSON into hashtables when provided
if ($QueryJson){
    $Query = ConvertFrom-Json -InputObject $QueryJson
}
if ($HeadersJson){
    $Headers = ConvertFrom-Json -InputObject $HeadersJson
}
#if ($BodyJson){
#    $Body = ConvertFrom-Json -InputObject $BodyJson
#}

if ($Query)   { $irParams['Body'] = $null; $irParams['Uri'] = ($uri + '?' + ($Query.GetEnumerator() | ForEach-Object { "{0}={1}" -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value) } -join "&")) }
if ($Headers) { $irParams['Headers'] = $Headers }
if ($BodyJson){ $irParams['Body'] = $BodyJson; $irParams['ContentType'] = 'application/json' }

# Optionally bypass TLS validation (NOT recommended; prefer adding CA to trusted root)
if ($IgnoreSslErrors) {
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
   public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
   }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

try {
    $resp = Invoke-RestMethod @irParams
    $json = $resp | ConvertTo-Json -Depth 6
    if (-not $json) { $json = "{}" }
    #[Console]::Out.Write($json) # Can't use this due to ContrainedLanguage Mode restrictions
    Write-Host $json -ForegroundColor Green
    exit 0
} catch {
    $msg = @{
        error = $_.Exception.Message
        uri   = $uri
        code  = ($_.Exception.Response.StatusCode.value__ | Out-String).Trim()
    } | ConvertTo-Json
    #[Console]::Error.WriteLine($msg) # Can't use this due to ContrainedLanguage Mode restrictions
    Write-Error ($msg | ConvertTo-Json -Compress)
    # Exit with non-zero code to indicate failure
    exit 1
}
