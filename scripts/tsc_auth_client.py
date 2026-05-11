import subprocess
import os
import json
from typing import Any, Dict, Optional
#import requests
#from OpenSSL import crypto

"""
.SYNOPSIS
    tsc_auth_client.py
    Windows-native Tenable SC client using CAC/PIV certificates.

.DESCRIPTION
    Updated for the CATT-Automation-Suite. This script manages mTLS communication by orchestrating PowerShell helpers in the /auth directory.
    This script provides a class to interact with Tenable SC using CAC/PIV certificates.
    It launches a PowerShell script to let the user pick the correct CAC certificate, then uses it for mTLS requests.

.NOTES
    Author: Steven "vypr" Laszloffy
    Date:   8-18-2025
"""

class TSCWindowsCAC:
    """
    Tenable Security Center client using a Windows CAC/PIV certificate.
    - Prompts user once via tsc_cac_native.ps1 to select a certificate.
    - Reads thumbprint and metadata from JSON file.
    - API calls: PowerShell helper (no prompts) via Schannel mTLS using thumbprint.
    - Fully handles exceptions and logging.
    - Safe: private keys are never exported, only metadata is saved.
    """

    def __init__(self, base_url: str, force_repick: bool = False):
        """
        Initialize the TSC client using CAC cert.

        :param base_url: Base URL of Tenable SC
        :param ps_native: Path to your tsc_cac_native.ps1 script
        :param api_script: Path to your tsc_cac_api.ps1 script
        :param ca_bundle: Optional path to a PEM bundle if custom roots are needed
        :param force_repick: If True, always prompt for cert selection
        """
        self.base_url = base_url.rstrip("/")

        # Unified folder paths
        self.auth_dir = "auth"
        self.ps_picker = os.path.join(self.auth_dir, "cac_picker.ps1")
        self.api_script = os.path.join(self.auth_dir, "tsc_api_helper.ps1")
        
        # Paths for exporting the selected cert info
        self.cert_info_path = os.path.join(os.environ["TEMP"], "cac_cert_info.json")

        # Optionally force repicking the cert
        if force_repick:
            self.clear_cert_cache()

        # Launch certificate picker script
        self.cert_info = self._pick_cert()
        self.thumbprint = self.cert_info["Thumbprint"]
        print(f"[INFO] Using CAC cert thumbprint: {self.thumbprint}")

    # -------------------- Cert Handling Methods --------------------

    def clear_cert_cache(self) -> None:
        """
        Clear the cached cert info.
        """
        if os.path.exists(self.cert_info_path):
            try:
                os.remove(self.cert_info_path)
                print("[INFO] Cleared cached certificate info.")
            except OSError as e:
                print(f"[ERROR] Failed to clear cert cache: {e}")
        else:
            print("[INFO] No cached certificate info found.")


    def _pick_cert(self) -> Dict[str, Any]:
        """
        Internal: Launches the PowerShell UI (cac_picker.ps1) to select a CAC.
        Reads the resulting JSON, validates the data, and returns the metadata.
        """
        # 1. Check if the picker needs to run
        if not os.path.exists(self.cert_info_path):
            print("[*] Launching CAC cert picker...")
            if not os.path.exists(self.ps_picker):
                raise FileNotFoundError(f"Missing critical component: {self.ps_picker}")
        
            try:
                # Run the merged picker script
                subprocess.run([
                    "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", self.ps_picker, "-ExportPath", self.cert_info_path
                ], check=True)
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Certificate selection failed: {e}")

        # 2. Load the data into a temporary variable (cert_info)
        # We use utf-8-sig to handle Windows/PowerShell Byte Order Marks
        try:
            with open(self.cert_info_path, "r", encoding="utf-8-sig") as f:
                cert_info = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON from {self.cert_info_path}: {e}")

        # 3. Security Validation: Ensure the PowerShell script gave us what we need
        # This prevents the script from crashing later when it tries to find the thumbprint
        required_keys = {"Thumbprint", "Subject", "Issuer", "NotBefore", "NotAfter", "EKUs"}
        if not required_keys.issubset(cert_info.keys()):
            missing = required_keys - cert_info.keys()
            raise ValueError(f"Certificate info missing required keys: {missing}")

        # 4. Final Return: Now that data is verified, we hand it back to the class
        return cert_info
    
    # --------------------- Requests Session ---------------------
    ''' Removing requests.Session and OpenSSL crypto as they are not used in this version.
    This version uses PowerShell for mTLS and does not require direct requests or OpenSSL handling.
    Due to the secure nature of the environment, we are unable to export the private key.

    def _create_session(self) -> requests.Session:
        """
        Create a requests session with mTLS using the selected CAC cert.
        """
        session = requests.Session()

        # Load the certificate from the Windows store using the thumbprint
        cert_pfx_path, cert_pfx_pass = self._export_cert_to_pfx()
        session.cert = (cert_pfx_path, cert_pfx_pass)

        if self.ca_bundle:
            # If a CA bundle is provided, use it for SSL verification
            session.verify = self.ca_bundle
        else:
            # Default to system CA store if no bundle provided
            session.verify = True
        
        return session

    def _export_cert_to_pfx(self) -> tuple[str, Optional[str]]:
        """
        Export the selected certificate from the Windows store to a PFX file.
        Returns the path to the PFX file and its password (if any).
        """
        import tempfile
        import subprocess

        pfx_path = os.path.join(tempfile.gettempdir(),f"{self.cert_info['Thumbprint']}.pfx")

        # Call PowerShell to export the cert to PFX
        export_script = f"""
        $thumb = '{self.cert_info['Thumbprint']}'
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $cert = $store.Certificates | Where-Object {{$_.Thumbprint -eq $thumb}}
        if(-not $cert){{throw 'Certificate not found'}}
        $pwd = ConvertTo-SecureString -String '' -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath '{pfx_path}' -Password $pwd
        $store.Close()
        """
        subprocess.run(["powershell", "-NoProfile", "-Command", export_script], check=True)
        return pfx_path, ""
    
    '''

    # ------------------ Internal API calls ------------------
    def _call(self, path: str, method: str = "GET",
              body: Optional[Dict[str, Any]] = None,
              query: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None,
              ignore_ssl_errors: bool = False) -> Any:
        '''
        Delegate the HTTPS request to the PowerShell API helper, which uses Schannel + certificate thumbprint.
        '''
        """
        Internal: Use previously selected cert with mTLS using selected cert.
        """
        
        # Build the PowerShell command
        args = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", self.api_script,
            "-BaseUrl", self.base_url,
            "-Path", path,
            "-Method", method,
            "-Thumbprint", self.thumbprint
        ]

        # Add optional JSON payloads if they exist
        if headers: args += ["-HeadersJson", json.dumps(headers)]
        if body:    args += ["-BodyJson", json.dumps(body)]
        if query:   args += ["-QueryJson", json.dumps(query)]

        # Execute the request through the PowerShell bridge
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if proc.returncode != 0:
            raise RuntimeError(f"API Call Failed: {proc.stderr}")

        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return proc.stdout.strip()

    # ------------------ Convenience methods ------------------

    def system(self) -> Any:
        """Get /rest/system info."""
        return self._call("/rest/system", "GET")

    def list_scan_results(self, fields: Optional[str] = None, filters: Optional[Dict[str, Any]] = None) -> Any:
        """List scan results."""
        query = {}
        if fields:
            query["fields"] = fields
        if filters:
            query.update(filters)
        return self._call("/rest/scanResult", "GET", query=query or None)

    def get_scan_result(self, result_id: int) -> Any:
        """Get a single scan result by ID."""
        return self._call(f"/rest/scanResult/{result_id}", "GET")

    def start_vuln_export(self, query_id: int, format: str = "csv") -> Any:
        """Start a vulnerability export job (adjust endpoint as needed)."""
        body = {"query_id": query_id, "format": format}
        return self._call("/rest/vulnerability/export", "POST", body=body)

# ---------------- Example usage ----------------
if __name__ == "__main__":
    BASE_URL = "https://sccv03.csp.noaa.gov"
    PICKER_SCRIPT = r"G:\My Drive\CATT_EXTRACTOR\tsc_cac_native.ps1"  # adjust path
    API_SCRIPT = r"G:\My Drive\CATT_EXTRACTOR\tsc_cac_api.ps1"  # adjust path
    CA_BUNDLE = None  # optional PEM bundle if needed

    tsc = TSCWindowsCAC(BASE_URL, PICKER_SCRIPT, API_SCRIPT, force_repick=True)

    print("== /rest/system ==")
    print(json.dumps(tsc.system(), indent=2))

    print("\n== /rest/scanResult (first page) ==")
    # Add Accept header for troubleshooting
    headers = {"Accept": "application/json"}
    results = tsc.list_scan_results(fields="id,name,status,repository,createdTime", filters=None)
    # Pass headers to _call via list_scan_results
    # To do this, update list_scan_results to accept headers
    # For now, call _call directly for demonstration:
    results = tsc._call("/rest/scanResult", "GET", query={"fields": "id,name,status,repository,createdTime"}, headers=headers)
    print(json.dumps(results, indent=2))