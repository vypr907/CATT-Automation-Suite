import os
import sys
from datetime import datetime
from pathlib import Path
import pandas as pd

# ==============================================================================
# CONFIGURATION & COLUMN MAPPING
# ==============================================================================
MASTER_IP_COL = "IP Address"
MASTER_HOST_COL = "Host Name"
MASTER_STIG_COL = "Benchmark Exceptions List"

INCOMING_IP_HOST_COL = "Host Name"  # This column holds the IP strings in incoming data
INCOMING_STIG_COL = "STIG"
INCOMING_RESULT_COL = "Result"
INCOMING_PLUGIN_COL = "Plugin ID"
INCOMING_PLUGIN_NAME = "Plugin Name"

def generate_composite_key(ip_or_host: str, stig_id: str) -> str:
    """Generates a tracking key combining asset and rule signature."""
    clean_ip = str(ip_or_host).strip().lower()
    clean_stig = str(stig_id).strip().split()[0].split(',')[0].upper()
    return f"{clean_ip}::{clean_stig}"

def load_local_source(file_path: Path) -> dict[str, pd.DataFrame]:
    """Loads an Excel file safely, mapping sheet names to dataframes."""
    print(f"[+] Parsing local Excel Workbook: {file_path.name}")
    try:
        return pd.read_excel(file_path, sheet_name=None)
    except Exception as e:
        print(f"[-] Critical Error reading workbook {file_path.name}: {e}")
        sys.exit(1)

def merge_deviation_sheets(master_path: Path, incoming_path: Path, output_dir: Path):
    print(f"\n[*] Starting STIG pipeline processing algorithm at {datetime.now()}")
    
    # 1. Ingest Master Tracker
    master_sheets = load_local_source(master_path)
    master_sheet_name = list(master_sheets.keys())[0]
    master_df = master_sheets[master_sheet_name].copy()
    print(f"[+] Loaded Master Tracker Sheet '{master_sheet_name}': {len(master_df)} rows found.")
    
    # 2. Ingest & Pool Incoming Multi-Sheet Scans
    incoming_sheets = load_local_source(incoming_path)
    combined_incoming_list = []
    
    for sheet_name, df in incoming_sheets.items():
        if df.empty or INCOMING_IP_HOST_COL not in df.columns:
            continue
        df = df.copy()
        df['Scan_Source_Sheet'] = sheet_name
        combined_incoming_list.append(df)
        
    if not combined_incoming_list:
        print("[-] Critical Error: No valid data sheets could be parsed from incoming scan workbook.")
        sys.exit(1)
        
    incoming_df = pd.concat(combined_incoming_list, ignore_index=True)
    print(f"[+] Combined Incoming Scan Inventory Total: {len(incoming_df)} rows.")

    # Apply string normalization safely across core keys
    incoming_df[INCOMING_IP_HOST_COL] = incoming_df[INCOMING_IP_HOST_COL].astype(str).str.strip()
    incoming_df[INCOMING_STIG_COL] = incoming_df[INCOMING_STIG_COL].astype(str).str.strip()
    incoming_df[INCOMING_RESULT_COL] = incoming_df[INCOMING_RESULT_COL].astype(str).str.strip().upper()

    # Build unique verification keys on incoming data
    incoming_keys = set()
    for idx, row in incoming_df.iterrows():
        key = generate_composite_key(row[INCOMING_IP_HOST_COL], row[INCOMING_STIG_COL])
        incoming_keys.add(key)
        incoming_df.at[idx, 'matching_key'] = key

    # 3. Core Evaluation / Merge Logic (Master Sheet Row Processing)
    master_df['Latest_Scan_Status'] = "Not Seen in Latest Scan"
    
    for idx, row in master_df.iterrows():
        master_ip = str(row.get(MASTER_IP_COL, "")).strip().lower()
        master_stig_blob = str(row.get(MASTER_STIG_COL, "")).strip().upper()
        
        if not master_ip or master_ip == "nan":
            continue
            
        matched_in_scan = False
        is_failing_in_scan = False
        
        for key in incoming_keys:
            scan_ip, scan_stig = key.split("::")
            if scan_ip == master_ip and scan_stig in master_stig_blob:
                matched_in_scan = True
                match_rows = incoming_df[incoming_df['matching_key'] == key]
                if any(match_rows[INCOMING_RESULT_COL].isin(["FAILED", "FAIL"])):
                    is_failing_in_scan = True
        
        if matched_in_scan:
            master_df.at[idx, 'Latest_Scan_Status'] = "FAIL / Still Failing" if is_failing_in_scan else "PASS / Candidate for Closure"

    # 4. Generate Hostname Summary Sheet (1 Row per Hostname/IP)
    print("[*] Compiling Hostname-centric summary telemetry...")
    host_summary_data = []
    unique_hosts = incoming_df[INCOMING_IP_HOST_COL].unique()
    
    for host in unique_hosts:
        host_findings = incoming_df[incoming_df[INCOMING_IP_HOST_COL] == host]
        fails = host_findings[host_findings[INCOMING_RESULT_COL].isin(["FAILED", "FAIL"])]
        passes = host_findings[host_findings[INCOMING_RESULT_COL].isin(["PASSED", "PASS"])]
        
        failed_stig_list = ", ".join(fails[INCOMING_STIG_COL].unique())
        source_sheets = ", ".join(host_findings['Scan_Source_Sheet'].unique())
        
        host_summary_data.append({
            "Host Name / IP Address": host,
            "Total Scan Checks": len(host_findings),
            "Total Open Failures": len(fails),
            "Total Passed Checks": len(passes),
            "Failed STIG IDs": failed_stig_list if failed_stig_list else "None",
            "System Classification Source Sheets": source_sheets
        })
    host_summary_df = pd.DataFrame(host_summary_data)

    # 5. Generate Plugin ID Summary Sheet (1 Row per Unique Plugin ID)
    print("[*] Compiling Plugin-centric vulnerability signature telemetry...")
    plugin_summary_data = []
    unique_plugins = incoming_df[INCOMING_PLUGIN_COL].unique()
    
    for plugin in unique_plugins:
        plugin_findings = incoming_df[incoming_df[INCOMING_PLUGIN_COL] == plugin]
        plugin_fails = plugin_findings[plugin_findings[INCOMING_RESULT_COL].isin(["FAILED", "FAIL"])]
        
        failed_hosts = ", ".join(plugin_fails[INCOMING_IP_HOST_COL].unique())
        sample_stig_id = plugin_findings[INCOMING_STIG_COL].iloc[0]
        sample_plugin_name = plugin_findings[INCOMING_PLUGIN_NAME].iloc[0] if INCOMING_PLUGIN_NAME in plugin_findings.columns else "N/A"
        
        plugin_summary_data.append({
            "Plugin ID": plugin,
            "Associated STIG ID": sample_stig_id,
            "Rule Title / Description": sample_plugin_name,
            "Total Evaluated Items": len(plugin_findings),
            "Total Active Host Failures": len(plugin_fails),
            "Impacted Host List": failed_hosts if failed_hosts else "None"
        })
    plugin_summary_df = pd.DataFrame(plugin_summary_data)

    # 6. Build the Combined Output Workbook Multi-Sheet Structure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"Consolidated_STIG_Merge_Report_{timestamp}.xlsx"
    output_file_path = output_dir / output_filename
    
    print(f"[*] Formatting review-ready workbook out to: {output_file_path}")
    
    with pd.ExcelWriter(output_file_path, engine='xlsxwriter') as writer:
        # Sheet 1: Master Consolidated View
        master_df.to_excel(writer, sheet_name="Master Tracker Evaluation", index=False)
        
        # Sheet 2: Rollup view - 1 row per Hostname/IP
        host_summary_df.to_excel(writer, sheet_name="Asset Summary", index=False)
        
        # Sheet 3: Rollup view - 1 row per Plugin ID
        plugin_summary_df.to_excel(writer, sheet_name="Plugin ID Summary", index=False)
        
        # Sheet 4: Raw Combined Scan Feed (for easy manual lookup)
        incoming_df.drop(columns=['matching_key'], errors='ignore').to_excel(
            writer, sheet_name="Raw Consolidated Scan Data", index=False
        )

    print(f"[+] Execution complete! Output file generated successfully: {output_file_path.name}")

# ==============================================================================
# RUNNER RUN INTERFACE
# ==============================================================================
if __name__ == "__main__":
    print("[*] Please locate your Master Tracker spreadsheet file...")
    MASTER_TARGET = Path("NOAA5047 DISA STIG Deviation Spreadsheet_offline.xlsx")
    
    print("[*] Please locate your Incoming Scan sheet data file...")
    INCOMING_TARGET = Path("CATT_Extracted_Data.xlsx")
    
    OUTPUT_DIRECTORY = Path(os.getcwd())
    
    if not MASTER_TARGET.exists() or not INCOMING_TARGET.exists():
        print(f"[-] Execution halted: Ensure '{MASTER_TARGET}' and '{INCOMING_TARGET}' are located in this directory.")
        sys.exit(1)
        
    merge_deviation_sheets(MASTER_TARGET, INCOMING_TARGET, OUTPUT_DIRECTORY)