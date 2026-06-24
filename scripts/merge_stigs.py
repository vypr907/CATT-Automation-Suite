import os
import sys
import json
from datetime import datetime
from pathlib import Path
import pandas as pd

# Import Tkinter for Graphical File Dialog Windows
import tkinter as tk
from tkinter import filedialog, messagebox

# Import Openpyxl styling utilities for formatting the output workbook
from openpyxl.styles import Alignment

# Try loading optional integrations for Google Sheets
try:
    import gspread
    from oauth2client.service_account import Credentials
    GSPREAD_AVAILABLE = True
except ImportError:
    GSPREAD_AVAILABLE = False

# ==============================================================================
# CONFIGURATION & COLUMN MAPPING
# ==============================================================================
MASTER_IP_COL = "IP Address"
MASTER_HOST_COL = "Host Name"
MASTER_STIG_COL = "Benchmark Exceptions List"

# Normal configurations
# INCOMING_IP_HOST_COL = "Host Name"  # This column holds the IP strings in incoming data //COMMENTING OUT FOR NOW
INCOMING_STIG_COL = "STIG"
INCOMING_RESULT_COL = "Result"
INCOMING_PLUGIN_COL = "Plugin ID"
INCOMING_PLUGIN_NAME = "Plugin Name"

def generate_composite_key(ip_or_host: str, stig_id: str) -> str:
    """Generates a tracking key combining asset and rule signature."""
    clean_ip = str(ip_or_host).strip().lower()
    clean_stig = str(stig_id).strip().split()[0].split(',')[0].upper()
    return f"{clean_ip}::{clean_stig}"

def find_hostname_column(columns) -> str:
    """Dynamically locates the asset/hostname identifier column matching variants."""
    normalized_cols = {str(c).strip().lower().replace(" ", ""): str(c) for c in columns}
    # Look for common variants
    for variant in ["hostname", "hostname", "hostaddress", "ipaddress"]:
        if variant in normalized_cols:
            return normalized_cols[variant]
    return ""

def load_from_google_sheets(target_input: str) -> dict[str, pd.DataFrame]:
    """Authenticates and pulls sheets from Google Drive environment, returning a mapping of sheet names to dataframes."""
    if not GSPREAD_AVAILABLE:
        print("[-] Error: 'gspread' or 'google-auth' dependencies missing. Run: pip install gspread google-auth")
        sys.exit(1)

    creds_path = Path("service_account.json")
    if not creds_path.exists():
        print(f"[-] Authentication Failure: Cloud credentials missing. Place '{creds_path}' in this directory.")
        sys.exit(1)

    print("[*] Connecting to Google Sheets API using service account credentials...")
    scopes = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
    creds = Credentials.from_service_account_file(str(creds_path), scopes=scopes)
    gc = gspread.authorize(creds)
    
    try:
        # Check if URL or exact sheet title/ID was supplied
        if "docs.google.com" in target_input:
            sh = gc.open_by_url(target_input)
        else:
            sh = gc.open(target_input)
            
        sheets_dict = {}
        for worksheet in sh.worksheets():
            records = worksheet.get_all_records()
            if records:
                sheets_dict[worksheet.title] = pd.DataFrame(records)
        return sheets_dict
    except Exception as e:
        print(f"[-] Failed to access Google Sheet '{target_input}': {e}")
        sys.exit(1)

def load_local_file(file_path: Path) -> dict[str, pd.DataFrame]:
    """Loads a local .xlsx or .csf file safely, mapping sheet names to dataframes."""
    print(f"[+] Parsing local Excel Workbook: {file_path.name}")
    suffix = file_path.suffix.lower()
    if suffix == ".xlsx":
        return pd.read_excel(file_path, sheet_name=None)
    elif suffix == ".csv":
        df = pd.read_csv(file_path)
        return {file_path.stem: df}
    else:
        print(f"[-] Unsupported file type '{suffix}' for file: {file_path.name}. Only .xlsx and .csv are supported.")
        sys.exit(1)

def gui_select_source(label: str) -> dict[str, pd.DataFrame]:
    """
    Uses Tkinter to pop up a native system dialog picker box. 
    Allows pasting a Google Sheets URL if the terminal is preferred.
    """
    # Initialize hidden tkinter background window environment
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)  # Forces pop-up folder dialog over terminal
    
    print(f"\n[*] Opening File Explorer Window: Choose [{label}]")
    
    # Prompt user option via popup box
    use_cloud = messagebox.askyesno(
        "Source Ingestion Interface", 
        f"Is the [{label}] hosted on Google Sheets?\n\n(Click 'No' to pick a local .xlsx or .csv file instead)"
    )
    
    if use_cloud:
        # Prompt user to paste link into terminal
        print(f"    --> Please paste the Google Sheets URL or Exact Sheet Title into the terminal below:")
        cloud_input = input(">> Paste Google Sheet URL/Name: ").strip()
        if not cloud_input:
            print("[-] Error: URL or name cannot be empty.")
            sys.exit(1)
        root.destroy()
        return load_from_google_sheets(cloud_input)
    else:
        # Launch Graphical Local File Picker window
        file_selected = filedialog.askopenfilename(
            title=f"Select {label} File",
            filetypes=[("Excel or CSV Files", "*.xlsx;*.csv"), ("Excel Workbooks", "*.xlsx"), ("Comma Separated Values", "*.csv")]
        )
        
        if not file_selected:
            print(f"[-] File selection canceled for [{label}]. Exiting pipeline.")
            root.destroy()
            sys.exit(0)
            
        print(f"[+] Graphical Selection Confirmed: {Path(file_selected).name}")
        root.destroy()
        return load_local_file(Path(file_selected))

def merge_deviation_sheets():
    print(f"[*] Starting STIG pipeline processing algorithm at {datetime.now()}")
    
    # 1. Graphical User Interface Data Ingestion Picker Steps
    master_sheets = gui_select_source("Master Deviation Tracker Spreadsheet")
    master_sheet_name = list(master_sheets.keys())[0]
    master_df = master_sheets[master_sheet_name].copy()
    print(f"[+] Loaded Master Tracker Sheet '{master_sheet_name}': {len(master_df)} rows found.")
    
    incoming_sheets = gui_select_source("Incoming Raw Scan Workbooks Pool")
    combined_incoming_list = []
    
    # Pool tracking records across sheets dynamically
    for sheet_name, df in incoming_sheets.items():
        if df.empty:
            continue

        # Dynamically search for the Host column variant (e.g., 'Host Name' vs 'Hostname')
        detected_host_col = find_hostname_column(df.columns)
        if not detected_host_col:
            print(f"[-] Skipping sheet '{sheet_name}': Could not determine Host Name / IP column header.")
            continue

        df = df.copy()
        # Normalize the detected column into a standard internal name for the pipeline processing
        df['Normalized_Host_Identifier'] = df[detected_host_col]
        df['Scan_Source_Sheet'] = sheet_name
        combined_incoming_list.append(df)
        
    if not combined_incoming_list:
        print("[-] Critical Error: No matching tracking headers could be found in the incoming scans selection.")
        sys.exit(1)
        
    incoming_df = pd.concat(combined_incoming_list, ignore_index=True)
    print(f"[+] Combined Incoming Scan Inventory Total: {len(incoming_df)} rows.")

    # 2. Normalize and Build Functional Tracking Keys
    string_cols = master_df.select_dtypes(include=["object", "string"]).columns
    master_df[string_cols] = master_df[string_cols].apply(lambda x: x.str.strip() if hasattr(x, 'str') else x)
    
    incoming_df['Normalized_Host_Identifier'] = incoming_df['Normalized_Host_Identifier'].astype(str).str.strip()
    incoming_df[INCOMING_STIG_COL] = incoming_df[INCOMING_STIG_COL].astype(str).str.strip()
    incoming_df[INCOMING_RESULT_COL] = incoming_df[INCOMING_RESULT_COL].astype(str).str.strip().str.upper()

    incoming_keys = set()
    for idx, row in incoming_df.iterrows():
        key = generate_composite_key(row['Normalized_Host_Identifier'], row[INCOMING_STIG_COL])
        incoming_keys.add(key)
        incoming_df.at[idx, 'matching_key'] = key

    # 3. Cross-Reference Evaluation Block
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

    # 4. Generate Asset Profiles Rollup Sheet (1 Row per Hostname/IP)
    print("[*] Compiling Hostname-centric rollup telemetry...")
    host_summary_data = []
    unique_hosts = incoming_df['Normalized_Host_Identifier'].unique()
    
    for host in unique_hosts:
        host_findings = incoming_df[incoming_df['Normalized_Host_Identifier'] == host]
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

    # 5. Generate Plugin ID Profiles Rollup Sheet (1 Row per Unique Plugin ID)
    print("[*] Compiling Plugin-centric rollup telemetry...")
    plugin_summary_data = []
    unique_plugins = incoming_df[INCOMING_PLUGIN_COL].unique()
    
    for plugin in unique_plugins:
        plugin_findings = incoming_df[incoming_df[INCOMING_PLUGIN_COL] == plugin]
        plugin_fails = plugin_findings[plugin_findings[INCOMING_RESULT_COL].isin(["FAILED", "FAIL"])]
        
        failed_hosts = ", ".join(plugin_fails['Normalized_Host_Identifier'].unique())
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

    # 6. Build the Final Multi-Sheet Output Workbook Layout
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"Consolidated_STIG_Merge_Report_{timestamp}.xlsx"
    output_file_path = Path.cwd() / output_filename
    
    print(f"[*] Compiling worksheets into spreadsheet: {output_file_path}")

    # Create the writer instance utilizing the openpyxl backend
    
    #with pd.ExcelWriter(output_file_path, engine='xlsxwriter') as writer:
    #    master_df.to_excel(writer, sheet_name="Master Tracker Evaluation", index=False)
    #    host_summary_df.to_excel(writer, sheet_name="Asset Summary", index=False)
    #    plugin_summary_df.to_excel(writer, sheet_name="Plugin ID Summary", index=False)
    #    incoming_df.drop(columns=['matching_key'], errors='ignore').to_excel(writer, sheet_name="Raw Scan Data Pool", index=False)

    with pd.ExcelWriter(output_file_path, engine='openpyxl') as writer:
        master_df.to_excel(writer, sheet_name="Master Tracker Evaluation", index=False)
        host_summary_df.to_excel(writer, sheet_name="Asset Summary", index=False)
        plugin_summary_df.to_excel(writer, sheet_name="Plugin ID Summary", index=False)
        incoming_df.drop(columns=['matching_key'], errors='ignore').to_excel(writer, sheet_name="Raw Scan Data Pool", index=False)

        # Using .items() gives us the exact sheet name string (sheet_name) 
        # and the sheet object (worksheet) with zero engine dependencies
        for sheet_name, worksheet in writer.sheets.items():
            print(f"   [>] Optimizing column spacing and text wrapping rules on: '{sheet_name}'")
            
            # If pandas wrapped the sheet object, extract the raw openpyxl context safely
            if hasattr(worksheet, 'sheet'):
                worksheet = worksheet.sheet
                
            for col in worksheet.columns:
                max_len = 0
                col_letter = col[0].column_letter
                
                for cell in col:
                    cell.alignment = Alignment(wrap_text=True, vertical="top", horizontal="left")
                    
                    if cell.value is not None:
                        lines = str(cell.value).split('\n')
                        for line in lines:
                            if len(line) > max_len:
                                max_len = len(line)
                
                calculated_width = max_len + 3
                
                if calculated_width > 60:
                    worksheet.column_dimensions[col_letter].width = 60
                else:
                    worksheet.column_dimensions[col_letter].width = max(calculated_width, 11)

        #COMMENTED OUT FOR NOW: Formatting block for column widths and text wrapping---------------------------------
        # Access the openpyxl workbook and apply formatting to each sheet
        #workbook = writer.book

        #for sheet_wrapper in writer.sheets.values():
        #    worksheet = sheet_wrapper.sheet # Access the underlying openpyxl worksheet object
        #    print(f"   [>] Optimizing column spacing and text wrapping rules on: '{worksheet.title}'")
        #    
        #    # Loop through each column in the active worksheet
        #    for col in worksheet.columns:
        #        # Find out the maximum text length inside this column's cells
        #        max_len = 0
        #        col_letter = col[0].column_letter  # Extract column address indicator (e.g., 'A', 'B')
        #        
        #        for cell in col:
        #            # Enforce top-left alignment and activate word-wrapping on every cell
        #            cell.alignment = Alignment(wrap_text=True, vertical="top", horizontal="left")
        #            
        #            if cell.value is not None:
        #                # Check line breaks to ensure correct width calculations on multi-line blobs
        #                lines = str(cell.value).split('\n')
        #                for line in lines:
        #                    if len(line) > max_len:
        #                        max_len = len(line)
        #        
        #        # Add padding to ensure header names/values aren't clipped by boundaries
        #        calculated_width = max_len + 3
        #        
        #        # Constrain dimensions to a maximum of 60 characters to trigger text wrapping
        #        if calculated_width > 60:
        #            worksheet.column_dimensions[col_letter].width = 60
        #        else:
        #            # Keep column width standard if everything comfortably fits under 30 characters
        #            worksheet.column_dimensions[col_letter].width = max(calculated_width, 11)
        #---------------------------------------------------------------------------------------------------------

    print(f"[+] Execution completed successfully! File output: {output_filename}")

# ==============================================================================
# RUNNER RUN INTERFACE
# ==============================================================================
if __name__ == "__main__": 
    merge_deviation_sheets()