#!/usr/bin/env python3
"""
STIG Deviation Merge Engine (Flexible Formats)
Description: Dynamically handles .xlsx, .csv, and accommodates Google Sheets.
             Prompts the user to pick their source files directly at runtime.
"""

import os
from datetime import datetime
from pathlib import Path
import pandas as pd
import tkinter as tk
from tkinter import filedialog, simpledialog

# ==============================================================================
# CONFIGURATION & COLUMN MAPPING
# ==============================================================================
MATCH_KEYS = ["IP Address", "Host Name"]
MANUAL_FIELDS = [
    "Justifications for Exemptions",
    "Mitigating Controls ",
    "Compensating Controls "
]

def load_any_source(file_target) -> pd.DataFrame:
    """
    Dynamically ingests data based on source type (.csv, .xlsx, or Google Sheets URL).
    """
    # Case 1: Handle Google Sheets URL/ID string
    if isinstance(file_target, str) and ("docs.google.com/spreadsheets" in file_target or file_target.startswith("gdoc:")):
        print(f"[*] Authenticating with Google Sheets API to pull cloud data...")
        return load_from_google_sheets(file_target)
    
    # Ensure we are working with a Path object for local files
    file_path = Path(file_target)
    if not file_path.exists():
        raise FileNotFoundError(f"Target file not found: {file_path}")
    
    ext = file_path.suffix.lower()
    
    # Case 2: Handle Local CSV
    if ext == ".csv":
        print(f"[+] Parsing local CSV file: {file_path.name}")
        df = pd.read_csv(file_path, dtype=str)
    
    # Case 3: Handle Local Excel Workbook
    elif ext in [".xlsx", ".xlsm"]:
        print(f"[+] Parsing local Excel Workbook: {file_path.name}")
        # Automatically loads the first visible sheet; specify sheet_name if needed
        df = pd.read_excel(file_path, dtype=str, sheet_name=0)
        
    else:
        raise ValueError(f"Unsupported file extension format: {ext}")
    
    # Normalize headers and whitespace blocks
    df.columns = df.columns.str.strip()
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].str.strip()
        
    return df


def load_from_google_sheets(spreadsheet_identifier: str) -> pd.DataFrame:
    """
    Placeholder for Google Sheets API integration using gspread.
    """
    # To use this block, run: pip install gspread oauth2client
    try:
        import gspread
        from oauth2client.service_account import ServiceAccountCredentials
        
        # Example least-privilege service account setup:
        # scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        # creds = ServiceAccountCredentials.from_json_keyfile_name("service_account_creds.json", scope)
        # client = gspread.authorize(creds)
        # sheet = client.open_by_url(spreadsheet_identifier).sheet1
        # return pd.DataFrame(sheet.get_all_records())
        
        raise NotImplementedError("Google Sheets credentials must be explicitly configured in the script.")
        
    except ImportError:
        print("[-] Missing dependencies for Google cloud synchronization. Please run `pip install gspread`.")
        raise


def generate_composite_key(df: pd.DataFrame, keys: list) -> pd.Series:
    return df[keys].astype(str).agg("-".join, axis=1)


def merge_deviation_sheets(master_source, incoming_source, output_dir: Path):
    """Core merge engine pipeline handling mixed data formats."""
    print(f"\n[*] Starting STIG pipeline processing algorithm at {datetime.now()}")
    
    # 1. Ingest mixed-format datasets
    master_df = load_any_source(master_source)
    incoming_df = load_any_source(incoming_source)
    
    print(f"[+] Loaded Master Tracker: {len(master_df)} rows.")
    print(f"[+] Loaded Incoming Scan Data: {len(incoming_df)} rows.")
    
    # 2. Key Generation & Processing
    master_df["_merge_key"] = generate_composite_key(master_df, MATCH_KEYS)
    incoming_df["_merge_key"] = generate_composite_key(incoming_df, MATCH_KEYS)
    
    manual_data_lookup = master_df[["_merge_key"] + MANUAL_FIELDS].set_index("_merge_key")
    incoming_clean = incoming_df.drop(columns=[col for col in MANUAL_FIELDS if col in incoming_df.columns], errors='ignore')
    
    new_findings = []
    updated_rows = []
    unchanged_count = 0
    master_keys = set(master_df["_merge_key"])
    
    for _, scan_row in incoming_clean.iterrows():
        key = scan_row["_merge_key"]
        if key in master_keys:
            merged_row = scan_row.to_dict()
            for field in MANUAL_FIELDS:
                # Safely fallback to blank string if field doesn't exist in lookup index
                merged_row[field] = manual_data_lookup.loc[key, field] if key in manual_data_lookup.index else ""
            updated_rows.append(merged_row)
            unchanged_count += 1
        else:
            merged_row = scan_row.to_dict()
            for field in MANUAL_FIELDS:
                merged_row[field] = "PENDING INITIAL ISSO REVIEW"
            new_findings.append(merged_row)
            
    final_merged_df = pd.DataFrame(updated_rows + new_findings)
    if "_merge_key" in final_merged_df.columns:
        final_merged_df = final_merged_df.drop(columns=["_merge_key"])
        
    # 3. Export Consolidated Excel Workbook Package
    TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"NOAA5047_STIG_Master_Merged_{TIMESTAMP}.xlsx"
    
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        final_merged_df.to_excel(writer, sheet_name="Consolidated Master Tracker", index=False)
        
        # Output sub-tabs for easier analyst workflows
        if new_findings:
            pd.DataFrame(new_findings).drop(columns=["_merge_key"], errors="ignore").to_excel(
                writer, sheet_name="ISSO Review Required", index=False
            )
            
    print(f"[+] Merge completed successfully!")
    print(f"[➔] Review-ready spreadsheet generated at: {output_path}")


if __name__ == "__main__":
    # Initialize UI Window environment
    root = tk.Tk()
    root.withdraw()
    
    print("[*] Launching STIG Deviation File Router Dashboard...")
    
    # 1. Ask user for input method
    use_cloud = simpledialog.askstring(
        "Source Ingestion Selector", 
        "Type 'LOCAL' for file files (.xlsx, .csv) or 'CLOUD' for Google Sheets URL:",
        initialvalue="LOCAL"
    )
    
    if not use_cloud:
        print("[-] Execution halted.")
        exit(0)
        
    if use_cloud.upper() == "CLOUD":
        # Prompt user to paste a Google Sheets URL
        MASTER_TARGET = simpledialog.askstring("Google Sheets Link", "Paste Master Tracker Google Sheet URL:")
        INCOMING_TARGET = simpledialog.askstring("Google Sheets Link", "Paste Incoming Scan Google Sheet URL:")
        OUTPUT_DIRECTORY = Path(filedialog.askdirectory(title="Select Destination Folder for Final Report"))
    else:
        # Prompt user to browse directly for local files via cross-compatible extension masks
        file_types = [("Spreadsheets", "*.xlsx *.csv *.xlsm"), ("Excel Workbooks", "*.xlsx"), ("Flat CSV Records", "*.csv")]
        
        print("[*] Please locate your Master Tracker spreadsheet file...")
        MASTER_TARGET = filedialog.askopenfilename(title="Select MASTER Deviation Tracker Spreadsheet", filetypes=file_types)
        
        print("[*] Please locate your Incoming Scan sheet data file...")
        INCOMING_TARGET = filedialog.askopenfilename(title="Select INCOMING Scan Findings File", filetypes=file_types)
        
        if not MASTER_TARGET or not INCOMING_TARGET:
            print("[-] Required selections are missing. Terminating pipeline workflow loop execution.")
            exit(1)
            
        OUTPUT_DIRECTORY = Path(MASTER_TARGET).parent

    # Run execution engine
    try:
        merge_deviation_sheets(MASTER_TARGET, INCOMING_TARGET, OUTPUT_DIRECTORY)
    except Exception as e:
        print(f"[-] Critical Error running pipeline execution: {e}")