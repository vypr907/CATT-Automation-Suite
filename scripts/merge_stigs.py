#!/usr/bin/env python3
"""
STIG Deviation Merge Engine
Description: Safely merges incoming Tenable compliance scan data (CATT Extracted Data)
             into the master DISA STIG Deviation Spreadsheet using a composite key matching scheme.
             Preserves human analysis and generates an audit-ready Change Log.
"""

import os
from datetime import datetime
from pathlib import Path
import pandas as pd


# ==============================================================================
# CONFIGURATION & COLUMN MAPPING
# ==============================================================================
# Stable matching key configuration
MATCH_KEYS = ["IP Address", "Host Name"]

# Map incoming machine-data columns to your master tracker's column schema
COLUMN_MAP = {
    "IP Address": "IP Address",
    "Host Name": "Host Name",
    "Host is Internal or Public-Facing": "Host is Internal or Public-Facing ",
    "Host Type": "Host Type  ",
    "Software Name": "Software Name ",
    "Specify Benchmark followed": "Specify Benchmark followed ",
    "Benchmark Exceptions List": "Benchmark Exceptions List ",
    "Justifications for Exemptions": "Justifications for Exemptions",
    "Mitigating Controls": "Mitigating Controls ",
    "Compensating Controls": "Compensating Controls "
}

# Fields managed exclusively by human analysts that MUST be preserved
MANUAL_FIELDS = [
    "Justifications for Exemptions",
    "Mitigating Controls ",
    "Compensating Controls "
]


def load_and_normalize_csv(file_path: Path) -> pd.DataFrame:
    """Loads a CSV file and strips whitespace from headers and string values."""
    if not file_path.exists():
        raise FileNotFoundError(f"Required file not found: {file_path}")
    
    # Read CSV, ensuring all IPs/IDs are kept cleanly as strings to avoid truncation
    df = pd.read_csv(file_path, dtype=str)
    df.columns = df.columns.str.strip()
    
    # Clean up string values inside cells
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].str.strip()
        
    return df


def generate_composite_key(df: pd.DataFrame, keys: list) -> pd.Series:
    """Generates a unique matching hash key from composite tracking fields."""
    return df[keys].astype(str).agg("-".join, axis=1)


def merge_deviation_sheets(master_path: Path, incoming_scan_path: Path, output_path: Path):
    """Executes the core merge pipeline logic preserving human analysis."""
    print(f"[*] Starting STIG pipeline processing algorithm at {datetime.now()}")
    
    # 1. Ingest datasets
    master_df = load_and_normalize_csv(master_path)
    incoming_df = load_and_normalize_csv(incoming_scan_path)
    
    print(f"[+] Loaded Master Tracker: {len(master_df)} rows.")
    print(f"[+] Loaded Incoming Scan Data: {len(incoming_df)} rows.")
    
    # 2. Establish lookup keys
    master_df["_merge_key"] = generate_composite_key(master_df, MATCH_KEYS)
    incoming_df["_merge_key"] = generate_composite_key(incoming_df, MATCH_KEYS)
    
    # Detect duplicates in latest scan profiles
    scan_duplicates = incoming_df[incoming_df.duplicated(subset=["_merge_key"])]
    if not scan_duplicates.empty:
        print(f"[!] Warning: {len(scan_duplicates)} duplicate keys detected in the incoming scan file.")
    
    # 3. Separate Human Data from Machine Data
    # Isolate existing manual comments to map back later
    manual_data_lookup = master_df[["_merge_key"] + MANUAL_FIELDS].set_index("_merge_key")
    
    # Drop columns from incoming scan data that will be populated via manual preservation
    incoming_clean = incoming_df.drop(columns=[col for col in MANUAL_FIELDS if col in incoming_df.columns])
    
    # 4. Process matches, updates, and additions
    new_findings = []
    updated_rows = []
    unchanged_count = 0
    
    # Create arrays for tracking audit updates
    master_keys = set(master_df["_merge_key"])
    
    for _, scan_row in incoming_clean.iterrows():
        key = scan_row["_merge_key"]
        
        if key in master_keys:
            # Existing host asset: Carry over existing human justifications safely
            merged_row = scan_row.to_dict()
            for field in MANUAL_FIELDS:
                merged_row[field] = manual_data_lookup.loc[key, field]
            updated_rows.append(merged_row)
            unchanged_count += 1
        else:
            # New host asset discovered in recent scans: Drop into review queue
            merged_row = scan_row.to_dict()
            for field in MANUAL_FIELDS:
                merged_row[field] = "PENDING INITIAL ISSO REVIEW"
            new_findings.append(merged_row)
            
    # Combine everything back into a uniform frame
    final_merged_df = pd.DataFrame(updated_rows + new_findings)
    
    # Clean up internal technical tooling columns
    if "_merge_key" in final_merged_df.columns:
        final_merged_df = final_merged_df.drop(columns=["_merge_key"])
        
    # 5. Compile automated audit Change Log metrics
    log_data = {
        "Metric": [
            "Execution Timestamp",
            "Source Deviation Sheet",
            "Source New Scan Ingest",
            "Pre-existing Hosts Verified",
            "New Systems Discovered (Review Queue)",
            "Total Consolidated Database Count"
        ],
        "Value": [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            master_path.name,
            incoming_scan_path.name,
            str(unchanged_count),
            str(len(new_findings)),
            str(len(final_merged_df))
        ]
    }
    change_log_df = pd.DataFrame(log_data)
    
    # 6. Write out cleanly structured Multi-Tab Excel Document
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        final_merged_df.to_excel(writer, sheet_name="Consolidated Master Tracker", index=False)
        change_log_df.to_excel(writer, sheet_name="Change Log Summary", index=False)
        
        # Isolate new items into an explicit actions worksheet
        if new_findings:
            pd.DataFrame(new_findings).drop(columns=["_merge_key"], errors="ignore").to_excel(
                writer, sheet_name="ISSO Review Required", index=False
            )
            
    print(f"[+] Merge completed successfully!")
    print(f"[➔] Review-ready spreadsheet generated at: {output_path}")


if __name__ == "__main__":
    import tkinter as tk
    from tkinter import filedialog

    # initialize a hidden tkinter root window for GUI file selection"
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    # Prompt the user to select the source folder containing the CSVs
    print("[*] Please select the directory containing your source documents in the pop-up window...")
    selected_dir = filedialog.askdirectory(title="Select Folder with Source STIG Documents")
    
    if not selected_dir:
        print("[-] Operation cancelled. No folder selected.")
        exit(1)
        
    # Convert the selected path to a Path object
    source_dir = Path(selected_dir)
    
    # Define file paths based on the user-selected folder
    MASTER_TRACKER = source_dir / "NOAA5047 DISA STIG Deviation Spreadsheet_offline.xlsx - Sheet1.csv"
    INCOMING_SCAN = source_dir / "CATT_Extracted_Data.csv" 
    
    # Keep the output workbook in the user-selected source folder as well
    TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
    OUTPUT_FILE = source_dir / f"NOAA5047_STIG_Master_Merged_{TIMESTAMP}.xlsx"
    
    try:
        merge_deviation_sheets(MASTER_TRACKER, INCOMING_SCAN, OUTPUT_FILE)
    except Exception as e:
        print(f"[-] Critical Error running pipeline execution: {e}")