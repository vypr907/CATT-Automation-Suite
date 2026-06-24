#!/usr/bin/env python3
"""
STIG Deviation Merge Engine (Robust Injection Release)
Description: Dynamically handles local .xlsx and .csv file selections.
             Features auto-mapping for standard Tenable network headers 
             and addresses Pandas 3.0/4.0 text-selection syntax specifications.
"""

import os
from datetime import datetime
from pathlib import Path
import pandas as pd
import tkinter as tk
from tkinter import filedialog

# ==============================================================================
# CONFIGURATION & COLUMN MAPPING
# ==============================================================================
# The exact column names expected in your MASTER deviation sheet
MASTER_MATCH_KEYS = ["IP Address", "Host Name"]

# Human-managed data fields that must be preserved
MANUAL_FIELDS = [
    "Justifications for Exemptions",
    "Mitigating Controls ",
    "Compensating Controls "
]

# Common alternative column names found in Tenable/Nessus exports
POTENTIAL_IP_HEADERS = ["IP Address", "IP", "ip", "Host IP", "Asset IP Address"]
POTENTIAL_HOST_HEADERS = ["Host Name", "Host", "host", "Hostname", "hostname", "DNS", "DNS Name"]


def load_local_source(file_target) -> pd.DataFrame:
    """Dynamically ingests data based on local file extension (.csv or .xlsx)."""
    file_path = Path(file_target)
    if not file_path.exists():
        raise FileNotFoundError(f"Target file not found: {file_path}")
    
    ext = file_path.suffix.lower()
    
    if ext == ".csv":
        print(f"[+] Parsing local CSV file: {file_path.name}")
        df = pd.read_csv(file_path, dtype=str)
    elif ext in [".xlsx", ".xlsm"]:
        print(f"[+] Parsing local Excel Workbook: {file_path.name}")
        df = pd.read_excel(file_path, dtype=str, sheet_name=0)
    else:
        raise ValueError(f"Unsupported file extension format: {ext}")
    
    # Clean up column headers (strip whitespaces)
    df.columns = df.columns.astype(str).str.strip()
    
    # Modern Pandas 3.0/4.0 safe string-trimming method to clear deprecation warnings
    string_cols = df.select_dtypes(include=["object", "string", "any"]).columns
    for col in string_cols:
        df[col] = df[col].astype(str).str.strip()
        
    return df


def normalize_scan_headers(scan_df: pd.DataFrame) -> pd.DataFrame:
    """Detects alternative Tenable network column layouts and maps them to master keys."""
    columns_present = list(scan_df.columns)
    rename_map = {}
    
    # Look for a usable IP column variation
    for ip_opt in POTENTIAL_IP_HEADERS:
        if ip_opt in columns_present:
            rename_map[ip_opt] = "IP Address"
            break
            
    # Look for a usable Hostname column variation
    for host_opt in POTENTIAL_HOST_HEADERS:
        if host_opt in columns_present:
            rename_map[host_opt] = "Host Name"
            break
            
    if rename_map:
        print(f"[*] Auto-mapping scan headers: {rename_map}")
        scan_df = scan_df.rename(columns=rename_map)
        
    return scan_df


def merge_deviation_sheets(master_source, incoming_source, output_dir: Path):
    """Core merge engine pipeline handling mixed data formats."""
    print(f"\n[*] Starting STIG pipeline processing algorithm at {datetime.now()}")
    
    master_df = load_local_source(master_source)
    incoming_raw_df = load_local_source(incoming_source)
    
    # Apply dynamic header translation matrix to incoming scan data
    incoming_df = normalize_scan_headers(incoming_raw_df)
    
    print(f"[+] Loaded Master Tracker: {len(master_df)} rows.")
    print(f"[+] Loaded Incoming Scan Data: {len(incoming_df)} rows.")
    
    # Safe validation check - ensures match keys are available before joining arrays
    for key in MASTER_MATCH_KEYS:
        if key not in master_df.columns:
            print(f"[-] Diagnostic: Master Sheet contains these columns: {list(master_df.columns)}")
            raise KeyError(f"Required tracking column '{key}' is missing from the MASTER sheet.")
        if key not in incoming_df.columns:
            print(f"[-] Diagnostic: Incoming Scan Sheet contains these columns: {list(incoming_df.columns)}")
            raise KeyError(f"Could not locate a match for tracking column '{key}' in the INCOMING scan sheet.")
    
    # Generate composite lookup keys
    master_df["_merge_key"] = master_df[MASTER_MATCH_KEYS].astype(str).agg("-".join, axis=1)
    incoming_df["_merge_key"] = incoming_df[MASTER_MATCH_KEYS].astype(str).agg("-".join, axis=1)
    
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
        
    TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"NOAA5047_STIG_Master_Merged_{TIMESTAMP}.xlsx"
    
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        final_merged_df.to_excel(writer, sheet_name="Consolidated Master Tracker", index=False)
        if new_findings:
            pd.DataFrame(new_findings).to_excel(writer, sheet_name="ISSO Review Required", index=False)
            
    print(f"[+] Merge completed successfully!")
    print(f"[➔] Review-ready spreadsheet generated at: {output_path}")


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    
    file_types = [("Spreadsheets", "*.xlsx *.csv *.xlsm"), ("Excel Workbooks", "*.xlsx"), ("Flat CSV Records", "*.csv")]
    
    print("[*] Please locate your Master Tracker spreadsheet file...")
    MASTER_TARGET = filedialog.askopenfilename(title="Select MASTER Deviation Tracker Spreadsheet", filetypes=file_types)
    
    print("[*] Please locate your Incoming Scan sheet data file...")
    INCOMING_TARGET = filedialog.askopenfilename(title="Select INCOMING Scan Findings File", filetypes=file_types)
    
    if not MASTER_TARGET or not INCOMING_TARGET:
        print("[-] Required selections are missing. Terminating execution.")
        exit(1)
        
    OUTPUT_DIRECTORY = Path(MASTER_TARGET).parent
    merge_deviation_sheets(MASTER_TARGET, INCOMING_TARGET, OUTPUT_DIRECTORY)