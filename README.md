# Nessus Cat II Compliance Extractor

## Overview

This Python script automates the extraction of Category II (Cat II) failed compliance findings from Tenable Nessus scan results. It uses the Nessus API to export scan data in .nessus (XML) format, parses the XML for relevant failed checks where the reference includes "CAT: II" (or "CAT|II"), and outputs the extracted data to an Excel workbook. Each specified scan is processed separately and written to its own sheet in the workbook.

The tool is designed for compliance scans (e.g., STIG-based audits on systems like RHEL), focusing on failed items with Cat II severity. It also parses check names to separate STIG IDs from descriptions for better organization.

## Features

- **API Authentication**: Securely logs into the Nessus server using username and password.
- **Multi-Scan Support**: Processes a list of scan IDs, exporting and parsing each one.
- **XML Parsing**: Extracts detailed fields from compliance tags, including Host, Plugin ID, STIG ID, Description, Full Check Name, Result, Reference, Actual Value, Policy Value, Audit File, See Also, Solution, and Info.


## Overview

CATT Extractor is a Python script designed to automate the extraction of Category II (Cat II) failed compliance findings from Tenable Nessus scans. It connects to a Nessus server via the API, exports scan results in .nessus (XML) format, parses the XML for relevant failed checks, and outputs the data into an Excel workbook. Each scan can be processed individually or in batch, with results placed in separate sheets within a single Excel file.

This tool is particularly useful for security analysts and compliance teams working with STIG-based audits on systems like RHEL, where Cat II findings need to be isolated and reported efficiently.

## Features

- **API Integration**: Authenticates with Nessus and exports scan data programmatically.
- **Compliance Filtering**: Extracts only FAILED compliance checks tagged as "CAT: II" (or "CAT|II") in the reference information.
- **Data Parsing**: Handles XML structure to pull key fields such as Host, Plugin ID, STIG ID, Description, Actual Value, Policy Value, and more.
- **Check Name Splitting**: Automatically separates STIG IDs (e.g., "RHEL-08-010040") from the full check name for better organization.
- **Multi-Scan Support**: Processes multiple scan IDs, creating one sheet per scan in a consolidated Excel file.
- **Customizable**: Easily extendable to include additional fields or adjust filters.

## Requirements

- Python 3.6+ (tested on 3.12)
- Required libraries:
  - `pandas` (for DataFrame handling and Excel export)
  - `xml.etree.ElementTree` (built-in for XML parsing)
  - `urllib.request`, `json`, `time`, `ssl` (built-in)
- Install dependencies: `pip install pandas xlsxwriter`
- Access to a Tenable Nessus server (on-prem) with API enabled.
- Valid Nessus credentials (username and password).
- Scan IDs from Nessus (found in the web UI or via API).

**Note**: For self-signed certificates, the script includes an optional SSL verification bypass (use cautiously on trusted networks).

## Installation

1. Clone or download the repository:
   ```
   git clone https://github.com/your-repo/catt-extractor.git
   cd catt-extractor
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

   Create a `requirements.txt` if not present:
   ```
   pandas
   xlsxwriter
   ```

## Usage

1. Configure the script (`catt_extract_nessus.py`):
   - Update `NESSUS_URL`, `USERNAME`, `PASSWORD`.
   - Set `SCAN_IDS` to a list of integers (e.g., `[123, 456]`).

2. Run the script:
   ```
   python catt_extract_nessus.py
   ```

3. Output:
   - Generates `nessus_multi_scan_cat_ii_failed.xlsx` with sheets named `Scan_{ID}` for each processed scan.
   - If no Cat II findings are found for a scan, the sheet is skipped, and a message is printed.

### Example Configuration Snippet

```python
NESSUS_URL = 'https://your-nessus-server:8834'
USERNAME = 'your_username'
PASSWORD = 'your_password'
SCAN_IDS = [123, 456, 789]  # List of Nessus scan IDs
```

### Handling Specific Scan Runs

To target a historical run of a scan (not the latest), add `'history_id': your_history_id` to the `export_data` dictionary. Retrieve history IDs via the Nessus API (GET `/scans/{scan_id}/history`).

## Script Structure

- **Authentication**: Logs in to obtain a session token.
- **Export Loop**: For each scan ID, requests .nessus export, waits for readiness, and downloads.
- **XML Parsing**: Uses ElementTree to navigate namespaces and extract compliance data.
- **Filtering**: Checks for 'FAILED' results and 'CAT: II' in references.
- **Data Enrichment**: Splits check names into STIG ID and description.
- **Excel Output**: Uses `pd.ExcelWriter` to create multi-sheet workbooks.

## Troubleshooting

- **SSL Errors**: If certificate verification fails, enable the SSL bypass in the script or add the Nessus cert to your trusted store.
- **No Data Found**: Verify scan types (must be compliance scans), CAT formatting in references, or print debug info (e.g., reference texts).
- **API Limits**: Large scans may require pagination or timeouts; adjust `time.sleep` as needed.
- **XML Parsing Issues**: Ensure `lxml` is installed for better performance (`pip install lxml`), though not required.

For detailed error logs, add `try-except` blocks around API calls.

## Contributing

Contributions are welcome! Fork the repo, make changes, and submit a pull request. Please include tests for new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with insights from Tenable Nessus API documentation.
- Thanks to the open-source community for libraries like pandas and ElementTree.