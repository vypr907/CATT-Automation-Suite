import argparse
import json
import os
import tkinter as tk
from tkinter import filedialog
from pathlib import Path
from typing import Any, Dict, List

from scripts.catt_engine import NessusWorkflow
from scripts.nessus_api_client import configured_nessus_client
from scripts.tsc_auth_client import TSCWindowsCAC


def _as_items(response: Any) -> List[Dict[str, Any]]:
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    if not isinstance(response, dict):
        return []

    for key in ("response", "scanResults", "scanResult", "items"):
        value = response.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _as_items(value)
            if nested:
                return nested
    return []


def _result_id(result: Dict[str, Any]) -> int:
    value = result.get("id", result.get("resultID", result.get("resultId")))
    if value is None:
        raise ValueError(f"TSC result has no ID: {result}")
    return int(value)


def _result_name(result: Dict[str, Any]) -> str:
    return str(
        result.get(
            "name",
            result.get("scanName", result.get("uuid", f"Scan result {_result_id(result)}")),
        )
    )


def _prompt_for_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not results:
        raise RuntimeError("TSC returned no scan results.")

    print("\nAvailable TSC scan results:")
    for index, result in enumerate(results, start=1):
        status = result.get("status", "unknown")
        created = result.get("createdTime", result.get("created", ""))
        print(f"  {index}. {_result_name(result)} (ID {_result_id(result)}, {status}, {created})")

    while True:
        selection = input("Select scan numbers separated by commas, or 'all': ").strip().lower()
        if selection == "all":
            return results
        try:
            indexes = [int(value.strip()) for value in selection.split(",")]
            selected = [results[index - 1] for index in indexes]
            if selected:
                return selected
        except (ValueError, IndexError):
            pass
        print("Invalid selection. Choose displayed scan numbers or 'all'.")


def _download_tsc_results(
    base_url: str,
    input_folder: Path,
    download_path: str,
    force_repick: bool,
) -> None:
    client = TSCWindowsCAC(base_url, force_repick=force_repick)
    response = client.list_scan_results(
        fields="id,name,status,repository,createdTime,scanName"
    )
    selected = _prompt_for_results(_as_items(response))
    input_folder.mkdir(parents=True, exist_ok=True)

    for result in selected:
        result_id = _result_id(result)
        safe_name = "".join(
            character if character.isalnum() or character in " ._-" else "_"
            for character in _result_name(result)
        ).strip()
        output_path = input_folder / f"{safe_name or f'scan_{result_id}'}_{result_id}.nessus"
        print(f"Downloading TSC scan result {result_id} to {output_path}...")
        client.download_scan_result(result_id, output_path, download_path=download_path)


def _download_nessus_results(input_folder: Path, base_url: str | None) -> None:
    client = configured_nessus_client(base_url)
    scans = client.list_scans()
    if not scans:
        raise RuntimeError("Nessus returned no scans.")

    print("\nAvailable Nessus scans:")
    for index, scan in enumerate(scans, start=1):
        print(f"  {index}. {scan.get('name', f'Scan {scan.get('id', '?')}')} (ID {scan.get('id', '?')})")

    while True:
        selection = input("Select scan numbers separated by commas, or 'all': ").strip().lower()
        if selection == "all":
            selected = scans
            break
        try:
            indexes = [int(value.strip()) for value in selection.split(",")]
            selected = [scans[index - 1] for index in indexes]
            if selected:
                break
        except (ValueError, IndexError):
            pass
        print("Invalid selection. Choose displayed scan numbers or 'all'.")

    input_folder.mkdir(parents=True, exist_ok=True)
    for scan in selected:
        scan_id = int(scan["id"])
        safe_name = "".join(
            character if character.isalnum() or character in " ._-" else "_"
            for character in str(scan.get("name", f"scan_{scan_id}"))
        ).strip()
        output_path = input_folder / f"{safe_name or f'scan_{scan_id}'}_{scan_id}.nessus"
        print(f"Downloading Nessus scan {scan_id} to {output_path}...")
        client.download_scan(scan_id, output_path)


def _choose_location_mode() -> bool:
    """Return True when the user wants to choose locations manually."""
    root = tk.Tk()
    root.withdraw()
    dialog = tk.Toplevel(root)
    dialog.title("CATT File Locations")
    dialog.resizable(False, False)
    dialog.protocol("WM_DELETE_WINDOW", lambda: dialog.destroy())

    tk.Label(
        dialog,
        text="Where should downloaded scans and the Excel report be stored?",
        padx=24,
        pady=18,
    ).pack()
    buttons = tk.Frame(dialog, padx=12, pady=12)
    buttons.pack()

    selection = {"manual": False}

    def choose_default() -> None:
        selection["manual"] = False
        dialog.destroy()

    def choose_manual() -> None:
        selection["manual"] = True
        dialog.destroy()

    default_button = tk.Button(
        buttons,
        text="Use Default Locations",
        command=choose_default,
        width=24,
        default="active",
    )
    default_button.pack(side="left", padx=6)
    tk.Button(
        buttons,
        text="Choose Locations Myself",
        command=choose_manual,
        width=24,
    ).pack(side="left", padx=6)
    default_button.focus_set()
    dialog.bind("<Return>", lambda _event: choose_default())
    root.wait_window(dialog)
    root.destroy()
    return selection["manual"]


def _pick_locations(input_folder: Path, output_file: Path) -> tuple[Path, Path]:
    root = tk.Tk()
    root.withdraw()
    selected_input = filedialog.askdirectory(
        title="Choose the folder for downloaded scans or existing Nessus files",
        initialdir=str(input_folder.parent),
    )
    if not selected_input:
        root.destroy()
        raise SystemExit("No input folder selected.")

    selected_output = filedialog.asksaveasfilename(
        title="Choose where to save the Excel report",
        defaultextension=".xlsx",
        filetypes=[("Excel files", "*.xlsx")],
        initialdir=str(output_file.parent),
        initialfile=output_file.name,
    )
    root.destroy()
    if not selected_output:
        raise SystemExit("No output file selected.")
    return Path(selected_input).resolve(), Path(selected_output).resolve()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select TSC or Nessus scans, download them, and extract CAT findings to Excel."
    )
    parser.add_argument(
        "--source", choices=("tsc", "nessus"),
        help="Scan source. If omitted, prompt for TSC or Nessus.",
    )
    parser.add_argument("--input", help="Nessus folder containing .nessus or .zip files")
    parser.add_argument("--output", help="Excel output file path")
    parser.add_argument(
        "--cat", nargs="+", default=["II"],
        help="CAT levels to extract, for example --cat II or --cat I II III",
    )
    parser.add_argument(
        "--tsc-url", default=os.getenv("TSC_BASE_URL"),
        help="TSC base URL, or set TSC_BASE_URL",
    )
    parser.add_argument(
        "--tsc-download-path", default="/rest/scanResult/{id}/download",
        help="TSC scan-result download path template",
    )
    parser.add_argument(
        "--nessus-url", default=os.getenv("NESSUS_URL") or os.getenv("NESSUS_OP_URL"),
        help="Nessus base URL, or set NESSUS_URL/NESSUS_OP_URL",
    )
    parser.add_argument(
        "--force-repick", action="store_true",
        help="Force CAC certificate selection instead of using the cached certificate",
    )
    args = parser.parse_args()

    source = args.source or input("Scan source (tsc/nessus): ").strip().lower()
    if source not in {"tsc", "nessus"}:
        parser.error("source must be 'tsc' or 'nessus'")

    input_folder = Path(args.input or "inputs/downloads").resolve()
    output_file = Path(args.output or "outputs/CATT_Extracted_Data.xlsx").resolve()
    if not (args.input and args.output) and _choose_location_mode():
        input_folder, output_file = _pick_locations(input_folder, output_file)

    if source == "tsc":
        if not args.tsc_url:
            parser.error("--tsc-url or TSC_BASE_URL is required for TSC mode")
        _download_tsc_results(
            args.tsc_url,
            input_folder,
            args.tsc_download_path,
            args.force_repick,
        )
    else:
        if args.input:
            input_folder = Path(args.input).resolve()
        else:
            _download_nessus_results(input_folder, args.nessus_url)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    NessusWorkflow(input_folder, output_file, args.cat).run()
    print(f"Done. Excel report saved to {output_file}")


if __name__ == "__main__":
    main()
