import argparse
import time
from nessus_tools import Logger
from nessus_tools import NessusWorkflow
from nessus_tools import pick_folders_gui
from pathlib import Path

def main():
    start_time = time.time() # ⏱ start timer

    parser = argparse.ArgumentParser(
        description="Extract CAT findings from Nessus scan files and save to an Excel file."
    )
    parser.add_argument("--input","-i", help="Input folder containing .nessus or .zip files")
    parser.add_argument("--output","-o", help="Output file path for the Excel file")
    parser.add_argument(
        "--cat", "-c", nargs="+", default=["II"],
        help="CAT levels to extract (e.g., --cat II or --cat I II III)"
    )

    args = parser.parse_args()
    
    # -----------------------------------------------
    # Determine input and output folder
    # -----------------------------------------------
    # If user provided input and output arguments, use them directly
    # Otherwise, prompt user to select folders
    # -----------------------------------------------
    if args.input and args.output:
        input_folder = Path(args.input).resolve()
        output_file = Path(args.output).resolve()
        cat_lvls = args.cat
    else:
        input_folder_path, output_file_path = pick_folders_gui()
        input_folder = Path(input_folder_path).resolve()
        output_file = Path(output_file_path).resolve()
        cat_lvls = ["II"]

    # -----------------------------------------------
    # Run the workflow
    # -----------------------------------------------
    workflow = NessusWorkflow(input_folder, output_file, cat_lvls)
    workflow.run()
# -----------------------------------------------
    # Print a success message
    # -----------------------------------------------
    print(f"✅ Done! Data saved to {output_file}")

    # -----------------------------------------------
    # 🕒 End timer and log/print execution time
    # -----------------------------------------------
    end_time = time.time() # ⏱ end timer
    elapsed = end_time - start_time
    minutes, seconds = divmod(int(elapsed), 60)

    Logger.log(f"⏱ Ran in {minutes}:{seconds}.")
    print(f"⏱ Execution time: {minutes}:{seconds}")


if __name__ == "__main__":
    main()
# g:\My Drive\CATT_EXTRACTOR\main.py