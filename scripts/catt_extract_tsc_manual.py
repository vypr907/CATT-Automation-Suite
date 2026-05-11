import pandas as pd
import glob
import os

def extract_cat2_findings(input_folder, output_folder):
    '''
    Reads all Tenable CSV scan result files in a folder,
    extracts rows where Cross-References contain CAT:II,
    and writes them to an Excel file with one sheet per scan.
    '''
    # Get a list of all .csv files in the input folder
    csv_files = glob.glob(os.path.join(input_folder, '*.csv'))

    if not csv_files:
        print("No CSV files found in", input_folder)
        return
    
    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        for csv_file in csv_files:
            try:
                # Load the CSV file into a DataFrame
                df = pd.read_csv(csv_file, encoding='utf-8', errors='ignore')

                # Normalize the column names
                df.columns = df.columns.str.strip().str.lower()

                # Try to find cross-reference column
                xref_col = None
                for col in df.columns:
                    if 'xref' in col.lower() or 'cross' in col.lower():
                        xref_col = col
                        break

                if not xref_col:
                    print(f"⚠️ Skipping {csv_file}, no Cross-References column found")
                    continue

                # Filter rows where Cross-References contain 'CAT: II'
                df_cat2 = df[df[xref_col].astype(str).str.contains('CAT: II', case=False, na=False)]

                if df_cat2.empty:
                    print(f"ℹ️ No CAT II findings in {csv_file}")
                    continue

                # Sheet name from filename
                sheet_name = os.path.splitext(os.path.basename(csv_file))[0][:31]

                # Write filtered rows
                df_cat2.to_excel(writer, sheet_name=sheet_name, index=False)
                print(f"✅ Processed {csv_file}, wrote {len(df_cat2)} CAT II findings")
            except Exception as e:
                print(f"❌ Error processing {csv_file}: {e}")

    print(f"\n🎉 Finished! CAT II findings saved in {output_file}")


if __name__ == "__main__":
    input_folder = 'path/to/your/csv/files'  # Change this to your input folder
    output_file = 'CAT_II_FINDINGS.xlsx'  # Output Excel file

    extract_cat2_findings(input_folder, output_file)