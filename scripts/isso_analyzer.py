import pandas as pd

# 1. Load the data
file_path = 'CATT_Extracted_Data.xlsx'
all_sheets = pd.read_excel(file_path, sheet_name=None)

# 2. Combine all sheets into one Master DataFrame and filter for Fails
df_list = []
for sheet_name, data in all_sheets.items():
    # Ensure standard column names and add source sheet info
    data['Source_Sheet'] = sheet_name
    df_list.append(data)

master_df = pd.concat(df_list, ignore_index=True)
failed_df = master_df[master_df['Result'] == 'FAILED'].copy()

# 3. Create Sheet 1: Hostnames with STIG cross-references
# We group by Hostname and join all unique STIG IDs into one string
hosts_df = failed_df.groupby('Hostname').agg({
    'STIG ID': lambda x: ', '.join(x.unique()),
    'IP Address': 'first' # Keeps the IP associated with the host
}).reset_index()
hosts_df.rename(columns={'STIG ID': 'Associated_STIGs'}, inplace=True)

# 4. Create Sheet 2: STIGs with Hostname cross-references
# We group by STIG ID and join all unique Hostnames into one string
stigs_df = failed_df.groupby('STIG ID').agg({
    'Hostname': lambda x: ', '.join(x.unique()),
    'Severity': 'first',
    'Finding': 'first'
}).reset_index()
stigs_df.rename(columns={'Hostname': 'Affected_Hosts'}, inplace=True)

# 5. Create Sheet 3: Individual Findings
# This is the raw list of every failure for granular tracking
findings_df = failed_df[['Hostname', 'IP Address', 'STIG ID', 'Severity', 'Finding', 'Source_Sheet']]

# 6. Save to a new Workbook with three sheets
with pd.ExcelWriter('PAAN_STIG_Analysis_Workbook.xlsx') as writer:
    hosts_df.to_excel(writer, sheet_name='Hostnames', index=False)
    stigs_df.to_excel(writer, sheet_name='STIG_IDs', index=False)
    findings_df.to_excel(writer, sheet_name='All_Findings', index=False)

print("Workbook created successfully!")