import urllib.request
import json
import time
import pandas as pd
import xml.etree.ElementTree as ET
from io import StringIO
import ssl # For SSL bypass
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

# Disable SSL verification (not recommended for production)
# Note: This is insecure and should only be used in trusted environments.
context = ssl.create_default_context();
context.check_hostname = False;
context.verify_mode = ssl.CERT_NONE

# Configuration - #Operational Suite
NESSUS_OP_URL = os.getenv('NESSUS_OP_URL')
USERNAME = os.getenv('NESSUS_USERNAME')
PASSWORD_OP = os.getenv('NESSUS_OP_PASSWORD')
# - #Test Suite
NESSUS_IT_URL = os.getenv('NESSUS_IT_URL')
PASSWORD_IT = os.getenv('NESSUS_IT_PASSWORD')

# Scan IDs
SCAN_ID = 1182
SCAN_RHEL8_IT = 596
SCAN_RHEL9_IT = 1182

# Step 1: Authenticate and get token
login_data = json.dumps({'username': USERNAME, 'password': PASSWORD_OP}).encode('utf-8')
req = urllib.request.Request(f'{NESSUS_OP_URL}/session', data=login_data, headers={'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req, context=context) as response:
    token = json.loads(response.read().decode('utf-8'))['token']

# Step 2: Request export of the scan in .nessus (XML) format
export_data = json.dumps({'format': 'nessus'}).encode('utf-8')
req = urllib.request.Request(f'{NESSUS_OP_URL}/scans/{SCAN_ID}/export', data=export_data, headers={'X-Cookie': f'token={token}', 'Content-Type': 'application/json'}, method='POST')
with urllib.request.urlopen(req, context=context) as response:
    export_response = json.loads(response.read().decode('utf-8'))
    file_id = export_response['file']

# Step 3: Check export status until ready
while True:
    req = urllib.request.Request(f'{NESSUS_OP_URL}/scans/{SCAN_ID}/export/{file_id}/status', headers={'X-Cookie': f'token={token}'})
    with urllib.request.urlopen(req, context=context) as response:
        status = json.loads(response.read().decode('utf-8'))['status']
    if status == 'ready':
        break
    time.sleep(5)

# Step 4: Download the .nessus file
req = urllib.request.Request(f'{NESSUS_OP_URL}/scans/{SCAN_ID}/export/{file_id}/download', headers={'X-Cookie': f'token={token}'})
with urllib.request.urlopen(req, context=context) as response:
    nessus_content = response.read().decode('utf-8')

# Step 5: Parse the .nessus XML content
root = ET.fromstring(nessus_content)
ns = {'cm': 'http://www.nessus.org/cm'}

# List to hold extracted data
data = []

for report_host in root.findall('.//ReportHost'):
    host_name = report_host.get('name')  #IP or hostname
    for report_item in report_host.findall('ReportItem'):
        result_elem = report_item.find('cm:compliance-result', ns)
        if result_elem is not None and result_elem.text == 'FAILED':
            reference_elem = report_item.find('cm:compliance-reference', ns)
            if reference_elem is not None and reference_elem.text and ('CAT: II' in reference_elem.text or 'CAT|II' in reference_elem.text):
                # Extract relevant fields (customize as needed)
                full_check_name = report_item.find('cm:compliance-check-name', ns).text if report_item.find('cm:compliance-check-name', ns) is not None else ''

                # Split the check name into STIG ID and Description
                if ' - ' in full_check_name:
                    stig_id, description = full_check_name.split(' - ', 1)
                else:
                    stig_id = full_check_name
                    description = ''

                actual_value = report_item.find('cm:compliance-actual-value', ns).text if report_item.find('cm:compliance-actual-value', ns) is not None else ''
                policy_value = report_item.find('cm:compliance-policy-value', ns).text if report_item.find('cm:compliance-policy-value', ns) is not None else ''
                audit_file = report_item.find('cm:compliance-audit-file', ns).text if report_item.find('cm:compliance-audit-file', ns) is not None else ''
                see_also = report_item.find('cm:compliance-see-also', ns).text if report_item.find('cm:compliance-see-also', ns) is not None else ''
                solution = report_item.find('cm:compliance-solution', ns).text if report_item.find('cm:compliance-solution', ns) is not None else ''
                info = report_item.find('cm:compliance-info', ns).text if report_item.find('cm:compliance-info', ns) is not None else ''
                
                data.append({
                    'Host': host_name,
                    'Plugin ID': report_item.get('pluginID'),
                    'STIG ID': stig_id.strip(),
                    'Description': description.strip(),
                    'Full Check Name': full_check_name,
                    'Result': 'FAILED',
                    'Reference': reference_elem.text,
                    'Actual Value': actual_value,
                    'Policy Value': policy_value,
                    'Audit File': audit_file,
                    'See Also': see_also,
                    'Solution': solution,
                    'Info': info,
                    # Add more fields like description = report_item.find('description').text if needed
                })

# Step 6: Convert to DataFram and export to Excel
if data:
    df = pd.DataFrame(data)
    df.to_excel('NESSUS_CAT_II_FINDINGS.xlsx', index=False)
    print('Cat II findings exported to nessus_cat_ii_findings.xlsx')
else:
    print('No Cat II findings found.')