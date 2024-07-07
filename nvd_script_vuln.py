import pandas as pd
import requests
from time import sleep

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

def read_input_excel(file_name):
    return pd.read_excel(file_name)

def fetch_vulnerabilities_from_nvd(component, version_prefix=None):
    vulnerabilities = []
    cpe_entries = []
    seen_vulnerabilities = set()  # Track seen (component, version, cve) combos
    seen_cpe_entries = set()      # Track seen CPEs for uniqueness
    results_per_page = 2000
    start_index = 0
    
    # Adjust CPE matching string based on the version_prefix availability
    if version_prefix:
        params = {
            'cpeName': f'cpe:2.3:*:*:{component}:{version_prefix}*:*:*:*:*:*:*',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
    else:
        params = {
            'cpeName': f'cpe:2.3:*:*:{component}:*:*:*:*:*:*:*',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }

    while True:
        response = requests.get(NVD_URL, params=params)
        if response.status_code == 429:
            print("Rate limit reached. Waiting for 30 seconds before retrying...")
            sleep(30)
            continue
        data = response.json()

        if 'vulnerabilities' not in data:
            print(f"Unexpected response for component {component} and version prefix {version_prefix}:")
            print(data)
            break

        for item in data['vulnerabilities']:
            cve_data = item['cve']
            metrics = cve_data.get('metrics', {})
            cvssv3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            cve_id = cve_data['id']
            
            if (component, version_prefix, cve_id) not in seen_vulnerabilities:
                seen_vulnerabilities.add((component, version_prefix, cve_id))
                
                vulnerabilities.append({
                    'component': component,
                    'version': version_prefix if version_prefix else 'All',
                    'cve': cve_id,
                    'description': cve_data['descriptions'][0]['value'],
                    'cvss': cvssv3.get('baseScore', 'N/A'),
                    'severity': cvssv3.get('baseSeverity', 'N/A'),
                    'cvss_string': cvssv3.get('vectorString', 'N/A')
                })

            # Extract CPEs for the version of the component that was scanned
            for cpe in cve_data.get('configurations', []):
                for node in cpe.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_uri = cpe_match['criteria']
                        if cpe_uri not in seen_cpe_entries:
                            seen_cpe_entries.add(cpe_uri)
                            cpe_component_name = cpe_uri.split(':')[4]
                            cpe_entries.append({
                                'component': component,
                                'version': version_prefix if version_prefix else 'All',
                                'cpe': cpe_uri,
                                'cpe_component_name': cpe_component_name
                            })

        if len(data['vulnerabilities']) < results_per_page:
            break

        start_index += results_per_page
        params['startIndex'] = start_index

    return vulnerabilities, cpe_entries

def write_to_excel(vulnerabilities_data, cpe_data, output_file_name):
    with pd.ExcelWriter(output_file_name, engine='openpyxl') as writer:
        pd.DataFrame(vulnerabilities_data).to_excel(writer, sheet_name='vulns', index=False)
        pd.DataFrame(cpe_data).to_excel(writer, sheet_name='Comp_CPE', index=False)

def main():
    input_file_name = 'input.xlsx'
    output_file_name = 'output.xlsx'

    components = read_input_excel(input_file_name)

    all_vulnerabilities = []
    all_cpe_entries = []

    for index, row in components.iterrows():
        component = row['component']
        version = row.get('version', None)  # Default to None if version isn't present
        vulnerabilities, cpe_entries = fetch_vulnerabilities_from_nvd(component, version)
        all_vulnerabilities.extend(vulnerabilities)
        all_cpe_entries.extend(cpe_entries)

    write_to_excel(all_vulnerabilities, all_cpe_entries, output_file_name)

if __name__ == '__main__':
    main()
