import pandas as pd
import requests

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

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
            'cpeMatchString': f'cpe:2.3:*:*:{component}:{version_prefix}*:*:*:*:*:*:*',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
    else:
        params = {
            'cpeMatchString': f'cpe:2.3:*:*:{component}:*:*:*:*:*:*:*',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }

    while True:
        response = requests.get(NVD_URL, params=params)
        data = response.json()

        if 'result' not in data:
            print(f"Unexpected response for component {component} and version prefix {version_prefix}:")
            print(data)
            break

        for item in data['result']['CVE_Items']:
            cve_data = item['cve']
            impact_data = item.get('impact', {})
            base_metric_data = impact_data.get('baseMetricV3', {})
            cve_id = cve_data['CVE_data_meta']['ID']
            
            if (component, version_prefix, cve_id) not in seen_vulnerabilities:
                seen_vulnerabilities.add((component, version_prefix, cve_id))
                
                vulnerabilities.append({
                    'component': component,
                    'version': version_prefix if version_prefix else 'All',
                    'cve': cve_id,
                    'description': cve_data['description']['description_data'][0]['value'],
                    'cvss': base_metric_data.get('cvssV3', {}).get('baseScore', 'N/A'),
                    'severity': base_metric_data.get('cvssV3', {}).get('baseSeverity', 'N/A'),
                    'cvss_string': base_metric_data.get('cvssV3', {}).get('vectorString', 'N/A')
                })

            # Extract CPEs for the version of the component that was scanned
            for node in item['configurations']['nodes']:
                if 'cpe_match' in node:
                    for cpe_data in node['cpe_match']:
                        cpe_uri = cpe_data['cpe23Uri']
                        if cpe_uri not in seen_cpe_entries:
                            seen_cpe_entries.add(cpe_uri)
                            cpe_component_name = cpe_uri.split(':')[4]
                            cpe_entries.append({
                                'component': component,
                                'version': version_prefix if version_prefix else 'All',
                                'cpe': cpe_uri,
                                'cpe_component_name': cpe_component_name
                            })

        if len(data['result']['CVE_Items']) < results_per_page:
            break

        start_index += results_per_page
        params['startIndex'] = start_index

    return vulnerabilities, cpe_entries

def write_to_excel(vulnerabilities_data, cpe_data, output_file_name):
    with pd.ExcelWriter(output_file_name) as writer:
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
