import csv
import re
from gvm.protocols.gmp import GMP

def main(gmp: GMP, args):
    # Fetch tasks using the GMP protocol
    response = gmp.get_tasks()
    tasks = response.xpath('task')

    print(f"{'Name':<40} | {'UUID':<36} | {'Last Run'}")
    print("-" * 115)

    for task in tasks:
        name_elem = task.find('name')
        name = name_elem.text if name_elem is not None else "Unknown"
        task_id = task.get('id')

        # Extract the last report's scan end date/time and report ID from the nested report element
        last_report = task.find('last_report')
        last_run = "Never"
        report_id = None

        if last_report is not None:
            report_elem = last_report.find('report')
            if report_elem is not None:
                report_id = report_elem.get('id')
            
            scan_end = last_report.find('.//scan_end')
            if scan_end is not None and scan_end.text:
                last_run = scan_end.text

        print(f"{name:<40} | {task_id:<36} | {last_run}")

        # If a last report exists, fetch it and export findings to CSV
        if report_id and last_run != "Never":
            # Sanitize name and timestamp for a valid filename
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
            safe_last_run = re.sub(r'[^a-zA-Z0-9_-]', '_', last_run)
            filename = f"{safe_name}-{safe_last_run}.csv"

            try:
                # Fetch report with details and ignore pagination; filter severity in Python
                report_response = gmp.get_report(
                    report_id=report_id, 
                    details=True, 
                    ignore_pagination=True
                )
                results = report_response.findall('.//result')

                with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
                    writer = csv.writer(csv_file)
                    
                    # Exact requested CSV Header
                    headers = [
                        'IP', 'Hostname', 'Port', 'Port Protocol', 'CVSS', 'Severity', 
                        'QoD', 'Solution Type', 'NVT Name', 'Summary', 'Specific Result', 
                        'NVT OID', 'CVEs', 'Task ID', 'Task Name', 'Timestamp', 
                        'Result ID', 'Impact', 'Solution', 'Affected Software/OS', 
                        'Vulnerability Insight', 'Vulnerability Detection Method', 
                        'Product Detection Result', 'BIDs', 'CERTs', 'Other References'
                    ]
                    writer.writerow(headers)

                    count = 0
                    for result in results:
                        threat_elem = result.find('threat')
                        threat = threat_elem.text if threat_elem is not None else "Unknown"

                        # Filter for High, Medium, and Low findings in Python
                        if threat in ['High', 'Medium', 'Low']:
                            # Extract basic fields
                            result_id = result.get('id', '')
                            timestamp = result.findtext('creation_time', '')
                            
                            # Host / IP / Hostname extraction
                            host_elem = result.find('host')
                            ip = host_elem.text if host_elem is not None else ""
                            hostname = host_elem.get('asset', '') if host_elem is not None else ""
                            
                            # Port details
                            port_full = result.findtext('port', '')
                            port = port_full
                            port_protocol = ''
                            if '/' in port_full:
                                parts = port_full.split('/')
                                port = parts[0]
                                port_protocol = parts[1]

                            # Metrics
                            cvss = result.findtext('cvss', '')
                            severity = result.findtext('severity', '')
                            qod = result.findtext('qod/value', '')
                            
                            # NVT metadata
                            nvt = result.find('nvt')
                            nvt_oid = nvt.get('oid', '') if nvt is not None else ""
                            nvt_name = result.findtext('nvt/name', '')
                            
                            solution_elem = result.find('nvt/solution')
                            solution_type = solution_elem.get('type', '') if solution_elem is not None else ''
                            impact = result.findtext('nvt/impact', '')
                            solution = result.findtext('nvt/solution', '')
                            affected = result.findtext('nvt/affected', '')
                            insight = result.findtext('nvt/insight', '')
                            vuln_detection_method = result.findtext('nvt/vulnerability_detection_method', '')
                            prod_detection_result = result.findtext('nvt/product_detection_result', '')

                            # References & CVEs (aggregating comma-separated text)
                            cves = ", ".join([cve.text for cve in result.findall('.//cve') if cve.text])
                            bids = ", ".join([bid.text for bid in result.findall('.//bid') if bid.text])
                            certs = ", ".join([cert.text for cert in result.findall('.//cert') if cert.text])
                            refs = ", ".join([ref.get('id', '') for ref in result.findall('.//xref') if ref.get('id')])

                            summary = result.findtext('description', '')
                            specific_result = result.findtext('scan_result', '')

                            # Clean up line breaks in large descriptive fields
                            def clean_text(val):
                                return val.replace('\n', ' ').replace('\r', ' ') if val else ''

                            row = [
                                ip, hostname, port, port_protocol, cvss, severity, 
                                qod, solution_type, nvt_name, clean_text(summary), clean_text(specific_result), 
                                nvt_oid, cves, task_id, name, timestamp, 
                                result_id, clean_text(impact), clean_text(solution), clean_text(affected), 
                                clean_text(insight), clean_text(vuln_detection_method), 
                                clean_text(prod_detection_result), bids, certs, refs
                            ]
                            
                            writer.writerow(row)
                            count += 1

                print(f"   └── Exported {count} findings to {filename}")
            except Exception as e:
                print(f"   └── Failed to export report for {name}: {e}")

if __name__ == '__main__':
    pass

if __name__ == '__gmp__':
    main(gmp, args)