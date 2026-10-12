import csv
import re
from gvm.protocols.gmp import GMP


def _parse_nvt_tags(nvt):
    tags = nvt.findtext('tags', '') if nvt is not None else ''
    return {
        key: value
        for item in tags.split('|')
        if '=' in item
        for key, value in [item.split('=', 1)]
    }


def _reference_values(result):
    references = {'cve': [], 'bid': [], 'cert': [], 'other': []}

    for reference in result.findall('.//ref'):
        kind = reference.get('type', '').lower()
        value = reference.get('id', '') or (reference.text or '').strip()
        if not value:
            continue

        if kind == 'cve':
            bucket = 'cve'
        elif kind == 'bid':
            bucket = 'bid'
        elif kind.startswith('cert'):
            bucket = 'cert'
        else:
            bucket = 'other'
        if value not in references[bucket]:
            references[bucket].append(value)

    for kind in ('cve', 'bid', 'cert'):
        for reference in result.findall(f'.//{kind}'):
            value = (reference.text or '').strip()
            if value and value not in references[kind]:
                references[kind].append(value)

    for reference in result.findall('.//xref'):
        value = reference.get('id', '')
        if value and value not in references['other']:
            references['other'].append(value)

    return {kind: ', '.join(values) for kind, values in references.items()}


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
                # Keep the response in structured GMP XML for field extraction.
                report_response = gmp.get_report(
                    report_id=report_id,
                    filter_string=(
                        'apply_overrides=0 levels=hml min-qod=1 first=1 '
                        'rows=100000 sort=name ignore-pagination=1'
                    ),
                    details=True,
                    report_format_id=CSV_RESULTS, 
                    ignore_pagination=True,
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
                            hostname = result.findtext('hostname', '')
                            if not hostname and host_elem is not None:
                                hostname = host_elem.get('asset', '')
                            
                            # Port details
                            port_full = result.findtext('port', '')
                            port = port_full
                            port_protocol = ''
                            if '/' in port_full:
                                parts = port_full.split('/')
                                port = parts[0]
                                port_protocol = parts[1]

                            # Metrics
                            cvss = (
                                result.findtext('severity', '')
                                or result.findtext('cvss', '')
                                or result.findtext('nvt/cvss_base', '')
                            )
                            severity = threat
                            qod = result.findtext('qod/value', '')
                            
                            # NVT metadata
                            nvt = result.find('nvt')
                            nvt_tags = _parse_nvt_tags(nvt)

                            def nvt_value(element, *tag_names):
                                value = nvt.findtext(element, '') if nvt is not None else ''
                                if value:
                                    return value
                                return next((nvt_tags[key] for key in tag_names if nvt_tags.get(key)), '')

                            nvt_oid = nvt.get('oid', '') if nvt is not None else ""
                            nvt_name = result.findtext('nvt/name', '')
                            
                            solution_elem = result.find('nvt/solution')
                            solution_type = solution_elem.get('type', '') if solution_elem is not None else ''
                            impact = nvt_value('impact', 'impact')
                            solution = nvt_value('solution', 'solution')
                            affected = nvt_value('affected', 'affected')
                            insight = nvt_value('insight', 'insight')
                            vuln_detection_method = nvt_value(
                                'vulnerability_detection_method', 'vuldetect', 'vulnerability_detection_method'
                            )
                            prod_detection_result = nvt_value(
                                'product_detection_result', 'product_detection_result', 'product_detection'
                            )

                            references = _reference_values(result)
                            cves = references['cve']
                            bids = references['bid']
                            certs = references['cert']
                            refs = references['other']

                            summary = nvt_value('summary', 'summary')
                            specific_result = result.findtext('description', '') or result.findtext('scan_result', '')

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
                if not results:
                    print(f"   └── GMP returned no result elements for {name}")
            except Exception as e:
                print(f"   └── Failed to export report for {name}: {e}")

if __name__ == '__main__':
    pass

if __name__ == '__gmp__':
    main(gmp, args)