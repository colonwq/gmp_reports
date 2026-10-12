import base64
import re
from gvm.protocols.gmp import GMP
from gvm.protocols.gmp.requests.v224 import ReportFormatType


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
                    report_format_id=ReportFormatType.CSV_RESULTS,
                    ignore_pagination=True,
                )
                report_format = report_response.find('.//report_format')
                if report_format is None or not report_format.tail:
                    raise ValueError('GMP response has no CSV payload in report_format tail')

                encoded_csv = ''.join(report_format.tail.split())
                csv_payload = base64.b64decode(encoded_csv, validate=True)

                with open(filename, mode='wb') as csv_file:
                    csv_file.write(csv_payload)

                print(f"   └── Exported CSV report to {filename}")
            except Exception as e:
                print(f"   └── Failed to export report for {name}: {e}")

if __name__ == '__main__':
    pass

if __name__ == '__gmp__':
    main(gmp, args)