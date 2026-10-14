import csv
from argparse import Namespace

from gvm.protocols.gmp import GMP


def _text(element, path):
    value = element.findtext(path, '')
    return value.strip() if value else ''


def _host_applications(host):
    applications = []
    for detail in host.findall('detail'):
        detail_name = _text(detail, 'name').casefold()
        value = _text(detail, 'value')
        if detail_name in {'app', 'application', 'software'} and value:
            if value not in applications:
                applications.append(value)
    return applications


def _package_fields(application):
    fields = [field.strip() for field in application.split(':')]
    package_name = fields[2] if len(fields) > 2 else ''
    package_version = fields[3] if len(fields) > 3 else ''
    return package_name, package_version


def main(gmp: GMP, args: Namespace) -> None:
    argv = getattr(args, 'argv', [])
    if len(argv) != 2:
        print('Usage: get_apps.gmp.py <scan-report-uuid>')
        return

    report_id = argv[1]
    report_response = gmp.get_report(
        report_id=report_id,
        details=True,
        ignore_pagination=True,
    )

    hosts = report_response.findall('.//report/host')
    filename = f'{report_id}-apps.csv'
    row_count = 0

    with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow([
            'IP address', 'host name', 'package name', 'package version'
        ])

        for host in hosts:
            ip = _text(host, 'ip') or _text(host, 'name')
            hostname = ''
            for detail in host.findall('detail'):
                if _text(detail, 'name').casefold() == 'hostname':
                    hostname = _text(detail, 'value')
                    if hostname:
                        break

            applications = _host_applications(host)
            if applications:
                for application in applications:
                    package_name, package_version = _package_fields(application)
                    writer.writerow([ip, hostname, package_name, package_version])
                    row_count += 1
            else:
                writer.writerow([ip, hostname, '', ''])
                row_count += 1

    print(f'Wrote {row_count} host/package rows to {filename}')


if __name__ == '__gmp__':
    main(gmp, args)