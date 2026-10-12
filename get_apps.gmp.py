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
    if not hosts:
        print(f'No host details found in scan report {report_id}.')
        return

    print(f'Hosts and discovered software in report {report_id}:')
    for host in hosts:
        ip = _text(host, 'ip') or _text(host, 'name') or 'Unknown IP'
        hostname = ''
        for detail in host.findall('detail'):
            if _text(detail, 'name').casefold() == 'hostname':
                hostname = _text(detail, 'value')
                if hostname:
                    break

        label = f'{ip} ({hostname})' if hostname else ip
        applications = _host_applications(host)
        print(f'\n{label}')
        if applications:
            for application in applications:
                print(f'  {application}')
        else:
            print('  No software details found')


if __name__ == '__gmp__':
    main(gmp, args)