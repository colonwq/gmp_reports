from gvm.protocols.gmp import GMP


def _print_element(element, depth=0):
    indent = '  ' * depth
    attributes = ''.join(
        f' {key}={value!r}'
        for key, value in element.attrib.items()
    )
    print(f'{indent}<{element.tag}{attributes}>')

    text = (element.text or '').strip()
    if text:
        for line in text.splitlines():
            print(f'{indent}  {line.strip()}')

    for child in element:
        _print_element(child, depth + 1)


def main(gmp: GMP, args):
    response = gmp.get_tasks()
    tasks = response.xpath('task')

    for task in tasks:
        name_elem = task.find('name')
        name = name_elem.text if name_elem is not None and name_elem.text else 'Unknown'
        task_id = task.get('id', '')
        last_report = task.find('last_report')
        report_elem = last_report.find('report') if last_report is not None else None
        report_id = report_elem.get('id') if report_elem is not None else None

        if not report_id:
            continue

        print(f'\nTask: {name} ({task_id}) | Report: {report_id}')
        try:
            report_response = gmp.get_report(
                report_id=report_id,
                details=True,
                ignore_pagination=True,
            )
            _print_element(report_response)
        except Exception as error:
            print(f'Failed to read report {report_id} for {name}: {error}')


if __name__ == '__main__':
    pass

if __name__ == '__gmp__':
    main(gmp, args)
