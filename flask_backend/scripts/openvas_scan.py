import os
import time
import xml.etree.ElementTree as ET


def _get_env(name, default=''):
    return os.getenv(name, default).strip()


def _find_first_id(xml_text, tag_suffix):
    root = ET.fromstring(xml_text)
    for elem in root.iter():
        if elem.tag.endswith(tag_suffix) and 'id' in elem.attrib:
            return elem.attrib['id']
    return None


def _find_first_text(xml_text, tag_suffix):
    root = ET.fromstring(xml_text)
    for elem in root.iter():
        if elem.tag.endswith(tag_suffix):
            return (elem.text or '').strip()
    return ''


def _find_target_id_by_name(gmp, target_name):
    xml_text = gmp.get_targets()
    root = ET.fromstring(xml_text)
    for elem in root.iter():
        if elem.tag.endswith('target') and 'id' in elem.attrib:
            for child in list(elem):
                if child.tag.endswith('name') and (child.text or '').strip() == target_name:
                    return elem.attrib['id']
    return None


def _summarize_report(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return (xml_text or 'OpenVAS returned non-XML report output.')[:5000]

    severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    results = []
    for elem in root.iter():
        if not elem.tag.endswith('result'):
            continue

        name = ''
        severity_value = 0.0
        host = ''
        port = ''

        for child in list(elem):
            tag = child.tag
            text = (child.text or '').strip()
            if tag.endswith('name'):
                name = text
            elif tag.endswith('host'):
                host = text
            elif tag.endswith('port'):
                port = text
            elif tag.endswith('severity'):
                try:
                    severity_value = float(text)
                except ValueError:
                    severity_value = 0.0

        if severity_value >= 9.0:
            severities['critical'] += 1
        elif severity_value >= 7.0:
            severities['high'] += 1
        elif severity_value >= 4.0:
            severities['medium'] += 1
        elif severity_value > 0.0:
            severities['low'] += 1
        else:
            severities['info'] += 1

        results.append((severity_value, name, host, port))

    results.sort(key=lambda item: item[0], reverse=True)
    top_findings = results[:10]

    summary_lines = [
        'OpenVAS scan completed.',
        f"Critical: {severities['critical']}, High: {severities['high']}, Medium: {severities['medium']}, Low: {severities['low']}, Info: {severities['info']}",
        '',
        'Top findings:',
    ]

    if not top_findings:
        summary_lines.append('- No findings in report.')
    else:
        for sev, name, host, port in top_findings:
            summary_lines.append(f'- severity={sev:.1f} | {name or "Unnamed finding"} | host={host or "n/a"} | port={port or "n/a"}')

    return '\n'.join(summary_lines)


def run_openvas(target):
    host = _get_env('OPENVAS_HOST')
    username = _get_env('OPENVAS_USERNAME')
    password = _get_env('OPENVAS_PASSWORD')
    port = int(_get_env('OPENVAS_PORT', '9390'))
    scan_config_id = _get_env('OPENVAS_SCAN_CONFIG_ID')
    scanner_id = _get_env('OPENVAS_SCANNER_ID')
    timeout_seconds = int(_get_env('OPENVAS_TIMEOUT_SECONDS', '1200'))
    poll_interval_seconds = int(_get_env('OPENVAS_POLL_INTERVAL_SECONDS', '10'))

    if not host or not username or not password:
        return (
            "OpenVAS integration not configured. Set OPENVAS_HOST, OPENVAS_USERNAME, and OPENVAS_PASSWORD "
            "environment variables for real scans."
        )

    try:
        from gvm.connections import TLSConnection
        from gvm.protocols.gmp import Gmp
    except Exception as exc:
        return f'OpenVAS dependency error: {exc}. Install python-gvm and gvm-tools.'

    try:
        connection = TLSConnection(hostname=host, port=port)
        with Gmp(connection) as gmp:
            gmp.authenticate(username, password)

            target_name = f'CrypticScan Target {target}'
            target_id = _find_target_id_by_name(gmp, target_name)
            if not target_id:
                create_target_response = gmp.create_target(name=target_name, hosts=[target])
                target_id = _find_first_id(create_target_response, 'create_target_response')
                if not target_id:
                    target_id = _find_first_id(create_target_response, 'target')
            if not target_id:
                return 'OpenVAS error: unable to create or resolve target.'

            if not scan_config_id:
                scan_config_id = _find_first_id(gmp.get_scan_configs(), 'config')
            if not scanner_id:
                scanner_id = _find_first_id(gmp.get_scanners(), 'scanner')

            if not scan_config_id or not scanner_id:
                return 'OpenVAS error: missing scan configuration or scanner ID.'

            task_name = f'CrypticScan Task {target} {int(time.time())}'
            create_task_response = gmp.create_task(
                name=task_name,
                config_id=scan_config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = _find_first_id(create_task_response, 'create_task_response')
            if not task_id:
                task_id = _find_first_id(create_task_response, 'task')
            if not task_id:
                return 'OpenVAS error: unable to create task.'

            start_task_response = gmp.start_task(task_id=task_id)
            report_id = _find_first_id(start_task_response, 'report')

            deadline = time.time() + timeout_seconds
            final_status = 'Unknown'
            while time.time() < deadline:
                task_xml = gmp.get_task(task_id=task_id)
                status_text = _find_first_text(task_xml, 'status')
                final_status = status_text or final_status
                if status_text in {'Done', 'Stopped', 'Interrupted'}:
                    break
                time.sleep(max(poll_interval_seconds, 1))

            if final_status != 'Done':
                return f'OpenVAS task did not complete successfully. Final status: {final_status}'

            if not report_id:
                task_xml = gmp.get_task(task_id=task_id)
                report_id = _find_first_id(task_xml, 'report')
            if not report_id:
                return 'OpenVAS error: report ID not found after task completion.'

            report_xml = gmp.get_report(report_id=report_id, details=True, ignore_pagination=True)
            return _summarize_report(report_xml)

    except Exception as exc:
        return f'OpenVAS scan failed: {exc}'

