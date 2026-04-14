from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def generate_report(scan_id, target, results_by_tool):
    base_dir = Path(__file__).resolve().parent.parent
    templates_dir = base_dir / 'static' / 'report_templates'
    reports_dir = base_dir / 'static' / 'reports'
    reports_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(['html', 'xml']),
    )
    template = env.get_template('report.html')
    rendered_html = template.render(
        scan_id=scan_id,
        target=target,
        generated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        results_by_tool=results_by_tool,
    )

    report_path = reports_dir / f'{scan_id}_report.html'
    report_path.write_text(rendered_html, encoding='utf-8')
    return str(report_path)
