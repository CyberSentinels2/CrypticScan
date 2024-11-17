from jinja2 import Environment, FileSystemLoader

def generate_report(results):
    env = Environment(loader=FileSystemLoader('static/report_templates'))
    template = env.get_template('report_template.html')
    rendered_html = template.render(results=results)

    # Save the rendered HTML to a file
    report_path = 'static/reports/scan_report.html'
    with open(report_path, 'w') as report_file:
        report_file.write(rendered_html)

    return report_path
