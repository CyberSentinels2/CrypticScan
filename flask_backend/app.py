import threading
from flask import Flask, request, jsonify
from scripts.nmap_scan import run_nmap
from scripts.openvas_scan import run_openvas
from scripts.report_generator import generate_report
from flask_sqlalchemy import SQLAlchemy
from models import db, Scan

app = Flask(__name__)

scan_status = {}  # Store scan statuses

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    ip_range = data['ipRange']
    tools = data['tools']  # Expect a list of tools
    scan_id = 'scan_' + str(len(scan_status) + 1)

    threading.Thread(target=execute_scan, args=(scan_id, tools, ip_range)).start()

    return jsonify({'scan_id': scan_id})

def execute_scan(scan_id, tools, ip_range):
    scan_status[scan_id] = {'status': 'running', 'results': {}}

    for tool in tools:
        if tool == 'nmap':
            result = run_nmap(ip_range)
        elif tool == 'openvas':
            result = run_openvas(ip_range)
        elif tool == 'zap':
            result = run_zap(ip_range)
        else:
            result = f"Tool {tool} not supported."

        scan_status[scan_id]['results'][tool] = result

    combined_results = "\n".join([f"{tool}:\n{output}" for tool, output in scan_status[scan_id]['results'].items()])
    report_path = generate_report(combined_results)
    scan_status[scan_id] = {'status': 'completed', 'results': combined_results, 'report': report_path}


@app.route('/scan_results/<scan_id>', methods=['GET'])
def scan_results(scan_id):
    # Logic to retrieve scan results based on scan_id
    results = get_scan_results(scan_id)
    return jsonify(results)

def get_scan_results(scan_id):
    # Mock implementation to return scan results
    return {"status": "completed", "details": "Scan results here."}

@app.route('/scan_status/<scan_id>', methods=['GET'])
def scan_status_endpoint(scan_id):
    status = scan_status.get(scan_id, {'status': 'unknown'})
    return jsonify(status)

@app.route('/download_report/<scan_id>', methods=['GET'])
def download_report(scan_id):
    report_path = scan_status.get(scan_id, {}).get('report')
    if report_path:
        return send_file(report_path, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db.init_app(app)

@app.route('/init_db', methods=['GET'])
def init_db():
    try:
        db.create_all()
        return "Database initialized successfully", 200
    except Exception as e:
        return f"Error initializing database: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)
