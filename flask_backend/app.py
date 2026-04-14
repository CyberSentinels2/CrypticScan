import ipaddress
import os
import shutil
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from uuid import uuid4

from flask import Flask, jsonify, request, send_file

from models import Scan, db
from scripts.nmap_scan import run_nmap
from scripts.openvas_scan import run_openvas
from scripts.report_generator import generate_report
from scripts.zap_scan import run_zap

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
db.init_app(app)

scan_status = {}  # In-memory active scan state
scan_lock = threading.Lock()
ALLOWED_TOOLS = {'nmap', 'openvas', 'zap'}

API_KEY = os.getenv('CRYPTICSCAN_API_KEY', '').strip()
RATE_LIMIT_COUNT = int(os.getenv('CRYPTICSCAN_RATE_LIMIT_COUNT', '60'))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('CRYPTICSCAN_RATE_LIMIT_WINDOW_SECONDS', '60'))
rate_limit_buckets = defaultdict(deque)
rate_limit_lock = threading.Lock()


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin', '')
    allowed_origins = {'null', 'http://127.0.0.1:5000', 'http://localhost:5000'}
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


@app.before_request
def handle_preflight_requests():
    if request.method == 'OPTIONS':
        return ('', 204)


def require_api_key(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not API_KEY:
            return view_func(*args, **kwargs)

        provided_key = request.headers.get('X-API-Key', '').strip()
        if provided_key != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

        return view_func(*args, **kwargs)

    return wrapper


def rate_limit(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        client_ip = (request.remote_addr or 'unknown').strip()
        current_time = time.time()

        with rate_limit_lock:
            bucket = rate_limit_buckets[client_ip]
            while bucket and (current_time - bucket[0]) >= RATE_LIMIT_WINDOW_SECONDS:
                bucket.popleft()

            if len(bucket) >= RATE_LIMIT_COUNT:
                retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (current_time - bucket[0]))
                response = jsonify({'error': 'Too many requests. Please retry later.'})
                response.status_code = 429
                response.headers['Retry-After'] = str(max(retry_after, 1))
                return response

            bucket.append(current_time)

        return view_func(*args, **kwargs)

    return wrapper


def _is_valid_target(target):
    target = (target or '').strip()
    if not target or len(target) > 255 or target.startswith('-'):
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.')
    return set(target).issubset(allowed_chars)


def _normalize_tools(tools):
    if not isinstance(tools, list) or not tools:
        return [], 'tools must be a non-empty list.'

    normalized = [str(tool).strip().lower() for tool in tools if str(tool).strip()]
    unsupported = [tool for tool in normalized if tool not in ALLOWED_TOOLS]
    if unsupported:
        return [], f"Unsupported tools: {', '.join(sorted(set(unsupported)))}"

    return sorted(set(normalized)), None


def _persist_scan_state(scan_id):
    with scan_lock:
        state = scan_status.get(scan_id)
        if not state:
            return
        state_copy = dict(state)

    tools = state_copy.get('tools', [])
    results_map = state_copy.get('results', {})
    serialized_results = state_copy.get('results_text')
    if not serialized_results and isinstance(results_map, dict):
        serialized_results = "\n\n".join([f"{tool}:\n{output}" for tool, output in results_map.items()])

    with app.app_context():
        try:
            scan_record = Scan.query.filter_by(scan_id=scan_id).first()
        except Exception:
            db.create_all()
            scan_record = Scan.query.filter_by(scan_id=scan_id).first()

        if not scan_record:
            scan_record = Scan(
                scan_id=scan_id,
                tool=','.join(tools) or 'multi',
                target=state_copy.get('target', ''),
                status='queued',
            )
            db.session.add(scan_record)

        scan_record.tool = ','.join(tools) or 'multi'
        scan_record.target = state_copy.get('target', '')
        scan_record.status = state_copy.get('status', 'unknown')
        scan_record.results = serialized_results
        scan_record.report_path = state_copy.get('report')
        db.session.commit()


def _get_scan_from_db(scan_id):
    scan_record = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan_record:
        return None
    return {
        'scan_id': scan_record.scan_id,
        'status': scan_record.status,
        'target': scan_record.target,
        'results_text': scan_record.results,
        'report': scan_record.report_path,
        'tools': scan_record.tool.split(',') if scan_record.tool else [],
    }


@app.route('/start_scan', methods=['POST'])
@rate_limit
@require_api_key
def start_scan():
    data = request.get_json(silent=True) or {}
    target = str(data.get('ipRange', '')).strip()
    tools, tools_error = _normalize_tools(data.get('tools', []))

    if not _is_valid_target(target):
        return jsonify({'error': 'Invalid target. Use a valid IP, CIDR, or hostname.'}), 400

    if tools_error:
        return jsonify({'error': tools_error}), 400

    scan_id = f'scan_{uuid4().hex[:12]}'

    with scan_lock:
        scan_status[scan_id] = {
            'status': 'queued',
            'target': target,
            'tools': tools,
            'cancelled': False,
            'results': {},
            'total_tools': len(tools),
            'completed_tools': 0,
            'current_tool': None,
        }

    _persist_scan_state(scan_id)
    threading.Thread(target=execute_scan, args=(scan_id, tools, target), daemon=True).start()
    return jsonify({'scan_id': scan_id})


def execute_scan(scan_id, tools, target):
    with scan_lock:
        if scan_id not in scan_status:
            return
        scan_status[scan_id]['status'] = 'running'
    _persist_scan_state(scan_id)

    for tool in tools:
        with scan_lock:
            if scan_status.get(scan_id, {}).get('cancelled'):
                scan_status[scan_id]['status'] = 'cancelled'
                _persist_scan_state(scan_id)
                return
            scan_status[scan_id]['current_tool'] = tool
            scan_status[scan_id]['status'] = 'running'

        if tool == 'nmap':
            try:
                result = run_nmap(target)
            except Exception as exc:
                result = f'nmap execution error: {exc}'
        elif tool == 'openvas':
            try:
                result = run_openvas(target)
            except Exception as exc:
                result = f'openvas execution error: {exc}'
        elif tool == 'zap':
            zap_target = target if target.startswith(('http://', 'https://')) else f'http://{target}'
            try:
                result = run_zap(zap_target)
            except Exception as exc:
                result = f'zap execution error: {exc}'
        else:
            result = f'Tool {tool} not supported.'

        with scan_lock:
            scan_status[scan_id]['results'][tool] = result
            scan_status[scan_id]['completed_tools'] = len(scan_status[scan_id]['results'])
        _persist_scan_state(scan_id)

    with scan_lock:
        tool_results = scan_status.get(scan_id, {}).get('results', {}).copy()

    try:
        report_path = generate_report(scan_id, target, tool_results)
    except Exception as exc:
        report_path = None
        tool_results['report_generation'] = f'Error generating report: {exc}'

    with scan_lock:
        combined_results = "\n\n".join([f"{tool}:\n{output}" for tool, output in tool_results.items()])
        scan_status[scan_id].update({
            'status': 'completed' if report_path else 'completed_with_errors',
            'results_text': combined_results,
            'report': report_path,
            'current_tool': None,
        })
    _persist_scan_state(scan_id)


@app.route('/scan_results/<scan_id>', methods=['GET'])
@rate_limit
@require_api_key
def scan_results(scan_id):
    with scan_lock:
        result = scan_status.get(scan_id)
    if result:
        return jsonify(result)

    with app.app_context():
        db_result = _get_scan_from_db(scan_id)
        if not db_result:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(db_result)


@app.route('/scan_status/<scan_id>', methods=['GET'])
@rate_limit
@require_api_key
def scan_status_endpoint(scan_id):
    with scan_lock:
        status = scan_status.get(scan_id, {'status': 'unknown'})
    if status.get('status') != 'unknown':
        tools = status.get('tools', [])
        results = status.get('results', {})
        tool_progress = {tool: ('done' if tool in results else 'pending') for tool in tools}
        current_tool = status.get('current_tool')
        if current_tool and current_tool in tool_progress and status.get('status') in {'running', 'cancelling'}:
            tool_progress[current_tool] = 'running'
        status['tool_progress'] = tool_progress
        return jsonify(status)

    with app.app_context():
        db_result = _get_scan_from_db(scan_id)
        if not db_result:
            return jsonify({'status': 'unknown'})
        return jsonify({
            'status': db_result['status'],
            'scan_id': db_result['scan_id'],
            'target': db_result['target'],
            'tools': db_result.get('tools', []),
            'tool_progress': {tool: 'done' for tool in db_result.get('tools', [])},
        })


@app.route('/scan_history', methods=['GET'])
@rate_limit
@require_api_key
def scan_history():
    limit = request.args.get('limit', default=20, type=int)
    q = (request.args.get('q', default='', type=str) or '').strip()
    status_filter = (request.args.get('status', default='', type=str) or '').strip().lower()
    tool_filter = (request.args.get('tool', default='', type=str) or '').strip().lower()
    limit = max(1, min(limit, 100))

    with app.app_context():
        try:
            db.create_all()
            query = Scan.query
            if q:
                like_value = f'%{q}%'
                query = query.filter((Scan.scan_id.ilike(like_value)) | (Scan.target.ilike(like_value)))
            if status_filter:
                query = query.filter(Scan.status == status_filter)
            if tool_filter:
                query = query.filter(Scan.tool.ilike(f'%{tool_filter}%'))

            rows = query.order_by(Scan.id.desc()).limit(limit).all()
        except Exception as exc:
            return jsonify({'error': f'Failed to read scan history: {exc}'}), 500

        history = [
            {
                'scan_id': row.scan_id,
                'status': row.status,
                'target': row.target,
                'tools': row.tool.split(',') if row.tool else [],
                'has_report': bool(row.report_path),
            }
            for row in rows
        ]

    return jsonify({'items': history, 'count': len(history)})


@app.route('/healthz', methods=['GET'])
@rate_limit
@require_api_key
def health_check():
    db_ok = True
    db_error = None
    try:
        with app.app_context():
            db.create_all()
    except Exception as exc:
        db_ok = False
        db_error = str(exc)

    with scan_lock:
        active_scans = sum(1 for value in scan_status.values() if value.get('status') in {'queued', 'running', 'cancelling'})

    data = {
        'status': 'ok' if db_ok else 'degraded',
        'api_key_required': bool(API_KEY),
        'db_ok': db_ok,
        'db_error': db_error,
        'active_scans': active_scans,
        'tools': {
            'nmap': shutil.which('nmap') is not None,
            'zap_cli': shutil.which('zap-cli') is not None,
            'openvas_env_configured': bool(os.getenv('OPENVAS_HOST') and os.getenv('OPENVAS_USERNAME') and os.getenv('OPENVAS_PASSWORD')),
        },
    }
    return jsonify(data), (200 if db_ok else 503)


@app.route('/cancel_scan/<scan_id>', methods=['POST'])
@rate_limit
@require_api_key
def cancel_scan(scan_id):
    with scan_lock:
        if scan_id not in scan_status:
            return jsonify({'error': 'Scan not found'}), 404

        if scan_status[scan_id].get('status') in {'completed', 'failed', 'cancelled'}:
            return jsonify({'status': scan_status[scan_id].get('status')}), 200

        scan_status[scan_id]['cancelled'] = True
        scan_status[scan_id]['status'] = 'cancelling'

    _persist_scan_state(scan_id)
    return jsonify({'status': 'cancelling'})


@app.route('/download_report/<scan_id>', methods=['GET'])
@rate_limit
@require_api_key
def download_report(scan_id):
    with scan_lock:
        report_path = scan_status.get(scan_id, {}).get('report')

    if not report_path:
        with app.app_context():
            db_result = _get_scan_from_db(scan_id)
            report_path = db_result.get('report') if db_result else None

    if report_path:
        return send_file(report_path, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404


@app.route('/init_db', methods=['GET'])
@rate_limit
@require_api_key
def init_db():
    try:
        db.create_all()
        return 'Database initialized successfully', 200
    except Exception as e:
        return f'Error initializing database: {e}', 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False, use_reloader=False)
