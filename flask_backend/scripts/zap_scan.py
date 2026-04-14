import subprocess

def run_zap(target_url):
    command = [
        'zap-cli',
        'quick-scan',
        '--self-contained',
        '--spider',
        '--',
        target_url
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return 'Error: zap-cli is not installed or not available in PATH.'
    except subprocess.TimeoutExpired:
        return 'Error: ZAP scan timed out after 600 seconds.'

    if result.returncode != 0:
        return (result.stderr or 'Error: ZAP scan failed.').strip()

    return (result.stdout or 'No output from ZAP scan.').strip()
