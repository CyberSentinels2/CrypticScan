import subprocess

def run_zap(target_url):
    command = [
        'zap-cli',
        'quick-scan',
        '--self-contained',
        '--spider',
        target_url
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout
