import subprocess

def run_nmap(ip_range):
    command = ['nmap', '-sV', '--', ip_range]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return 'Error: nmap is not installed or not available in PATH.'
    except subprocess.TimeoutExpired:
        return 'Error: nmap scan timed out after 300 seconds.'

    if result.returncode != 0:
        return (result.stderr or 'Error: nmap scan failed.').strip()

    return (result.stdout or 'No output from nmap.').strip()
