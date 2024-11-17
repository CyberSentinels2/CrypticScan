import subprocess

def run_nmap(ip_range):
    command = ['nmap', '-sV', ip_range]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout
