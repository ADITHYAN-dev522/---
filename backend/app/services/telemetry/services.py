# app/services/telemetry/services.py

import subprocess

def collect_services():
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
            capture_output=True,
            text=True,
        )
        return result.stdout.splitlines()
    except Exception:
        return []
