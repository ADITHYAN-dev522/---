# app/services/telemetry/software.py

import subprocess

def collect_installed_software():
    try:
        result = subprocess.run(
            ["dpkg", "-l"],
            capture_output=True,
            text=True,
        )
        return result.stdout.splitlines()
    except Exception:
        return []
