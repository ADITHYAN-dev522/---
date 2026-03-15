# app/services/telemetry/files.py

import subprocess
from datetime import datetime

# -------------------------------------------------
# BACKWARD-COMPATIBILITY FUNCTION (DO NOT REMOVE)
# -------------------------------------------------
def collect_recent_files(path="/home"):
    """
    Legacy helper used by auto_scanner.
    Returns a list of file paths (strings).
    """
    try:
        result = subprocess.run(
            ["find", path, "-type", "f", "-mtime", "-1"],
            capture_output=True,
            text=True,
        )
        return result.stdout.splitlines()
    except Exception:
        return []


# -------------------------------------------------
# THREATFUSION-AWARE FILE EVENTS (NEW)
# -------------------------------------------------
def collect_file_events():
    """
    Collect file access events with PID attribution
    using lsof (EDR-style approach).
    """
    events = []

    try:
        result = subprocess.run(
            ["lsof", "-F", "pn"],
            capture_output=True,
            text=True
        )
    except Exception:
        return events

    current_pid = None

    for line in result.stdout.splitlines():
        if line.startswith("p"):
            try:
                current_pid = int(line[1:])
            except ValueError:
                current_pid = None

        elif line.startswith("n") and current_pid:
            path = line[1:]
            events.append({
                "path": path,
                "action": "access",
                "pid": current_pid,
                "timestamp": datetime.utcnow().isoformat()
            })

    return events
