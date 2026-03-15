# app/services/telemetry/processes.py
import subprocess
from datetime import datetime

def collect_processes():
    processes = []

    result = subprocess.run(
        ["ps", "-eo", "pid,ppid,user,cmd"],
        capture_output=True,
        text=True
    )

    lines = result.stdout.strip().split("\n")[1:]

    for line in lines:
        parts = line.split(maxsplit=3)
        if len(parts) < 4:
            continue

        pid, ppid, user, cmd = parts

        processes.append({
            "pid": int(pid),
            "ppid": int(ppid),
            "user": user,
            "name": cmd,
            "timestamp": datetime.utcnow().isoformat()
        })

    return processes
