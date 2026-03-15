# app/services/telemetry/network.py
import subprocess
from datetime import datetime
import re

def collect_network_connections():
    events = []

    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True,
            text=True
        )
    except Exception:
        return events

    for line in result.stdout.splitlines():
        if "pid=" not in line:
            continue

        # Extract PID
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match:
            continue

        pid = int(pid_match.group(1))

        # Extract destination IP:PORT
        parts = line.split()
        if len(parts) < 6:
            continue

        dst = parts[5]
        if ":" not in dst:
            continue

        dst_ip, dst_port = dst.rsplit(":", 1)

        events.append({
            "pid": pid,
            "dst_ip": dst_ip,
            "port": int(dst_port) if dst_port.isdigit() else None,
            "protocol": parts[0],
            "timestamp": datetime.utcnow().isoformat()
        })

    return events
