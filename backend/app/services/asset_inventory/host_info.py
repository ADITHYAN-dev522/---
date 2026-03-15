# app/services/asset_inventory/host_info.py

import platform
import socket

def collect_host_info():
    hostname = socket.gethostname()

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "unknown"

    return {
        "asset_id": hostname,          # Phase-1 asset identifier
        "hostname": hostname,
        "ip_address": ip_address,
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
        }
    }
