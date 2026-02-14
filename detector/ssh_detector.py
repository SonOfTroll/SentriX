import os
import re
import time
import platform
from typing import List, Dict, Optional

# Supported Linux auth log locations
POSSIBLE_AUTH_LOGS = [
    "/var/log/auth.log",   # Debian/Ubuntu/Kali
    "/var/log/secure"      # RHEL/CentOS/Fedora
]

FAILED_THRESHOLD = 5
SCAN_INTERVAL = 12  # seconds

_last_position = 0  # Track log read offset


def detect_auth_log() -> Optional[str]:
    """
    Detects the correct authentication log path for Linux systems.
    """
    for path in POSSIBLE_AUTH_LOGS:
        if os.path.exists(path):
            return path
    return None


def parse_ssh_failures() -> List[Dict]:
    """
    Parses Linux SSH authentication logs and extracts brute-force attempts.

    Returns:
        List of structured SSH events.
    """

    global _last_position

    # Ensure system is Linux
    if platform.system() != "Linux":
        return []

    log_path = detect_auth_log()
    if not log_path:
        return []

    ip_counter = {}
    ip_pattern = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")

    try:
        with open(log_path, "r") as log_file:
            log_file.seek(_last_position)

            for line in log_file:
                if "Failed password" in line:
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        ip_counter[ip] = ip_counter.get(ip, 0) + 1

            _last_position = log_file.tell()

    except (FileNotFoundError, PermissionError):
        # File missing or insufficient permissions (run as root)
        return []

    events = []
    current_time = int(time.time())

    for ip, count in ip_counter.items():
        if count >= FAILED_THRESHOLD:
            events.append({
                "type": "ssh",
                "ip": ip,
                "failed_attempts": count,
                "timestamp": current_time,

                # ML FEATURE HOOK START
                "threshold": FAILED_THRESHOLD,
                "log_source": log_path
                # ML FEATURE HOOK END
            })

    return events


def monitor_ssh():
    """
    Continuous SSH monitoring loop.
    """
    while True:
        events = parse_ssh_failures()
        if events:
            return events
        time.sleep(SCAN_INTERVAL)
