import re
import time
from typing import List, Dict

AUTH_LOG=  "/var/log/auth.log"
FAILED_THRESHOLD = 5
SCAN_INTERVAL = 12 #seconds btw

def parse_ssh_failures()->List[Dict]:
    # Parses SSH authentication logs and extracts failed login attempts.

    # Returns:
    #     List of structured events:
    #     {
    #         "source": "ssh",
    #         "ip": "1.2.3.4",
    #         "failed_attempts": 7,
    #         "timestamp": 1700000000
    #     }
    ip_counter = {}
    ip_pattern = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
    try:
        with open(AUTH_LOG, "r") as log_file:
            for line in log_file:
                if "Failed password" in line:
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        ip_counter[ip] = ip_counter.get(ip, 0) + 1
    except FileNotFoundError:
        #Non Linux env
        return[]
    events = []
    current_time = int(time.time())

    for ip, count in ip_counter.items():
        if count >= FAILED_THRESHOLD:
            events.append({
                source: "ssh",
                "ip": ip,
                "failed_attempts": count,
                "timestamp": current_time
            })
    return events


def run():
    while True:
        events = parse_ssh_failures()
        if events:
            return events
        time.sleep(SCAN_INTERVAL)
        