import psutil
import time
import platform
from typing import List, Dict

CPU_THRESHOLD = 30     
MEMORY_THRESHOLD = 20     
TRUSTED_PATHS = ["/usr/", "/bin/", "/sbin/", "/lib/"]


def is_trusted_path(path: str) -> bool:
    if not path:
        return False
    return any(path.startswith(trusted) for trusted in TRUSTED_PATHS)


def monitor_processes() -> List[Dict]:
    """
    Monitors Linux processes for suspicious privileged behavior.

    Detection logic:
    - Process running as root
    - High CPU or memory usage
    - Executable not in common trusted system paths
    """

    if platform.system() != "Linux":
        return []

    events = []
    current_time = int(time.time())

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "exe"]
    ):
        try:
            pid = process.info["pid"]
            name = process.info["name"]
            user = process.info["username"]
            cpu = process.info["cpu_percent"]
            memory = process.info["memory_percent"]
            exe_path = process.info["exe"]

            # Detection condition
            if (
                user == "root"
                and (cpu > CPU_THRESHOLD or memory > MEMORY_THRESHOLD)
                and not is_trusted_path(exe_path)
            ):
                events.append({
                    "type": "process",
                    "pid": pid,
                    "name": name,
                    "timestamp": current_time,

                    # ML FEATURE HOOK START
                    "username": user,
                    "cpu_usage": cpu,
                    "memory_usage": memory,
                    "executable_path": exe_path,
                    "is_root": True,
                    "trusted_path": False
                    # ML FEATURE HOOK END
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return events
