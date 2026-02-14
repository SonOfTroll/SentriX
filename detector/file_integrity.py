import hashlib
import os
import time

FILES_TO_MONITOR = [
    "/etc/passwd",
    "/etc/shadow"
]

BASELINE_FILE = "logs/file_baseline.txt"


def hash_file(path):
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def initialize_baseline():
    os.makedirs("logs", exist_ok=True)

    with open(BASELINE_FILE, "w") as base:
        for file_path in FILES_TO_MONITOR:
            file_hash = hash_file(file_path)
            if file_hash:
                base.write(f"{file_path}:{file_hash}\n")


def check_files():
    if not os.path.exists(BASELINE_FILE):
        raise RuntimeError(
            "Baseline not initialized. Run with --init on a clean system."
        )

    baseline_hashes = {}
    with open(BASELINE_FILE, "r") as base:
        for line in base:
            path, hash_value = line.strip().split(":")
            baseline_hashes[path] = hash_value

    events = []
    current_time = int(time.time())

    for file_path in FILES_TO_MONITOR:
        current_hash = hash_file(file_path)

        if not current_hash:
            continue  #skip unreadable files safely

        baseline_hash = baseline_hashes.get(file_path)

        #detect new file not in baseline
        if baseline_hash is None:
            events.append({
                "type": "file",
                "path": file_path,
                "timestamp": current_time,
                "reason": "File missing from baseline"
            })
            continue

        if current_hash != baseline_hash:
            events.append({
                "type": "file",
                "path": file_path,
                "timestamp": current_time,

                #ML FEATURE HOOK START
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
                "hash_changed": True
                #ML FEATURE HOOK END
            })

    return events
