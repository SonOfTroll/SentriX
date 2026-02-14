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
    with open(path, "rb") as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def initialize_baseline():
    os.makedirs("logs", exist_ok=True)

    with open(BASELINE_FILE, "w") as base:
        for file_path in FILES_TO_MONITOR:
            if os.path.exists(file_path):
                base.write(f"{file_path}:{hash_file(file_path)}\n")


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
        if os.path.exists(file_path):
            current_hash = hash_file(file_path)
            baseline_hash = baseline_hashes.get(file_path)

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

