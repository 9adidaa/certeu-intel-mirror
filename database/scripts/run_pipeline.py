#!/usr/bin/env python3

import subprocess
import sys


STEPS = [
    ("Mirror advisories", "python database/scripts/mirror.py"),
    ("Build unique CVE index", "python database/scripts/cve_table.py"),
    ("Build first-seen intel", "python database/scripts/build_first_seen.py"),
]


def run():
    for name, cmd in STEPS:
        print(f"\n===== {name} =====")

        r = subprocess.run(cmd, shell=True)
        if r.returncode != 0:
            print(f"\n❌ Step failed: {name}")
            return r.returncode

    print("\n✅ Pipeline complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run())