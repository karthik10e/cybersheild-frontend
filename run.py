"""
CyberShield Root Quickstart Launcher.
Delegates execution to backend/run.py with proper path resolution.
"""

import os
import sys
import subprocess

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

if __name__ == "__main__":
    run_script = os.path.join(BACKEND_DIR, "run.py")
    sys.exit(subprocess.call([sys.executable, run_script], cwd=BACKEND_DIR))
