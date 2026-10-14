"""
CyberShield Root Application Entrypoint.
Delegates to backend/app.py with appropriate template and static paths.
"""

import os
import sys

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
