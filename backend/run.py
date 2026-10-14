"""
CyberShield Backend Launcher.
Checks ML model artifacts and launches Flask server.
"""

import os
import sys
import webbrowser
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def main():
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("""
    ===================================================================
    [*] CYBERSHIELD: INTELLIGENT NETWORK INTRUSION DETECTION SYSTEM
    ===================================================================
    [*] Backend Engine:       Flask REST API & WebSockets / SSE
    [*] Machine Learning Core: Random Forest + Isolation Forest
    [*] Active Defense:       Real-Time Firewall Synthesis
    ===================================================================
    """)

    # Verify models exist in backend/ml/models
    models_dir = os.path.join(BASE_DIR, "ml", "models")
    rf_model = os.path.join(models_dir, "cybershield_rf.joblib")
    
    if not os.path.exists(rf_model):
        print("[!] Pre-trained models not found. Running training pipeline...")
        from ml.train_model import train_models
        train_models()

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open("http://127.0.0.1:5000")
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()

    print("[*] Launching CyberShield on http://127.0.0.1:5000 ...")
    from app import app
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    main()
