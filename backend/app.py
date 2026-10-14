"""
CyberShield: Intelligent Network Intrusion Detection System (NIDS)
Flask Web Application & SOC Management Server.
"""

import os
import io
import csv
import json
import sys
import time
import logging
from collections import deque
from flask import Flask, render_template, request, jsonify, Response, send_file
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
TEMPLATE_DIR = os.path.join(FRONTEND_DIR, "templates")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

from core.detector import CyberShieldDetector
from core.mitigation import ActiveDefense
from core.traffic_generator import TrafficSimulator
from core.sniffer import LivePacketSniffer
from core.feature_extractor import NetworkFeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cybershield.app")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)
app.config["SECRET_KEY"] = "cybershield-secret-soc-key-2026"
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024 # 32MB upload limit
CORS(app)

# Core Instances
detector = CyberShieldDetector()
defense = ActiveDefense()

# In-memory streaming and stats stores
MAX_RECENT_PACKETS = 100
recent_packets = deque(maxlen=MAX_RECENT_PACKETS)
stats_timeline = deque(maxlen=30) # Last 30 seconds traffic volume

# Global counters
stats_lock = deque(maxlen=1)
traffic_stats = {
    "total_packets": 0,
    "total_threats": 0,
    "attacks_by_type": {
        "DoS": 0,
        "Probe": 0,
        "R2L": 0,
        "U2R": 0,
        "Zero-Day Anomaly": 0
    },
    "protocol_distribution": {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0
    },
    "start_time": time.time()
}

# Packet ingestion callback (shared between Simulator and Live Sniffer)
def handle_incoming_packet(packet_data):
    """Processes captured or simulated packet through detection & defense pipelines."""
    res = detector.predict_packet(packet_data)
    
    # Update global counters
    traffic_stats["total_packets"] += 1
    proto = packet_data.get("_meta", {}).get("protocol", "TCP")
    traffic_stats["protocol_distribution"][proto] = traffic_stats["protocol_distribution"].get(proto, 0) + 1

    if res["is_attack"]:
        traffic_stats["total_threats"] += 1
        atk_type = res["attack_type"]
        traffic_stats["attacks_by_type"][atk_type] = traffic_stats["attacks_by_type"].get(atk_type, 0) + 1

    # Active Defense evaluation (auto-block high-risk IPs)
    incident = defense.record_packet(
        packet_info=packet_data.get("_meta", {}),
        attack_type=res["attack_type"],
        confidence=res["confidence"],
        is_attack=res["is_attack"]
    )

    enriched_packet = {
        "id": traffic_stats["total_packets"],
        "timestamp": time.time(),
        "time_str": time.strftime("%H:%M:%S", time.localtime()),
        "src_ip": packet_data.get("_meta", {}).get("src_ip", "192.168.1.50"),
        "dst_ip": packet_data.get("_meta", {}).get("dst_ip", "192.168.1.1"),
        "src_port": packet_data.get("_meta", {}).get("src_port", 0),
        "dst_port": packet_data.get("_meta", {}).get("dst_port", 80),
        "protocol": proto,
        "service": packet_data.get("service", "other"),
        "flag": packet_data.get("flag", "SF"),
        "attack_type": res["attack_type"],
        "is_attack": res["is_attack"],
        "confidence": res["confidence"],
        "severity": res["severity"],
        "reasons": res["reasons"],
        "is_blocked": defense.is_blocked(packet_data.get("_meta", {}).get("src_ip", "")),
        "incident": incident
    }

    recent_packets.appendleft(enriched_packet)
    return enriched_packet

# Initialize Simulator and Sniffer
simulator = TrafficSimulator(callback=handle_incoming_packet)
sniffer = LivePacketSniffer(packet_callback=handle_incoming_packet)

# Automatically start background traffic simulator in mixed mode for out-of-the-box live demonstration
simulator.start(mode="mixed", delay=0.9)


# ==========================================
# PAGE ROUTES
# ==========================================

@app.route("/")
def index():
    """SOC Dashboard View."""
    return render_template("dashboard.html", sniffer_status=sniffer.status)

@app.route("/scanner")
def scanner_page():
    """Batch File Scanner & Manual Inspector View."""
    return render_template("scanner.html")

@app.route("/firewall")
def firewall_page():
    """Firewall & Active Defense View."""
    return render_template("firewall.html")

@app.route("/models")
def models_page():
    """Machine Learning Evaluation & Architecture View."""
    return render_template("models.html", metadata=detector.metadata)

@app.route("/api-docs")
def api_docs_page():
    """REST API Documentation View."""
    return render_template("api_docs.html")


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns real-time telemetry, threat rates, and engine statuses."""
    uptime = int(time.time() - traffic_stats["start_time"])
    threat_rate = 0.0
    if traffic_stats["total_packets"] > 0:
        threat_rate = round((traffic_stats["total_threats"] / traffic_stats["total_packets"]) * 100, 2)

    return jsonify({
        "uptime_seconds": uptime,
        "total_packets": traffic_stats["total_packets"],
        "total_threats": traffic_stats["total_threats"],
        "threat_rate_percent": threat_rate,
        "attacks_by_type": traffic_stats["attacks_by_type"],
        "protocol_distribution": traffic_stats["protocol_distribution"],
        "blocked_ips_count": len(defense.blocked_ips),
        "simulator": {
            "is_running": simulator.is_running,
            "mode": simulator.attack_mode,
            "delay": simulator.delay
        },
        "sniffer": {
            "status": sniffer.status,
            "is_running": sniffer.is_running,
            "last_error": sniffer.last_error
        }
    })

@app.route("/api/packets/recent", methods=["GET"])
def get_recent_packets():
    """Returns the most recent inspected packets."""
    limit = int(request.args.get("limit", 40))
    return jsonify(list(recent_packets)[:limit])

@app.route("/api/stream")
def sse_stream():
    """Server-Sent Events (SSE) live packet stream for realtime UI updates."""
    def event_stream():
        last_id = -1
        while True:
            if recent_packets:
                latest = recent_packets[0]
                if latest["id"] != last_id:
                    last_id = latest["id"]
                    yield f"data: {json.dumps(latest)}\n\n"
            time.sleep(0.35)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/predict", methods=["POST"])
def predict_single():
    """REST API to evaluate a custom network packet JSON."""
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    result = detector.predict_packet(data)
    
    # Check if defense triggers
    meta = data.get("_meta", {})
    if result["is_attack"] and meta.get("src_ip"):
        defense.record_packet(meta, result["attack_type"], result["confidence"], result["is_attack"])

    return jsonify(result)

@app.route("/api/scan-file", methods=["POST"])
def scan_file():
    """Batch scans an uploaded CSV or PCAP file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    filename = file.filename.lower()
    results = []

    try:
        if filename.endswith(".csv"):
            import pandas as pd
            df = pd.read_csv(file.stream)
            # Cap at 500 records for fast browser rendering
            df_slice = df.head(500)
            records = df_slice.to_dict(orient="records")
            results = detector.predict_batch(records)

        elif filename.endswith(".pcap") or filename.endswith(".pcapng"):
            from scapy.all import rdpcap
            extractor = NetworkFeatureExtractor()
            pcap_bytes = io.BytesIO(file.read())
            packets = rdpcap(pcap_bytes)
            for pkt in packets[:300]: # Cap at 300 packets
                extracted = extractor.extract_from_scapy(pkt)
                pred = detector.predict_packet(extracted)
                results.append(pred)
        else:
            return jsonify({"error": "Unsupported file format. Please upload .csv or .pcap"}), 400

        # Summary aggregates
        total = len(results)
        threat_count = sum(1 for r in results if r["is_attack"])
        breakdown = {}
        for r in results:
            atk = r["attack_type"]
            breakdown[atk] = breakdown.get(atk, 0) + 1

        return jsonify({
            "filename": file.filename,
            "total_analyzed": total,
            "threats_detected": threat_count,
            "safe_count": total - threat_count,
            "threat_percentage": round((threat_count / max(1, total)) * 100, 2),
            "breakdown": breakdown,
            "samples": results[:50] # Return top 50 for table display
        })

    except Exception as e:
        logger.error(f"Error processing file: {e}")
        return jsonify({"error": f"Failed to process file: {str(e)}"}), 500

@app.route("/api/simulate/start", methods=["POST"])
def start_simulator():
    """Controls traffic simulator."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "mixed")
    delay = float(data.get("delay", 0.8))
    simulator.start(mode=mode, delay=delay)
    return jsonify({"status": "SUCCESS", "mode": mode, "delay": delay})

@app.route("/api/simulate/stop", methods=["POST"])
def stop_simulator():
    simulator.stop()
    return jsonify({"status": "SUCCESS", "message": "Simulator paused."})

@app.route("/api/simulate/burst", methods=["POST"])
def burst_simulator():
    """Triggers an on-demand burst attack (e.g. syn_flood, port_scan, brute_force, u2r)."""
    data = request.get_json(silent=True) or {}
    attack = data.get("attack", "syn_flood")
    count = int(data.get("count", 15))
    simulator.trigger_burst_attack(attack_name=attack, count=count)
    return jsonify({"status": "SUCCESS", "message": f"Burst {attack} triggered with {count} packets."})

@app.route("/api/sniff/start", methods=["POST"])
def start_sniffer():
    """Starts live network packet sniffing."""
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    res = sniffer.start(interface=iface)
    return jsonify(res)

@app.route("/api/sniff/stop", methods=["POST"])
def stop_sniffer():
    res = sniffer.stop()
    return jsonify(res)

@app.route("/api/firewall/list", methods=["GET"])
def get_firewall_list():
    return jsonify({
        "blocked_ips": defense.get_blocked_list(),
        "incidents": defense.get_incidents(limit=50)
    })

@app.route("/api/firewall/block", methods=["POST"])
def block_ip():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    reason = data.get("reason", "Manual SOC block")
    if not ip:
        return jsonify({"error": "Missing IP parameter"}), 400

    success = defense.block_ip(ip, reason=reason, attack_type="Manual")
    return jsonify({"success": success, "ip": ip})

@app.route("/api/firewall/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing IP parameter"}), 400

    success = defense.unblock_ip(ip)
    return jsonify({"success": success, "ip": ip})

@app.route("/api/presets", methods=["GET"])
def get_presets():
    preset_file = os.path.join(os.path.dirname(__file__), "samples", "attack_samples.json")
    if os.path.exists(preset_file):
        with open(preset_file, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({})

@app.route("/api/models/metadata", methods=["GET"])
def get_model_metadata():
    return jsonify(detector.metadata)

@app.route("/api/export-logs", methods=["GET"])
def export_logs():
    """Generates and downloads CSV of detected incidents."""
    incidents = defense.get_incidents(limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Source IP", "Destination IP", "Port", "Protocol", "Attack Type", "Confidence", "Action", "Blocked"])

    for inc in incidents:
        writer.writerow([
            inc.get("id"),
            inc.get("time_str"),
            inc.get("src_ip"),
            inc.get("dst_ip"),
            inc.get("dst_port"),
            inc.get("protocol"),
            inc.get("attack_type"),
            inc.get("confidence"),
            inc.get("action"),
            inc.get("is_blocked")
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=cybershield_incidents_{int(time.time())}.csv"}
    )

@app.route("/api/download-zip", methods=["GET"])
def download_project_zip():
    """Endpoint allowing 1-click download of the complete project zip."""
    zip_path = os.path.abspath(os.path.join(BASE_DIR, "..", "CyberShield_NIDS_Project.zip"))
    if os.path.exists(zip_path):
        return send_file(zip_path, as_attachment=True, download_name="CyberShield_NIDS_Project.zip")
    return jsonify({"error": "Zip file not found"}), 404


if __name__ == "__main__":
    try:
        import sys
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 65)
    print("[*] CYBERSHIELD: INTELLIGENT NETWORK INTRUSION DETECTION SYSTEM")
    print("[*] Running on: http://127.0.0.1:5000")
    print("[*] SOC Dashboard, ML Classifier, Active Defense Online")
    print("=" * 65)
    app.run(host="0.0.0.0", port=5000, debug=False)
