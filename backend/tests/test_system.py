"""
CyberShield Automated Test Suite.
Verifies Feature Extraction, Detection Pipeline, Active Defense, Traffic Simulation, and Flask REST Endpoints.
"""

import unittest
import json
import os
import sys

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.feature_extractor import NetworkFeatureExtractor
from core.detector import CyberShieldDetector
from core.mitigation import ActiveDefense
from core.traffic_generator import TrafficSimulator
from app import app


class TestCyberShield(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.detector = CyberShieldDetector()
        cls.defense = ActiveDefense()
        cls.simulator = TrafficSimulator()
        cls.client = app.test_client()

    def test_01_feature_sanitization(self):
        """Test feature extractor sanitization and default fallback values."""
        raw = {
            "protocol_type": "TCP",
            "service": "HTTP",
            "flag": "sf",
            "src_bytes": "120",
            "count": 5
        }
        sanitized = NetworkFeatureExtractor.sanitize_features(raw)
        self.assertEqual(sanitized["protocol_type"], "tcp")
        self.assertEqual(sanitized["service"], "http")
        self.assertEqual(sanitized["flag"], "SF")
        self.assertEqual(sanitized["src_bytes"], 120.0)
        self.assertEqual(sanitized["count"], 5.0)
        self.assertIn("dst_bytes", sanitized)

    def test_02_normal_packet_detection(self):
        """Test detector classifies normal web flow as Safe / Normal."""
        normal_pkt = {
            "duration": 0.1,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 350,
            "dst_bytes": 4500,
            "count": 2,
            "srv_count": 2,
            "serror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": 10,
            "dst_host_srv_count": 10
        }
        res = self.detector.predict_packet(normal_pkt)
        self.assertEqual(res["attack_type"], "Normal")
        self.assertFalse(res["is_attack"])
        self.assertEqual(res["severity"], "SAFE")

    def test_03_syn_flood_detection(self):
        """Test detector flags TCP SYN flood as DoS / CRITICAL."""
        dos_pkt = {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "S0",
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": 480,
            "srv_count": 450,
            "serror_rate": 0.99,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 255
        }
        res = self.detector.predict_packet(dos_pkt)
        self.assertEqual(res["attack_type"], "DoS")
        self.assertTrue(res["is_attack"])
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])

    def test_04_port_scan_detection(self):
        """Test detector flags multi-port sweep as Probe."""
        probe_pkt = {
            "duration": 0.02,
            "protocol_type": "tcp",
            "service": "other",
            "flag": "REJ",
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": 75,
            "srv_count": 2,
            "serror_rate": 0.0,
            "rerror_rate": 0.85,
            "same_srv_rate": 0.05,
            "diff_srv_rate": 0.95,
            "dst_host_count": 255,
            "dst_host_srv_count": 2
        }
        res = self.detector.predict_packet(probe_pkt)
        self.assertEqual(res["attack_type"], "Probe")
        self.assertTrue(res["is_attack"])

    def test_05_active_defense_auto_block(self):
        """Test auto-quarantine mitigation triggered on high threat score."""
        defense = ActiveDefense(auto_block_threshold=0.8)
        attacker_ip = "198.51.100.44"
        pkt_meta = {"src_ip": attacker_ip, "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"}

        # Send high confidence attack
        defense.record_packet(pkt_meta, attack_type="DoS", confidence=0.95, is_attack=True)
        self.assertTrue(defense.is_blocked(attacker_ip))

        # Test unblock
        defense.unblock_ip(attacker_ip)
        self.assertFalse(defense.is_blocked(attacker_ip))

    def test_06_synthetic_traffic_generator(self):
        """Test synthetic traffic generator creates valid packet flows."""
        normal_pkt = self.simulator.generate_packet(scenario="normal_only")
        self.assertIn("_meta", normal_pkt)
        self.assertEqual(normal_pkt["flag"], "SF")

        dos_pkt = self.simulator.generate_packet(scenario="syn_flood")
        self.assertIn(dos_pkt["flag"], ["S0", "REJ"])

    def test_07_api_stats(self):
        """Test GET /api/stats endpoint."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("total_packets", data)
        self.assertIn("attacks_by_type", data)
        self.assertIn("simulator", data)

    def test_08_api_predict_endpoint(self):
        """Test POST /api/predict endpoint."""
        payload = {
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 200,
            "dst_bytes": 3000,
            "count": 2,
            "srv_count": 2,
            "serror_rate": 0.0
        }
        response = self.client.post("/api/predict", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("attack_type", data)
        self.assertIn("confidence", data)
        self.assertIn("reasons", data)

    def test_09_api_firewall_actions(self):
        """Test POST /api/firewall/block and /api/firewall/unblock endpoints."""
        block_ip = "203.0.113.88"
        # 1. Block
        res1 = self.client.post("/api/firewall/block", data=json.dumps({"ip": block_ip, "reason": "Unit Test Block"}), content_type="application/json")
        self.assertEqual(res1.status_code, 200)
        d1 = json.loads(res1.data)
        self.assertTrue(d1["success"])

        # 2. Verify list
        res2 = self.client.get("/api/firewall/list")
        d2 = json.loads(res2.data)
        blocked_ips = [item["ip"] for item in d2["blocked_ips"]]
        self.assertIn(block_ip, blocked_ips)

        # 3. Unblock
        res3 = self.client.post("/api/firewall/unblock", data=json.dumps({"ip": block_ip}), content_type="application/json")
        d3 = json.loads(res3.data)
        self.assertTrue(d3["success"])

    def test_10_html_views(self):
        """Test all frontend page routes return HTTP 200 OK."""
        routes = ["/", "/scanner", "/firewall", "/models", "/api-docs"]
        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} failed with status {resp.status_code}")


if __name__ == "__main__":
    unittest.main()
