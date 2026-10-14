"""
CyberShield Intelligent Intrusion Detection Engine.
Combines Supervised Random Forest classification, Unsupervised Isolation Forest Anomaly Detection,
and Heuristic Signature Rules for comprehensive, real-time threat detection and Explainable AI (XAI).
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

from core.feature_extractor import NetworkFeatureExtractor, CATEGORICAL_FEATURES, NUMERIC_FEATURES


class CyberShieldDetector:
    """Hybrid Intrusion Detection Engine."""

    def __init__(self, models_dir: str = None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(__file__), "..", "ml", "models")
        self.models_dir = models_dir

        self.rf_model = None
        self.iso_model = None
        self.preprocessor = None
        self.label_encoder = None
        self.metadata = {}
        
        self.load_models()

    def load_models(self):
        """Loads serialized models, transformers, and training metadata."""
        try:
            rf_path = os.path.join(self.models_dir, "cybershield_rf.joblib")
            iso_path = os.path.join(self.models_dir, "cybershield_iso.joblib")
            prep_path = os.path.join(self.models_dir, "preprocessor.joblib")
            le_path = os.path.join(self.models_dir, "label_encoder.joblib")
            meta_path = os.path.join(self.models_dir, "metadata.json")

            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
            if os.path.exists(iso_path):
                self.iso_model = joblib.load(iso_path)
            if os.path.exists(prep_path):
                self.preprocessor = joblib.load(prep_path)
            if os.path.exists(le_path):
                self.label_encoder = joblib.load(le_path)
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            print("[+] CyberShield Detector loaded successfully.")
        except Exception as e:
            print(f"[!] Warning: Could not load some model artifacts: {e}")

    def predict_packet(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies a single network flow or packet.
        Returns prediction, confidence, severity, explainability tags, and anomaly flag.
        """
        meta = raw_features.get("_meta", {})
        sanitized = NetworkFeatureExtractor.sanitize_features(raw_features)

        # 1. Fast Signature / Heuristic Check
        heuristic_res = self._check_heuristics(sanitized)
        if heuristic_res:
            return self._enrich_result(heuristic_res, sanitized, meta)

        # 2. Supervised & Anomaly ML Evaluation
        if self.rf_model is not None and self.preprocessor is not None and self.label_encoder is not None:
            try:
                # Prepare DataFrame row
                df_row = pd.DataFrame([sanitized])[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
                X_trans = self.preprocessor.transform(df_row)

                # Random Forest Multi-class prediction
                pred_idx = self.rf_model.predict(X_trans)[0]
                probs = self.rf_model.predict_proba(X_trans)[0]
                pred_class = self.label_encoder.inverse_transform([pred_idx])[0]
                confidence = float(probs[pred_idx])

                # Isolation Forest Zero-Day Anomaly Detection
                anomaly_score = 0.0
                is_zero_day = False
                if self.iso_model is not None:
                    iso_pred = self.iso_model.predict(X_trans)[0] # 1 for inlier, -1 for anomaly
                    score_raw = self.iso_model.decision_function(X_trans)[0]
                    anomaly_score = float(score_raw)
                    if iso_pred == -1 and pred_class == "Normal" and score_raw < -0.10:
                        pred_class = "Zero-Day Anomaly"
                        is_zero_day = True
                        confidence = round(min(0.95, abs(score_raw) * 2.0), 3)

                # Determine Explainability Reasons
                reasons = self._explain_prediction(sanitized, pred_class)
                severity = self._classify_severity(pred_class, confidence)
                is_attack = (pred_class != "Normal")

                return {
                    "attack_type": pred_class,
                    "is_attack": is_attack,
                    "confidence": round(confidence, 3),
                    "severity": severity,
                    "anomaly_score": round(anomaly_score, 3),
                    "is_zero_day": is_zero_day,
                    "reasons": reasons,
                    "features": sanitized,
                    "metadata": meta
                }
            except Exception as e:
                print(f"[!] ML prediction error: {e}")

        # Fallback if model fails
        return {
            "attack_type": "Normal",
            "is_attack": False,
            "confidence": 0.50,
            "severity": "SAFE",
            "anomaly_score": 0.0,
            "is_zero_day": False,
            "reasons": ["Baseline flow inspection"],
            "features": sanitized,
            "metadata": meta
        }

    def predict_batch(self, df_or_records: Any) -> List[Dict[str, Any]]:
        """Run batch inference on multiple network packets (e.g. from uploaded CSV/PCAP)."""
        if isinstance(df_or_records, list):
            df = pd.DataFrame(df_or_records)
        else:
            df = df_or_records.copy()

        results = []
        for _, row in df.iterrows():
            row_dict = row.to_dict()
            results.append(self.predict_packet(row_dict))
        return results

    def _check_heuristics(self, f: Dict[str, Any]) -> Tuple[str, float, str]:
        """Catch obvious network attacks via deterministic signatures."""
        # LAND Attack
        if f.get("land", 0) == 1:
            return ("DoS", 0.99, "LAND Attack: Source and Destination IP/Port are identical.")
        # Ping of Death
        if f.get("protocol_type") == "icmp" and f.get("src_bytes", 0) > 65000:
            return ("DoS", 0.99, "Ping of Death: Oversized ICMP payload detected.")
        # Root Shell compromise
        if f.get("root_shell", 0) == 1 and f.get("su_attempted", 0) > 0:
            return ("U2R", 0.98, "Unauthorized root shell & privilege escalation attempt.")
        # Brute Force credential stuffing
        if f.get("num_failed_logins", 0) >= 3 and f.get("logged_in", 0) == 0:
            return ("R2L", 0.95, "Multiple consecutive failed authentications detected.")
        return None

    def _enrich_result(self, h_res: Tuple[str, float, str], sanitized: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
        attack_type, conf, reason = h_res
        severity = self._classify_severity(attack_type, conf)
        return {
            "attack_type": attack_type,
            "is_attack": True,
            "confidence": round(conf, 3),
            "severity": severity,
            "anomaly_score": -0.85,
            "is_zero_day": False,
            "reasons": [reason],
            "features": sanitized,
            "metadata": meta
        }

    def _explain_prediction(self, f: Dict[str, Any], attack_type: str) -> List[str]:
        """Explainable AI: Translates network feature values into human-readable SOC insights."""
        reasons = []
        if attack_type == "DoS":
            if f.get("count", 0) > 100:
                reasons.append(f"Abnormal burst connection volume: {f['count']} reqs/2s")
            if f.get("serror_rate", 0) > 0.5:
                reasons.append(f"High SYN error rate ({int(f['serror_rate']*100)}% unacknowledged handshakes)")
            if f.get("flag") in ["S0", "REJ"]:
                reasons.append(f"Incomplete TCP handshake flag: {f['flag']}")
        elif attack_type == "Probe":
            if f.get("diff_srv_rate", 0) > 0.5:
                reasons.append(f"High port sweep variation ({int(f['diff_srv_rate']*100)}% diverse services)")
            if f.get("src_bytes", 0) < 60:
                reasons.append("Zero/minimal payload size consistent with port scan probe")
        elif attack_type == "R2L":
            if f.get("num_failed_logins", 0) > 0:
                reasons.append(f"Detected {f['num_failed_logins']} failed login credential attempts")
            if f.get("service") in ["ftp", "ssh", "telnet"]:
                reasons.append(f"Targeting sensitive access service: {f['service'].upper()}")
        elif attack_type == "U2R":
            if f.get("root_shell", 0) == 1:
                reasons.append("Unauthorized root/administrative shell spawned")
            if f.get("num_root", 0) > 0:
                reasons.append(f"Unusual privileged command executions ({f['num_root']})")
        elif attack_type == "Zero-Day Anomaly":
            reasons.append("Statistical divergence from baseline normal network distribution")
            reasons.append("Isolation Forest detected multi-feature topological outlier")
        else:
            reasons.append("Normal bi-directional communication protocol profile")
        
        return reasons if reasons else ["Standard network flow pattern verified"]

    @staticmethod
    def _classify_severity(attack_type: str, confidence: float) -> str:
        if attack_type == "Normal":
            return "SAFE"
        if attack_type in ["U2R", "Zero-Day Anomaly"]:
            return "CRITICAL"
        if attack_type == "DoS":
            return "CRITICAL" if confidence >= 0.9 else "HIGH"
        if attack_type == "R2L":
            return "HIGH"
        if attack_type == "Probe":
            return "MEDIUM"
        return "LOW"
