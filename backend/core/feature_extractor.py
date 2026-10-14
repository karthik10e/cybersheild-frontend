"""
CyberShield Network Feature Extractor.
Extracts network flow features from raw packets (Scapy/Socket) or JSON dictionaries,
aligning them with standardized intrusion detection benchmark schemas (NSL-KDD style).
"""

import time
import math
from typing import Dict, Any, List, Tuple

# Standard categorical mappings
PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "dns", "ftp", "ssh", "smtp", "telnet", "private", "eco_i", "other"]
FLAGS = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "S2", "OTH"]

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "count", "srv_count", "serror_rate",
    "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count"
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "count", "srv_count", "serror_rate",
    "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count"
]
NUMERIC_COLUMNS = NUMERIC_FEATURES


class NetworkFeatureExtractor:
    """Extracts and formats features for machine learning intrusion detection."""

    def __init__(self):
        # Rolling flow tracker for live stream statistical aggregation
        self.host_connections = {}
        self.service_connections = {}
        self.last_clean_time = time.time()

    def extract_from_scapy(self, packet: Any) -> Dict[str, Any]:
        """
        Parses a live Scapy packet into network flow features + metadata.
        """
        now = time.time()
        pkt_len = len(packet) if hasattr(packet, "__len__") else 64
        
        # Default defaults
        src_ip = "192.168.1.50"
        dst_ip = "192.168.1.1"
        src_port = 0
        dst_port = 80
        proto_name = "tcp"
        service = "other"
        flag = "SF"
        land = 0
        wrong_fragment = 0
        urgent = 0

        # Layer 3 IP Inspection
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            if src_ip == dst_ip:
                land = 1
            if hasattr(ip_layer, "flags") and str(ip_layer.flags) == "MF":
                wrong_fragment = 1

        # Layer 4 TCP / UDP / ICMP
        if packet.haslayer("TCP"):
            tcp_layer = packet.getlayer("TCP")
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            proto_name = "tcp"
            
            # Map TCP flags
            flags_str = str(tcp_layer.flags)
            if "S" in flags_str and "A" not in flags_str:
                flag = "S0"
            elif "R" in flags_str:
                flag = "REJ"
            elif "F" in flags_str and "A" not in flags_str:
                flag = "RSTO"
            else:
                flag = "SF"

            if hasattr(tcp_layer, "urgptr") and tcp_layer.urgptr > 0:
                urgent = 1

            # Identify service by common ports
            service = self._port_to_service(dst_port)

        elif packet.haslayer("UDP"):
            udp_layer = packet.getlayer("UDP")
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            proto_name = "udp"
            flag = "SF"
            service = self._port_to_service(dst_port)

        elif packet.haslayer("ICMP"):
            proto_name = "icmp"
            service = "eco_i"
            flag = "SF"

        # Update statistical flow aggregates
        count, srv_count, serror_rate, same_srv_rate = self._update_aggregates(dst_ip, service, flag)

        feature_dict = {
            "duration": 0.0,
            "protocol_type": proto_name,
            "service": service,
            "flag": flag,
            "src_bytes": pkt_len,
            "dst_bytes": 0,
            "land": land,
            "wrong_fragment": wrong_fragment,
            "urgent": urgent,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if service in ["http", "smtp"] and flag == "SF" else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "rerror_rate": 0.0 if flag != "REJ" else 1.0,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": max(0.0, 1.0 - same_srv_rate),
            "dst_host_count": min(count * 2, 255),
            "dst_host_srv_count": min(srv_count * 2, 255),
            # Metadata for frontend display
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "timestamp": now,
                "protocol": proto_name.upper(),
                "length": pkt_len
            }
        }
        return feature_dict

    def _port_to_service(self, port: int) -> str:
        """Map well-known ports to service labels."""
        mapping = {
            80: "http", 443: "http", 8080: "http",
            53: "dns",
            21: "ftp", 20: "ftp",
            22: "ssh",
            25: "smtp", 587: "smtp",
            23: "telnet"
        }
        return mapping.get(port, "other")

    def _update_aggregates(self, dst_ip: str, service: str, flag: str) -> Tuple[int, int, float, float]:
        """Rolling window statistical feature updates."""
        now = time.time()
        # Periodically purge old entries (every 10 seconds)
        if now - self.last_clean_time > 10.0:
            self.host_connections.clear()
            self.service_connections.clear()
            self.last_clean_time = now

        self.host_connections[dst_ip] = self.host_connections.get(dst_ip, 0) + 1
        self.service_connections[service] = self.service_connections.get(service, 0) + 1
        
        count = self.host_connections[dst_ip]
        srv_count = self.service_connections[service]
        serror_rate = 1.0 if flag in ["S0", "S1", "S2"] else 0.0
        same_srv_rate = min(1.0, srv_count / max(1, count))
        
        return count, srv_count, serror_rate, same_srv_rate

    @staticmethod
    def sanitize_features(data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures all expected feature keys are present with appropriate types."""
        sanitized = {}
        for col in FEATURE_COLUMNS:
            val = data.get(col)
            if col in ["protocol_type", "service", "flag"]:
                sanitized[col] = str(val if val is not None else ("tcp" if col == "protocol_type" else ("http" if col == "service" else "SF"))).lower()
                if col == "flag":
                    sanitized[col] = sanitized[col].upper()
            else:
                try:
                    sanitized[col] = float(val) if val is not None else 0.0
                except (ValueError, TypeError):
                    sanitized[col] = 0.0
        return sanitized
