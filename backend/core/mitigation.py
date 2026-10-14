"""
CyberShield Active Defense & Mitigation Subsystem.
Handles IP scoring, automated quarantine, firewall rule synthesis (Windows netsh / Linux iptables),
and security incident history management.
"""

import time
import subprocess
import platform
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("cybershield.mitigation")


class ActiveDefense:
    def __init__(self, auto_block_threshold: float = 0.85):
        self.auto_block_threshold = auto_block_threshold
        # Whitelisted addresses that should never be auto-blocked
        self.whitelist = {"127.0.0.1", "localhost", "::1", "192.168.1.1", "10.0.0.1"}
        
        # In-memory stores
        # blocked_ips[ip] = { "blocked_at": timestamp, "reason": str, "attack_type": str, "rule_id": str }
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        
        # ip_threat_scores[ip] = float (cumulative threat score 0.0 to 10.0)
        self.ip_threat_scores: Dict[str, float] = {}
        
        # List of incident logs
        self.incidents: List[Dict[str, Any]] = []
        self.max_incidents = 1000

    def record_packet(self, packet_info: Dict[str, Any], attack_type: str, confidence: float, is_attack: bool) -> Optional[Dict[str, Any]]:
        """
        Evaluate packet threat level, update IP threat score, and trigger mitigation if required.
        """
        src_ip = packet_info.get("src_ip", "0.0.0.0")
        dst_ip = packet_info.get("dst_ip", "0.0.0.0")
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "TCP")

        if src_ip in self.whitelist or src_ip.startswith("127."):
            return None

        action_taken = "MONITORED"
        auto_blocked = False

        if is_attack:
            # Increase threat score based on confidence and attack severity
            severity_weights = {
                "DoS": 2.5,
                "Probe": 1.5,
                "R2L": 3.0,
                "U2R": 4.0,
                "Anomaly": 2.0
            }
            weight = severity_weights.get(attack_type, 1.5)
            added_score = weight * confidence
            self.ip_threat_scores[src_ip] = self.ip_threat_scores.get(src_ip, 0.0) + added_score

            # Check if auto-block condition met
            if (confidence >= self.auto_block_threshold or self.ip_threat_scores[src_ip] >= 5.0) and src_ip not in self.blocked_ips:
                self.block_ip(src_ip, reason=f"High-threat {attack_type} detected (confidence: {confidence*100:.1f}%)", attack_type=attack_type)
                action_taken = "AUTO-BLOCKED"
                auto_blocked = True
            else:
                action_taken = "ALERT_FLAGGED"
        else:
            # Legitimate traffic slowly cools down threat score
            if src_ip in self.ip_threat_scores:
                self.ip_threat_scores[src_ip] = max(0.0, self.ip_threat_scores[src_ip] - 0.1)

        # Log incident
        incident = {
            "id": len(self.incidents) + 1,
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S", time.localtime()),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "threat_score": round(self.ip_threat_scores.get(src_ip, 0.0), 2),
            "action": action_taken,
            "is_blocked": src_ip in self.blocked_ips
        }
        
        self.incidents.append(incident)
        if len(self.incidents) > self.max_incidents:
            self.incidents.pop(0)

        return incident if is_attack else None

    def block_ip(self, ip: str, reason: str = "Manual security block", attack_type: str = "Manual") -> bool:
        """Add IP to blocklist and synthesize host firewall command."""
        if ip in self.whitelist:
            logger.warning(f"Cannot block whitelisted IP: {ip}")
            return False

        if ip in self.blocked_ips:
            return True

        rule_cmd = self._generate_firewall_command(ip, action="BLOCK")
        self.blocked_ips[ip] = {
            "ip": ip,
            "blocked_at": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "reason": reason,
            "attack_type": attack_type,
            "rule_command": rule_cmd,
            "status": "ACTIVE"
        }
        
        # Attempt OS firewall rule injection (safely handled)
        self._apply_firewall_rule(rule_cmd)
        logger.info(f"[CyberShield Mitigation] Blocked IP {ip} | Reason: {reason}")
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove IP from blocklist and clear firewall rule."""
        if ip in self.blocked_ips:
            rule_cmd = self._generate_firewall_command(ip, action="UNBLOCK")
            self._apply_firewall_rule(rule_cmd)
            del self.blocked_ips[ip]
            if ip in self.ip_threat_scores:
                self.ip_threat_scores[ip] = 0.0
            logger.info(f"[CyberShield Mitigation] Unblocked IP {ip}")
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        return ip in self.blocked_ips

    def get_blocked_list(self) -> List[Dict[str, Any]]:
        """Return list of currently blocked IPs with metadata."""
        return list(self.blocked_ips.values())

    def get_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return most recent incidents."""
        return self.incidents[-limit:][::-1]

    def _generate_firewall_command(self, ip: str, action: str = "BLOCK") -> str:
        """Synthesizes OS-specific firewall command for the target IP."""
        os_type = platform.system().lower()
        rule_name = f"CyberShield_Block_{ip.replace('.', '_')}"
        if "windows" in os_type:
            if action == "BLOCK":
                return f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            else:
                return f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            if action == "BLOCK":
                return f"iptables -A INPUT -s {ip} -j DROP"
            else:
                return f"iptables -D INPUT -s {ip} -j DROP"

    def _apply_firewall_rule(self, cmd: str) -> bool:
        """
        Executes firewall command with graceful fallback if non-elevated.
        Does not throw exception to maintain dashboard stability.
        """
        try:
            # We run in quiet mode, if permissions permit it blocks, otherwise logs
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Could not execute system firewall rule directly (requires admin): {e}")
            return False
