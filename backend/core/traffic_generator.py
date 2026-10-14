"""
CyberShield Synthetic Network Traffic Generator & Attack Simulator.
Generates realistic normal network traffic and reproduces targeted cyber attacks:
- TCP SYN Flood (DoS)
- Nmap Port Sweep & Stealth Scanning (Probe)
- SSH/FTP Brute Force (R2L)
- Buffer Overflow / Rootkit Exploit (U2R)
- Distributed Denial of Service (DDoS)
"""

import time
import random
import threading
from typing import Dict, Any, Callable, Optional


class TrafficSimulator:
    def __init__(self, callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.callback = callback
        self.is_running = False
        self._thread = None
        self.delay = 0.8 # Seconds between packets
        self.attack_mode = "mixed" # "mixed", "normal_only", "syn_flood", "port_scan", "brute_force", "u2r"
        self._lock = threading.Lock()

        # Attacker IP pools
        self.botnet_ips = [f"45.33.32.{i}" for i in range(10, 40)] + [f"185.220.101.{i}" for i in range(5, 30)]
        self.internal_ips = [f"192.168.1.{i}" for i in range(20, 90)]
        self.victim_ip = "192.168.1.10"

    def start(self, mode: str = "mixed", delay: float = 0.8):
        """Starts background traffic generation."""
        with self._lock:
            self.attack_mode = mode
            self.delay = max(0.1, delay)
            if not self.is_running:
                self.is_running = True
                self._thread = threading.Thread(target=self._run_loop, daemon=True)
                self._thread.start()

    def stop(self):
        """Stops background traffic generation."""
        with self._lock:
            self.is_running = False

    def trigger_burst_attack(self, attack_name: str, count: int = 15):
        """Triggers an immediate burst of specific attack packets."""
        def burst_worker():
            for _ in range(count):
                pkt = self.generate_packet(scenario=attack_name)
                if self.callback:
                    self.callback(pkt)
                time.sleep(0.08)

        t = threading.Thread(target=burst_worker, daemon=True)
        t.start()

    def set_mode(self, mode: str):
        with self._lock:
            self.attack_mode = mode

    def set_speed(self, delay: float):
        with self._lock:
            self.delay = max(0.05, delay)

    def _run_loop(self):
        while self.is_running:
            with self._lock:
                current_mode = self.attack_mode
                sleep_time = self.delay

            packet = self.generate_packet(scenario=current_mode)
            if self.callback:
                self.callback(packet)

            time.sleep(sleep_time)

    def generate_packet(self, scenario: str = "mixed") -> Dict[str, Any]:
        """Generates a single synthetic packet with network flow properties."""
        if scenario == "mixed":
            # 65% normal, 35% attacks
            r = random.random()
            if r < 0.65:
                return self._generate_normal_packet()
            elif r < 0.80:
                return self._generate_dos_packet()
            elif r < 0.92:
                return self._generate_probe_packet()
            elif r < 0.97:
                return self._generate_r2l_packet()
            else:
                return self._generate_u2r_packet()

        elif scenario == "normal_only":
            return self._generate_normal_packet()
        elif scenario in ["syn_flood", "dos"]:
            return self._generate_dos_packet()
        elif scenario in ["port_scan", "probe"]:
            return self._generate_probe_packet()
        elif scenario in ["brute_force", "r2l"]:
            return self._generate_r2l_packet()
        elif scenario in ["exploit", "u2r"]:
            return self._generate_u2r_packet()
        else:
            return self._generate_normal_packet()

    def _generate_normal_packet(self) -> Dict[str, Any]:
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(["142.250.190.46", "1.1.1.1", "151.101.1.140", "192.168.1.1"])
        service = random.choice(["http", "http", "dns", "smtp", "ssh"])
        
        ports = {"http": 443 if random.random() > 0.3 else 80, "dns": 53, "smtp": 587, "ssh": 22}
        proto = "udp" if service == "dns" else "tcp"
        dst_port = ports.get(service, 80)
        src_port = random.randint(30000, 65000)

        src_bytes = random.randint(120, 1800)
        dst_bytes = random.randint(250, 15000)
        now = time.time()

        return {
            "duration": round(random.uniform(0.01, 1.2), 2),
            "protocol_type": proto,
            "service": service,
            "flag": "SF",
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1 if proto == "tcp" and service in ["http", "smtp"] else 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": random.randint(1, 12),
            "srv_count": random.randint(1, 8),
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": round(random.uniform(0.85, 1.0), 2),
            "diff_srv_rate": round(random.uniform(0.0, 0.1), 2),
            "dst_host_count": random.randint(5, 30),
            "dst_host_srv_count": random.randint(5, 30),
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto.upper(),
                "timestamp": now,
                "length": src_bytes + 54
            }
        }

    def _generate_dos_packet(self) -> Dict[str, Any]:
        src_ip = random.choice(self.botnet_ips)
        dst_ip = self.victim_ip
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080])
        now = time.time()

        return {
            "duration": 0.0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": random.choice(["S0", "S0", "S0", "REJ"]),
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": random.randint(250, 510),
            "srv_count": random.randint(200, 500),
            "serror_rate": round(random.uniform(0.88, 1.0), 2),
            "rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": 255,
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "timestamp": now,
                "length": 60
            }
        }

    def _generate_probe_packet(self) -> Dict[str, Any]:
        src_ip = random.choice(self.botnet_ips[:5]) # Consistent scanning IP
        dst_ip = self.victim_ip
        src_port = random.randint(40000, 60000)
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        dst_port = random.choice(target_ports)
        now = time.time()

        return {
            "duration": round(random.uniform(0.01, 0.08), 2),
            "protocol_type": "tcp",
            "service": "other",
            "flag": random.choice(["REJ", "RSTO", "RSTR", "SH"]),
            "src_bytes": 0,
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": random.randint(25, 95),
            "srv_count": random.randint(1, 5),
            "serror_rate": 0.0,
            "rerror_rate": round(random.uniform(0.75, 1.0), 2),
            "same_srv_rate": round(random.uniform(0.05, 0.2), 2),
            "diff_srv_rate": round(random.uniform(0.8, 1.0), 2),
            "dst_host_count": random.randint(150, 255),
            "dst_host_srv_count": random.randint(1, 10),
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "timestamp": now,
                "length": 44
            }
        }

    def _generate_r2l_packet(self) -> Dict[str, Any]:
        src_ip = random.choice(self.botnet_ips[5:15])
        dst_ip = self.victim_ip
        src_port = random.randint(30000, 50000)
        dst_port = random.choice([22, 21]) # SSH or FTP
        service = "ssh" if dst_port == 22 else "ftp"
        now = time.time()

        return {
            "duration": round(random.uniform(2.0, 5.0), 2),
            "protocol_type": "tcp",
            "service": service,
            "flag": "SF",
            "src_bytes": random.randint(240, 550),
            "dst_bytes": random.randint(120, 300),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": random.randint(1, 3),
            "num_failed_logins": random.randint(3, 7), # Multi-failed attempts
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": random.randint(3, 10),
            "srv_count": random.randint(3, 10),
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": random.randint(5, 20),
            "dst_host_srv_count": random.randint(5, 20),
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "timestamp": now,
                "length": 350
            }
        }

    def _generate_u2r_packet(self) -> Dict[str, Any]:
        src_ip = random.choice(self.internal_ips) # Compromised internal host
        dst_ip = self.victim_ip
        src_port = random.randint(32000, 55000)
        dst_port = 23 # Telnet / Terminal
        now = time.time()

        return {
            "duration": round(random.uniform(10.0, 30.0), 2),
            "protocol_type": "tcp",
            "service": "telnet",
            "flag": "SF",
            "src_bytes": random.randint(800, 2400),
            "dst_bytes": random.randint(2000, 6000),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 1,
            "hot": random.randint(3, 6),
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": random.randint(2, 5),
            "root_shell": 1, # Gained root shell
            "su_attempted": 1, # su attempted
            "num_root": random.randint(2, 6),
            "num_file_creations": random.randint(1, 3),
            "count": 2,
            "srv_count": 2,
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": 5,
            "dst_host_srv_count": 5,
            "_meta": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "timestamp": now,
                "length": 1500
            }
        }
