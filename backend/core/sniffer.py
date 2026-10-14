"""
CyberShield Live Network Packet Sniffer.
Captures real-time packets from local network interfaces using Scapy or raw sockets.
Gracefully handles environments without Npcap/admin privileges.
"""

import time
import threading
import logging
from typing import Callable, Optional, Dict, Any, List

logger = logging.getLogger("cybershield.sniffer")


class LivePacketSniffer:
    def __init__(self, packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.packet_callback = packet_callback
        self.is_running = False
        self._thread = None
        self.interface = None
        self.packet_count = 0
        self.status = "STOPPED" # "RUNNING", "STOPPED", "ERROR_NO_DRIVER"
        self.last_error = ""

    def get_interfaces(self) -> List[str]:
        """Lists available network interfaces on the host machine."""
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception as e:
            logger.debug(f"Could not list interfaces via scapy: {e}")
            return ["Default Interface"]

    def start(self, interface: Optional[str] = None) -> Dict[str, Any]:
        """Starts live packet capture in a background daemon thread."""
        if self.is_running:
            return {"status": "ALREADY_RUNNING", "message": "Live capture already active."}

        self.interface = interface
        self.is_running = True
        self.status = "RUNNING"
        self.last_error = ""

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        return {"status": "SUCCESS", "message": f"Sniffer started on interface: {interface or 'all'}"}

    def stop(self) -> Dict[str, Any]:
        """Stops live packet capture."""
        self.is_running = False
        self.status = "STOPPED"
        return {"status": "SUCCESS", "message": "Sniffer stopped."}

    def _sniff_loop(self):
        try:
            from scapy.all import sniff
            from core.feature_extractor import NetworkFeatureExtractor

            extractor = NetworkFeatureExtractor()

            def process_pkt(scapy_pkt):
                if not self.is_running:
                    return
                self.packet_count += 1
                try:
                    features = extractor.extract_from_scapy(scapy_pkt)
                    if self.packet_callback:
                        self.packet_callback(features)
                except Exception as ex:
                    logger.debug(f"Error parsing packet: {ex}")

            logger.info("[*] Starting Scapy sniff session...")
            
            # Use sniff with stop_filter to allow graceful exit
            sniff(
                iface=self.interface,
                prn=process_pkt,
                stop_filter=lambda x: not self.is_running,
                store=False
            )

        except Exception as e:
            err_msg = str(e)
            logger.warning(f"[!] Sniffing failed or stopped: {err_msg}")
            self.status = "ERROR_NO_DRIVER" if "winpcap" in err_msg.lower() or "npcap" in err_msg.lower() or "permission" in err_msg.lower() else "ERROR"
            self.last_error = err_msg
            self.is_running = False
