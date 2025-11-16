import threading
import time
from scapy.all import sniff

class NetworkSniffer:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        self.callback({"type": "status", "msg": "[*] NetworkSniffer started."})

    def stop(self):
        self.running = False
        self.callback({"type": "status", "msg": "[*] NetworkSniffer stopped."})

    def _sniff_loop(self):
        sniff(prn=self._process_packet, stop_filter=lambda x: not self.running)

    def _process_packet(self, pkt):
        try:
            pkt_dict = {
                "src": getattr(pkt, "src", ""),
                "dst": getattr(pkt, "dst", ""),
                "proto": pkt.summary().split()[1] if len(pkt.summary().split()) > 1 else "",
                "raw": str(pkt),
            }
            self.callback(pkt_dict)
        except Exception as e:
            self.callback({"type": "error", "msg": f"Packet parsing error: {e}"})
####Prototype v1.4####