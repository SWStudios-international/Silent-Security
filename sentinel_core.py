# sentinel_core.py v1.7+
import threading
import time
import random
from sentinel_sniffer import NetworkSniffer
from learning_journal import LearningJournal

_sniffer_instance = None
_sentinel_thread = None
_observer_thread = None
_journal = LearningJournal("learning_journal.txt")

# Baseline stats for AI learning
baseline_stats = {
    "packet_count": 0,
    "protocol_distribution": {},
    "port_activity": {},
}

anomaly_threshold = 1.5  # multiplier over baseline for anomaly detection

# Silent Observer: continuously learns traffic baseline
def silent_observer():
    global baseline_stats
    while True:
        if _sniffer_instance and _sniffer_instance.active:
            stats = _sniffer_instance.get_stats()
            # simple moving average baseline update
            baseline_stats["packet_count"] = (baseline_stats["packet_count"] + stats.get("packet_count",0)) / 2
            for proto, count in stats.get("protocol_distribution", {}).items():
                baseline_stats["protocol_distribution"][proto] = (baseline_stats["protocol_distribution"].get(proto,0) + count) / 2
            for port, count in stats.get("port_activity", {}).items():
                baseline_stats["port_activity"][port] = (baseline_stats["port_activity"].get(port,0) + count) / 2
        time.sleep(5)

# anomaly detection based on baseline
def detect_anomaly(packet_info):
    severity = 0
    proto = packet_info.get("protocol", "UNKNOWN")
    port = packet_info.get("port", 0)
    if proto in baseline_stats["protocol_distribution"]:
        if packet_info.get("count",1) > baseline_stats["protocol_distribution"][proto] * anomaly_threshold:
            severity += 1
    if port in baseline_stats["port_activity"]:
        if packet_info.get("count",1) > baseline_stats["port_activity"][port] * anomaly_threshold:
            severity += 1
    return severity

# AI learning log
def ai_learn(packet_info):
    _journal.record(f"[AI] Learning from packet: {packet_info}")

# Start sentinel
def start_sentinel(callback=None):
    global _sniffer_instance, _sentinel_thread, _observer_thread
    if _sniffer_instance is None:
        _sniffer_instance = NetworkSniffer(callback=callback)
    _sniffer_instance.start()
    # start observer thread
    _observer_thread = threading.Thread(target=silent_observer, daemon=True)
    _observer_thread.start()
    if callback:
        callback("[*] Sentinel monitoring started with AI learning.")

# Stop sentinel
def stop_sentinel():
    global _sniffer_instance
    if _sniffer_instance:
        _sniffer_instance.stop()
        _sniffer_instance = None
    _journal.record("[*] Sentinel stopped.")

# Bootstrap sentinel (called automatically on start)
def bootstrap_sentinel(callback=None):
    _journal.record("[*] Bootstrapping Sentinel v1.7+ AI system...")
    time.sleep(1)  # simulate initialization
    if callback:
        callback("[*] Bootstrap complete. AI learning online.")
    _journal.record("[*] Bootstrap complete. AI learning online.")
####Prototype v1.7####