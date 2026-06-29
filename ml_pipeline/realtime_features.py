"""
realtime_features.py — Live Feature Extractor for ML Inference
===============================================================
Converts raw network events into the same 10-feature vector
that the unsupervised models were trained on.

Each device maintains a rolling 30-second window of packets.
Every time a new event arrives for device X:
  1. Add event to device X window buffer
  2. Drop events older than 30 seconds
  3. Compute 10 features from current buffer
  4. Return feature vector → ready for ML model input

This mirrors exactly how the training data was built
(10-second windows → features → model training).

Usage:
  from ml_pipeline.realtime_features import DeviceFeatureExtractor
  extractor = DeviceFeatureExtractor()
  extractor.add_event({...})
  vec = extractor.get_feature_vector("192.168.10.50")
"""

import math
import time
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta

WINDOW_SECONDS = 30  # rolling window size


class DeviceFeatureExtractor:
    """
    Maintains per-device rolling windows.
    Computes the exact same 10 ML features used during training.
    """

    def __init__(self):
        # {device_ip: deque of (timestamp, event_dict)}
        self.windows = defaultdict(deque)

    def add_event(self, event):
        """
        Add a new event to the device's rolling window.

        event dict keys:
            src_ip      — source IP address
            dst_ip      — destination IP address
            protocol    — "Modbus", "MQTT", "HTTP", "TCP", "UDP", "OTHER"
            action      — "NORMAL", "PORT_SCAN", "MALICIOUS_WRITE", etc.
            packet_size — int, bytes
            src_zone    — "OT", "IoT", "DMZ"
            dst_zone    — "OT", "IoT", "DMZ"
            dst_port    — int, destination port (optional)
            timestamp   — datetime or string
        """
        ip = event["src_ip"]
        ts = event.get("timestamp", datetime.now())
        if isinstance(ts, str):
            ts = (
                datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
                if "." in ts
                else datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            )
        self.windows[ip].append((ts, event))
        self._drop_old(ip, ts)

    def _drop_old(self, ip, now):
        """Remove events older than WINDOW_SECONDS from the device buffer."""
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        while self.windows[ip] and self.windows[ip][0][0] < cutoff:
            self.windows[ip].popleft()

    def _shannon_entropy(self, counts_dict):
        """Compute Shannon entropy over a {label: count} frequency dict."""
        total = sum(counts_dict.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in counts_dict.values():
            p = c / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def get_feature_vector(self, ip):
        """
        Returns numpy array of 10 features for the given device IP.
        Uses events in the current rolling window.
        Returns zeros if no events.

        Feature order (matches training columns in AGG_FEATURES):
          [0] total_packets
          [1] unique_destinations
          [2] unique_ports
          [3] avg_packet_size
          [4] protocol_diversity
          [5] modbus_ratio
          [6] mqtt_ratio
          [7] scan_rate
          [8] write_ratio
          [9] cross_zone_ratio
        """
        events = [e for (_, e) in self.windows.get(ip, deque())]

        if not events:
            return np.zeros(10)  # 10 ML features

        total = len(events)
        dst_ips = set()
        dst_ports = set()
        sizes = []
        proto_counts = defaultdict(int)
        syn_count = 0
        write_count = 0
        cross_zone = 0
        modbus_count = 0
        mqtt_count = 0
        http_count = 0

        for e in events:
            dst_ips.add(e.get("dst_ip", ""))
            dst_ports.add(e.get("dst_port", 0))
            sizes.append(e.get("packet_size", 64))

            proto = e.get("protocol", "OTHER")
            proto_counts[proto] += 1
            if proto == "Modbus":
                modbus_count += 1
            if proto == "MQTT":
                mqtt_count += 1
            if proto == "HTTP":
                http_count += 1

            if e.get("action") in ["PORT_SCAN"]:
                syn_count += 1
            if e.get("action") == "MALICIOUS_WRITE":
                write_count += 1
            if e.get("src_zone", "") != e.get("dst_zone", ""):
                cross_zone += 1

        # 10 features matching training columns
        features = np.array([
            float(total),                                     # total_packets
            float(len(dst_ips)),                              # unique_destinations
            float(len(dst_ports)),                            # unique_ports
            float(sum(sizes) / total) if total else 0.0,     # avg_packet_size
            self._shannon_entropy(proto_counts),              # protocol_diversity
            float(modbus_count / total),                      # modbus_ratio
            float(mqtt_count / total),                        # mqtt_ratio
            float(syn_count / total),                         # scan_rate
            float(write_count / total),                       # write_ratio
            float(cross_zone / total),                        # cross_zone_ratio
        ], dtype=np.float64)

        return features

    def get_all_device_features(self, device_ips):
        """
        Returns dict {ip: feature_vector} for all devices.
        Used for batch inference.
        """
        return {ip: self.get_feature_vector(ip) for ip in device_ips}

    def clear_device(self, ip):
        """Clear the rolling window for a specific device."""
        if ip in self.windows:
            self.windows[ip].clear()

    def clear_all(self):
        """Clear all device windows."""
        self.windows.clear()

    def get_window_size(self, ip):
        """Return the number of events in a device's current window."""
        return len(self.windows.get(ip, deque()))


if __name__ == "__main__":
    # ── Unit test ──────────────────────────────────────────────
    extractor = DeviceFeatureExtractor()

    # Simulate normal PLC events
    for i in range(20):
        extractor.add_event({
            "src_ip": "192.168.10.10",
            "dst_ip": "192.168.10.20",
            "protocol": "Modbus",
            "action": "NORMAL",
            "packet_size": 64,
            "src_zone": "OT",
            "dst_zone": "OT",
            "dst_port": 502,
            "timestamp": datetime.now(),
        })

    # Simulate C2 device events (Engineering-WS at 192.168.10.50)
    for i in range(50):
        extractor.add_event({
            "src_ip": "192.168.10.50",
            "dst_ip": f"192.168.10.{i % 25}",
            "protocol": "TCP",
            "action": "PORT_SCAN",
            "packet_size": 40,
            "src_zone": "OT",
            "dst_zone": "OT",
            "dst_port": 1000 + i,
            "timestamp": datetime.now(),
        })

    plc1_vec = extractor.get_feature_vector("192.168.10.10")
    ews_vec  = extractor.get_feature_vector("192.168.10.50")

    print("PLC1           features:", plc1_vec.round(3))
    print("Engineering-WS features:", ews_vec.round(3))
    print()
    print("PLC1           scan_rate:", plc1_vec[7])
    print("Engineering-WS scan_rate:", ews_vec[7])
    print()

    assert ews_vec[7] > plc1_vec[7], "FAIL: C2 device should have higher scan_rate"
    assert ews_vec[2] > plc1_vec[2], "FAIL: C2 device should have more unique ports"
    print("  Feature extractor working correctly")
