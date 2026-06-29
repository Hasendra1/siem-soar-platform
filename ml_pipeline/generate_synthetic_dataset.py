"""
generate_synthetic_dataset.py
=============================
Generates a synthetic clustering_dataset.csv that matches
the exact schema our capture_traffic.py would produce.
Used when Docker containers aren't running.
9 devices x 30 windows = 270 rows.
Attacker has elevated scan_rate, write_ratio, cross_zone_ratio.
"""

import csv
import random
import numpy as np
from datetime import datetime, timedelta

OUTPUT = r"C:\siem-soar-platform\dataset\clustering_dataset.csv"

DEVICES = [
    {"ip": "192.168.10.10",  "name": "PLC1",         "type": "PLC",      "zone": "OT"},
    {"ip": "192.168.10.11",  "name": "PLC2",         "type": "PLC",      "zone": "OT"},
    {"ip": "192.168.10.20",  "name": "HMI",          "type": "HMI",      "zone": "OT"},
    {"ip": "192.168.10.50",  "name": "Engineering-WS", "type": "WORKSTATION", "zone": "OT"},
    {"ip": "192.168.20.10",  "name": "Sensor-Temp",  "type": "SENSOR",   "zone": "IoT"},
    {"ip": "192.168.20.11",  "name": "Sensor-Press", "type": "SENSOR",   "zone": "IoT"},
    {"ip": "192.168.20.100", "name": "MQTT-Broker",  "type": "BROKER",   "zone": "IoT"},
    {"ip": "192.168.30.10",  "name": "CCTV-Camera",  "type": "CAMERA",   "zone": "DMZ"},
    {"ip": "192.168.30.100", "name": "Cloud-Gateway", "type": "GATEWAY", "zone": "DMZ"},
]

random.seed(42)
np.random.seed(42)

def normal_profile(device, window_id):
    """Generate normal traffic features for a non-attacker device."""
    base_packets = {"PLC": 25, "HMI": 18, "SENSOR": 6, "BROKER": 12, "CAMERA": 4, "GATEWAY": 9, "WORKSTATION": 15}
    bp = base_packets.get(device["type"], 10)
    return {
        "total_packets":       max(1, int(bp + np.random.normal(0, 3))),
        "unique_destinations": random.choice([1, 2]),
        "unique_ports":        random.choice([1, 2]),
        "avg_packet_size":     round(64 + np.random.normal(0, 5), 2),
        "protocol_diversity":  round(random.uniform(0, 0.5), 4),
        "modbus_ratio":        round(0.9 + random.uniform(-0.1, 0.1), 4) if device["type"] in ["PLC", "HMI"] else 0.0,
        "mqtt_ratio":          round(0.8 + random.uniform(-0.1, 0.1), 4) if device["type"] in ["SENSOR", "BROKER"] else 0.0,
        "http_ratio":          round(0.7 + random.uniform(-0.1, 0.1), 4) if device["type"] == "CAMERA" else 0.0,
        "scan_rate":           0.0,
        "write_ratio":         0.0,
        "cross_zone_ratio":    0.0,
    }

def attacker_profile(window_id):
    """Generate attacker traffic — escalating over time."""
    phase = window_id / 30.0  # 0.0 to 1.0
    if phase < 0.3:
        # Reconnaissance phase
        return {
            "total_packets":       int(50 + phase * 300),
            "unique_destinations": int(5 + phase * 20),
            "unique_ports":        int(10 + phase * 40),
            "avg_packet_size":     round(40 + np.random.normal(0, 3), 2),
            "protocol_diversity":  round(1.5 + random.uniform(0, 0.5), 4),
            "modbus_ratio":        round(0.1 * phase, 4),
            "mqtt_ratio":          0.0,
            "http_ratio":          round(0.05, 4),
            "scan_rate":           round(0.6 + phase * 0.3, 4),
            "write_ratio":         0.0,
            "cross_zone_ratio":    round(0.3 + phase * 0.2, 4),
        }
    elif phase < 0.7:
        # Attack phase — Modbus writes
        return {
            "total_packets":       int(200 + (phase - 0.3) * 500),
            "unique_destinations": int(3 + random.randint(0, 2)),
            "unique_ports":        int(5 + random.randint(0, 3)),
            "avg_packet_size":     round(80 + np.random.normal(0, 5), 2),
            "protocol_diversity":  round(1.2 + random.uniform(0, 0.3), 4),
            "modbus_ratio":        round(0.5 + (phase - 0.3) * 0.5, 4),
            "mqtt_ratio":          0.0,
            "http_ratio":          0.0,
            "scan_rate":           round(0.2 + random.uniform(0, 0.1), 4),
            "write_ratio":         round(0.3 + (phase - 0.3) * 0.8, 4),
            "cross_zone_ratio":    round(0.5 + random.uniform(0, 0.2), 4),
        }
    else:
        # Lateral movement phase
        return {
            "total_packets":       int(300 + random.randint(0, 100)),
            "unique_destinations": int(8 + random.randint(0, 3)),
            "unique_ports":        int(15 + random.randint(0, 10)),
            "avg_packet_size":     round(60 + np.random.normal(0, 8), 2),
            "protocol_diversity":  round(1.8 + random.uniform(0, 0.3), 4),
            "modbus_ratio":        round(0.3 + random.uniform(0, 0.1), 4),
            "mqtt_ratio":          round(0.1 + random.uniform(0, 0.05), 4),
            "http_ratio":          round(0.1 + random.uniform(0, 0.05), 4),
            "scan_rate":           round(0.4 + random.uniform(0, 0.2), 4),
            "write_ratio":         round(0.2 + random.uniform(0, 0.1), 4),
            "cross_zone_ratio":    round(0.7 + random.uniform(0, 0.2), 4),
        }

rows = []
base_time = datetime(2026, 6, 1, 12, 0, 0)

for w in range(1, 31):
    ts = (base_time + timedelta(seconds=w * 10)).strftime("%Y-%m-%d %H:%M:%S")
    for dev in DEVICES:
        if dev["name"] == "Engineering-WS":
            features = attacker_profile(w)
        else:
            features = normal_profile(dev, w)
        row = {
            "device_ip":   dev["ip"],
            "device_name": dev["name"],
            "device_type": dev["type"],
            "zone":        dev["zone"],
            "window_id":   w,
            "timestamp":   ts,
            **features,
        }
        rows.append(row)

fieldnames = [
    "device_ip", "device_name", "device_type", "zone",
    "window_id", "timestamp", "total_packets", "unique_destinations",
    "unique_ports", "avg_packet_size", "protocol_diversity",
    "modbus_ratio", "mqtt_ratio", "http_ratio",
    "scan_rate", "write_ratio", "cross_zone_ratio"
]

with open(OUTPUT, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} rows -> {OUTPUT}")
print(f"  Devices: {len(DEVICES)}")
print(f"  Windows: 30")

# Quick verification
import pandas as pd
df = pd.read_csv(OUTPUT)
print(f"\nEngineering-WS averages (C2 traffic):")
atk = df[df["device_name"] == "Engineering-WS"]
print(f"  scan_rate  : {atk['scan_rate'].mean():.3f} (max {atk['scan_rate'].max():.3f})")
print(f"  write_ratio: {atk['write_ratio'].mean():.3f} (max {atk['write_ratio'].max():.3f})")
print(f"  cross_zone : {atk['cross_zone_ratio'].mean():.3f} (max {atk['cross_zone_ratio'].max():.3f})")
print(f"\nPLC1 averages:")
plc = df[df["device_name"] == "PLC1"]
print(f"  scan_rate  : {plc['scan_rate'].mean():.3f}")
print(f"  write_ratio: {plc['write_ratio'].mean():.3f}")
