"""
capture_traffic.py — 5-Minute Traffic Capture for ML Dataset
============================================================
Captures real Docker network traffic for exactly 5 minutes.
Aggregates per device per 10-second window.
Output: clustering_dataset.csv ready for unsupervised ML.

Usage (2 terminals):
  Terminal 1:  python ml_pipeline\capture_traffic.py
  Terminal 2:  python agents\live_attack_simulator.py --full-sequence
"""

import time
import math
import csv
import json
import threading
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, Raw

CAPTURE_DURATION = 300  # 5 minutes exactly
WINDOW_SIZE = 10        # 10 seconds per window
OUTPUT_CSV = r"C:\siem-soar-platform\dataset\clustering_dataset.csv"

DEVICE_REGISTRY = {
    "192.168.10.10":  {"name": "PLC1",            "zone": "OT",  "type": "PLC"},
    "192.168.10.11":  {"name": "PLC2",            "zone": "OT",  "type": "PLC"},
    "192.168.10.20":  {"name": "HMI",             "zone": "OT",  "type": "HMI"},
    "192.168.10.50":  {"name": "Engineering-WS",  "zone": "OT",  "type": "WORKSTATION"},
    "192.168.20.10":  {"name": "Sensor-Temp",     "zone": "IoT", "type": "SENSOR"},
    "192.168.20.11":  {"name": "Sensor-Press",    "zone": "IoT", "type": "SENSOR"},
    "192.168.20.100": {"name": "MQTT-Broker",     "zone": "IoT", "type": "BROKER"},
    "192.168.30.10":  {"name": "CCTV-Camera",     "zone": "DMZ", "type": "CAMERA"},
    "192.168.30.100": {"name": "Cloud-Gateway",   "zone": "DMZ", "type": "GATEWAY"},
}

ZONE_MAP = {ip: d["zone"] for ip, d in DEVICE_REGISTRY.items()}

# Per-window packet buffer: {src_ip: [packet_info, ...]}
window_buffer = defaultdict(list)
buffer_lock = threading.Lock()
all_rows = []


def get_zone(ip):
    """Return the network zone for a given IP address."""
    return ZONE_MAP.get(ip, "EXTERNAL")


def detect_protocol(pkt):
    """Classify the application-layer protocol of a packet."""
    if TCP in pkt:
        dport = pkt[TCP].dport
        if dport == 502:
            return "Modbus"
        if dport in [80, 8080]:
            return "HTTP"
        return "TCP"
    if UDP in pkt:
        dport = pkt[UDP].dport
        if dport == 1883:
            return "MQTT"
        return "UDP"
    return "OTHER"


def is_syn_only(pkt):
    """Check if a packet is a SYN-only TCP segment (port scan indicator)."""
    if TCP in pkt:
        flags = pkt[TCP].flags
        return flags == 0x02  # SYN only, no ACK
    return False


def is_modbus_write(pkt):
    """Check if a packet contains a Modbus write function code (FC6 or FC16)."""
    if TCP in pkt and pkt[TCP].dport == 502 and Raw in pkt:
        payload = bytes(pkt[Raw].load)
        if len(payload) >= 8:
            func_code = payload[7]
            return func_code in [6, 16]  # FC6=write single, FC16=write multiple
    return False


def get_dst_port(pkt):
    """Extract the destination port from a TCP or UDP packet."""
    if TCP in pkt:
        return pkt[TCP].dport
    if UDP in pkt:
        return pkt[UDP].dport
    return None


def packet_handler(pkt):
    """Scapy callback: buffer packet metadata for the current window."""
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if src not in DEVICE_REGISTRY:
        return

    info = {
        "src": src,
        "dst": dst,
        "size": len(pkt),
        "protocol": detect_protocol(pkt),
        "is_syn": is_syn_only(pkt),
        "is_write": is_modbus_write(pkt),
        "src_zone": get_zone(src),
        "dst_zone": get_zone(dst),
        "dst_port": get_dst_port(pkt),
    }
    with buffer_lock:
        window_buffer[src].append(info)


def shannon_entropy(values):
    """Compute Shannon entropy over a frequency dict {label: count}."""
    if not values:
        return 0.0
    total = sum(values.values())
    if total == 0:
        return 0.0
    entropy = 0
    for count in values.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_features(src_ip, packets, window_id, ts):
    """
    Compute the 14 behavioural features for one device in one time window.

    Features:
      device_ip, window_id, timestamp, total_packets, unique_destinations,
      unique_ports, avg_packet_size, protocol_diversity, modbus_ratio,
      mqtt_ratio, http_ratio, scan_rate, write_ratio, cross_zone_ratio
    """
    device = DEVICE_REGISTRY.get(src_ip, {})

    if not packets:
        return {
            "device_ip": src_ip,
            "device_name": device.get("name", "Unknown"),
            "device_type": device.get("type", "Unknown"),
            "zone": device.get("zone", "Unknown"),
            "window_id": window_id,
            "timestamp": ts,
            "total_packets": 0,
            "unique_destinations": 0,
            "unique_ports": 0,
            "avg_packet_size": 0.0,
            "protocol_diversity": 0.0,
            "modbus_ratio": 0.0,
            "mqtt_ratio": 0.0,
            "http_ratio": 0.0,
            "scan_rate": 0.0,
            "write_ratio": 0.0,
            "cross_zone_ratio": 0.0,
        }

    total = len(packets)
    protocol_counts = defaultdict(int)
    dst_ips = set()
    dst_ports = set()
    sizes = []
    syn_count = 0
    write_count = 0
    cross_zone_count = 0

    for p in packets:
        protocol_counts[p["protocol"]] += 1
        dst_ips.add(p["dst"])
        sizes.append(p["size"])
        if p["is_syn"]:
            syn_count += 1
        if p["is_write"]:
            write_count += 1
        if p["src_zone"] != p["dst_zone"]:
            cross_zone_count += 1
        if p["dst_port"] is not None:
            dst_ports.add(p["dst_port"])

    return {
        "device_ip": src_ip,
        "device_name": device.get("name", "Unknown"),
        "device_type": device.get("type", "Unknown"),
        "zone": device.get("zone", "Unknown"),
        "window_id": window_id,
        "timestamp": ts,
        "total_packets": total,
        "unique_destinations": len(dst_ips),
        "unique_ports": len(dst_ports),
        "avg_packet_size": round(sum(sizes) / total, 2),
        "protocol_diversity": shannon_entropy(protocol_counts),
        "modbus_ratio": round(protocol_counts["Modbus"] / total, 4),
        "mqtt_ratio": round(protocol_counts["MQTT"] / total, 4),
        "http_ratio": round(protocol_counts["HTTP"] / total, 4),
        "scan_rate": round(syn_count / total, 4),
        "write_ratio": round(write_count / total, 4),
        "cross_zone_ratio": round(cross_zone_count / total, 4),
    }


def process_window(window_id):
    """Drain the packet buffer and compute features for every registered device."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with buffer_lock:
        snapshot = dict(window_buffer)
        window_buffer.clear()

    for ip in DEVICE_REGISTRY.keys():
        pkts = snapshot.get(ip, [])
        row = compute_features(ip, pkts, window_id, ts)
        all_rows.append(row)
        print(f"  Window {window_id:02d} | {row['device_name']:15s} | "
              f"packets={row['total_packets']:4d} | "
              f"scan_rate={row['scan_rate']:.2f} | "
              f"write={row['write_ratio']:.2f}")


def save_csv():
    """Write all accumulated rows to the output CSV file."""
    fieldnames = [
        "device_ip", "device_name", "device_type", "zone",
        "window_id", "timestamp", "total_packets", "unique_destinations",
        "unique_ports", "avg_packet_size", "protocol_diversity",
        "modbus_ratio", "mqtt_ratio", "http_ratio",
        "scan_rate", "write_ratio", "cross_zone_ratio"
    ]
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\n{'='*55}")
    print(f"  Dataset saved: {OUTPUT_CSV}")
    print(f"  Total rows: {len(all_rows)} ({len(DEVICE_REGISTRY)} devices x 30 windows)")
    print(f"{'='*55}")


def run_capture():
    """Main entry point: sniff traffic for 5 minutes, process in 10s windows."""
    print("=" * 55)
    print("  IoT/OT ML Traffic Capture - 5 Minute Session")
    print("=" * 55)
    print(f"  Devices monitored : {len(DEVICE_REGISTRY)}")
    print(f"  Capture duration  : {CAPTURE_DURATION}s (5 minutes)")
    print(f"  Window size       : {WINDOW_SIZE}s")
    print(f"  Expected windows  : {CAPTURE_DURATION // WINDOW_SIZE}")
    print(f"  Output            : {OUTPUT_CSV}")
    print("=" * 55)
    print("\n>>> Start the attack simulator in ANOTHER terminal now!")
    print("    python agents\\live_attack_simulator.py --full-sequence")
    print("\nCapture starts in 5 seconds...")
    time.sleep(5)

    # Start background sniffer thread
    sniffer = threading.Thread(
        target=sniff,
        kwargs={"prn": packet_handler, "timeout": CAPTURE_DURATION, "store": False}
    )
    sniffer.start()

    # Process windows
    num_windows = CAPTURE_DURATION // WINDOW_SIZE
    for w in range(1, num_windows + 1):
        time.sleep(WINDOW_SIZE)
        print(f"\n--- Window {w}/{num_windows} ---")
        process_window(w)

    sniffer.join()
    save_csv()
    print("\n  CAPTURE COMPLETE")


if __name__ == "__main__":
    run_capture()
