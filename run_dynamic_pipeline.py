#!/usr/bin/env python3
"""
Full Dynamic Pipeline
======================
Phase 1: Generate synthetic dataset (simulates 5-min traffic capture)
Phase 2: Train 5 ML models
Phase 3: Start ML monitor
Phase 4: Simulate live attack events → ML detects → isolates → dashboard updates

This script orchestrates the entire flow so the dashboard
goes from 0 → detecting → isolating in real-time.
"""

import sys, os, time, json, sqlite3, random
from pathlib import Path
from datetime import datetime, timedelta

# Fix Windows console encoding for unicode chars
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

DB_PATH = BASE / "dataset" / "siem_database.db"
API = "http://localhost:5000/api"

DEVICE_REGISTRY = {
    "192.168.10.10":  {"name": "PLC1",           "zone": "OT",  "type": "PLC"},
    "192.168.10.11":  {"name": "PLC2",           "zone": "OT",  "type": "PLC"},
    "192.168.10.20":  {"name": "HMI",            "zone": "OT",  "type": "HMI"},
    "192.168.10.50":  {"name": "Engineering-WS", "zone": "OT",  "type": "WORKSTATION"},
    "192.168.20.10":  {"name": "Sensor-Temp",    "zone": "IoT", "type": "SENSOR"},
    "192.168.20.11":  {"name": "Sensor-Press",   "zone": "IoT", "type": "SENSOR"},
    "192.168.20.100": {"name": "MQTT-Broker",    "zone": "IoT", "type": "BROKER"},
    "192.168.30.10":  {"name": "CCTV-Camera",    "zone": "DMZ", "type": "CAMERA"},
    "192.168.30.100": {"name": "Cloud-Gateway",  "zone": "DMZ", "type": "GATEWAY"},
}


def banner(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def api_call(method, path, data=None):
    import requests
    url = f"{API}{path}"
    try:
        if method == "GET":
            return requests.get(url, timeout=5).json()
        else:
            return requests.post(url, json=data, timeout=5).json()
    except Exception as e:
        print(f"  API error: {e}")
        return {}


def insert_event(conn, src_ip, dst_ip, protocol, action, port, payload_size, zone):
    """Insert a single event into the database."""
    conn.execute("""
        INSERT INTO events (src_ip, dst_ip, protocol, src_port, dst_port,
                           action, payload_size, zone, timestamp, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        src_ip, dst_ip, protocol,
        random.randint(40000, 65535), port,
        action, payload_size, zone,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "HIGH" if action in ("PORT_SCAN", "MALICIOUS_WRITE", "UNAUTHORIZED_READ") else "LOW"
    ))
    conn.commit()


# ═══════════════════════════════════════════════════════════════
# PHASE 1: Generate synthetic dataset (traffic capture simulation)
# ═══════════════════════════════════════════════════════════════
def phase1_capture():
    banner("PHASE 1: Traffic Capture (Synthetic Dataset)")
    print("  Generating 30 windows × 9 devices = 270 rows...")
    import subprocess
    result = subprocess.run(
        [sys.executable, str(BASE / "ml_pipeline" / "generate_synthetic_dataset.py")],
        cwd=str(BASE), capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr}")
        return
    print("  ✅ Traffic capture complete → clustering_dataset.csv")


# ═══════════════════════════════════════════════════════════════
# PHASE 2: Train 2 ML models
# ═══════════════════════════════════════════════════════════════
def phase2_train():
    banner("PHASE 2: Training Two-Tier ML Pipeline")
    print("  Tier 1 (Fast Pass): Isolation Forest - filters normal traffic")
    print("  Tier 2 (Deep Scan): DBSCAN - clusters suspicious behaviors")
    import subprocess
    result = subprocess.run(
        [sys.executable, str(BASE / "ml_pipeline" / "train_models.py")],
        cwd=str(BASE), capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr}")
        return
    print("  ✅ Models saved → results/ml_models.pkl")


# ═══════════════════════════════════════════════════════════════
# PHASE 3: Start ML real-time monitor
# ═══════════════════════════════════════════════════════════════
def phase3_start_monitor():
    banner("PHASE 3: Starting Real-Time ML Monitor")
    result = api_call("POST", "/system/monitor/start")
    print(f"  {result.get('message', 'Monitor started')}")
    print("  Monitor is now watching for new events...")
    time.sleep(1)
    print("  ✅ ML monitor active")


# ═══════════════════════════════════════════════════════════════
# PHASE 4: Simulate live attack (events flow into DB in real-time)
# ═══════════════════════════════════════════════════════════════
def phase4_simulate_attack():
    banner("PHASE 4: Simulating Live Attack")
    print("  Engineering-WS (192.168.10.50) will now:")
    print("    1. Scan all devices on the network (PORT_SCAN)")
    print("    2. Send malicious Modbus writes to PLCs")
    print("    3. Attempt lateral movement")
    print()
    print("  Watch the dashboard at http://localhost:5173/dashboard")
    print("  Events will appear in the Live Event Feed in real-time.")
    print()

    conn = sqlite3.connect(str(DB_PATH))
    c2_ip = "192.168.10.50"
    event_count = 0

    # ── Stage 1: Normal traffic baseline (5 events from normal devices) ──
    print("  [Stage 1] Normal baseline traffic...")
    normal_events = [
        ("192.168.10.10", "192.168.10.20", "Modbus", "NORMAL", 502, 64, "OT"),
        ("192.168.10.11", "192.168.10.20", "Modbus", "NORMAL", 502, 64, "OT"),
        ("192.168.20.10", "192.168.20.100", "MQTT",   "NORMAL", 1883, 48, "IoT"),
        ("192.168.20.11", "192.168.20.100", "MQTT",   "NORMAL", 1883, 52, "IoT"),
        ("192.168.30.10", "192.168.30.100", "HTTP",   "NORMAL", 443, 1200, "DMZ"),
    ]
    for src, dst, proto, action, port, size, zone in normal_events:
        insert_event(conn, src, dst, proto, action, port, size, zone)
        event_count += 1
        time.sleep(0.3)
    print(f"    → {event_count} normal events injected")
    time.sleep(1)

    # ── Stage 2: Port scanning phase ──
    print("  [Stage 2] Engineering-WS begins port scanning...")
    targets = [
        ("192.168.10.10", "OT"),   # PLC1
        ("192.168.10.11", "OT"),   # PLC2
        ("192.168.10.20", "OT"),   # HMI
        ("192.168.20.10", "IoT"),  # Sensor-Temp
        ("192.168.20.11", "IoT"),  # Sensor-Press
        ("192.168.20.100", "IoT"), # MQTT-Broker
        ("192.168.30.10", "DMZ"),  # CCTV
        ("192.168.30.100", "DMZ"), # Cloud-Gateway
    ]
    for dst_ip, zone in targets:
        # Scan multiple ports per device
        for port in [22, 80, 443, 502, 1883, 8080]:
            insert_event(conn, c2_ip, dst_ip, "TCP", "PORT_SCAN", port, 40, zone)
            event_count += 1
        time.sleep(0.5)
        dev_name = DEVICE_REGISTRY.get(dst_ip, {}).get("name", dst_ip)
        print(f"    → Scanned {dev_name} ({dst_ip}) — 6 ports")

    print(f"    → {48} scan events total")
    time.sleep(2)

    # ── Stage 3: Unauthorized Modbus reads ──
    print("  [Stage 3] Engineering-WS reading PLC registers (recon)...")
    for _ in range(5):
        for plc in ["192.168.10.10", "192.168.10.11"]:
            insert_event(conn, c2_ip, plc, "Modbus", "UNAUTHORIZED_READ", 502, 64, "OT")
            event_count += 1
        time.sleep(0.4)
    print(f"    → 10 unauthorized read events")
    time.sleep(1)

    # ── Stage 4: Malicious Modbus writes ──
    print("  [Stage 4] Engineering-WS writing malicious values to PLCs...")
    for i in range(8):
        target_plc = "192.168.10.10" if i % 2 == 0 else "192.168.10.11"
        insert_event(conn, c2_ip, target_plc, "Modbus", "MALICIOUS_WRITE", 502,
                     random.randint(80, 200), "OT")
        event_count += 1
        plc_name = DEVICE_REGISTRY[target_plc]["name"]
        print(f"    → Malicious write to {plc_name} (register {random.randint(1, 100)})")
        time.sleep(0.8)

    time.sleep(1)

    # ── Stage 5: Lateral movement attempts ──
    print("  [Stage 5] Lateral movement to IoT zone...")
    for dst in ["192.168.20.10", "192.168.20.100"]:
        insert_event(conn, c2_ip, dst, "TCP", "LATERAL_MOVEMENT", 22, 120, "IoT")
        event_count += 1
        time.sleep(0.5)
    print(f"    → 2 lateral movement events")

    # ── Stage 6: Data exfiltration ──
    print("  [Stage 6] Data exfiltration attempt...")
    insert_event(conn, c2_ip, "192.168.30.100", "HTTP", "DATA_EXFIL", 443, 8500, "DMZ")
    event_count += 1
    time.sleep(0.5)

    conn.close()

    print()
    print(f"  ═══ ATTACK SIMULATION COMPLETE ═══")
    print(f"  Total events injected: {event_count}")
    print(f"  Port scans: 48 | Reads: 10 | Writes: 8 | Lateral: 2 | Exfil: 1")
    print()
    print("  Waiting for ML monitor to process events...")


# ═══════════════════════════════════════════════════════════════
# PHASE 5: Wait for ML to detect and isolate
# ═══════════════════════════════════════════════════════════════
def phase5_wait_and_report():
    banner("PHASE 5: ML Detection & Isolation Results")

    # Wait for ML monitor to process all events
    for i in range(15):
        time.sleep(2)
        status = api_call("GET", "/system/status")
        inferences = status.get("ml_inferences", 0)
        isolations = status.get("isolations_total", 0)
        print(f"  [{i*2:2d}s] Inferences: {inferences} | Isolations: {isolations}")
        if isolations > 0 and inferences > 10:
            break

    print()

    # Get final status
    status = api_call("GET", "/system/status")
    print(f"  ── Final System Status ──")
    print(f"  Events processed:    {status.get('events_total', 0)}")
    print(f"  ML inferences:       {status.get('ml_inferences', 0)}")
    print(f"  Devices isolated:    {status.get('isolations_total', 0)}")
    print(f"  Anomalies detected:  {status.get('anomalies_total', 0)}")
    print(f"  Avg inference time:  {status.get('ml_avg_latency', 0):.1f} ms")
    print()

    # Check isolated devices
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT DISTINCT ip_address, container_name, isolation_reason, isolation_timestamp
        FROM isolations WHERE success=1
        ORDER BY isolation_timestamp
    """).fetchall()
    conn.close()

    if rows:
        print(f"  ── Isolated Devices ({len(rows)}) ──")
        for r in rows:
            print(f"    🔒 {r['container_name']:15s} ({r['ip_address']}) — {r['isolation_reason']}")
    else:
        print("  ⚠ No devices isolated yet — ML threshold may not be reached")
        print("    This is expected if the ensemble score < 0.90")

    print()
    print("  ✅ Pipeline complete!")
    print("  Open http://localhost:5173/dashboard to see live results")
    print("  Open http://localhost:5173/isolated-devices to see isolation details")


# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    banner("SIEM SOAR — Full Dynamic Pipeline")
    print("  This will:")
    print("    1. Generate synthetic traffic data")
    print("    2. Train 2 unsupervised ML models")
    print("    3. Start ML real-time monitor")
    print("    4. Simulate a live cyberattack")
    print("    5. Watch ML detect and isolate threats")
    print()

    phase1_capture()
    phase2_train()
    phase3_start_monitor()
    phase4_simulate_attack()
    phase5_wait_and_report()
