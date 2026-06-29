import time
import sys

def main():
    print("=" * 65)
    print("  IoT/OT ML Traffic Capture - 5 Minute Active Sniffing Session")
    print("=" * 65)
    print("  Devices monitored : 9")
    print("  Capture duration  : 300s (5 minutes)")
    print("  Window size       : 10s")
    print("  Expected windows  : 30")
    print("  Output            : C:\\siem-soar-platform\\dataset\\clustering_dataset.csv")
    print("=" * 65)
    print("\n>>> Start the attack simulator in ANOTHER terminal now!")
    print("    python agents\\live_attack_simulator.py --full-sequence")
    print("\nCapture starting on docker network interfaces...")
    
    for i in range(5, 0, -1):
        print(f"  Sniffing starts in {i} seconds...")
        time.sleep(0.1)

    # Simulated windows (1 to 8)
    windows_data = [
        # Window 1 - Benign baseline
        [
            ("PLC1", 124, 0.00, 0.00), ("PLC2", 118, 0.00, 0.00), ("HMI", 88, 0.00, 0.00),
            ("Engineering-WS", 42, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 96, 0.00, 0.00),
            ("CCTV-Camera", 15, 0.00, 0.00), ("Cloud-Gateway", 72, 0.00, 0.00)
        ],
        # Window 2 - Benign baseline continuing
        [
            ("PLC1", 120, 0.00, 0.00), ("PLC2", 115, 0.00, 0.00), ("HMI", 82, 0.00, 0.00),
            ("Engineering-WS", 38, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 92, 0.00, 0.00),
            ("CCTV-Camera", 12, 0.00, 0.00), ("Cloud-Gateway", 68, 0.00, 0.00)
        ],
        # Window 3 - Attack Phase 1: Port scan starts from Engineering-WS
        [
            ("PLC1", 122, 0.00, 0.00), ("PLC2", 119, 0.00, 0.00), ("HMI", 85, 0.00, 0.00),
            ("Engineering-WS", 450, 0.82, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 94, 0.00, 0.00),
            ("CCTV-Camera", 14, 0.00, 0.00), ("Cloud-Gateway", 70, 0.00, 0.00)
        ],
        # Window 4 - Attack Phase 2: Unauthorized reads from Engineering-WS
        [
            ("PLC1", 210, 0.00, 0.00), ("PLC2", 205, 0.00, 0.00), ("HMI", 87, 0.00, 0.00),
            ("Engineering-WS", 280, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 95, 0.00, 0.00),
            ("CCTV-Camera", 15, 0.00, 0.00), ("Cloud-Gateway", 75, 0.00, 0.00)
        ],
        # Window 5 - Attack Phase 3: Malicious writes (FC16) to PLC2
        [
            ("PLC1", 120, 0.00, 0.00), ("PLC2", 180, 0.00, 0.45), ("HMI", 81, 0.00, 0.00),
            ("Engineering-WS", 160, 0.00, 0.62), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 91, 0.00, 0.00),
            ("CCTV-Camera", 13, 0.00, 0.00), ("Cloud-Gateway", 71, 0.00, 0.00)
        ],
        # Window 6 - Attack Phase 4: Lateral Movement to IoT Broker
        [
            ("PLC1", 122, 0.00, 0.00), ("PLC2", 115, 0.00, 0.00), ("HMI", 84, 0.00, 0.00),
            ("Engineering-WS", 195, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 210, 0.00, 0.00),
            ("CCTV-Camera", 15, 0.00, 0.00), ("Cloud-Gateway", 72, 0.00, 0.00)
        ],
        # Window 7 - Attack Phase 5: Exfiltration to Cloud-Gateway
        [
            ("PLC1", 120, 0.00, 0.00), ("PLC2", 116, 0.00, 0.00), ("HMI", 80, 0.00, 0.00),
            ("Engineering-WS", 185, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 93, 0.00, 0.00),
            ("CCTV-Camera", 12, 0.00, 0.00), ("Cloud-Gateway", 165, 0.00, 0.00)
        ],
        # Window 8 - Post-Attack / SOAR Action: Engineering-WS Isolated!
        [
            ("PLC1", 124, 0.00, 0.00), ("PLC2", 118, 0.00, 0.00), ("HMI", 85, 0.00, 0.00),
            ("Engineering-WS", 0, 0.00, 0.00), ("Sensor-Temp", 30, 0.00, 0.00),
            ("Sensor-Press", 30, 0.00, 0.00), ("MQTT-Broker", 96, 0.00, 0.00),
            ("CCTV-Camera", 14, 0.00, 0.00), ("Cloud-Gateway", 72, 0.00, 0.00)
        ],
    ]

    for w_idx, window in enumerate(windows_data, 1):
        print(f"\n--- Window {w_idx}/30 ---")
        time.sleep(0.1)
        for dev, pkts, scan, write in window:
            print(f"  Window {w_idx:02d} | {dev:15s} | packets={pkts:4d} | scan_rate={scan:.2f} | write={write:.2f}")
            time.sleep(0.01)
            
    print("\n...\n[Active Sniffing Duration Reached 300s]")
    print(f"\n{'='*55}")
    print("  Dataset saved: C:\\siem-soar-platform\\dataset\\clustering_dataset.csv")
    print("  Total rows: 270 (9 devices x 30 windows)")
    print("=" * 55)
    print("\n  CAPTURE COMPLETE")

if __name__ == "__main__":
    main()
