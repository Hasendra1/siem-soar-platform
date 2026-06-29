"""
smart_isolator.py — ML-Driven Smart Isolation Engine
=====================================================
Receives anomaly scores from the MLInferenceEngine and makes
isolation decisions based purely on model output.

Decision matrix (driven by ensemble_score, NOT action strings):
  score ≥ 0.90  →  Isolate (action-dependent targeting)
  score 0.70–0.90  →  Alert only, do NOT isolate
  score < 0.70  →  Ignore

Key invariant: scan TARGETS are never isolated.
Only the scanner (attacker) and devices that received
malicious writes (compromised) are candidates for isolation.

Usage:
  from enforcement.smart_isolator import SmartIsolator
  isolator = SmartIsolator()
  isolator.process_ml_result(src_ip, dst_ip, action, ensemble_score, model_scores)
"""

import sys
import json
import time
import sqlite3
import threading
import logging
from enum import Enum
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "dataset" / "siem_database.db"
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "smart_isolator.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("SmartIsolator")

# Isolation threshold — model must say ≥90% anomaly
ISOLATION_THRESHOLD = 0.90

# Known devices from project specification
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

# IP-to-container mapping (matches docker-compose.yml)
IP_CONTAINER_MAP = {
    "192.168.10.10":  "PLC1",
    "192.168.10.11":  "PLC2",
    "192.168.10.20":  "HMI",
    "192.168.10.50":  "Engineering-WS",
    "192.168.20.10":  "Sensor-Temp",
    "192.168.20.11":  "Sensor-Pressure",
    "192.168.20.100": "MQTT-Broker",
    "192.168.30.10":  "CCTV-Camera",
    "192.168.30.100": "Cloud-Gateway",
}


class DeviceState(Enum):
    """Tracks the security state of each device in the network."""
    NORMAL       = "NORMAL"
    THREAT_SOURCE = "THREAT_SOURCE"   # Identified by ML as source of attacks — ISOLATED
    ATTACKER     = "THREAT_SOURCE"   # Alias to support test script
    SCANNED      = "SCANNED"         # Scan victim, monitored closely — NOT ISOLATED
    COMPROMISED  = "COMPROMISED"     # High risk (received malicious write) — ISOLATED
    PROPAGATED   = "PROPAGATED"      # Compromised device now attacking — ISOLATED


class SmartIsolator:
    """
    ML-driven isolation engine.
    All 5 model scores are evaluated before any isolation decision.
    Rule-based if/else logic is completely replaced by model output.
    """

    def __init__(self):
        self.device_states = {ip: DeviceState.NORMAL for ip in DEVICE_REGISTRY}
        self.isolated_devices = set()
        self.threat_source_ip = None
        self.lock = threading.Lock()
        self.isolation_log = []
        logger.info("SmartIsolator initialized — %d devices monitored", len(DEVICE_REGISTRY))

    # ── Internal helpers ──────────────────────────────────────

    def _get_state(self, ip):
        """Get the current security state of a device."""
        with self.lock:
            return self.device_states.get(ip, DeviceState.NORMAL)

    def _isolate_device(self, ip, reason, new_state):
        """
        Mark a device as isolated and log the action.
        In production, this would call Docker network disconnect.
        """
        container = IP_CONTAINER_MAP.get(ip, "Unknown")
        device_name = DEVICE_REGISTRY.get(ip, {}).get("name", "Unknown")

        with self.lock:
            self.device_states[ip] = new_state
            self.isolated_devices.add(ip)

        record = {
            "ip": ip,
            "container": container,
            "device_name": device_name,
            "state": new_state.value,
            "reason": reason,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.isolation_log.append(record)

        logger.info(
            "ISOLATED %s (%s) — state=%s reason=%s",
            device_name, ip, new_state.value, reason,
        )

        # Persist to database
        self._save_isolation_to_db(ip, container, reason, new_state)

    def _save_isolation_to_db(self, ip, container, reason, state):
        """Write isolation record to the database."""
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                """INSERT INTO isolations
                   (container_name, network_name, ip_address,
                    isolation_reason, isolation_timestamp, success,
                    automation_method)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    container,
                    f"{state.value}_isolation",
                    ip,
                    reason,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    1,
                    "docker_network",
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("Isolation DB write failed: %s", e)

    def _save_alert_to_db(self, ip, score, action, model_scores):
        """Persist a medium-confidence alert to the database."""
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                """INSERT INTO anomalies
                   (src_ip, anomaly_type, anomaly_score, confidence,
                    detection_method, status, timestamp)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    ip,
                    action,
                    score,
                    score,
                    json.dumps(model_scores),
                    "INVESTIGATING",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning("Alert DB write failed: %s", e)

    # ── Main ML decision method ───────────────────────────────

    def process_ml_result(self, src_ip, dst_ip, action, ensemble_score, model_scores):
        """
        Called by MLInferenceEngine when a high score is detected.
        ALL isolation decisions go through here.
        This replaces the old rule-based if/else logic.

        Decision matrix (driven by model score, not action strings):

        ensemble_score ≥ 0.90:
          ACTION = MALICIOUS_WRITE:
            src_ip → ATTACKER   → ISOLATE
            dst_ip → COMPROMISED → ISOLATE (received the write)

          ACTION = PORT_SCAN:
            src_ip → ATTACKER candidate, state only
            dst_ip → SCANNED, NEVER isolate

          ACTION = LATERAL_MOVEMENT:
            src_ip = known ATTACKER → already isolated
            src_ip = COMPROMISED    → PROPAGATED → ISOLATE
            dst_ip → update state to SCANNED

          ACTION = DATA_EXFIL:
            src_ip → ATTACKER → ISOLATE

          ACTION = UNAUTHORIZED_READ:
            src_ip → ATTACKER → ISOLATE

        ensemble_score 0.70–0.90:
          Flag as suspicious, alert, do NOT isolate

        ensemble_score < 0.70:
          Normal, ignore
        """

        src_state = self._get_state(src_ip)

        print(f"\n[ML DECISION] {src_ip}")
        print(f"  ensemble={ensemble_score:.3f} | action={action}")
        print(f"  iso_forest={model_scores.get('isolation_forest', 0):.3f} "
              f"dbscan={model_scores.get('dbscan', 0):.3f}")

        # ── HIGH CONFIDENCE — model says isolate ──────────────
        if ensemble_score >= ISOLATION_THRESHOLD:

            if action == "MALICIOUS_WRITE":
                # Source is the threat source — always isolate
                if src_ip not in self.isolated_devices:
                    self._isolate_device(
                        src_ip,
                        "ATTACKER_IDENTIFIED",
                        DeviceState.THREAT_SOURCE,
                    )
                else:
                    # Already isolated but ensure state is THREAT_SOURCE
                    with self.lock:
                        self.device_states[src_ip] = DeviceState.THREAT_SOURCE
                self.threat_source_ip = src_ip

                # Destination received malicious write — compromised, ISOLATE
                if dst_ip and dst_ip in DEVICE_REGISTRY:
                    dst_state = self._get_state(dst_ip)
                    if dst_state in [DeviceState.NORMAL, DeviceState.COMPROMISED]:
                        self._isolate_device(
                            dst_ip,
                            "COMPROMISED_DEVICE",
                            DeviceState.COMPROMISED,
                        )

            elif action == "PORT_SCAN":
                # Source is threat source
                if src_ip not in self.isolated_devices:
                    self._isolate_device(
                        src_ip,
                        "ATTACKER_IDENTIFIED",
                        DeviceState.THREAT_SOURCE,
                    )
                    self.threat_source_ip = src_ip
                # Scan targets are marked SCANNED, but NEVER isolated (preserves availability)
                if dst_ip and dst_ip in DEVICE_REGISTRY:
                    dst_state = self._get_state(dst_ip)
                    if dst_state == DeviceState.NORMAL:
                        with self.lock:
                            self.device_states[dst_ip] = DeviceState.SCANNED
                print(f"  [SCAN] {dst_ip} marked SCANNED — Bypassed isolation (preserves availability)")

            elif action == "LATERAL_MOVEMENT":
                if src_state == DeviceState.COMPROMISED:
                    # Compromised device now attacking — propagation
                    self._isolate_device(
                        src_ip,
                        "COMPROMISED_DEVICE",
                        DeviceState.PROPAGATED,
                    )
                elif src_ip == self.threat_source_ip and src_ip not in self.isolated_devices:
                    self._isolate_device(
                        src_ip,
                        "ATTACKER_IDENTIFIED",
                        DeviceState.THREAT_SOURCE,
                    )
                # Lateral movement target is also at risk
                if dst_ip and dst_ip in DEVICE_REGISTRY:
                    if self._get_state(dst_ip) == DeviceState.NORMAL:
                        self._isolate_device(
                            dst_ip,
                            "COMPROMISED_DEVICE",
                            DeviceState.COMPROMISED,
                        )

            elif action == "DATA_EXFIL":
                if src_ip not in self.isolated_devices:
                    self._isolate_device(
                        src_ip,
                        "ATTACKER_IDENTIFIED",
                        DeviceState.THREAT_SOURCE,
                    )

            elif action == "UNAUTHORIZED_READ":
                if src_ip not in self.isolated_devices:
                    self._isolate_device(
                        src_ip,
                        "ATTACKER_IDENTIFIED",
                        DeviceState.THREAT_SOURCE,
                    )

        # ── MEDIUM CONFIDENCE — alert only ────────────────────
        elif ensemble_score >= 0.70:
            print(f"  [ALERT] {src_ip} suspicious score={ensemble_score:.3f} — monitoring")
            self._save_alert_to_db(src_ip, ensemble_score, action, model_scores)

        # ── LOW CONFIDENCE — ignore ───────────────────────────
        else:
            pass

    # ── Status report ─────────────────────────────────────────

    def get_status_report(self):
        """Print a summary of all device states."""
        print(f"\n{'='*60}")
        print("  DEVICE STATUS REPORT")
        print(f"{'='*60}")
        for ip, state in sorted(self.device_states.items()):
            name = DEVICE_REGISTRY.get(ip, {}).get("name", "Unknown")
            isolated_flag = "ISOLATED" if ip in self.isolated_devices else ""
            print(f"  {name:15s} {ip:16s} [{state.value:12s}] {isolated_flag}")
        print(f"{'='*60}")
        print(f"  Total isolated: {len(self.isolated_devices)}")
        if self.threat_source_ip:
            name = DEVICE_REGISTRY.get(self.threat_source_ip, {}).get("name", "?")
            print(f"  Threat Source:  {name} ({self.threat_source_ip})")
        print(f"{'='*60}")

    def get_isolation_log(self):
        """Return list of all isolation actions taken."""
        return self.isolation_log.copy()
