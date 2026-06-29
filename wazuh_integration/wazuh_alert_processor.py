#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Wazuh Alert Processor
============================================
Receives real-time alerts from Wazuh agents via UDP socket,
maps them to the SIEM anomaly taxonomy, and persists them
to the SQLite database for downstream ML analysis.

Usage:
    python wazuh_alert_processor.py              # default port 5000
    python wazuh_alert_processor.py --port 5001  # custom port
"""

import os
import sys
import json
import socket
import sqlite3
import logging
import argparse
from datetime import datetime
from pathlib import Path

# --- Resolve project paths ----------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "dataset" / "siem_database.db"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# --- Logging ------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "wazuh_alerts.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("WazuhAlertProcessor")

# --- Mappings -----------------------------------------------------------------

# Wazuh rule ID -> SIEM anomaly type
ANOMALY_TYPE_MAP = {
    "9001": "UNAUTHORIZED_READ",
    "9002": "MALICIOUS_WRITE",
    "9003": "PORT_SCAN",
    "9004": "LATERAL_MOVEMENT",
    "9005": "DATA_EXFIL",
    "9006": "BEHAVIORAL_DEVIATION",
}

# Wazuh rule ID -> SIEM severity
SEVERITY_MAP = {
    "9001": "HIGH",
    "9002": "CRITICAL",
    "9003": "MEDIUM",
    "9004": "CRITICAL",
    "9005": "HIGH",
    "9006": "MEDIUM",
}

# Wazuh rule ID -> base anomaly score
SCORE_MAP = {
    "9001": 0.80,
    "9002": 0.95,
    "9003": 0.60,
    "9004": 0.90,
    "9005": 0.85,
    "9006": 0.70,
}


# --- Processor ----------------------------------------------------------------

class WazuhAlertProcessor:
    """
    UDP listener that receives Wazuh JSON alerts, normalises them,
    and writes them into the SIEM SQLite database.
    """

    def __init__(self, listen_host: str = "0.0.0.0", listen_port: int = 5000):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.sock: socket.socket | None = None
        self.db_conn: sqlite3.Connection | None = None

        # Counters
        self.alerts_received = 0
        self.alerts_stored = 0
        self.alerts_failed = 0

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        """Bind the UDP socket and open the database connection."""
        # Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.listen_host, self.listen_port))
        logger.info(
            "Wazuh Alert Processor listening on %s:%d",
            self.listen_host, self.listen_port,
        )

        # Database
        if not DB_PATH.exists():
            logger.warning("Database not found at %s - run init_database.py first", DB_PATH)
        self.db_conn = sqlite3.connect(str(DB_PATH))
        self.db_conn.execute("PRAGMA journal_mode=WAL;")
        self.db_conn.execute("PRAGMA foreign_keys=ON;")
        logger.info("Connected to database: %s", DB_PATH)

    def stop(self) -> None:
        """Clean up resources."""
        if self.sock:
            self.sock.close()
            logger.info("Socket closed")
        if self.db_conn:
            self.db_conn.close()
            logger.info("Database connection closed")
        self._print_summary()

    # -- main loop -------------------------------------------------------------

    def receive_alerts(self) -> None:
        """Block and receive Wazuh alerts forever."""
        logger.info("Waiting for Wazuh alerts...")
        while True:
            try:
                data, addr = self.sock.recvfrom(8192)
                self.alerts_received += 1
                logger.debug("Received %d bytes from %s", len(data), addr)

                alert = json.loads(data.decode("utf-8"))
                self.process_alert(alert)

            except json.JSONDecodeError as exc:
                logger.error("Invalid JSON from %s: %s", addr, exc)
                self.alerts_failed += 1
            except KeyboardInterrupt:
                logger.info("Interrupted - shutting down")
                break
            except Exception as exc:
                logger.error("Alert processing error: %s", exc, exc_info=True)
                self.alerts_failed += 1

    # -- alert handling --------------------------------------------------------

    def process_alert(self, alert: dict) -> None:
        """
        Parse a Wazuh alert dict, map it to SIEM fields,
        and persist it in the anomalies table.
        """
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        rule_desc = rule.get("description", "Unknown rule")
        rule_level = rule.get("level", 0)

        agent = alert.get("agent", {})
        agent_name = agent.get("name", "unknown")
        agent_ip = agent.get("ip", "0.0.0.0")

        src_ip = alert.get("data", {}).get("srcip", agent_ip)
        raw_ts = alert.get("timestamp")

        # Map to SIEM taxonomy
        anomaly_type = ANOMALY_TYPE_MAP.get(rule_id, "BEHAVIORAL_DEVIATION")
        severity = SEVERITY_MAP.get(rule_id, "MEDIUM")
        anomaly_score = SCORE_MAP.get(rule_id, 0.5)

        # Confidence scales with Wazuh rule level (0-15 -> 0.0-1.0)
        confidence = min(round(rule_level / 15.0, 2), 1.0)

        # Parse timestamp
        try:
            detection_ts = (
                datetime.fromisoformat(raw_ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                if raw_ts else datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            )
        except (ValueError, TypeError):
            detection_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Persist to database
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                """
                INSERT INTO anomalies
                    (src_ip, anomaly_type, anomaly_score, confidence,
                     detection_method, status, detection_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    src_ip,
                    anomaly_type,
                    anomaly_score,
                    confidence,
                    "wazuh_agent",
                    "DETECTED",
                    detection_ts,
                ),
            )
            self.db_conn.commit()
            self.alerts_stored += 1

            logger.info(
                "WAZUH ALERT [%s] %s | src=%s | type=%s | severity=%s | score=%.2f",
                rule_id, rule_desc, src_ip, anomaly_type, severity, anomaly_score,
            )

        except sqlite3.Error as exc:
            logger.error("Database insert failed: %s", exc)
            self.alerts_failed += 1

    # -- reporting -------------------------------------------------------------

    def _print_summary(self) -> None:
        """Print a summary of processed alerts."""
        print()
        print("-" * 50)
        print("  Wazuh Alert Processor Summary")
        print("-" * 50)
        print(f"  Alerts received : {self.alerts_received}")
        print(f"  Alerts stored   : {self.alerts_stored}")
        print(f"  Alerts failed   : {self.alerts_failed}")
        print("-" * 50)


# --- CLI entry point ----------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wazuh Alert Processor - receives and stores SIEM alerts"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="UDP port to listen on (default: 5000)",
    )
    parser.add_argument(
        "--host", type=str, default="0.0.0.0",
        help="Host address to bind (default: 0.0.0.0)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    processor = WazuhAlertProcessor(
        listen_host=args.host,
        listen_port=args.port,
    )
    try:
        processor.start()
        processor.receive_alerts()
    except OSError as exc:
        logger.error("Could not bind to %s:%d - %s", args.host, args.port, exc)
        sys.exit(1)
    finally:
        processor.stop()


if __name__ == "__main__":
    main()
