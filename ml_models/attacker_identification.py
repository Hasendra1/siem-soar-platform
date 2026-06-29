#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Attacker Identification Engine
=====================================================
5-method ensemble analysis to identify the attacker device
among all network devices with 95%+ confidence.

Methods:
  1. Anomaly Score Ranking
  2. Behavior Escalation Pattern
  3. Critical Action Detection
  4. Zone Violation Analysis
  5. Protocol Abuse Detection
"""

import sys, sqlite3, logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "dataset" / "siem_database.db"
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOGS_DIR / "detection.log", encoding="utf-8"),
              logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("AttackerID")

ALL_DEVICES = {
    "192.168.10.10": {"name": "PLC1",            "zone": "OT",  "protocols": {"Modbus"}},
    "192.168.10.11": {"name": "PLC2",            "zone": "OT",  "protocols": {"Modbus"}},
    "192.168.10.20": {"name": "HMI",             "zone": "OT",  "protocols": {"Modbus", "TCP"}},
    "192.168.10.50": {"name": "Attacker",        "zone": "OT",  "protocols": {"Modbus"}},
    "192.168.20.10": {"name": "Sensor-Temp",     "zone": "IoT", "protocols": {"MQTT"}},
    "192.168.20.11": {"name": "Sensor-Pressure", "zone": "IoT", "protocols": {"MQTT"}},
    "192.168.30.10": {"name": "CCTV",            "zone": "DMZ", "protocols": {"HTTP"}},
    "192.168.30.100":{"name": "Gateway",         "zone": "DMZ", "protocols": {"HTTP", "MQTT"}},
}

ZONE_OF_IP = {}
for ip, info in ALL_DEVICES.items():
    ZONE_OF_IP[ip] = info["zone"]
# External
ZONE_OF_IP["10.0.0.1"] = "EXTERNAL"

ACTION_WEIGHTS = {
    "MALICIOUS_WRITE": 99, "LATERAL_MOVEMENT": 95, "UNAUTHORIZED_READ": 90,
    "DATA_EXFIL": 85, "PORT_SCAN": 80, "BEHAVIORAL_DEVIATION": 60,
}

METHOD_WEIGHTS = {
    "anomaly": 0.30, "escalation": 0.25, "action": 0.25,
    "zone": 0.10, "protocol": 0.10,
}


def ok(msg):
    try:
        print(f"  \u2713 {msg}")
    except UnicodeEncodeError:
        print(f"  [OK] {msg}")


class AttackerIdentifier:
    """5-method ensemble to identify the attacker device."""

    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH))
        self.conn.row_factory = sqlite3.Row
        self.device_ips = list(ALL_DEVICES.keys())
        self.scores = {ip: {} for ip in self.device_ips}
        self.evidence = {ip: [] for ip in self.device_ips}

    # ------------------------------------------------------------------ #
    # METHOD 1: Anomaly Score Ranking                                     #
    # ------------------------------------------------------------------ #

    def calculate_anomaly_scores(self):
        """Sum anomaly_score per device from anomalies table."""
        print("\n  [Method 1] Anomaly Score Ranking...")
        totals = defaultdict(float)
        counts = defaultdict(int)
        rows = self.conn.execute(
            "SELECT src_ip, anomaly_score FROM anomalies").fetchall()
        for r in rows:
            totals[r["src_ip"]] += r["anomaly_score"]
            counts[r["src_ip"]] += 1

        # Also sum from events table for devices not in anomalies
        evt_rows = self.conn.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM events "
            "WHERE action != 'NORMAL' GROUP BY src_ip").fetchall()
        for r in evt_rows:
            if r["src_ip"] not in totals:
                totals[r["src_ip"]] = 0
            totals[r["src_ip"]] += r["cnt"] * 0.5

        # Normalize: highest score -> 1.0
        max_score = max(totals.values()) if totals else 1
        if max_score == 0:
            max_score = 1
        for ip in self.device_ips:
            raw = totals.get(ip, 0)
            norm = min(1.0, raw / max_score)
            self.scores[ip]["anomaly"] = round(norm, 4)
            if raw > 0:
                self.evidence[ip].append(f"Anomaly Score: {raw:.1f}")
        print(f"    Analyzed {len(totals)} devices with anomalies")

    # ------------------------------------------------------------------ #
    # METHOD 2: Escalation Pattern                                        #
    # ------------------------------------------------------------------ #

    def analyze_escalation(self):
        """Detect escalating attack progression per device."""
        print("  [Method 2] Escalation Pattern Analysis...")
        phase_order = ["PORT_SCAN", "UNAUTHORIZED_READ", "MALICIOUS_WRITE",
                       "LATERAL_MOVEMENT", "DATA_EXFIL"]

        for ip in self.device_ips:
            rows = self.conn.execute(
                "SELECT action, timestamp FROM events WHERE src_ip=? "
                "ORDER BY timestamp", (ip,)).fetchall()
            if not rows:
                self.scores[ip]["escalation"] = 0.0
                continue

            seen_phases = []
            for r in rows:
                a = r["action"]
                if a in phase_order and a not in seen_phases:
                    seen_phases.append(a)

            # Score based on how many phases seen in correct order
            ordered = 0
            for i, phase in enumerate(seen_phases):
                if phase in phase_order:
                    idx = phase_order.index(phase)
                    if i == 0 or idx > phase_order.index(seen_phases[i - 1]):
                        ordered += 1

            n_phases = len(seen_phases)
            if n_phases >= 4:
                esc_score = min(1.0, 0.7 + ordered * 0.075)
            elif n_phases >= 3:
                esc_score = 0.5 + ordered * 0.1
            elif n_phases >= 2:
                esc_score = 0.3
            elif n_phases == 1:
                esc_score = 0.1
            else:
                esc_score = 0.0

            self.scores[ip]["escalation"] = round(esc_score, 4)
            if n_phases >= 3:
                self.evidence[ip].append(
                    f"Escalation Pattern: {' -> '.join(seen_phases)}")

    # ------------------------------------------------------------------ #
    # METHOD 3: Critical Action Detection                                 #
    # ------------------------------------------------------------------ #

    def detect_critical_actions(self):
        """Weight devices by the severity of their actions."""
        print("  [Method 3] Critical Action Detection...")

        for ip in self.device_ips:
            rows = self.conn.execute(
                "SELECT action, COUNT(*) as cnt FROM events "
                "WHERE src_ip=? GROUP BY action", (ip,)).fetchall()
            if not rows:
                self.scores[ip]["action"] = 0.0
                continue

            weighted_sum = 0
            total_events = 0
            action_counts = {}
            for r in rows:
                a, c = r["action"], r["cnt"]
                action_counts[a] = c
                w = ACTION_WEIGHTS.get(a, 10)
                weighted_sum += w * c
                total_events += c

            action_score = weighted_sum / (total_events * 50) if total_events else 0
            action_score = min(1.0, action_score)
            self.scores[ip]["action"] = round(action_score, 4)

            # Evidence
            for critical in ["MALICIOUS_WRITE", "LATERAL_MOVEMENT",
                              "UNAUTHORIZED_READ", "PORT_SCAN", "DATA_EXFIL"]:
                if critical in action_counts:
                    self.evidence[ip].append(
                        f"{critical}: {action_counts[critical]} events")

    # ------------------------------------------------------------------ #
    # METHOD 4: Zone Violation Analysis                                   #
    # ------------------------------------------------------------------ #

    def analyze_zone_behavior(self):
        """Detect cross-zone traffic anomalies."""
        print("  [Method 4] Zone Violation Analysis...")

        for ip in self.device_ips:
            home_zone = ALL_DEVICES.get(ip, {}).get("zone", "UNKNOWN")
            rows = self.conn.execute(
                "SELECT dst_ip, zone FROM events WHERE src_ip=?", (ip,)
            ).fetchall()

            transitions = set()
            for r in rows:
                dst_zone = ZONE_OF_IP.get(r["dst_ip"], r["zone"])
                if dst_zone and dst_zone != home_zone:
                    transitions.add(f"{home_zone}->{dst_zone}")

            n = len(transitions)
            zone_score = min(1.0, n * 0.35)
            self.scores[ip]["zone"] = round(zone_score, 4)

            if transitions:
                self.evidence[ip].append(
                    f"Zone Violations: {', '.join(sorted(transitions))}")

    # ------------------------------------------------------------------ #
    # METHOD 5: Protocol Abuse Detection                                  #
    # ------------------------------------------------------------------ #

    def detect_protocol_abuse(self):
        """Compare actual protocols to expected baseline."""
        print("  [Method 5] Protocol Abuse Detection...")

        for ip in self.device_ips:
            expected = ALL_DEVICES.get(ip, {}).get("protocols", set())
            rows = self.conn.execute(
                "SELECT DISTINCT protocol FROM events WHERE src_ip=?",
                (ip,)).fetchall()
            actual = {r["protocol"] for r in rows}

            extra = actual - expected
            n_actual = len(actual)
            n_expected = max(len(expected), 1)
            abuse_ratio = max(0, n_actual - n_expected) / max(n_expected, 1)
            proto_score = min(1.0, abuse_ratio * 0.5)
            if n_actual >= 4:
                proto_score = max(proto_score, 0.8)
            elif n_actual >= 3:
                proto_score = max(proto_score, 0.5)

            self.scores[ip]["protocol"] = round(proto_score, 4)
            if extra:
                self.evidence[ip].append(
                    f"Protocol Abuse: expected {expected}, "
                    f"actual {actual} (+{extra})")

    # ------------------------------------------------------------------ #
    # Ensemble scoring                                                    #
    # ------------------------------------------------------------------ #

    def ensemble_scoring(self):
        """Combine all 5 methods into a final attacker probability."""
        print("\n  Computing ensemble scores...")
        results = {}

        for ip in self.device_ips:
            s = self.scores[ip]
            total = sum(
                s.get(method, 0) * weight
                for method, weight in METHOD_WEIGHTS.items()
            )
            results[ip] = round(min(1.0, total), 4)

        return results

    # ------------------------------------------------------------------ #
    # Main identification                                                 #
    # ------------------------------------------------------------------ #

    def identify_attacker(self):
        """Run full 5-method analysis and identify the attacker."""
        print("\n" + "=" * 60)
        print("  ATTACKER IDENTIFICATION ANALYSIS")
        print("=" * 60)
        print(f"  Querying database: {DB_PATH}")
        print(f"  Analyzing {len(self.device_ips)} devices...")

        # Run all 5 methods
        self.calculate_anomaly_scores()
        self.analyze_escalation()
        self.detect_critical_actions()
        self.analyze_zone_behavior()
        self.detect_protocol_abuse()

        # Ensemble
        probabilities = self.ensemble_scoring()

        # Rank devices
        ranked = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)

        # Print ranking
        print("\n" + "=" * 60)
        print("  Device Ranking (Attacker Probability):")
        print("=" * 60)

        for rank, (ip, prob) in enumerate(ranked, 1):
            name = ALL_DEVICES.get(ip, {}).get("name", "Unknown")
            pct = prob * 100

            if prob > 0.90:
                tag = "<-- CONFIRMED ATTACKER"
            elif prob > 0.70:
                tag = "<-- SUSPECTED"
            else:
                tag = f"Normal ({name})"

            print(f"  {rank}. {ip:<18} {prob:.3f} ({pct:5.1f}%) {tag}")

        # Identify top threat
        top_ip, top_prob = ranked[0]
        top_name = ALL_DEVICES.get(top_ip, {}).get("name", "Unknown")

        if top_prob > 0.90:
            classification = "CONFIRMED ATTACKER"
            status = "READY FOR ISOLATION"
        elif top_prob > 0.70:
            classification = "SUSPECTED ATTACKER"
            status = "INVESTIGATING"
        else:
            classification = "NO ATTACKER FOUND"
            status = "ALL CLEAR"

        # Print identification result
        print(f"\n{'='*60}")
        print(f"  {classification}: {top_ip} ({top_name})")
        print(f"  Confidence: {top_prob*100:.1f}%")
        print(f"  Status: {status}")
        print(f"{'='*60}")

        # Print evidence
        if self.evidence.get(top_ip):
            print(f"\n  EVIDENCE for {top_ip}:")
            for ev in self.evidence[top_ip]:
                ok(ev)

        # Print method breakdown
        print(f"\n  Method Breakdown for {top_ip}:")
        s = self.scores.get(top_ip, {})
        for method, weight in METHOD_WEIGHTS.items():
            val = s.get(method, 0)
            contrib = val * weight
            bar = "#" * int(val * 20)
            print(f"    {method:<14} score={val:.4f} x{weight:.2f} "
                  f"= {contrib:.4f}  |{bar}|")
        print(f"    {'TOTAL':<14} = {top_prob:.4f}")

        # Store incident in DB
        self._store_incident(top_ip, top_prob, classification, status)

        print(f"\n{'='*60}")
        print(f"  Analysis complete.")
        print(f"{'='*60}")

        return {
            "attacker_ip": top_ip,
            "confidence": top_prob,
            "classification": classification,
            "status": status,
            "evidence": self.evidence.get(top_ip, []),
            "all_rankings": ranked,
        }

    def _store_incident(self, ip, confidence, classification, status):
        """Write incident to investigations table."""
        try:
            self.conn.execute(
                """INSERT INTO investigations
                   (investigator_name, status, findings,
                    evidence, conclusion, start_timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                ("ML_ENGINE", "OPEN",
                 f"Attacker identified: {ip}",
                 f"{classification} conf={confidence:.3f}",
                 f"Device {ip} confirmed as attacker",
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
            ok(f"Incident record created for {ip}")
        except sqlite3.Error as e:
            logger.error("Incident DB write failed: %s", e)

    def close(self):
        if self.conn:
            self.conn.close()


def main():
    identifier = AttackerIdentifier()
    result = identifier.identify_attacker()
    identifier.close()
    return result


if __name__ == "__main__":
    main()
