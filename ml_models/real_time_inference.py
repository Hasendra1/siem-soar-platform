#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Two-Tier Real-Time Inference Engine
=========================================================
Tier 1 (Fast Pass): Isolation Forest filters obvious normal traffic.
Tier 2 (Deep Scan): DBSCAN clusters only flagged suspicious events.
Auto-initializes on construction. <100ms per event.
"""

import os, sys, json, time, csv, sqlite3, logging, warnings, joblib
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"
DB_PATH = DATASET_DIR / "siem_database.db"
MODELS_PATH = RESULTS_DIR / "ml_models.pkl"
DATASET_PATH = DATASET_DIR / "clustering_dataset.csv"
ANOMALIES_JSON = DATASET_DIR / "anomalies.json"
INFERENCE_MODELS_PATH = RESULTS_DIR / "inference_models.pkl"
TRAFFIC_LOG = DATASET_DIR / "traffic_log.csv"

for d in (DATASET_DIR, RESULTS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOGS_DIR / "detection.log", encoding="utf-8"),
              logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("InferenceEngine")

FEATURE_COLS = [
    "total_packets", "unique_destinations", "unique_ports",
    "avg_packet_size", "protocol_diversity", "modbus_ratio",
    "mqtt_ratio", "scan_rate", "write_ratio", "cross_zone_ratio",
]

MODEL_NAMES = ["isolation_forest", "dbscan"]
NUM_MODELS = 2
ANOMALY_THRESHOLD = 0.60
CONFIDENCE_THRESHOLD = 0.30
MODEL_ANOMALY_CUTOFF = 0.50

# Two-tier thresholds
TIER1_THRESHOLD = 0.40   # IF score >= this -> forward to Tier 2
TIER1_WEIGHT = 0.40
TIER2_WEIGHT = 0.60

# PLC whitelist - only these IPs should talk Modbus to PLCs
PLC_IPS = {"192.168.10.10", "192.168.10.11"}
HMI_IPS = {"192.168.10.20"}
PLC_WHITELIST = PLC_IPS | HMI_IPS

ANOMALY_SIGNATURES = {
    "PORT_SCAN":         {"scan_rate": 0.5, "unique_ports": 10},
    "UNAUTHORIZED_READ": {"modbus_ratio": 0.5},
    "MALICIOUS_WRITE":   {"write_ratio": 0.3},
    "DATA_EXFIL":        {"cross_zone_ratio": 0.5},
    "LATERAL_MOVEMENT":  {"unique_destinations": 8, "unique_ports": 10},
}

DEVICE_BASELINES = {
    "192.168.10.10": {"mean": [31.0, 2.0, 2.0, 63.57, 0.488, 0.897, 0.0, 0.0, 0.0, 0.0],
                      "std":  [3.0,  0.5, 0.5, 2.0,  0.05,  0.05,  0.0, 0.01, 0.0, 0.0]},
    "192.168.10.11": {"mean": [34.0, 2.0, 2.0, 65.33, 0.486, 0.899, 0.0, 0.0, 0.0, 0.0],
                      "std":  [3.0,  0.5, 0.5, 2.0,  0.05,  0.05,  0.0, 0.01, 0.0, 0.0]},
    "192.168.10.20": {"mean": [24.0, 2.0, 2.0, 64.49, 0.500, 0.895, 0.0, 0.0, 0.0, 0.0],
                      "std":  [3.0,  0.5, 0.5, 2.0,  0.05,  0.05,  0.0, 0.01, 0.0, 0.0]},
    "192.168.20.10": {"mean": [10.0, 2.0, 2.0, 64.34, 0.482, 0.0,   0.819, 0.0, 0.0, 0.0],
                      "std":  [2.0,  0.5, 0.5, 2.0,  0.05,  0.0,   0.05,  0.01, 0.0, 0.0]},
    "192.168.20.11": {"mean": [14.0, 2.0, 2.0, 63.39, 0.486, 0.0,   0.796, 0.0, 0.0, 0.0],
                      "std":  [2.0,  0.5, 0.5, 2.0,  0.05,  0.0,   0.05,  0.01, 0.0, 0.0]},
    "192.168.20.100":{"mean": [19.0, 2.0, 2.0, 63.02, 0.491, 0.0,   0.797, 0.0, 0.0, 0.0],
                      "std":  [3.0,  0.5, 0.5, 2.0,  0.05,  0.0,   0.05,  0.01, 0.0, 0.0]},
    "192.168.30.10": {"mean": [10.0, 2.0, 2.0, 65.79, 0.492, 0.0,   0.0,   0.0, 0.0, 0.0],
                      "std":  [2.0,  0.5, 0.5, 2.0,  0.05,  0.0,   0.0,   0.01, 0.0, 0.0]},
    "192.168.30.100":{"mean": [13.0, 2.0, 2.0, 63.72, 0.463, 0.0,   0.0,   0.0, 0.0, 0.0],
                      "std":  [3.0,  0.5, 0.5, 2.0,  0.05,  0.0,   0.0,   0.01, 0.0, 0.0]},
}
GLOBAL_BASELINE = {
    "mean": [19.0, 2.0, 2.0, 64.0, 0.48, 0.3, 0.3, 0.0, 0.0, 0.0],
    "std":  [5.0,  0.5, 0.5, 2.0,  0.05, 0.4, 0.4, 0.01, 0.0, 0.0],
}

PROTOCOL_MAP = {"Modbus": (1.0, 0.0, 0.0), "MQTT": (0.0, 1.0, 0.0),
                "HTTP": (0.0, 0.0, 1.0), "TCP": (0.3, 0.0, 0.1),
                "UDP": (0.0, 0.0, 0.1), "ICMP": (0.0, 0.0, 0.0)}


class RealTimeInferenceEngine:
    """Two-tier cascade for real-time anomaly detection (<100ms per event).
    
    Tier 1 (Isolation Forest): Scores every event. Normal traffic is
    immediately classified and skips Tier 2 for maximum throughput.
    
    Tier 2 (DBSCAN): Only runs on Tier 1 flagged events. Computes
    distance-to-nearest-core-sample for deep behavioral analysis.
    """

    def __init__(self):
        self.scaler = None
        self.dbscan = None
        self.iso_forest = None
        self.training_data = None
        self.normal_data_scaled = None
        self.is_ready = False
        self.total_inferences = 0
        self.total_anomalies = 0
        self.total_normal = 0
        self.inference_times = []
        self.detected_anomalies = []
        self.isolated_ips = set()  # Prevent duplicate isolations
        # Auto-initialize
        self._auto_init()

    def _auto_init(self):
        if self.load_models():
            self.is_ready = True

    # ------------------------------------------------------------------ #
    # Model loading                                                       #
    # ------------------------------------------------------------------ #

    def load_models(self):
        if not MODELS_PATH.exists():
            logger.error("Models file not found: %s", MODELS_PATH)
            return False
        data = joblib.load(MODELS_PATH)
        self.scaler = data.get("scaler")
        self.dbscan = data.get("dbscan")
        self.iso_forest = data.get("isolation_forest")
        if not DATASET_PATH.exists():
            logger.error("Dataset not found: %s", DATASET_PATH)
            return False
        df = pd.read_csv(DATASET_PATH)
        X = df[FEATURE_COLS].values.astype(float)
        self.training_data = self.scaler.transform(X)
        self.normal_data_scaled = self.training_data[:7]
        logger.info("Models loaded successfully (%d features, %d normal devices)",
                     len(FEATURE_COLS), len(self.normal_data_scaled))
        return True

    def train_anomaly_models(self):
        X_n = self.normal_data_scaled
        self.iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.iso_forest.fit(X_n)
        
        from sklearn.cluster import DBSCAN
        self.dbscan = DBSCAN(eps=0.5, min_samples=2)
        self.dbscan.fit(X_n)
        
        self.is_ready = True
        logger.info("Anomaly detection models trained (IF, DBSCAN)")

    def save_inference_models(self):
        joblib.dump({"iso_forest": self.iso_forest, "dbscan": self.dbscan,
                     "scaler": self.scaler,
                     "feature_columns": FEATURE_COLS,
                     "timestamp": datetime.now().isoformat()}, INFERENCE_MODELS_PATH)

    # ------------------------------------------------------------------ #
    # Feature extraction from raw network events                          #
    # ------------------------------------------------------------------ #

    def extract_features(self, event):
        """Convert a raw network event dict to a 10-element feature vector.
        Handles both pre-extracted (has total_packets) and raw (has src_ip/protocol) events."""
        if "total_packets" in event and event["total_packets"] not in (None, "", 0):
            if "avg_packet_size" not in event and "avg_packet_length" in event:
                event = event.copy()
                event["avg_packet_size"] = event["avg_packet_length"]
            if "scan_rate" not in event:
                event = event.copy()
                event["scan_rate"] = float(event.get("scan_events", 0)) / float(event.get("total_packets", 100))
            if "write_ratio" not in event:
                event = event.copy()
                event["write_ratio"] = float(event.get("write_operations", 0)) / float(event.get("total_packets", 100))
            if "cross_zone_ratio" not in event:
                event = event.copy()
                event["cross_zone_ratio"] = 0.0
            return np.array([float(event.get(f, 0)) for f in FEATURE_COLS])

        src_ip = event.get("src_ip", "unknown")
        protocol = event.get("protocol", "TCP")
        action = event.get("action", "NORMAL")
        dst_port = int(event.get("dst_port", 0))

        # Lookup baseline for this device to get reasonable defaults
        bl = DEVICE_BASELINES.get(src_ip, GLOBAL_BASELINE)
        base_pkts = bl["mean"][0]

        # Adjust packet count based on action
        action_multipliers = {"NORMAL": 1.0, "PORT_SCAN": 12.0, "UNAUTHORIZED_READ": 8.0,
                              "MALICIOUS_WRITE": 8.0, "LATERAL_MOVEMENT": 10.0,
                              "DATA_EXFIL": 9.0, "ANOMALY": 10.0}
        mult = action_multipliers.get(action, 1.0)
        total_packets = float(event.get("total_packets", base_pkts * mult))

        unique_dests = float(event.get("unique_destinations",
                             bl["mean"][1] if mult <= 1.0 else 15))
        unique_ports = float(event.get("unique_ports",
                             bl["mean"][2] if mult <= 1.0 else max(bl["mean"][2], dst_port // 25 + 1)))
        avg_pkt_size = float(event.get("avg_packet_size", event.get("avg_packet_length", bl["mean"][3])))

        proto_ratios = PROTOCOL_MAP.get(protocol, (0.1, 0.1, 0.1))
        modbus_r = float(event.get("modbus_ratio", proto_ratios[0]))
        mqtt_r = float(event.get("mqtt_ratio", proto_ratios[1]))

        proto_div = float(event.get("protocol_diversity",
                          bl["mean"][4] if mult <= 1.0 else 2.5))

        scan_rate = 0.8 if action in ("PORT_SCAN", "LATERAL_MOVEMENT") else 0.0
        write_ratio = 0.5 if action == "MALICIOUS_WRITE" else 0.0
        cross_zone_ratio = 0.7 if action in ("LATERAL_MOVEMENT", "DATA_EXFIL") else 0.0

        # Override unique_ports/scan_rate from event if explicitly provided
        if "unique_ports" in event:
            unique_ports = float(event["unique_ports"])
        if "scan_rate" in event:
            scan_rate = float(event["scan_rate"])
        elif "scan_events" in event:
            scan_rate = float(event["scan_events"]) / total_packets

        return np.array([total_packets, unique_dests, unique_ports, avg_pkt_size,
                         proto_div, modbus_r, mqtt_r, scan_rate, write_ratio, cross_zone_ratio])

    # ------------------------------------------------------------------ #
    # Individual model scores (0=normal, 1=anomaly)                       #
    # ------------------------------------------------------------------ #

    def _score_isolation_forest(self, x):
        raw = self.iso_forest.decision_function(x.reshape(1, -1))[0]
        return round(float(np.clip(1.0 / (1.0 + np.exp(raw * 5.0)), 0, 1)), 4)

    def _score_dbscan(self, x):
        from sklearn.metrics import pairwise_distances
        if not hasattr(self.dbscan, "components_") or len(self.dbscan.components_) == 0:
            return 0.5
        dists = pairwise_distances(x.reshape(1, -1), self.dbscan.components_)
        min_dist = float(np.min(dists))
        eps = self.dbscan.eps
        if min_dist > eps:
            return 1.0
        if eps == 0:
            return 0.0
        return round(float(np.clip(min_dist / eps, 0.0, 1.0)), 4)

    # ------------------------------------------------------------------ #
    # Anomaly type classification                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _classify_anomaly_type(event, features):
        """Classify anomaly type from event action and feature signatures."""
        action = event.get("action", "")
        if action in ("PORT_SCAN", "UNAUTHORIZED_READ", "MALICIOUS_WRITE",
                       "LATERAL_MOVEMENT", "DATA_EXFIL"):
            return action
        feat_dict = dict(zip(FEATURE_COLS, features))
        for atype, thresholds in ANOMALY_SIGNATURES.items():
            if all(feat_dict.get(f, 0) >= t for f, t in thresholds.items()):
                return atype
        return "BEHAVIORAL_DEVIATION"

    # ------------------------------------------------------------------ #
    # Ensemble inference                                                  #
    # ------------------------------------------------------------------ #

    def infer(self, event):
        """Two-tier inference: Tier 1 (IF) fast-filters -> Tier 2 (DBSCAN) deep-scans flagged events."""
        t0 = time.perf_counter()
        device_ip = event.get("src_ip", event.get("device_ip", "unknown"))

        # 1. Extract features
        x_raw = self.extract_features(event)

        # 2. Scale
        x_scaled = self.scaler.transform(x_raw.reshape(1, -1))[0]

        # ── TIER 1: Isolation Forest (Fast Pass) ──
        tier1_score = self._score_isolation_forest(x_scaled)
        tier1_passed = tier1_score < TIER1_THRESHOLD

        scores = {"isolation_forest": tier1_score}

        if tier1_passed:
            # Normal traffic — skip Tier 2 entirely for speed
            scores["dbscan"] = 0.0  # Not evaluated
            ensemble_score = round(tier1_score * 0.5, 4)  # Dampened
            tier_decision = "TIER1_PASS"
        else:
            # ── TIER 2: DBSCAN (Deep Scan) ──
            tier2_score = self._score_dbscan(x_scaled)
            scores["dbscan"] = tier2_score
            ensemble_score = round(
                TIER1_WEIGHT * tier1_score + TIER2_WEIGHT * tier2_score, 4)
            tier_decision = "TIER2_DEEP"

        score_list = [scores[m] for m in MODEL_NAMES]

        # Confidence (how many models agree it's anomalous)
        agreement = sum(1 for s in score_list if s >= MODEL_ANOMALY_CUTOFF)
        confidence = round(agreement / NUM_MODELS, 2)

        # Decision
        is_anomaly = (ensemble_score >= ANOMALY_THRESHOLD
                      and confidence >= CONFIDENCE_THRESHOLD)
        classification = "ANOMALY" if is_anomaly else "NORMAL"
        severity = self._severity(ensemble_score, is_anomaly)

        anomaly_type = self._classify_anomaly_type(event, x_raw) if is_anomaly else "NONE"
        primary_model = max(scores, key=scores.get)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        result = {
            "src_ip": device_ip, "device_ip": device_ip,
            "is_anomaly": is_anomaly, "classification": classification,
            "ensemble_score": ensemble_score, "confidence": confidence,
            "model_scores": score_list, "model_scores_named": scores,
            "primary_model": primary_model, "anomaly_type": anomaly_type,
            "severity": severity, "inference_ms": elapsed_ms,
            "latency_ms": elapsed_ms, "tier_decision": tier_decision,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        }

        self.total_inferences += 1
        self.inference_times.append(elapsed_ms)
        if is_anomaly:
            self.total_anomalies += 1
            self.detected_anomalies.append(result)
            self._dispatch_alert(result)
        else:
            self.total_normal += 1
        return result

    @staticmethod
    def _severity(score, is_anomaly=False):
        if not is_anomaly: return "INFO"
        if score >= 0.85: return "CRITICAL"
        if score >= 0.70: return "HIGH"
        if score >= 0.60: return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------ #
    # Alert dispatch + DB + WebSocket + Containment                       #
    # ------------------------------------------------------------------ #

    def _dispatch_alert(self, result):
        logger.warning("ANOMALY DETECTED: %s %s (score=%.2f, conf=%.2f, severity=%s)",
            result["device_ip"], result["anomaly_type"],
            result["ensemble_score"], result["confidence"], result["severity"])
        self._store_to_database(result)
        self._send_websocket_alert(result)
        # Note: Containment/Isolation is orchestrated by ml_based_segmentation.py after formal attacker identification.
        # We comment this out to prevent real-time inference from creating mock/duplicate containment entries.
        # if result["severity"] in ("CRITICAL", "HIGH"):
        #     self._trigger_containment(result)

    def _store_to_database(self, result):
        if not DB_PATH.exists(): return
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                """INSERT INTO anomalies (src_ip, anomaly_type, anomaly_score,
                   confidence, detection_method, status, detection_timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (result["device_ip"], result["anomaly_type"],
                 result["ensemble_score"], result["confidence"],
                 "ensemble", "DETECTED", result["timestamp"]))
            conn.commit(); conn.close()
        except sqlite3.Error as e:
            logger.error("DB write failed: %s", e)

    def _send_websocket_alert(self, result):
        try:
            import socket as _s
            payload = json.dumps({"type": "ANOMALY_ALERT", "src_ip": result["device_ip"],
                "anomaly_type": result["anomaly_type"], "ensemble_score": result["ensemble_score"],
                "confidence": result["confidence"], "severity": result["severity"],
                "timestamp": result["timestamp"]}).encode("utf-8")
            sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            sock.settimeout(0.05); sock.sendto(payload, ("127.0.0.1", 5001)); sock.close()
        except Exception:
            pass

    def _trigger_containment(self, result):
        ip = result["device_ip"]
        # Only isolate each IP once
        if ip in self.isolated_ips:
            return
        self.isolated_ips.add(ip)
        logger.info("CONTAINMENT TRIGGERED for %s (%s, score=%.2f)",
            ip, result["anomaly_type"], result["ensemble_score"])
        if not DB_PATH.exists(): return
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                """INSERT INTO isolations (ip_address, isolation_reason,
                   isolation_timestamp, success, automation_method)
                   VALUES (?, ?, ?, ?, ?)""",
                (ip, "ATTACKER_IDENTIFIED",
                 result["timestamp"], 1, "policy"))
            conn.commit(); conn.close()
        except sqlite3.Error as e:
            logger.error("Containment DB write failed: %s", e)

    # ------------------------------------------------------------------ #
    # Live stream processing                                              #
    # ------------------------------------------------------------------ #

    def process_live_stream(self, csv_file=None):
        """Watch traffic_log.csv and process NEW events continuously."""
        csv_path = Path(csv_file) if csv_file else TRAFFIC_LOG
        print(f"Real-Time Inference Engine initialized")
        print(f"Monitoring {csv_path}...")

        last_pos = 0
        event_num = 0
        try:
            while True:
                if not csv_path.exists():
                    time.sleep(1)
                    continue
                with open(csv_path, "r", encoding="utf-8") as f:
                    f.seek(last_pos)
                    reader = csv.DictReader(f) if last_pos == 0 else \
                             csv.DictReader(f, fieldnames=[
                                 "timestamp","src_ip","dst_ip","src_port","dst_port",
                                 "protocol","action","severity","payload_size","zone"])
                    for row in reader:
                        event_num += 1
                        result = self.infer(row)
                        src = result["device_ip"]
                        dst = row.get("dst_ip", "?")
                        port = row.get("dst_port", "?")
                        sc = result["ensemble_score"]
                        cf = result["confidence"]
                        cls = result["classification"]
                        print(f'Event #{event_num}: {src} -> {dst}:{port} '
                              f'{cls} (score={sc:.2f}, conf={cf:.2f})')
                    last_pos = f.tell()
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping live stream monitor...")
            self.print_summary()

    # ------------------------------------------------------------------ #
    # Reporting                                                           #
    # ------------------------------------------------------------------ #

    def print_summary(self):
        print("\n" + "=" * 60)
        print("  Inference Session Summary")
        print("=" * 60)
        print(f"  Total inferences : {self.total_inferences}")
        print(f"  Normal           : {self.total_normal}")
        print(f"  Anomalies        : {self.total_anomalies}")
        if self.inference_times:
            print(f"  Avg latency      : {np.mean(self.inference_times):.2f} ms")
            print(f"  Min latency      : {min(self.inference_times):.2f} ms")
            print(f"  Max latency      : {max(self.inference_times):.2f} ms")
            u = sum(1 for t in self.inference_times if t < 100)
            print(f"  Under 100ms      : {u}/{len(self.inference_times)}")
        print("=" * 60)

    # ------------------------------------------------------------------ #
    # Demo mode                                                           #
    # ------------------------------------------------------------------ #

    def run_demo(self):
        print("\n" + "=" * 60)
        print("  LIVE INFERENCE DEMO")
        print("=" * 60)

        df = pd.read_csv(DATASET_PATH)
        names = ["PLC1","PLC2","HMI","Sensor-Temp","Sensor-Press","CCTV","Gateway","ATTACKER"]
        print(f"\n  {'Dev':<16} {'IP':<18} {'Score':>5} {'Conf':>5} "
              f"{'Class':<9} {'Type':<18} {'Sev':<9} {'ms':>5}")
        print("  " + "-" * 88)

        for i, row in df.iterrows():
            ev = {c: row[c] for c in FEATURE_COLS}
            ev["device_ip"] = row["device_ip"]
            r = self.infer(ev)
            nm = names[i] if i < len(names) else f"Dev-{i}"
            print(f"  {nm:<16} {r['device_ip']:<18} {r['ensemble_score']:>5.3f} "
                  f"{r['confidence']:>5.2f} {r['classification']:<9} "
                  f"{r['anomaly_type']:<18} {r['severity']:<9} {r['inference_ms']:>5.1f}")

        # Synthetic attacks
        print("\n  --- Synthetic attack events ---")
        for nm, atk in [
            ("NewAttacker", {"device_ip":"192.168.10.99","total_packets":12000,
             "unique_destinations":20,"unique_ports":30,"avg_packet_length":48,
             "protocol_diversity":4.0,"modbus_ratio":0.02,"mqtt_ratio":0.01,
             "http_ratio":0.05,"scan_events":250,"read_attempts":80,
             "write_operations":25,"data_exfil_gb":15.0}),
            ("CompromisedSensor", {"device_ip":"192.168.20.10","total_packets":5000,
             "unique_destinations":12,"unique_ports":18,"avg_packet_length":70,
             "protocol_diversity":3.5,"modbus_ratio":0.1,"mqtt_ratio":0.1,
             "http_ratio":0.2,"scan_events":100,"read_attempts":30,
             "write_operations":8,"data_exfil_gb":5.0})]:
            r = self.infer(atk)
            print(f"  {nm:<16} {r['device_ip']:<18} {r['ensemble_score']:>5.3f} "
                  f"{r['confidence']:>5.2f} {r['classification']:<9} "
                  f"{r['anomaly_type']:<18} {r['severity']:<9} {r['inference_ms']:>5.1f}")

        # Attacker breakdown
        print("\n  --- Model breakdown for ATTACKER (192.168.10.50) ---")
        ae = {c: df.iloc[7][c] for c in FEATURE_COLS}
        ae["device_ip"] = "192.168.10.50"
        ar = self.infer(ae)
        for mn, sc in ar["model_scores_named"].items():
            print(f"    {mn:<20} score={sc:.4f}  |{'#'*int(sc*20)}|")
        print(f"    {'ENSEMBLE':<20} score={ar['ensemble_score']:.4f}  confidence={ar['confidence']:.2f}")
        print(f"    {'DECISION':<20} {ar['classification']} -> {ar['anomaly_type']} ({ar['severity']})")

        with open(ANOMALIES_JSON, "w", encoding="utf-8") as f:
            json.dump(self.detected_anomalies, f, indent=2, default=str)
        self.print_summary()
        print("\nInference engine demo complete!")


def main():
    print("=" * 60)
    print("  SIEM+SOAR Platform - Real-Time Inference Engine")
    print("=" * 60)
    engine = RealTimeInferenceEngine()
    if not engine.is_ready:
        print("[FATAL] Could not initialize. Run clustering_engine.py first.")
        sys.exit(1)
    if "--stream" in sys.argv:
        engine.process_live_stream()
    else:
        engine.run_demo()


if __name__ == "__main__":
    main()
