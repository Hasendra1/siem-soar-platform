"""
inference_engine.py — Real-Time ML Inference Engine
=====================================================
Loads ml_models.pkl (5 trained unsupervised models).
Accepts feature vectors from DeviceFeatureExtractor.
Runs all 5 models on every new event.
Computes weighted ensemble anomaly score (0.0–1.0).
Triggers isolation decisions based on model output only.

Usage:
  from ml_pipeline.inference_engine import MLInferenceEngine
  engine = MLInferenceEngine()
  result = engine.process_event(event_dict)
  if result["is_anomaly"]:
      isolate(result["device_ip"])
"""

import pickle
import time
import numpy as np
import sqlite3
import json
import threading
from datetime import datetime
from collections import defaultdict
from ml_pipeline.realtime_features import DeviceFeatureExtractor

MODELS_PATH = r"C:\siem-soar-platform\results\ml_models.pkl"
DB_PATH     = r"C:\siem-soar-platform\dataset\siem_database.db"

# Isolation threshold — model must say >90% anomaly
ISOLATION_THRESHOLD = 0.90

# Ensemble weights (match project specification)
WEIGHTS = {
    "isolation_forest": 0.50,
    "dbscan":           0.50,
}

DEVICE_IPS = [
    "192.168.10.10", "192.168.10.11", "192.168.10.20",
    "192.168.10.50", "192.168.20.10", "192.168.20.11",
    "192.168.20.100", "192.168.30.10", "192.168.30.100",
]


class MLInferenceEngine:
    """
    Loads trained models and runs real inference.
    Both models are called for every new event.
    Isolation decision comes from model output only.
    """

    def __init__(self):
        self._load_models()
        self.extractor  = DeviceFeatureExtractor()
        self.lock       = threading.Lock()
        self.inferences = 0
        self.total_ms   = 0.0

    def _load_models(self):
        """Load the trained model bundle from disk."""
        with open(MODELS_PATH, "rb") as f:
            bundle = pickle.load(f)

        self.scaler     = bundle["scaler"]
        self.dbscan     = bundle["dbscan"]
        self.iso_forest = bundle["isolation_forest"]
        print(f"  Loaded models from {MODELS_PATH}")

    def _normalize(self, raw, low, high):
        """Clip and normalise a raw score to [0.0, 1.0]."""
        if high == low:
            return 0.0
        return float(np.clip((raw - low) / (high - low), 0.0, 1.0))

    # ── Individual model runners ──────────────────────────────

    def _run_dbscan(self, X_scaled):
        """
        DBSCAN cannot predict on new points directly.
        Use distance to nearest core point instead.
        If farther than eps → outlier → score = 1.0.
        """
        from sklearn.metrics import pairwise_distances
        if not hasattr(self.dbscan, "components_") or len(self.dbscan.components_) == 0:
            return 0.5  # no core points found during training

        dists = pairwise_distances(X_scaled, self.dbscan.components_)
        min_dist = float(np.min(dists))
        eps = self.dbscan.eps
        if min_dist > eps:
            return 1.0  # outlier
        return self._normalize(min_dist, 0, eps)

    def _run_isolation_forest(self, X_scaled):
        """
        decision_function returns negative values for anomalies.
        Convert: more negative = higher anomaly score.
        """
        raw = -float(self.iso_forest.decision_function(X_scaled)[0])
        # Typical range: -0.5 to +0.5, anomalies above 0
        return self._normalize(raw, -0.5, 0.5)

    # ── Main inference ────────────────────────────────────────

    def infer(self, device_ip):
        """
        Main inference method.
        Returns dict with score per model + ensemble score.
        Runs in <100ms on CPU.
        """
        t_start = time.time()

        # Step 1: Extract features from rolling window
        features = self.extractor.get_feature_vector(device_ip)

        # Step 2: Scale using same scaler as training
        features_2d = features.reshape(1, -1)
        try:
            X_scaled = self.scaler.transform(features_2d)
        except Exception as e:
            return {"error": str(e), "ensemble_score": 0.0}

        # Step 3: Run all 2 models
        scores = {
            "dbscan":           self._run_dbscan(X_scaled),
            "isolation_forest": self._run_isolation_forest(X_scaled),
        }

        # Step 4: Weighted ensemble
        ensemble = sum(
            WEIGHTS[model] * score
            for model, score in scores.items()
        )

        # Step 5: Track latency
        elapsed_ms = (time.time() - t_start) * 1000
        with self.lock:
            self.inferences += 1
            self.total_ms   += elapsed_ms

        return {
            "device_ip":      device_ip,
            "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "feature_vector": features.tolist(),
            "model_scores":   {k: round(v, 4) for k, v in scores.items()},
            "ensemble_score": round(ensemble, 4),
            "is_anomaly":     ensemble > ISOLATION_THRESHOLD,
            "inference_ms":   round(elapsed_ms, 2),
        }

    def process_event(self, event):
        """
        Called every time a new network event arrives.
        1. Add to feature window.
        2. Run inference on source device.
        3. Return result.
        """
        self.extractor.add_event(event)
        src_ip = event.get("src_ip", "")
        if src_ip not in DEVICE_IPS:
            return None
        return self.infer(src_ip)

    def get_all_scores(self):
        """
        Run inference on ALL devices simultaneously.
        Returns ranked list (highest anomaly first).
        """
        results = []
        for ip in DEVICE_IPS:
            result = self.infer(ip)
            if result and "error" not in result:
                results.append(result)
        results.sort(key=lambda x: x["ensemble_score"], reverse=True)
        return results

    def avg_latency_ms(self):
        """Average inference latency across all calls."""
        if self.inferences == 0:
            return 0.0
        return round(self.total_ms / self.inferences, 2)


class RealTimeMonitor:
    """
    Polls database for new events.
    Runs ML inference on each event.
    Triggers isolation if score > threshold.
    """

    def __init__(self):
        self.engine   = MLInferenceEngine()
        self.last_id  = 0
        self.isolator = None  # injected by smart_isolator

    def set_isolator(self, isolator):
        """Inject the isolation handler (SmartIsolator)."""
        self.isolator = isolator

    def _poll_db(self):
        """Fetch new events from the database since last poll."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute("""
            SELECT event_id, src_ip, dst_ip, protocol,
                   action, payload_size, zone,
                   timestamp
            FROM events
            WHERE event_id > ?
            ORDER BY event_id
            LIMIT 50
        """, (self.last_id,))
        rows = cursor.fetchall()
        conn.close()
        return rows

    def run(self):
        """Main loop: poll DB → extract features → infer → isolate."""
        print("\n[ML MONITOR] Real-time inference engine started")
        print(f"  Models loaded : 2 (DBSCAN, IsoForest)")
        print(f"  Threshold     : {ISOLATION_THRESHOLD}")
        print(f"  Poll interval : 1 second")
        print()

        while True:
            rows = self._poll_db()

            for row in rows:
                (event_id, src_ip, dst_ip, protocol,
                 action, payload_size, zone, timestamp) = row

                self.last_id = max(self.last_id, event_id)

                # Build event dict matching extractor format
                event = {
                    "src_ip":      src_ip,
                    "dst_ip":      dst_ip,
                    "protocol":    protocol,
                    "action":      action,
                    "packet_size": payload_size or 64,
                    "src_zone":    zone or "OT",
                    "dst_zone":    "OT",
                    "timestamp":   timestamp,
                }

                # Run real ML inference
                result = self.engine.process_event(event)

                if result and result["ensemble_score"] > 0.3:
                    print(
                        f"[INFERENCE] {src_ip:16s} | "
                        f"action={action:20s} | "
                        f"score={result['ensemble_score']:.3f} | "
                        f"dbscan={result['model_scores']['dbscan']:.3f} | "
                        f"iso={result['model_scores']['isolation_forest']:.3f} | "
                        f"{result['inference_ms']:.1f}ms"
                    )

                    # Trigger isolation if models say so
                    if result["is_anomaly"] and self.isolator:
                        self.isolator.process_ml_result(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            action=action,
                            ensemble_score=result["ensemble_score"],
                            model_scores=result["model_scores"],
                        )

                    # Save inference result to DB
                    self._save_inference(src_ip, result)

            if rows:
                avg_lat = self.engine.avg_latency_ms()
                print(f"  [AVG LATENCY] {avg_lat}ms over {self.engine.inferences} inferences")

            time.sleep(1)

    def _save_inference(self, ip, result):
        """Persist anomaly detection result to the database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT OR REPLACE INTO anomalies
                (src_ip, anomaly_type, anomaly_score,
                 confidence, detection_method, status, timestamp)
                VALUES (?,?,?,?,?,?,?)
            """, (
                ip,
                "ML_ENSEMBLE",
                result["ensemble_score"],
                result["ensemble_score"],
                "2_model_ensemble",
                "DETECTED" if result["is_anomaly"] else "NORMAL",
                result["timestamp"],
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    monitor = RealTimeMonitor()

    try:
        from enforcement.smart_isolator import SmartIsolator
        isolator = SmartIsolator()
        monitor.set_isolator(isolator)
    except ImportError:
        print("  SmartIsolator not available, running without isolation")

    monitor.run()
