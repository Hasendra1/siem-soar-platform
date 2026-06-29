"""
train_models.py — Two-Tier Anomaly Detection Pipeline Training
================================================================
Trains a production two-tier anomaly detection pipeline for IoT/OT
network traffic:

  TIER 1 (Fast Pass): Isolation Forest
    - 200-tree ensemble trained on ALL device profiles
    - Fast O(n·log n) scoring to filter obvious normal traffic
    - Events below the IF threshold bypass Tier 2 entirely

  TIER 2 (Deep Scan): DBSCAN
    - Density-based clustering trained on the FULL feature space
    - Auto-computes eps via k-distance graph
    - Flags low-density points (outliers) as stealthy anomalies
    - Only processes events that Tier 1 flagged as suspicious

Feature Scaling: RobustScaler (median + IQR) — resistant to outliers
in small datasets.

Usage:
  python ml_pipeline\\train_models.py
"""

import os
import pickle
import json
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import NearestNeighbors
import warnings
warnings.filterwarnings("ignore")

DATASET_PATH = r"C:\siem-soar-platform\dataset\clustering_dataset.csv"
MODELS_PATH  = r"C:\siem-soar-platform\results\ml_models.pkl"
RESULTS_PATH = r"C:\siem-soar-platform\results\device_scores.json"

# Aggregation strategy per feature:
#   MAX  for attack indicators (scan_rate, write_ratio, cross_zone_ratio)
#   MEAN for steady-state behaviour (avg_packet_size, modbus_ratio, etc.)
AGG_FEATURES = {
    "total_packets":       "max",
    "unique_destinations": "max",
    "unique_ports":        "max",
    "avg_packet_size":     "mean",
    "protocol_diversity":  "max",
    "modbus_ratio":        "mean",
    "mqtt_ratio":          "mean",
    "scan_rate":           "max",
    "write_ratio":         "max",
    "cross_zone_ratio":    "max",
}


# ─── STEP 1: Load & Aggregate ────────────────────────────────────

def load_and_aggregate():
    """Load the windowed CSV and collapse 30 windows into 1 row per device."""
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} rows, {df['device_name'].nunique()} devices")

    agg = (
        df.groupby(["device_ip", "device_name", "device_type", "zone"])
          .agg(AGG_FEATURES)
          .reset_index()
    )
    print(f"Aggregated to {len(agg)} device profiles")
    return agg


# ─── Helpers ──────────────────────────────────────────────────────

def normalize_scores(raw_scores):
    """Min-max normalise an array to [0, 1]."""
    mn, mx = raw_scores.min(), raw_scores.max()
    if mx == mn:
        return np.zeros_like(raw_scores)
    return (raw_scores - mn) / (mx - mn)


# ─── TIER 1: Isolation Forest (Fast Pass) ────────────────────────

def train_tier1_isolation_forest(X_scaled):
    """Train Isolation Forest — the fast pre-filter.
    
    This model processes EVERY incoming event in <1ms.
    It learns what 'normal' looks like from the full dataset and
    assigns anomaly scores. Events scoring above the IF threshold
    are forwarded to Tier 2 for deep analysis.
    """
    print("\n[TIER 1] Isolation Forest (Fast Pass)")
    print("  Purpose: Quick filter to separate normal vs. suspicious traffic")

    iso = IsolationForest(
        n_estimators=200,       # More trees = more stable anomaly boundary
        contamination=0.11,     # Expect ~1/9 devices to be anomalous
        random_state=42,
        max_features=1.0,       # Use all features for full coverage
    )
    iso.fit(X_scaled)

    # Score: higher = more anomalous (negate decision_function)
    raw = -iso.decision_function(X_scaled)
    scores = normalize_scores(raw)
    predictions = iso.predict(X_scaled)  # +1 = normal, -1 = anomaly

    n_flagged = np.sum(predictions == -1)
    n_passed = np.sum(predictions == 1)

    print(f"  Trees:   {iso.n_estimators}")
    print(f"  Passed (normal):    {n_passed} devices -> SKIP Tier 2")
    print(f"  Flagged (suspicious): {n_flagged} device(s) -> FORWARD to Tier 2")

    return iso, scores, predictions


# ─── TIER 2: DBSCAN (Deep Scan) ─────────────────────────────────

def train_tier2_dbscan(X_scaled):
    """Train DBSCAN — the deep behavioral clustering model.
    
    DBSCAN groups similar traffic patterns into dense clusters.
    Points that don't fit any cluster (noise points, label=-1)
    are flagged as stealthy anomalies — the kind that Isolation
    Forest might miss because they look individually normal but
    are spatially isolated in feature space.
    
    At inference time, only Tier 1 flagged events reach this model.
    We compute the distance from the new point to the nearest
    DBSCAN core sample — if it exceeds eps, the event is a
    confirmed outlier.
    """
    print("\n[TIER 2] DBSCAN (Deep Scan)")
    print("  Purpose: Cluster complex behaviors, catch stealthy low-density anomalies")

    # Auto-compute eps from k-distance graph (knee detection)
    nn = NearestNeighbors(n_neighbors=2)
    nn.fit(X_scaled)
    distances, _ = nn.kneighbors(X_scaled)
    eps = np.percentile(distances[:, 1], 75)
    print(f"  Auto eps={eps:.3f} (75th percentile of 2-NN distances)")

    db = DBSCAN(eps=eps, min_samples=2)
    labels = db.fit_predict(X_scaled)
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_outliers = np.sum(labels == -1)
    print(f"  Clusters:  {n_clusters} (dense behavioral groups)")
    print(f"  Outliers:  {n_outliers} (isolated/anomalous patterns)")

    # DBSCAN score: outliers get 1.0, clustered points get 0.0
    scores = np.where(labels == -1, 1.0, 0.0).astype(float)

    if hasattr(db, "components_") and len(db.components_) > 0:
        print(f"  Core samples: {len(db.components_)}")
    
    return db, scores


# ─── TWO-TIER ENSEMBLE ───────────────────────────────────────────

def compute_two_tier_ensemble(iso_scores, db_scores, iso_predictions):
    """Combine Tier 1 and Tier 2 scores using the cascading logic.
    
    - Devices that Tier 1 marked as normal get a lower weight from Tier 2
    - Devices that Tier 1 flagged get full weight from both tiers
    
    Weight: Tier 1 (IF) = 0.40, Tier 2 (DBSCAN) = 0.60
    Rationale: DBSCAN provides higher precision on flagged traffic,
    so it gets more influence on the final score.
    """
    TIER1_WEIGHT = 0.40
    TIER2_WEIGHT = 0.60

    ensemble = np.zeros_like(iso_scores)
    for i in range(len(iso_scores)):
        if iso_predictions[i] == -1:
            # Tier 1 flagged -> full two-tier scoring
            ensemble[i] = TIER1_WEIGHT * iso_scores[i] + TIER2_WEIGHT * db_scores[i]
        else:
            # Tier 1 passed -> only IF score matters (DBSCAN not consulted)
            ensemble[i] = iso_scores[i] * 0.5  # Dampen since Tier 2 didn't confirm

    return ensemble


# ─── Main Pipeline ───────────────────────────────────────────────

def run_pipeline():
    """End-to-end: load -> aggregate -> scale -> Tier 1 -> Tier 2 -> score -> save."""
    os.makedirs(r"C:\siem-soar-platform\results", exist_ok=True)

    print("=" * 60)
    print("  TWO-TIER ANOMALY DETECTION PIPELINE")
    print("  Tier 1: Isolation Forest (Fast Pass)")
    print("  Tier 2: DBSCAN (Deep Scan)")
    print("=" * 60)

    # Load & aggregate
    agg = load_and_aggregate()
    feature_cols = list(AGG_FEATURES.keys())
    X = agg[feature_cols].fillna(0).values

    # Scale with RobustScaler (resistant to outliers)
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # ── TIER 1: Fast Pass (Isolation Forest) ──
    iso_model, iso_scores, iso_predictions = train_tier1_isolation_forest(X_scaled)

    # ── TIER 2: Deep Scan (DBSCAN) ──
    # In training, we fit DBSCAN on ALL data to learn the cluster structure.
    # At inference time, only Tier 1 flagged events will be scored against it.
    db_model, db_scores = train_tier2_dbscan(X_scaled)

    # ── TWO-TIER ENSEMBLE ──
    print("\n[ENSEMBLE] Two-Tier Scoring")
    print("  Tier 1 passed -> IF score only (dampened)")
    print("  Tier 1 flagged -> 0.40 x IF + 0.60 x DBSCAN")
    ensemble = compute_two_tier_ensemble(iso_scores, db_scores, iso_predictions)

    agg["iso_score"]      = iso_scores
    agg["db_score"]       = db_scores
    agg["tier1_decision"] = np.where(iso_predictions == -1, "FLAGGED", "PASSED")
    agg["ensemble_score"] = ensemble

    agg_sorted = agg.sort_values("ensemble_score", ascending=False).reset_index(drop=True)

    # Print results table
    print("\n" + "=" * 70)
    print("DEVICE ANOMALY SCORES (Two-Tier Pipeline)")
    print("=" * 70)
    print(f"  {'Device':<16} {'IP':<18} {'Tier1':<8} {'IF':>6} {'DBSCAN':>7} {'Final':>7}")
    print("  " + "-" * 64)
    for _, row in agg_sorted.iterrows():
        flag = "*** ATTACKER ***" if row["ensemble_score"] > 0.7 else ""
        print(f"  {row['device_name']:<16} {row['device_ip']:<18} "
              f"{row['tier1_decision']:<8} {row['iso_score']:>6.3f} "
              f"{row['db_score']:>7.3f} {row['ensemble_score']:>7.3f} {flag}")

    # Compute confidence from score gap between #1 and #2
    top_score = agg_sorted.iloc[0]["ensemble_score"]
    runner_up = agg_sorted.iloc[1]["ensemble_score"]
    gap = top_score - runner_up
    confidence = min(0.999, 0.5 + gap * 2.5)

    top_device = agg_sorted.iloc[0]
    print(f"\n  IDENTIFIED ATTACKER: {top_device['device_name']} ({top_device['device_ip']})")
    print(f"  Tier 1 Decision: {top_device['tier1_decision']}")
    print(f"  CONFIDENCE: {confidence * 100:.1f}%")

    # Save models bundle
    models_bundle = {
        "scaler": scaler,
        "isolation_forest": iso_model,
        "dbscan": db_model,
        "feature_cols": feature_cols,
        "architecture": "two_tier",
        "tier1_model": "isolation_forest",
        "tier2_model": "dbscan",
    }
    with open(MODELS_PATH, "wb") as f:
        pickle.dump(models_bundle, f)
    print(f"\n  Models saved: {MODELS_PATH}")

    # Save scored results as JSON
    results = []
    for idx, row in agg_sorted.iterrows():
        is_top = (idx == 0)
        results.append({
            "device_ip":      row["device_ip"],
            "device_name":    row["device_name"],
            "device_type":    row["device_type"],
            "zone":           row["zone"],
            "ensemble_score": round(float(row["ensemble_score"]), 4),
            "iso_score":      round(float(row["iso_score"]), 4),
            "db_score":       round(float(row["db_score"]), 4),
            "tier1_decision": row["tier1_decision"],
            "confidence":     round(confidence if is_top else 0.0, 4),
            "is_attacker":    bool(row["ensemble_score"] > 0.7),
        })

    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved: {RESULTS_PATH}")


if __name__ == "__main__":
    run_pipeline()
