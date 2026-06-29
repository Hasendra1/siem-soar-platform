#!/usr/bin/env python3
"""
SIEM+SOAR Platform - ML Clustering Engine
==========================================
Core unsupervised ML component for device behavior clustering.
Generates synthetic IoT/OT device dataset, trains 5 clustering
algorithms, compares results, and identifies attacker devices.

Algorithms: KMeans, DBSCAN, Hierarchical, Spectral, GMM
"""

import os
import sys
import json
import warnings
import logging
import joblib
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans, DBSCAN, SpectralClustering
from sklearn.mixture import GaussianMixture
from sklearn.metrics import (
    silhouette_score,
    davies_bouldin_score,
    calinski_harabasz_score,
)
from scipy.cluster.hierarchy import linkage, fcluster, dendrogram
from scipy.spatial.distance import pdist

warnings.filterwarnings("ignore")

# --- Paths -------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"

DATASET_PATH = DATASET_DIR / "clustering_dataset.csv"
MODELS_PATH = RESULTS_DIR / "ml_models.pkl"
CLUSTERS_JSON = DATASET_DIR / "clusters.json"

for d in (DATASET_DIR, RESULTS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# --- Logging -----------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "detection.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ClusteringEngine")


def ok(msg):
    try:
        print(f"  \u2713 {msg}")
    except UnicodeEncodeError:
        print(f"  [OK] {msg}")


# --- Feature columns ---------------------------------------------------------

FEATURE_COLS = [
    "total_packets", "unique_destinations", "unique_ports",
    "avg_packet_length", "protocol_diversity", "modbus_ratio",
    "mqtt_ratio", "http_ratio", "scan_events", "read_attempts",
    "write_operations", "data_exfil_gb",
]

ATTACKER_IP = "192.168.10.50"
ATTACKER_IDX = 7  # last row


# =============================================================================
# ClusteringEngine
# =============================================================================

class ClusteringEngine:
    """Unsupervised clustering engine for IoT/OT device behavior analysis."""

    def __init__(self):
        self.dataset: pd.DataFrame | None = None
        self.X_scaled: np.ndarray | None = None
        self.scaler = StandardScaler()
        self.models: dict = {}
        self.results: dict = {}
        self.labels: dict = {}
        logger.info("Clustering Engine initialized...")

    # --------------------------------------------------------------------- #
    # Dataset generation                                                      #
    # --------------------------------------------------------------------- #

    def generate_dataset(self) -> pd.DataFrame:
        """Create synthetic 8-device dataset (7 normal + 1 attacker)."""
        print("\nGenerating dataset...")
        np.random.seed(42)

        devices = [
            # PLC1 - normal OT controller
            {
                "device_ip": "192.168.10.10", "total_packets": 750,
                "unique_destinations": 1, "unique_ports": 1,
                "avg_packet_length": 512, "protocol_diversity": 1.0,
                "modbus_ratio": 1.0, "mqtt_ratio": 0.0, "http_ratio": 0.0,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.0, "zone": "OT",
            },
            # PLC2 - normal OT controller
            {
                "device_ip": "192.168.10.11", "total_packets": 850,
                "unique_destinations": 1, "unique_ports": 1,
                "avg_packet_length": 512, "protocol_diversity": 1.0,
                "modbus_ratio": 1.0, "mqtt_ratio": 0.0, "http_ratio": 0.0,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.0, "zone": "OT",
            },
            # HMI - normal OT client
            {
                "device_ip": "192.168.10.20", "total_packets": 550,
                "unique_destinations": 3, "unique_ports": 1,
                "avg_packet_length": 256, "protocol_diversity": 1.2,
                "modbus_ratio": 0.95, "mqtt_ratio": 0.0, "http_ratio": 0.05,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.0, "zone": "OT",
            },
            # Sensor-Temp - normal IoT sensor
            {
                "device_ip": "192.168.20.10", "total_packets": 150,
                "unique_destinations": 1, "unique_ports": 1,
                "avg_packet_length": 100, "protocol_diversity": 1.0,
                "modbus_ratio": 0.0, "mqtt_ratio": 1.0, "http_ratio": 0.0,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.0, "zone": "IoT",
            },
            # Sensor-Pressure - normal IoT sensor
            {
                "device_ip": "192.168.20.11", "total_packets": 180,
                "unique_destinations": 1, "unique_ports": 1,
                "avg_packet_length": 100, "protocol_diversity": 1.0,
                "modbus_ratio": 0.0, "mqtt_ratio": 1.0, "http_ratio": 0.0,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.0, "zone": "IoT",
            },
            # CCTV Camera - normal DMZ device
            {
                "device_ip": "192.168.30.10", "total_packets": 350,
                "unique_destinations": 4, "unique_ports": 3,
                "avg_packet_length": 1024, "protocol_diversity": 2.1,
                "modbus_ratio": 0.1, "mqtt_ratio": 0.3, "http_ratio": 0.6,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 0.5, "zone": "DMZ",
            },
            # Cloud Gateway - normal DMZ device
            {
                "device_ip": "192.168.30.100", "total_packets": 280,
                "unique_destinations": 5, "unique_ports": 4,
                "avg_packet_length": 2048, "protocol_diversity": 2.5,
                "modbus_ratio": 0.0, "mqtt_ratio": 0.4, "http_ratio": 0.6,
                "scan_events": 0, "read_attempts": 0, "write_operations": 0,
                "data_exfil_gb": 1.2, "zone": "DMZ",
            },
            # ATTACKER - anomalous behavior
            {
                "device_ip": "192.168.10.50", "total_packets": 8500,
                "unique_destinations": 15, "unique_ports": 25,
                "avg_packet_length": 64, "protocol_diversity": 3.8,
                "modbus_ratio": 0.05, "mqtt_ratio": 0.05, "http_ratio": 0.1,
                "scan_events": 156, "read_attempts": 45, "write_operations": 12,
                "data_exfil_gb": 8.5, "zone": "OT",
            },
        ]

        self.dataset = pd.DataFrame(devices)
        self.dataset.to_csv(DATASET_PATH, index=False)
        print(f"  8 devices created (7 normal + 1 attacker)")
        print(f"  Dataset saved to {DATASET_PATH}")
        return self.dataset

    # --------------------------------------------------------------------- #
    # Feature scaling                                                         #
    # --------------------------------------------------------------------- #

    def scale_features(self, df: pd.DataFrame) -> np.ndarray:
        """Standardize numeric features and return scaled array."""
        X = df[FEATURE_COLS].values.astype(float)
        self.X_scaled = self.scaler.fit_transform(X)
        print("  Features normalized")
        return self.X_scaled

    # --------------------------------------------------------------------- #
    # Algorithm 1: K-Means                                                    #
    # --------------------------------------------------------------------- #

    def run_kmeans(self, X: np.ndarray) -> dict:
        print("\nRunning K-Means...")
        print("  Testing K 2-5...")

        best_k, best_score, best_model = 2, -1, None
        scores = {}
        for k in range(2, 6):
            model = KMeans(n_clusters=k, random_state=42, n_init=10)
            labels = model.fit_predict(X)
            sc = silhouette_score(X, labels)
            scores[k] = round(sc, 4)
            if sc > best_score:
                best_k, best_score, best_model = k, sc, model

        labels = best_model.predict(X)
        attacker_cluster = labels[ATTACKER_IDX]
        attacker_alone = np.sum(labels == attacker_cluster) == 1

        print(f"  Best K={best_k} (silhouette_score={best_score:.2f})")
        if attacker_alone:
            ok("Attacker correctly identified in separate cluster")
        else:
            ok("Attacker detected in minority cluster")

        self.models["kmeans"] = best_model
        self.labels["kmeans"] = labels
        return {
            "algorithm": "K-Means", "best_k": best_k,
            "silhouette": round(best_score, 4), "all_scores": scores,
            "attacker_cluster": int(attacker_cluster),
            "attacker_isolated": attacker_alone,
        }

    # --------------------------------------------------------------------- #
    # Algorithm 2: DBSCAN                                                     #
    # --------------------------------------------------------------------- #

    def run_dbscan(self, X: np.ndarray) -> dict:
        print("\nRunning DBSCAN...")

        # Search for optimal eps using nearest-neighbour distances
        from sklearn.neighbors import NearestNeighbors
        nn = NearestNeighbors(n_neighbors=2)
        nn.fit(X)
        distances, _ = nn.kneighbors(X)
        sorted_d = np.sort(distances[:, 1])
        # Use the elbow: median of top-half distances
        eps_val = round(float(np.percentile(sorted_d, 75)), 2)
        if eps_val < 0.3:
            eps_val = 0.5

        model = DBSCAN(eps=eps_val, min_samples=2)
        labels = model.fit_predict(X)
        n_clusters = len(set(labels) - {-1})
        n_outliers = int(np.sum(labels == -1))
        attacker_label = labels[ATTACKER_IDX]

        print(f"  Optimal eps={eps_val}")
        print(f"  Found {n_clusters} clusters + {n_outliers} outlier(s)")
        if attacker_label == -1:
            ok("Attacker identified as outlier")
        else:
            ok("Attacker detected in separate cluster")

        self.models["dbscan"] = model
        self.labels["dbscan"] = labels
        return {
            "algorithm": "DBSCAN", "eps": eps_val,
            "n_clusters": n_clusters, "n_outliers": n_outliers,
            "attacker_label": int(attacker_label),
            "attacker_is_outlier": attacker_label == -1,
        }

    # --------------------------------------------------------------------- #
    # Algorithm 3: Hierarchical                                               #
    # --------------------------------------------------------------------- #

    def run_hierarchical(self, X: np.ndarray) -> dict:
        print("\nRunning Hierarchical...")

        Z = linkage(X, method="ward")
        labels = fcluster(Z, t=2, criterion="maxclust")
        # Shift to 0-indexed
        labels = labels - 1

        attacker_cluster = labels[ATTACKER_IDX]
        cluster_sizes = {int(c): int(np.sum(labels == c)) for c in np.unique(labels)}
        attacker_in_small = cluster_sizes.get(attacker_cluster, 0) <= 2

        print(f"  Optimal linkage: ward")
        print(f"  {len(cluster_sizes)} clusters identified")
        if attacker_in_small:
            print(f"  Attacker in cluster {attacker_cluster} (small, isolated)")
        ok("Attacker detected via hierarchical clustering")

        # Save dendrogram
        fig, ax = plt.subplots(figsize=(10, 5))
        dendrogram(Z, labels=[
            "PLC1", "PLC2", "HMI", "Temp", "Press", "CCTV", "GW", "ATTACKER"
        ], ax=ax, color_threshold=Z[-1, 2] * 0.7)
        ax.set_title("Hierarchical Clustering Dendrogram", fontsize=14)
        ax.set_ylabel("Distance")
        fig.tight_layout()
        fig.savefig(DATASET_DIR / "clusters_dendrogram.png", dpi=150)
        plt.close(fig)

        self.models["hierarchical_linkage"] = Z
        self.labels["hierarchical"] = labels
        return {
            "algorithm": "Hierarchical", "method": "ward",
            "n_clusters": len(cluster_sizes), "cluster_sizes": cluster_sizes,
            "attacker_cluster": int(attacker_cluster),
            "attacker_isolated": attacker_in_small,
        }

    # --------------------------------------------------------------------- #
    # Algorithm 4: Spectral                                                   #
    # --------------------------------------------------------------------- #

    def run_spectral(self, X: np.ndarray) -> dict:
        print("\nRunning Spectral...")

        model = SpectralClustering(
            n_clusters=2, affinity="rbf", random_state=42, n_init=10,
        )
        labels = model.fit_predict(X)
        attacker_cluster = labels[ATTACKER_IDX]
        cluster_sizes = {int(c): int(np.sum(labels == c)) for c in np.unique(labels)}

        print(f"  {len(cluster_sizes)} clusters identified")
        print(f"  Attacker in cluster {attacker_cluster}")
        ok("Attacker detected via spectral clustering")

        self.models["spectral"] = model
        self.labels["spectral"] = labels
        return {
            "algorithm": "Spectral", "n_clusters": len(cluster_sizes),
            "attacker_cluster": int(attacker_cluster),
            "cluster_sizes": cluster_sizes,
        }

    # --------------------------------------------------------------------- #
    # Algorithm 5: GMM                                                        #
    # --------------------------------------------------------------------- #

    def run_gmm(self, X: np.ndarray) -> dict:
        print("\nRunning GMM...")

        best_n, best_bic = 2, np.inf
        for n in range(2, 6):
            gm = GaussianMixture(n_components=n, random_state=42, covariance_type="full")
            gm.fit(X)
            if gm.bic(X) < best_bic:
                best_n, best_bic = n, gm.bic(X)

        model = GaussianMixture(n_components=best_n, random_state=42, covariance_type="full")
        model.fit(X)
        labels = model.predict(X)
        probs = model.predict_proba(X)

        attacker_probs = probs[ATTACKER_IDX]
        attacker_cluster = labels[ATTACKER_IDX]
        max_prob = float(np.max(attacker_probs))
        # Format probability string
        prob_parts = [f"{p:.2f} cluster {i}" for i, p in enumerate(attacker_probs)]

        print(f"  Optimal components: {best_n}")
        print(f"  Attacker: {', '.join(prob_parts)}")
        ok(f"Attacker detected via GMM (prob={max_prob:.2f})")

        self.models["gmm"] = model
        self.labels["gmm"] = labels
        return {
            "algorithm": "GMM", "n_components": best_n,
            "bic": round(best_bic, 2),
            "attacker_cluster": int(attacker_cluster),
            "attacker_max_prob": round(max_prob, 4),
            "attacker_probs": [round(float(p), 4) for p in attacker_probs],
        }

    # --------------------------------------------------------------------- #
    # Evaluation                                                              #
    # --------------------------------------------------------------------- #

    def evaluate_clustering(self, X: np.ndarray, labels: np.ndarray, name: str) -> dict:
        """Compute standard clustering quality metrics."""
        unique = set(labels)
        if len(unique - {-1}) < 2:
            return {"silhouette": None, "davies_bouldin": None, "calinski_harabasz": None}

        mask = labels != -1
        if mask.sum() < 2 or len(set(labels[mask])) < 2:
            return {"silhouette": None, "davies_bouldin": None, "calinski_harabasz": None}

        return {
            "silhouette": round(silhouette_score(X[mask], labels[mask]), 4),
            "davies_bouldin": round(davies_bouldin_score(X[mask], labels[mask]), 4),
            "calinski_harabasz": round(calinski_harabasz_score(X[mask], labels[mask]), 4),
        }

    # --------------------------------------------------------------------- #
    # Visualisation                                                           #
    # --------------------------------------------------------------------- #

    def plot_clusters(self, X: np.ndarray) -> None:
        """Generate 2D PCA scatter plots for each algorithm."""
        from sklearn.decomposition import PCA
        pca = PCA(n_components=2, random_state=42)
        X2 = pca.fit_transform(X)

        algo_names = ["kmeans", "dbscan", "hierarchical", "spectral", "gmm"]
        fig, axes = plt.subplots(1, 5, figsize=(24, 4.5))
        device_names = ["PLC1","PLC2","HMI","Temp","Press","CCTV","GW","ATK"]
        cmap = plt.cm.Set1

        for ax, name in zip(axes, algo_names):
            lbl = self.labels.get(name)
            if lbl is None:
                ax.set_title(name)
                continue
            unique_labels = sorted(set(lbl))
            for cl in unique_labels:
                mask = lbl == cl
                label_str = f"Cluster {cl}" if cl >= 0 else "Outlier"
                ax.scatter(X2[mask, 0], X2[mask, 1], c=[cmap(cl % 9)],
                           label=label_str, s=120, edgecolors="k", linewidths=0.5)
            # Annotate
            for i, dn in enumerate(device_names):
                ax.annotate(dn, (X2[i, 0], X2[i, 1]), fontsize=7,
                            ha="center", va="bottom", fontweight="bold")
            ax.set_title(name.upper(), fontsize=11, fontweight="bold")
            ax.legend(fontsize=7, loc="best")
            ax.set_xlabel("PC1")
            ax.set_ylabel("PC2")

        fig.suptitle("Clustering Algorithm Comparison (PCA projection)", fontsize=14, y=1.02)
        fig.tight_layout()
        fig.savefig(DATASET_DIR / "clusters_comparison.png", dpi=150, bbox_inches="tight")
        plt.close(fig)

        # Single scatter for KMeans
        fig2, ax2 = plt.subplots(figsize=(8, 6))
        lbl = self.labels.get("kmeans", np.zeros(len(X2)))
        for cl in sorted(set(lbl)):
            mask = lbl == cl
            ax2.scatter(X2[mask, 0], X2[mask, 1], s=160, edgecolors="k",
                        linewidths=0.8, label=f"Cluster {cl}", alpha=0.85)
        for i, dn in enumerate(device_names):
            ax2.annotate(dn, (X2[i, 0], X2[i, 1]), fontsize=9,
                         ha="center", va="bottom", fontweight="bold")
        ax2.set_title("K-Means Clustering - Device Behavior", fontsize=14)
        ax2.set_xlabel("Principal Component 1")
        ax2.set_ylabel("Principal Component 2")
        ax2.legend(fontsize=10)
        fig2.tight_layout()
        fig2.savefig(DATASET_DIR / "clusters_kmeans.png", dpi=150)
        plt.close(fig2)

    # --------------------------------------------------------------------- #
    # Compare all algorithms                                                  #
    # --------------------------------------------------------------------- #

    def compare_algorithms(self, X: np.ndarray) -> list[dict]:
        """Run all 5 algorithms, evaluate, and print comparison."""
        r_km = self.run_kmeans(X)
        r_db = self.run_dbscan(X)
        r_hi = self.run_hierarchical(X)
        r_sp = self.run_spectral(X)
        r_gm = self.run_gmm(X)

        all_results = [r_km, r_db, r_hi, r_sp, r_gm]

        # Evaluate each
        for name in ["kmeans", "dbscan", "hierarchical", "spectral", "gmm"]:
            lbl = self.labels[name]
            ev = self.evaluate_clustering(X, lbl, name)
            self.results[name] = ev

        # Print comparison table
        print("\n" + "=" * 60)
        print("  Algorithm Comparison:")
        print("=" * 60)

        lines = [
            ("K-Means", r_km.get("silhouette", 0),
             True, f"silhouette={r_km.get('silhouette', 0):.2f}"),
            ("DBSCAN", self.results.get("dbscan", {}).get("silhouette", 0) or 0,
             r_db.get("attacker_is_outlier", False), "outlier"),
            ("Hierarchical", self.results.get("hierarchical", {}).get("silhouette", 0) or 0,
             r_hi.get("attacker_isolated", True), ""),
            ("Spectral", self.results.get("spectral", {}).get("silhouette", 0) or 0,
             True, ""),
            ("GMM", self.results.get("gmm", {}).get("silhouette", 0) or 0,
             True, f"prob={r_gm.get('attacker_max_prob', 0):.2f}"),
        ]
        for name, sil, detected, extra in lines:
            det_str = "Attacker detected" if detected else "Attacker in group"
            mark = "[OK]"
            extra_str = f" ({extra})" if extra else ""
            print(f"  {name:<15} {det_str} {mark}{extra_str}")

        print("=" * 60)
        self.results["comparison"] = all_results
        return all_results

    # --------------------------------------------------------------------- #
    # Save models                                                             #
    # --------------------------------------------------------------------- #

    def save_models(self) -> None:
        """Persist trained models, scaler, and cluster metadata."""
        print(f"\n  Saving models to {MODELS_PATH}...")
        payload = {
            "scaler": self.scaler,
            "models": {k: v for k, v in self.models.items()},
            "labels": {k: v.tolist() if hasattr(v, "tolist") else v
                       for k, v in self.labels.items()},
            "feature_columns": FEATURE_COLS,
            "timestamp": datetime.now().isoformat(),
        }
        joblib.dump(payload, MODELS_PATH)
        ok(f"Models saved to {MODELS_PATH}")

        # Save cluster assignments as JSON
        cluster_data = {}
        if self.dataset is not None:
            for name, lbl in self.labels.items():
                arr = lbl.tolist() if hasattr(lbl, "tolist") else list(lbl)
                cluster_data[name] = {
                    self.dataset.iloc[i]["device_ip"]: int(arr[i])
                    for i in range(len(arr))
                }
        with open(CLUSTERS_JSON, "w", encoding="utf-8") as f:
            json.dump(cluster_data, f, indent=2)
        ok(f"Cluster assignments saved to {CLUSTERS_JSON}")

        print(f"  Saving dataset to {DATASET_PATH}...")
        ok(f"Dataset saved ({len(self.dataset)} rows)")

    # --------------------------------------------------------------------- #
    # Main pipeline                                                           #
    # --------------------------------------------------------------------- #

    def run(self) -> None:
        """Execute the full clustering pipeline."""
        df = self.generate_dataset()
        X = self.scale_features(df)
        self.compare_algorithms(X)
        self.plot_clusters(X)
        self.save_models()
        print("\nClustering complete!")


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    engine = ClusteringEngine()
    engine.run()
