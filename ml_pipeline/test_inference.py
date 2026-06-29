"""Quick verification test for the inference engine."""
import sys
sys.path.insert(0, r"C:\siem-soar-platform")

import numpy as np
from datetime import datetime
from ml_pipeline.inference_engine import MLInferenceEngine

engine = MLInferenceEngine()
ext = engine.extractor

# Simulate 50 attacker events
for i in range(50):
    ext.add_event({
        "src_ip": "192.168.10.50",
        "dst_ip": f"192.168.10.{i % 25}",
        "protocol": "TCP",
        "action": "PORT_SCAN",
        "packet_size": 40,
        "src_zone": "OT",
        "dst_zone": "OT",
        "dst_port": 1000 + i,
        "timestamp": datetime.now(),
    })

# Simulate 20 normal PLC events
for i in range(20):
    ext.add_event({
        "src_ip": "192.168.10.10",
        "dst_ip": "192.168.10.20",
        "protocol": "Modbus",
        "action": "NORMAL",
        "packet_size": 64,
        "src_zone": "OT",
        "dst_zone": "OT",
        "dst_port": 502,
        "timestamp": datetime.now(),
    })

atk = engine.infer("192.168.10.50")
plc = engine.infer("192.168.10.10")

print("=== ML INFERENCE RESULTS ===")
print(f"Attacker  ensemble={atk['ensemble_score']:.3f}  is_anomaly={atk['is_anomaly']}  latency={atk['inference_ms']}ms")
print(f"PLC1      ensemble={plc['ensemble_score']:.3f}  is_anomaly={plc['is_anomaly']}  latency={plc['inference_ms']}ms")
print()
print("Model breakdown (Attacker):")
for m, s in atk["model_scores"].items():
    print(f"  {m:20s}: {s:.3f}")
print()
print("Model breakdown (PLC1):")
for m, s in plc["model_scores"].items():
    print(f"  {m:20s}: {s:.3f}")

assert atk["ensemble_score"] > plc["ensemble_score"], "FAIL: Attacker should score higher"
assert atk["inference_ms"] < 100, "FAIL: Too slow"
print()
print("All assertions passed")
