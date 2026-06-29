"""Verification test for SmartIsolator — 3 scenario tests."""
import sys
sys.path.insert(0, r"C:\siem-soar-platform")

from enforcement.smart_isolator import SmartIsolator, DeviceState, ISOLATION_THRESHOLD

iso = SmartIsolator()

# Test 1: Port scan — destination must NOT be isolated
print("--- Test 1: Port Scan ---")
iso.process_ml_result(
    src_ip="192.168.10.50",
    dst_ip="192.168.10.10",
    action="PORT_SCAN",
    ensemble_score=0.95,
    model_scores={"isolation_forest": 0.96, "lof": 0.92, "kmeans": 0.91, "dbscan": 1.0, "gmm": 0.80},
)
assert "192.168.10.10" not in iso.isolated_devices, "FAIL: PLC1 should NOT be isolated"
assert iso.device_states.get("192.168.10.10") == DeviceState.SCANNED, "FAIL: PLC1 should be SCANNED"
print("  Test 1 PASS: Scan target NOT isolated, marked SCANNED")

# Test 2: Malicious write — both source and destination isolated
print("\n--- Test 2: Malicious Write ---")
iso.process_ml_result(
    src_ip="192.168.10.50",
    dst_ip="192.168.10.11",
    action="MALICIOUS_WRITE",
    ensemble_score=0.97,
    model_scores={"isolation_forest": 0.98, "lof": 0.95, "kmeans": 0.96, "dbscan": 1.0, "gmm": 0.85},
)
assert "192.168.10.50" in iso.isolated_devices, "FAIL: Attacker not isolated"
assert "192.168.10.11" in iso.isolated_devices, "FAIL: PLC2 not isolated"
assert iso.device_states["192.168.10.50"] == DeviceState.ATTACKER, "FAIL: Attacker state wrong"
assert iso.device_states["192.168.10.11"] == DeviceState.COMPROMISED, "FAIL: PLC2 state wrong"
print("  Test 2 PASS: Attacker ISOLATED, PLC2 COMPROMISED and ISOLATED")

# Test 3: Compromised device attacking — propagation
print("\n--- Test 3: Lateral Movement (Propagation) ---")
iso.device_states["192.168.10.11"] = DeviceState.COMPROMISED
iso.process_ml_result(
    src_ip="192.168.10.11",
    dst_ip="192.168.10.20",
    action="LATERAL_MOVEMENT",
    ensemble_score=0.91,
    model_scores={"isolation_forest": 0.90, "lof": 0.89, "kmeans": 0.88, "dbscan": 0.95, "gmm": 0.76},
)
assert iso.device_states["192.168.10.11"] == DeviceState.PROPAGATED, "FAIL: PLC2 should be PROPAGATED"
print("  Test 3 PASS: Compromised device propagation detected")

print("\n  ALL TESTS PASSED")
iso.get_status_report()
