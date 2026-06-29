"""
System Control API Routes
==========================
POST /api/system/reset       — Clear all dynamic data (isolations, anomalies, events)
GET  /api/system/status      — Current system state (monitoring on/off, counts)
POST /api/system/monitor/start — Start ML real-time inference monitor
POST /api/system/monitor/stop  — Stop ML monitor
"""

import sqlite3
import threading
import time
from pathlib import Path
from flask import Blueprint, jsonify, request

system_bp = Blueprint("system", __name__)
DB = Path(__file__).resolve().parent.parent / "dataset" / "siem_database.db"


def get_db():
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    return conn


# ── Global ML Monitor state ──────────────────────────────────
_monitor_thread = None
_monitor_running = False
_monitor_stats = {
    "inferences": 0,
    "isolations_made": 0,
    "last_event_id": 0,
    "avg_latency_ms": 0.0,
    "started_at": None,
}


def _run_ml_monitor(socketio):
    """
    Background thread: polls DB for new events → runs ML inference → isolates.
    This is the REAL-TIME bridge between events and ML models.
    """
    global _monitor_running, _monitor_stats

    try:
        from ml_pipeline.inference_engine import MLInferenceEngine
        from enforcement.smart_isolator import SmartIsolator, DEVICE_REGISTRY
    except ImportError as e:
        print(f"[ML MONITOR] Import error: {e}")
        _monitor_running = False
        return

    engine = MLInferenceEngine()
    isolator = SmartIsolator()
    poll_interval = 1.0  # 1 second

    # Start from the latest event_id already in DB
    conn = get_db()
    row = conn.execute("SELECT MAX(event_id) FROM events").fetchone()
    last_id = row[0] or 0
    conn.close()
    _monitor_stats["last_event_id"] = last_id

    print(f"[ML MONITOR] Started — watching for events after ID {last_id}")
    print(f"[ML MONITOR] Models: 2 (DBSCAN, IsoForest)")
    print(f"[ML MONITOR] Isolation threshold: 0.90")

    while _monitor_running:
        try:
            conn = sqlite3.connect(str(DB))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT event_id, src_ip, dst_ip, protocol,
                       action, payload_size, zone, timestamp
                FROM events
                WHERE event_id > ?
                ORDER BY event_id
                LIMIT 50
            """, (last_id,)).fetchall()
            conn.close()

            for row in rows:
                last_id = row["event_id"]
                _monitor_stats["last_event_id"] = last_id

                # Build event dict
                event = {
                    "src_ip":      row["src_ip"],
                    "dst_ip":      row["dst_ip"],
                    "protocol":    row["protocol"],
                    "action":      row["action"],
                    "packet_size": row["payload_size"] or 64,
                    "src_zone":    row["zone"] or "OT",
                    "dst_zone":    "OT",
                    "timestamp":   row["timestamp"],
                }

                # Run ML inference
                result = engine.process_event(event)
                if result is None:
                    continue

                _monitor_stats["inferences"] += 1
                _monitor_stats["avg_latency_ms"] = engine.avg_latency_ms()

                score = result["ensemble_score"]
                action = event["action"]
                src_ip = event["src_ip"]

                # Log significant detections
                if score > 0.3:
                    src_name = DEVICE_REGISTRY.get(src_ip, {}).get("name", src_ip)
                    print(
                        f"[ML] {src_name:15s} | action={action:20s} | "
                        f"score={score:.3f} | {result['inference_ms']:.1f}ms"
                    )

                    # Push ML score to frontend via WebSocket
                    if socketio:
                        socketio.emit("ml_score", {
                            "device_ip":      src_ip,
                            "device_name":    src_name,
                            "action":         action,
                            "ensemble_score": score,
                            "model_scores":   result["model_scores"],
                            "is_anomaly":     result["is_anomaly"],
                            "timestamp":      result["timestamp"],
                        })

                # If ML says ISOLATE → trigger smart_isolator
                if result["is_anomaly"]:
                    prev_isolated = set(isolator.isolated_devices)

                    isolator.process_ml_result(
                        src_ip=src_ip,
                        dst_ip=event["dst_ip"],
                        action=action,
                        ensemble_score=score,
                        model_scores=result["model_scores"],
                    )

                    # Check if new devices were isolated
                    new_isolated = isolator.isolated_devices - prev_isolated
                    for ip in new_isolated:
                        dev = DEVICE_REGISTRY.get(ip, {})
                        state = isolator.device_states.get(ip)
                        state_str = state.value if state else "UNKNOWN"

                        # Save isolation to DB
                        _save_isolation(ip, dev, state_str, score)
                        _monitor_stats["isolations_made"] += 1

                        print(f"[ISOLATION] 🔒 {dev.get('name','?')} ({ip}) → {state_str}")

                        # Push real-time isolation event to frontend
                        if socketio:
                            socketio.emit("new_isolation", {
                                "device_ip":     ip,
                                "device_name":   dev.get("name", "Unknown"),
                                "device_type":   dev.get("type", "Unknown"),
                                "zone":          dev.get("zone", "Unknown"),
                                "state":         state_str,
                                "ensemble_score": score,
                                "reason":        "ML_ENSEMBLE_DETECTION",
                                "timestamp":     result["timestamp"],
                            })

                    # Save ML anomaly to DB
                    _save_anomaly(src_ip, action, result)

                    # Push anomaly event to frontend
                    if socketio:
                        socketio.emit("anomaly_detected", {
                            "src_ip":           src_ip,
                            "anomaly_type":     action,
                            "anomaly_score":    score,
                            "detection_method": "2_model_ensemble",
                            "status":           "DETECTED",
                            "timestamp":        result["timestamp"],
                        })

        except Exception as e:
            print(f"[ML MONITOR] Error: {e}")

        time.sleep(poll_interval)

    print("[ML MONITOR] Stopped")


def _save_isolation(ip, dev, state, score):
    """Persist a new isolation record to the database."""
    try:
        conn = sqlite3.connect(str(DB))
        reason = "ATTACKER_IDENTIFIED" if state == "THREAT_SOURCE" else "COMPROMISED_DEVICE"
        container = dev.get("name", "Unknown")
        network = f"siem-soar-platform_{'ot' if dev.get('zone')=='OT' else 'iot' if dev.get('zone')=='IoT' else 'dmz'}-network"
        conn.execute("""
            INSERT INTO isolations
            (container_name, network_name, ip_address, isolation_reason,
             isolation_timestamp, success, automation_method)
            VALUES (?, ?, ?, ?, datetime('now'), 1, ?)
        """, (container, network, ip, reason, "ml_ensemble"))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Isolation save error: {e}")


def _save_anomaly(src_ip, action, result):
    """Persist anomaly detection to the database."""
    try:
        conn = sqlite3.connect(str(DB))
        conn.execute("""
            INSERT INTO anomalies
            (src_ip, anomaly_type, anomaly_score, confidence,
             detection_method, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            src_ip, action, result["ensemble_score"],
            result["ensemble_score"], "2_model_ensemble",
            "DETECTED", result["timestamp"],
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Anomaly save error: {e}")


# ── API Endpoints ─────────────────────────────────────────────

@system_bp.route("/reset", methods=["POST"])
def reset_system():
    """
    Clear all dynamic data — start fresh.
    Keeps the DB schema intact but removes:
      - All isolation records
      - All anomaly records
      - All events
      - All incidents
    After reset, dashboard shows 0 everywhere.
    """
    conn = get_db()
    try:
        conn.execute("DELETE FROM isolations")
        conn.execute("DELETE FROM anomalies")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.commit()

        # Reset sequences
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events','anomalies','isolations','incidents')")
        conn.commit()
        conn.close()

        # Reset monitor stats
        _monitor_stats["inferences"] = 0
        _monitor_stats["isolations_made"] = 0
        _monitor_stats["last_event_id"] = 0

        print("[SYSTEM] Database reset — all dynamic data cleared")
        return jsonify({
            "status": "ok",
            "message": "System reset complete. All events, isolations, and anomalies cleared.",
        })
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": str(e)}), 500


@system_bp.route("/status")
def system_status():
    """Return current system state."""
    conn = get_db()
    events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    isolations = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM isolations WHERE success=1").fetchone()[0]
    anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    conn.close()

    return jsonify({
        "monitoring":       _monitor_running,
        "events_total":     events,
        "isolations_total": isolations,
        "anomalies_total":  anomalies,
        "ml_inferences":    _monitor_stats["inferences"],
        "ml_isolations":    _monitor_stats["isolations_made"],
        "ml_last_event_id": _monitor_stats["last_event_id"],
        "ml_avg_latency":   _monitor_stats["avg_latency_ms"],
        "started_at":       _monitor_stats["started_at"],
    })


@system_bp.route("/monitor/start", methods=["POST"])
def start_monitor():
    """Start the ML real-time inference monitor."""
    global _monitor_thread, _monitor_running

    if _monitor_running:
        return jsonify({"status": "already_running", "message": "ML monitor is already active"})

    # Get socketio from the app
    from app import get_socketio
    sio = get_socketio()

    _monitor_running = True
    import datetime
    _monitor_stats["started_at"] = datetime.datetime.now().isoformat()
    _monitor_thread = threading.Thread(target=_run_ml_monitor, args=(sio,), daemon=True)
    _monitor_thread.start()

    return jsonify({"status": "started", "message": "ML inference monitor started"})


@system_bp.route("/monitor/stop", methods=["POST"])
def stop_monitor():
    """Stop the ML monitor."""
    global _monitor_running
    _monitor_running = False
    return jsonify({"status": "stopped", "message": "ML monitor stopped"})
