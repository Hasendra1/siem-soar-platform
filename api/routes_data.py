"""
Data API Routes
================
GET /api/data/events     - Recent events
GET /api/data/anomalies  - Detected anomalies
GET /api/data/incidents  - Incidents
GET /api/data/clusters   - Cluster analysis
"""

import json
import sqlite3
from pathlib import Path
from flask import Blueprint, jsonify, request

data_bp = Blueprint("data", __name__)
DB = Path(__file__).resolve().parent.parent / "dataset" / "siem_database.db"
SCORES_JSON = Path(__file__).resolve().parent.parent / "results" / "device_scores.json"


def get_db():
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    return conn


@data_bp.route("/events")
def events():
    limit = request.args.get("limit", 50, type=int)
    action = request.args.get("action", None)
    conn = get_db()
    if action:
        rows = conn.execute(
            "SELECT * FROM events WHERE action=? ORDER BY event_id DESC LIMIT ?",
            (action, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY event_id DESC LIMIT ?",
            (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@data_bp.route("/anomalies")
def anomalies():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM anomalies ORDER BY anomaly_id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@data_bp.route("/incidents")
def incidents():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY incident_id DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@data_bp.route("/clusters")
def clusters():
    conn = get_db()
    total = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
    attackers = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM events WHERE action != 'NORMAL'"
    ).fetchone()[0]
    normal = max(0, total - attackers) if total else 7

    # Action breakdown
    actions = conn.execute(
        "SELECT action, COUNT(*) as cnt FROM events "
        "GROUP BY action ORDER BY cnt DESC").fetchall()
    conn.close()

    return jsonify({
        "clusters": [
            {"label": "Normal Devices", "count": normal, "color": "#00e676"},
            {"label": "Attackers", "count": max(1, attackers), "color": "#ff1744"},
        ],
        "actions": [{"action": r["action"], "count": r["cnt"]} for r in actions],
    })


@data_bp.route("/events/query", methods=["POST"])
def query_events():
    """Advanced threat hunting query endpoint."""
    body = request.get_json() or {}
    f = body.get("filters", {})
    limit = body.get("limit", 1000)

    conditions, params = [], []

    if f.get("src_ip"):
        conditions.append("src_ip LIKE ?")
        params.append(f"%{f['src_ip']}%")
    if f.get("dst_ip"):
        conditions.append("dst_ip LIKE ?")
        params.append(f"%{f['dst_ip']}%")
    if f.get("protocol") and f["protocol"] != "all":
        conditions.append("protocol = ?")
        params.append(f["protocol"])
    if f.get("action") and f["action"] != "all":
        conditions.append("action = ?")
        params.append(f["action"])
    if f.get("severity") and isinstance(f["severity"], list) and f["severity"]:
        ph = ",".join("?" * len(f["severity"]))
        conditions.append(f"severity IN ({ph})")
        params.extend(f["severity"])
    if f.get("zone") and isinstance(f["zone"], list) and f["zone"]:
        ph = ",".join("?" * len(f["zone"]))
        conditions.append(f"zone IN ({ph})")
        params.extend(f["zone"])
    if f.get("timeStart"):
        conditions.append("timestamp >= ?")
        params.append(f["timeStart"].replace("T", " "))
    if f.get("timeEnd"):
        conditions.append("timestamp <= ?")
        params.append(f["timeEnd"].replace("T", " "))

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM events {where} ORDER BY event_id DESC LIMIT ?"
    params.append(limit)

    conn = get_db()
    try:
        rows = conn.execute(sql, params).fetchall()
        results = [dict(r) for r in rows]
        conn.close()
        return jsonify({"results": results, "total_results": len(results)})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "results": []}), 500


# ── ML Endpoints ──────────────────────────────────────────────

DEVICE_REGISTRY = {
    "192.168.10.10":  {"name": "PLC1",         "type": "PLC",      "zone": "OT"},
    "192.168.10.11":  {"name": "PLC2",         "type": "PLC",      "zone": "OT"},
    "192.168.10.20":  {"name": "HMI",          "type": "HMI",      "zone": "OT"},
    "192.168.10.50":  {"name": "Engineering-WS",  "type": "WORKSTATION", "zone": "OT"},
    "192.168.20.10":  {"name": "Sensor-Temp",  "type": "SENSOR",   "zone": "IoT"},
    "192.168.20.11":  {"name": "Sensor-Press", "type": "SENSOR",   "zone": "IoT"},
    "192.168.20.100": {"name": "MQTT-Broker",  "type": "BROKER",   "zone": "IoT"},
    "192.168.30.10":  {"name": "CCTV-Camera",  "type": "CAMERA",   "zone": "DMZ"},
    "192.168.30.100": {"name": "Cloud-Gateway","type": "GATEWAY",  "zone": "DMZ"},
}


@data_bp.route("/ml/device-states")
def ml_device_states():
    """Return all device states with isolation info and ML scores."""
    # Load ML scores if available
    ml_scores = {}
    if SCORES_JSON.exists():
        try:
            with open(SCORES_JSON) as f:
                for entry in json.load(f):
                    ml_scores[entry["device_ip"]] = entry
        except Exception:
            pass

    # Load isolation records from DB
    iso_map = {}
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT ip_address, isolation_reason, isolation_timestamp,
                      container_name, automation_method, success
               FROM isolations ORDER BY isolation_id DESC"""
        ).fetchall()
        for r in rows:
            ip = r["ip_address"]
            if ip not in iso_map:  # keep most recent
                iso_map[ip] = dict(r)
    except Exception:
        pass
    finally:
        conn.close()

    # Build device list
    devices = []
    for ip, info in DEVICE_REGISTRY.items():
        iso = iso_map.get(ip, {})
        sc = ml_scores.get(ip, {})

        # Determine state from isolation_reason
        reason = iso.get("isolation_reason", "")
        if reason == "ATTACKER_IDENTIFIED":
            state = "THREAT_SOURCE"
        elif reason == "COMPROMISED_DEVICE":
            state = "COMPROMISED"
        else:
            state = "NORMAL"

        # Check if the device was a port scan target (high risk → COMPROMISED)
        if state == "NORMAL" and sc.get("ensemble_score", 0) > 0 and sc.get("ensemble_score", 0) < 0.7:
            try:
                conn2 = get_db()
                scan_count = conn2.execute(
                    "SELECT COUNT(*) FROM events WHERE dst_ip=? AND action='PORT_SCAN'",
                    (ip,)
                ).fetchone()[0]
                conn2.close()
                if scan_count > 0:
                    state = "COMPROMISED"
            except Exception:
                pass

        devices.append({
            "device_ip":           ip,
            "device_name":         info["name"],
            "device_type":         info["type"],
            "zone":                info["zone"],
            "state":               state,
            "isolation_reason":    iso.get("isolation_reason"),
            "isolation_timestamp": iso.get("isolation_timestamp"),
            "ensemble_score":      sc.get("ensemble_score", 0.0),
            "confidence":          sc.get("confidence", 0.0),
            "is_attacker":         sc.get("is_attacker", False),
        })

    # Sort by ensemble_score descending
    devices.sort(key=lambda d: d["ensemble_score"], reverse=True)
    return jsonify({"devices": devices})


@data_bp.route("/ml/scores")
def ml_scores():
    """Return raw ML model scores from training pipeline."""
    if SCORES_JSON.exists():
        try:
            with open(SCORES_JSON) as f:
                scores = json.load(f)
            return jsonify({"scores": scores})
        except Exception as e:
            return jsonify({"scores": [], "error": str(e)})
    return jsonify({"scores": [], "error": "Run ML training first"})
