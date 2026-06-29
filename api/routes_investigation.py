"""
Investigation / Incidents blueprint
Uses the REAL schema from siem_database.db:
  incidents  : incident_id, incident_name, severity, status, description,
               related_anomaly_ids, related_device_ips, created_timestamp,
               updated_timestamp, assigned_to, resolution_notes
  anomalies  : anomaly_id, event_id, src_ip, anomaly_type, anomaly_score,
               confidence, detection_method, detection_timestamp, status, created_at
  isolations : isolation_id, container_name, network_name, ip_address,
               isolation_reason, isolation_timestamp, success, automation_method
  events     : event_id, timestamp, src_ip, dst_ip, protocol, action,
               severity, zone, ...
"""
import sqlite3, json
from pathlib import Path
from flask import Blueprint, jsonify, request

investigation_bp = Blueprint("investigation", __name__)
DB = Path(__file__).resolve().parent.parent / "dataset" / "siem_database.db"


def get_db():
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    return conn


# ── helpers ────────────────────────────────────────────────────
def safe_list(val):
    """Always return a Python list — never crash on int / None / str."""
    if val is None or val == "":
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, (int, float)):
        return [int(val)]
    try:
        parsed = json.loads(val)
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return []


def row_to_dict(row):
    d = dict(row)
    for k in ("related_anomaly_ids", "related_device_ips"):
        d[k] = safe_list(d.get(k))
    return d


def ensure_incidents_table(conn):
    """Create incidents table only if it does not exist at all."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_name       TEXT    NOT NULL,
            severity            TEXT    DEFAULT 'MEDIUM',
            status              TEXT    DEFAULT 'OPEN',
            description         TEXT,
            related_anomaly_ids TEXT    DEFAULT '[]',
            related_device_ips  TEXT    DEFAULT '[]',
            created_timestamp   TEXT    DEFAULT (datetime('now','localtime')),
            updated_timestamp   TEXT    DEFAULT (datetime('now','localtime')),
            assigned_to         TEXT    DEFAULT 'Security Team',
            resolution_notes    TEXT    DEFAULT ''
        )
    """)
    conn.commit()


def seed_if_empty(conn):
    """Insert one real incident from live DB data if table is empty."""
    try:
        count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if count > 0:
            return

        # Best attacker IP
        row = conn.execute(
            "SELECT src_ip FROM events WHERE action!='NORMAL' "
            "GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        attacker_ip = row[0] if row else "192.168.10.50"

        # Unique IPs in isolations
        iso_rows = conn.execute(
            "SELECT DISTINCT ip_address FROM isolations LIMIT 4"
        ).fetchall()
        device_ips = [attacker_ip] + [r["ip_address"] for r in iso_rows
                                       if r["ip_address"] != attacker_ip]
        device_ips = list(dict.fromkeys(device_ips))[:5]

        # Anomaly IDs
        anom_rows = conn.execute(
            "SELECT anomaly_id FROM anomalies LIMIT 5"
        ).fetchall()
        anom_ids = [r["anomaly_id"] for r in anom_rows]

        conn.execute("""
            INSERT INTO incidents
              (incident_name, severity, status, description, assigned_to,
               related_anomaly_ids, related_device_ips,
               created_timestamp, updated_timestamp)
            VALUES (?,?,?,?,?,?,?,
               datetime('now','localtime'), datetime('now','localtime'))
        """, (
            "Industrial Control System Compromise",
            "CRITICAL", "CONTAINED",
            f"Attacker {attacker_ip} identified performing port scan, "
            "unauthorized Modbus read/write, and lateral movement across the OT network. "
            "Automated isolation triggered by the ML segmentation engine.",
            "Security Team",
            json.dumps(anom_ids),
            json.dumps(device_ips),
        ))
        conn.commit()
    except Exception as exc:
        print(f"[investigation] seed error: {exc}")


# ── GET /incidents ──────────────────────────────────────────────
@investigation_bp.route("/incidents", methods=["GET"])
def list_incidents():
    try:
        conn = get_db()
        ensure_incidents_table(conn)
        seed_if_empty(conn)
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_timestamp DESC"
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = row_to_dict(r)
            d["evidence_count"] = len(d["related_anomaly_ids"])
            result.append(d)
        return jsonify({"incidents": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── GET /incidents/<id> ─────────────────────────────────────────
@investigation_bp.route("/incidents/<int:incident_id>", methods=["GET"])
def get_incident(incident_id):
    try:
        conn = get_db()
        ensure_incidents_table(conn)
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not found"}), 404

        inc = row_to_dict(row)
        inc["evidence_count"] = len(inc["related_anomaly_ids"])

        device_ips = inc["related_device_ips"]   # already a list via safe_list
        anom_ids   = inc["related_anomaly_ids"]   # already a list via safe_list

        # ── Timeline: events ──────────────────────────────────
        related_events = []
        if device_ips:
            ph = ",".join("?" * len(device_ips))
            evts = conn.execute(
                f"SELECT timestamp, action AS event_type, src_ip, dst_ip, protocol "
                f"FROM events WHERE src_ip IN ({ph}) "
                f"ORDER BY timestamp ASC LIMIT 50",
                device_ips,
            ).fetchall()
            for e in evts:
                related_events.append({
                    "timestamp":  e["timestamp"],
                    "event_type": e["event_type"],
                    "src_ip":     e["src_ip"],
                    "details":    f"{e['protocol']} {e['event_type']} → {e['dst_ip']}",
                })

        # ── Timeline: isolations ──────────────────────────────
        if device_ips:
            ph = ",".join("?" * len(device_ips))
            isos = conn.execute(
                f"SELECT isolation_timestamp, ip_address, isolation_reason "
                f"FROM isolations WHERE ip_address IN ({ph}) LIMIT 10",
                device_ips,
            ).fetchall()
            for iso in isos:
                related_events.append({
                    "timestamp":  iso["isolation_timestamp"],
                    "event_type": "ISOLATION",
                    "src_ip":     iso["ip_address"],
                    "details":    f"Device {iso['ip_address']} isolated — {iso['isolation_reason']}",
                })

        related_events.sort(key=lambda x: x.get("timestamp") or "")

        # ── Evidence: anomalies ───────────────────────────────
        evidence = []
        if anom_ids:
            ph = ",".join("?" * len(anom_ids))
            anoms = conn.execute(
                f"SELECT anomaly_id, detection_timestamp AS timestamp, anomaly_type, "
                f"anomaly_score, confidence FROM anomalies WHERE anomaly_id IN ({ph})",
                anom_ids,
            ).fetchall()
            for a in anoms:
                score = a["anomaly_score"] or 0.0
                sev   = "CRITICAL" if score > 0.9 else "HIGH" if score > 0.7 else "MEDIUM"
                evidence.append({
                    "evidence_id": a["anomaly_id"],
                    "type":        "ml_anomaly",
                    "description": f"{a['anomaly_type']} detected (score {score:.2f})",
                    "timestamp":   a["timestamp"],
                    "severity":    sev,
                })

        conn.close()
        inc["related_events"] = related_events
        inc["evidence"]       = evidence
        return jsonify({"incident": inc})

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── POST /incidents ─────────────────────────────────────────────
@investigation_bp.route("/incidents", methods=["POST"])
def create_incident():
    try:
        body = request.get_json() or {}
        if not body.get("incident_name"):
            return jsonify({"error": "incident_name is required"}), 400

        conn = get_db()
        ensure_incidents_table(conn)
        cur = conn.execute("""
            INSERT INTO incidents
              (incident_name, severity, status, description, assigned_to,
               related_anomaly_ids, related_device_ips,
               created_timestamp, updated_timestamp)
            VALUES (?,?,?,?,?, '[]','[]',
               datetime('now','localtime'), datetime('now','localtime'))
        """, (
            body["incident_name"],
            body.get("severity", "MEDIUM"),
            body.get("status",   "OPEN"),
            body.get("description", ""),
            body.get("assigned_to", "Security Team"),
        ))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (cur.lastrowid,)
        ).fetchone()
        conn.close()
        d = row_to_dict(row)
        d["evidence_count"] = 0
        return jsonify({"incident": d}), 201

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── PUT /incidents/<id> ─────────────────────────────────────────
@investigation_bp.route("/incidents/<int:incident_id>", methods=["PUT"])
def update_incident(incident_id):
    try:
        body = request.get_json() or {}
        allowed = {"status", "severity", "description", "assigned_to", "resolution_notes"}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "No valid fields to update"}), 400

        conn = get_db()
        ensure_incidents_table(conn)
        set_clause = ", ".join(f"{k}=?" for k in updates)
        conn.execute(
            f"UPDATE incidents SET {set_clause}, "
            f"updated_timestamp=datetime('now','localtime') "
            f"WHERE incident_id=?",
            list(updates.values()) + [incident_id],
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Not found"}), 404
        d = row_to_dict(row)
        d["evidence_count"] = len(d["related_anomaly_ids"])
        return jsonify({"incident": d})

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── DELETE /incidents/<id> ──────────────────────────────────────
@investigation_bp.route("/incidents/<int:incident_id>", methods=["DELETE"])
def delete_incident(incident_id):
    try:
        conn = get_db()
        ensure_incidents_table(conn)
        conn.execute("DELETE FROM incidents WHERE incident_id=?", (incident_id,))
        conn.commit()
        conn.close()
        return jsonify({"deleted": incident_id})

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
