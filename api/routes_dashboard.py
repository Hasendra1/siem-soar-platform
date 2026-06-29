"""
Dashboard API Routes
=====================
GET /api/dashboard/summary           - Stats overview
GET /api/dashboard/timeline          - Event counts by time window
GET /api/dashboard/topology          - Network topology
GET /api/dashboard/isolations        - Isolated devices
GET /api/dashboard/rules-triggered   - Detection rules that fired
GET /api/dashboard/anomalies-detailed- Detailed anomaly list
GET /api/dashboard/clusters          - Cluster analysis
"""

import sqlite3
from pathlib import Path
from flask import Blueprint, jsonify, request

dashboard_bp = Blueprint("dashboard", __name__)
DB = Path(__file__).resolve().parent.parent / "dataset" / "siem_database.db"


def get_db():
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    return conn


@dashboard_bp.route("/summary")
def summary():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    normal = conn.execute("SELECT COUNT(*) FROM events WHERE action='NORMAL'").fetchone()[0]
    attacks = total - normal
    anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    isolations = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM isolations WHERE success=1").fetchone()[0]
    incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    # Threat level: 0-100 based on recent anomaly density
    recent = conn.execute(
        "SELECT COUNT(*) FROM events WHERE action != 'NORMAL' "
        "AND timestamp > datetime('now', '-300 seconds')").fetchone()[0]
    threat_level = min(100, int(recent * 1.5))

    # Active attacker
    attacker = conn.execute(
        "SELECT src_ip, COUNT(*) as cnt FROM events "
        "WHERE action != 'NORMAL' GROUP BY src_ip ORDER BY cnt DESC LIMIT 1"
    ).fetchone()
    attacker_ip = attacker["src_ip"] if attacker else None

    conn.close()
    return jsonify({
        "total_events": total,
        "normal_events": normal,
        "attack_events": attacks,
        "anomalies": anomalies,
        "isolations": isolations,
        "incidents": incidents,
        "threat_level": threat_level,
        "attacker_ip": attacker_ip,
        "threat_source_label": "Threat Source Identified",
    })


@dashboard_bp.route("/timeline")
def timeline():
    conn = get_db()
    rows = conn.execute("""
        SELECT
            strftime('%H:%M:%S', timestamp) as ts,
            SUM(CASE WHEN action = 'NORMAL' THEN 1 ELSE 0 END) as normal,
            SUM(CASE WHEN action != 'NORMAL' THEN 1 ELSE 0 END) as attack
        FROM events GROUP BY ts ORDER BY ts DESC LIMIT 30
    """).fetchall()
    conn.close()
    data = [{"time": r["ts"], "normal": r["normal"], "attack": r["attack"]}
            for r in reversed(rows)]
    return jsonify(data)


@dashboard_bp.route("/topology")
def topology():
    devices = [
        {"id": "PLC1", "ip": "192.168.10.10", "zone": "OT", "type": "plc",
         "x": 150, "y": 120, "status": "online"},
        {"id": "PLC2", "ip": "192.168.10.11", "zone": "OT", "type": "plc",
         "x": 150, "y": 220, "status": "online"},
        {"id": "HMI", "ip": "192.168.10.20", "zone": "OT", "type": "hmi",
         "x": 300, "y": 170, "status": "online"},
        {"id": "MQTT", "ip": "192.168.20.100", "zone": "IoT", "type": "broker",
         "x": 500, "y": 100, "status": "online"},
        {"id": "Sensor-T", "ip": "192.168.20.10", "zone": "IoT", "type": "sensor",
         "x": 650, "y": 70, "status": "online"},
        {"id": "Sensor-P", "ip": "192.168.20.11", "zone": "IoT", "type": "sensor",
         "x": 650, "y": 150, "status": "online"},
        {"id": "CCTV", "ip": "192.168.30.10", "zone": "DMZ", "type": "camera",
         "x": 500, "y": 280, "status": "online"},
        {"id": "Gateway", "ip": "192.168.30.100", "zone": "DMZ", "type": "gateway",
         "x": 650, "y": 280, "status": "online"},
        {"id": "Eng-WS", "ip": "192.168.10.50", "zone": "OT", "type": "workstation",
         "x": 30, "y": 170, "status": "online"},
    ]
    links = [
        {"source": "PLC1", "target": "HMI", "type": "normal"},
        {"source": "PLC2", "target": "HMI", "type": "normal"},
        {"source": "Sensor-T", "target": "MQTT", "type": "normal"},
        {"source": "Sensor-P", "target": "MQTT", "type": "normal"},
        {"source": "CCTV", "target": "Gateway", "type": "normal"},
        {"source": "Eng-WS", "target": "PLC1", "type": "attack"},
        {"source": "Eng-WS", "target": "PLC2", "type": "attack"},
        {"source": "Eng-WS", "target": "CCTV", "type": "attack"},
    ]

    # Check isolation status
    conn = get_db()
    isolated = conn.execute(
        "SELECT DISTINCT ip_address FROM isolations WHERE success=1"
    ).fetchall()
    isolated_ips = {r["ip_address"] for r in isolated}
    conn.close()

    for d in devices:
        if d["ip"] in isolated_ips:
            d["status"] = "isolated"

    return jsonify({"devices": devices, "links": links})


@dashboard_bp.route("/isolations")
def isolations():
    conn = get_db()
    rows = conn.execute("""
        SELECT container_name, network_name, ip_address,
               isolation_reason, MAX(isolation_timestamp) as isolation_timestamp,
               automation_method, success
        FROM isolations WHERE success=1
        GROUP BY ip_address, network_name
        ORDER BY isolation_timestamp DESC LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@dashboard_bp.route("/rules-triggered")
def rules_triggered():
    """
    Derive triggered rules from the events table.
    Groups by action type and returns a rule-like structure.
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT
            action,
            COUNT(*) as triggered_count,
            GROUP_CONCAT(DISTINCT src_ip) as source_ips,
            GROUP_CONCAT(DISTINCT dst_ip) as destination_ips,
            MAX(timestamp) as last_triggered
        FROM events
        WHERE action != 'NORMAL'
        GROUP BY action
        ORDER BY triggered_count DESC
    """).fetchall()
    conn.close()

    RULE_MAP = {
        'PORT_SCAN':          {'rule_id': 9001, 'rule_name': 'Unauthorized Port Scan Detected',      'severity': 'HIGH'},
        'UNAUTHORIZED_READ':  {'rule_id': 9002, 'rule_name': 'Unauthorized Modbus Read',             'severity': 'HIGH'},
        'MALICIOUS_WRITE':    {'rule_id': 9003, 'rule_name': 'Malicious PLC Write Attempt',          'severity': 'CRITICAL'},
        'LATERAL_MOVEMENT':   {'rule_id': 9004, 'rule_name': 'Lateral Movement in OT Network',      'severity': 'CRITICAL'},
        'DATA_EXFIL':         {'rule_id': 9005, 'rule_name': 'Data Exfiltration Detected',          'severity': 'CRITICAL'},
    }

    result = []
    for r in rows:
        meta = RULE_MAP.get(r['action'], {
            'rule_id': 9999, 'rule_name': r['action'], 'severity': 'MEDIUM'
        })
        src_ips = [ip.strip() for ip in (r['source_ips'] or '').split(',') if ip.strip()]
        dst_ips = [ip.strip() for ip in (r['destination_ips'] or '').split(',') if ip.strip()]
        result.append({
            'rule_id':         meta['rule_id'],
            'rule_name':       meta['rule_name'],
            'triggered_count': r['triggered_count'],
            'last_triggered':  r['last_triggered'],
            'severity':        meta['severity'],
            'source_ips':      src_ips,
            'destination_ips': dst_ips,
            'affected_devices': src_ips + dst_ips,
            'details':         f"{r['triggered_count']} events: {', '.join(src_ips[:2])} → {', '.join(dst_ips[:3])}",
        })

    return jsonify({'rules_triggered': result})


@dashboard_bp.route("/anomalies-detailed")
def anomalies_detailed():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM anomalies ORDER BY anomaly_id DESC LIMIT 100"
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        score = float(d.get('anomaly_score', 0) or 0)
        severity = 'CRITICAL' if score > 0.9 else 'HIGH' if score > 0.7 else 'MEDIUM' if score > 0.4 else 'LOW'
        result.append({
            'anomaly_id':       d.get('anomaly_id'),
            'timestamp':        d.get('timestamp'),
            'src_ip':           d.get('src_ip'),
            'anomaly_type':     d.get('anomaly_type', 'UNKNOWN'),
            'anomaly_score':    score,
            'confidence':       float(d.get('confidence', score * 0.95) or 0),
            'detection_method': d.get('detection_method', 'ensemble_voting'),
            'severity':         severity,
            'status':           d.get('status', 'DETECTED'),
            'details':          d.get('details', ''),
        })

    return jsonify({'anomalies': result})


@dashboard_bp.route("/clusters")
def clusters():
    conn = get_db()
    total = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
    attackers = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM events WHERE action != 'NORMAL'"
    ).fetchone()[0]
    normal = max(0, total - attackers) if total else 7
    actions = conn.execute(
        "SELECT action, COUNT(*) as cnt FROM events GROUP BY action ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return jsonify({
        'clusters': [
            {'label': 'Normal Devices', 'count': normal,           'color': '#00e676'},
            {'label': 'Threat Sources', 'count': max(1, attackers), 'color': '#ff1744'},
        ],
        'actions': [{'action': r['action'], 'count': r['cnt']} for r in actions],
    })
