#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Database Initialization
=============================================
Creates and validates the persistent SQLite database schema for
all security event data, device profiles, anomaly records,
clustering results, incident tracking, and investigation logs.

Database: C:\\siem-soar-platform\\dataset\\siem_database.db

Tables:
    1. events              - Raw security events
    2. devices             - Device inventory and risk scores
    3. anomalies           - Detected anomalies
    4. clusters            - ML clustering results
    5. incidents           - Security incidents
    6. isolations          - Network isolation actions
    7. investigations      - Investigation records
    8. behavior_profiles   - Device behavioral baselines
"""

import os
import sys
import sqlite3
import json
from pathlib import Path
from datetime import datetime


# --- Configuration -----------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "dataset"
DATABASE_PATH = DATABASE_DIR / "siem_database.db"

EXPECTED_TABLES = [
    "events",
    "devices",
    "anomalies",
    "clusters",
    "incidents",
    "isolations",
    "investigations",
    "behavior_profiles",
]


# --- Utility helpers ---------------------------------------------------------

def log(message: str, level: str = "INFO") -> None:
    """Print a timestamped log message to the console."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  [{level}] {ts}  {message}")


def ok(message: str) -> None:
    """Print a success status line (ASCII-safe for Windows console)."""
    try:
        print(f"  \u2713 {message}")
    except UnicodeEncodeError:
        print(f"  [OK] {message}")


def fail(message: str) -> None:
    """Print a failure status line (ASCII-safe for Windows console)."""
    try:
        print(f"  \u2717 {message}")
    except UnicodeEncodeError:
        print(f"  [FAIL] {message}")


# --- Table DDL ---------------------------------------------------------------

TABLE_SCHEMAS = {
    "events": """
        CREATE TABLE IF NOT EXISTS events (
            event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            dst_ip          TEXT    NOT NULL,
            src_port        INTEGER,
            dst_port        INTEGER,
            protocol        TEXT    CHECK (protocol IN ('TCP','UDP','MQTT','Modbus','HTTP','ICMP')),
            action          TEXT    CHECK (action IN ('NORMAL','PORT_SCAN','UNAUTHORIZED_READ',
                                         'MALICIOUS_WRITE','LATERAL_MOVEMENT','DATA_EXFIL','ANOMALY')),
            severity        TEXT    CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            payload_size    INTEGER,
            zone            TEXT    CHECK (zone IN ('OT','IoT','DMZ','EXTERNAL')),
            device_ip       TEXT,
            packet_count    INTEGER DEFAULT 1,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,

    "devices": """
        CREATE TABLE IF NOT EXISTS devices (
            device_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address          TEXT    UNIQUE NOT NULL,
            hostname            TEXT,
            device_type         TEXT    CHECK (device_type IN ('PLC','SENSOR','MQTT_BROKER',
                                              'CAMERA','GATEWAY','ATTACKER','UNKNOWN')),
            zone                TEXT    CHECK (zone IN ('OT','IoT','DMZ')),
            first_seen          TIMESTAMP,
            last_seen           TIMESTAMP,
            is_active           BOOLEAN DEFAULT 1,
            risk_score          REAL    CHECK (risk_score >= 0 AND risk_score <= 100),
            total_anomalies     INTEGER DEFAULT 0,
            behavioral_profile  TEXT,
            cluster_assignment  INTEGER,
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """,

    "anomalies": """
        CREATE TABLE IF NOT EXISTS anomalies (
            anomaly_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id            INTEGER,
            src_ip              TEXT    NOT NULL,
            anomaly_type        TEXT    CHECK (anomaly_type IN ('PORT_SCAN','UNAUTHORIZED_READ',
                                              'MALICIOUS_WRITE','LATERAL_MOVEMENT','DATA_EXFIL',
                                              'BEHAVIORAL_DEVIATION')),
            anomaly_score       REAL    CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
            confidence          REAL    CHECK (confidence >= 0 AND confidence <= 1),
            detection_method    TEXT    CHECK (detection_method IN ('isolation_forest','one_class_svm',
                                              'lof','kmeans','behavioral','ensemble')),
            detection_timestamp TIMESTAMP,
            status              TEXT    CHECK (status IN ('DETECTED','INVESTIGATING','CONTAINED','RESOLVED')),
            created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events (event_id)
                ON DELETE SET NULL ON UPDATE CASCADE
        );
    """,

    "clusters": """
        CREATE TABLE IF NOT EXISTS clusters (
            cluster_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            clustering_algorithm    TEXT    CHECK (clustering_algorithm IN ('kmeans','dbscan',
                                                  'hierarchical','spectral','gmm')),
            cluster_label           INTEGER,
            device_ips              TEXT,
            cluster_centroid        TEXT,
            silhouette_score        REAL,
            davies_bouldin_index    REAL,
            n_members               INTEGER,
            cluster_profile         TEXT,
            creation_timestamp      TIMESTAMP
        );
    """,

    "incidents": """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_name       TEXT    NOT NULL,
            severity            TEXT    CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            status              TEXT    CHECK (status IN ('OPEN','INVESTIGATING','CONTAINED','RESOLVED')),
            description         TEXT,
            related_anomaly_ids TEXT,
            related_device_ips  TEXT,
            created_timestamp   TIMESTAMP,
            updated_timestamp   TIMESTAMP,
            assigned_to         TEXT,
            resolution_notes    TEXT
        );
    """,

    "isolations": """
        CREATE TABLE IF NOT EXISTS isolations (
            isolation_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            container_name      TEXT,
            network_name        TEXT,
            ip_address          TEXT,
            isolation_reason    TEXT    CHECK (isolation_reason IN ('ATTACKER_IDENTIFIED',
                                              'COMPROMISED_DEVICE','MANUAL_CONTAINMENT')),
            isolation_timestamp TIMESTAMP,
            success             BOOLEAN,
            automation_method   TEXT    CHECK (automation_method IN ('docker_network','iptables',
                                              'policy','manual')),
            reversal_timestamp  TIMESTAMP,
            reversal_reason     TEXT
        );
    """,

    "investigations": """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            investigator_name   TEXT,
            related_incident_id INTEGER,
            start_timestamp     TIMESTAMP,
            end_timestamp       TIMESTAMP,
            findings            TEXT,
            evidence            TEXT,
            conclusion          TEXT,
            status              TEXT    CHECK (status IN ('OPEN','COMPLETE')),
            FOREIGN KEY (related_incident_id) REFERENCES incidents (incident_id)
                ON DELETE SET NULL ON UPDATE CASCADE
        );
    """,

    "behavior_profiles": """
        CREATE TABLE IF NOT EXISTS behavior_profiles (
            profile_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip               TEXT    UNIQUE,
            baseline_features       TEXT,
            communication_pattern   TEXT,
            temporal_pattern        TEXT,
            protocol_distribution   TEXT,
            packet_size_distribution TEXT,
            learned_timestamp       TIMESTAMP,
            last_update             TIMESTAMP,
            learning_confidence     REAL    CHECK (learning_confidence >= 0 AND learning_confidence <= 1)
        );
    """,
}


# --- Index definitions -------------------------------------------------------
# Each entry: (index_name, table_name, column_expression)

INDEX_DEFINITIONS = [
    # events indexes
    ("idx_events_timestamp",   "events",    "timestamp"),
    ("idx_events_src_ip",      "events",    "src_ip"),
    ("idx_events_dst_ip",      "events",    "dst_ip"),
    ("idx_events_severity",    "events",    "severity"),
    ("idx_events_action",      "events",    "action"),
    # devices indexes
    ("idx_devices_ip_address", "devices",   "ip_address"),
    ("idx_devices_risk_score", "devices",   "risk_score"),
    ("idx_devices_device_type","devices",   "device_type"),
    # anomalies indexes
    ("idx_anomalies_src_ip",              "anomalies", "src_ip"),
    ("idx_anomalies_anomaly_type",        "anomalies", "anomaly_type"),
    ("idx_anomalies_detection_timestamp", "anomalies", "detection_timestamp"),
    ("idx_anomalies_status",              "anomalies", "status"),
    # clusters indexes
    ("idx_clusters_algorithm",    "clusters",  "clustering_algorithm"),
    ("idx_clusters_cluster_label","clusters",  "cluster_label"),
    # incidents indexes
    ("idx_incidents_severity",          "incidents", "severity"),
    ("idx_incidents_status",            "incidents", "status"),
    ("idx_incidents_created_timestamp", "incidents", "created_timestamp"),
    # isolations indexes
    ("idx_isolations_ip_address",          "isolations", "ip_address"),
    ("idx_isolations_isolation_timestamp", "isolations", "isolation_timestamp"),
    # investigations indexes
    ("idx_investigations_related_incident_id", "investigations", "related_incident_id"),
    ("idx_investigations_status",              "investigations", "status"),
    # behavior_profiles indexes
    ("idx_behavior_profiles_device_ip", "behavior_profiles", "device_ip"),
]


# --- Core functions ----------------------------------------------------------

def ensure_database_directory() -> None:
    """Create the dataset directory if it does not exist."""
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    log(f"Database directory: {DATABASE_DIR}")


def get_connection() -> sqlite3.Connection:
    """Open a connection to the SQLite database with recommended pragmas."""
    conn = sqlite3.connect(str(DATABASE_PATH))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA cache_size=-8000;")      # 8 MB cache
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


def create_tables(conn: sqlite3.Connection) -> int:
    """Create all tables from TABLE_SCHEMAS. Returns the number created."""
    cursor = conn.cursor()
    created = 0
    for table_name in EXPECTED_TABLES:
        ddl = TABLE_SCHEMAS.get(table_name)
        if ddl is None:
            fail(f"No DDL found for table '{table_name}'")
            continue
        try:
            cursor.execute(ddl)
            ok(f"Table '{table_name}' created")
            created += 1
        except sqlite3.Error as exc:
            fail(f"Table '{table_name}' failed: {exc}")
    conn.commit()
    return created


def create_indexes(conn: sqlite3.Connection) -> int:
    """Create all indexes from INDEX_DEFINITIONS. Returns the number created."""
    cursor = conn.cursor()
    created = 0
    for idx_name, table, column in INDEX_DEFINITIONS:
        try:
            cursor.execute(
                f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({column});"
            )
            created += 1
        except sqlite3.Error as exc:
            fail(f"Index '{idx_name}' on {table}({column}) failed: {exc}")
    conn.commit()
    return created


def validate_schema(conn: sqlite3.Connection) -> bool:
    """
    Validate that every expected table exists and contains the expected columns.
    Returns True if the schema is fully valid.
    """
    cursor = conn.cursor()
    all_valid = True

    # 1. Check all expected tables are present
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    existing_tables = {row[0] for row in cursor.fetchall()}
    for table_name in EXPECTED_TABLES:
        if table_name not in existing_tables:
            fail(f"Missing table: {table_name}")
            all_valid = False

    # 2. Column-level validation for each table
    expected_columns = {
        "events": [
            "event_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "action", "severity", "payload_size", "zone", "device_ip",
            "packet_count", "created_at",
        ],
        "devices": [
            "device_id", "ip_address", "hostname", "device_type", "zone",
            "first_seen", "last_seen", "is_active", "risk_score",
            "total_anomalies", "behavioral_profile", "cluster_assignment",
            "created_at",
        ],
        "anomalies": [
            "anomaly_id", "event_id", "src_ip", "anomaly_type", "anomaly_score",
            "confidence", "detection_method", "detection_timestamp", "status",
            "created_at",
        ],
        "clusters": [
            "cluster_id", "clustering_algorithm", "cluster_label", "device_ips",
            "cluster_centroid", "silhouette_score", "davies_bouldin_index",
            "n_members", "cluster_profile", "creation_timestamp",
        ],
        "incidents": [
            "incident_id", "incident_name", "severity", "status", "description",
            "related_anomaly_ids", "related_device_ips", "created_timestamp",
            "updated_timestamp", "assigned_to", "resolution_notes",
        ],
        "isolations": [
            "isolation_id", "container_name", "network_name", "ip_address",
            "isolation_reason", "isolation_timestamp", "success",
            "automation_method", "reversal_timestamp", "reversal_reason",
        ],
        "investigations": [
            "investigation_id", "investigator_name", "related_incident_id",
            "start_timestamp", "end_timestamp", "findings", "evidence",
            "conclusion", "status",
        ],
        "behavior_profiles": [
            "profile_id", "device_ip", "baseline_features",
            "communication_pattern", "temporal_pattern", "protocol_distribution",
            "packet_size_distribution", "learned_timestamp", "last_update",
            "learning_confidence",
        ],
    }

    for table_name, columns in expected_columns.items():
        if table_name not in existing_tables:
            continue
        cursor.execute(f"PRAGMA table_info({table_name});")
        actual_cols = [row[1] for row in cursor.fetchall()]
        missing = [c for c in columns if c not in actual_cols]
        if missing:
            fail(f"Table '{table_name}' missing columns: {missing}")
            all_valid = False

    return all_valid


def validate_indexes(conn: sqlite3.Connection) -> bool:
    """Check that all expected indexes exist."""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
    existing = {row[0] for row in cursor.fetchall()}
    all_valid = True
    for idx_name, _, _ in INDEX_DEFINITIONS:
        if idx_name not in existing:
            fail(f"Missing index: {idx_name}")
            all_valid = False
    return all_valid


def test_database_connection(conn: sqlite3.Connection) -> bool:
    """
    Perform a write -> read -> delete round-trip test to verify the database
    is fully functional.
    """
    cursor = conn.cursor()
    test_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    try:
        # --- Write test ---
        cursor.execute(
            """
            INSERT INTO events (timestamp, src_ip, dst_ip, src_port, dst_port,
                                protocol, action, severity, payload_size, zone,
                                device_ip, packet_count)
            VALUES (?, '192.168.1.100', '192.168.1.200', 12345, 1883,
                    'MQTT', 'NORMAL', 'LOW', 128, 'IoT',
                    '192.168.1.100', 1);
            """,
            (test_ts,),
        )
        conn.commit()
        test_event_id = cursor.lastrowid
        ok("Write test successful")

        # --- Read test ---
        cursor.execute(
            "SELECT event_id, src_ip, dst_ip, protocol FROM events WHERE event_id = ?;",
            (test_event_id,),
        )
        row = cursor.fetchone()
        if row is None:
            fail("Read test failed: inserted row not found")
            return False
        if row[1] != "192.168.1.100" or row[2] != "192.168.1.200":
            fail(f"Read test failed: data mismatch {row}")
            return False
        ok("Read test successful")

        # --- Delete test (clean up) ---
        cursor.execute("DELETE FROM events WHERE event_id = ?;", (test_event_id,))
        conn.commit()
        ok("Cleanup test row deleted")

        return True

    except sqlite3.Error as exc:
        fail(f"Database test failed: {exc}")
        return False


def print_database_summary(conn: sqlite3.Connection) -> None:
    """Print a formatted summary of all tables and their row counts."""
    cursor = conn.cursor()
    print()
    print("  " + "-" * 50)
    print("  DATABASE SUMMARY")
    print("  " + "-" * 50)
    print(f"  {'Table':<25} {'Columns':>8}  {'Rows':>8}")
    print("  " + "-" * 50)

    for table_name in EXPECTED_TABLES:
        try:
            cursor.execute(f"PRAGMA table_info({table_name});")
            col_count = len(cursor.fetchall())
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            row_count = cursor.fetchone()[0]
            print(f"  {table_name:<25} {col_count:>8}  {row_count:>8}")
        except sqlite3.Error:
            print(f"  {table_name:<25} {'ERROR':>8}  {'---':>8}")

    # Index count
    cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%';")
    idx_count = cursor.fetchone()[0]
    print("  " + "-" * 50)
    print(f"  Total indexes: {idx_count}")

    # Database file size
    db_size = DATABASE_PATH.stat().st_size
    if db_size < 1024:
        size_str = f"{db_size} bytes"
    elif db_size < 1024 * 1024:
        size_str = f"{db_size / 1024:.1f} KB"
    else:
        size_str = f"{db_size / (1024 * 1024):.2f} MB"
    print(f"  Database size: {size_str}")
    print(f"  Database path: {DATABASE_PATH}")
    print("  " + "-" * 50)


# --- Main entry point --------------------------------------------------------

def main() -> int:
    """
    Run the full database initialization pipeline.
    Returns 0 on success, 1 on failure.
    """
    print()
    print("=" * 60)
    print("  SIEM+SOAR Platform - Database Initialization")
    print("=" * 60)
    print()

    print("Initializing SIEM Database...")
    print(f"  Database file: {DATABASE_PATH}")
    print()

    # 1. Ensure dataset directory exists
    try:
        ensure_database_directory()
    except OSError as exc:
        fail(f"Could not create database directory: {exc}")
        return 1

    db_existed = DATABASE_PATH.exists()
    if db_existed:
        log("Existing database found - will validate and update schema")
    else:
        log("No existing database - creating fresh")

    # 2. Connect
    try:
        conn = get_connection()
        log("Database connection established")
    except sqlite3.Error as exc:
        fail(f"Could not connect to database: {exc}")
        return 1

    try:
        # 3. Create tables
        print()
        print("Creating schema...")
        tables_created = create_tables(conn)
        if tables_created < len(EXPECTED_TABLES):
            fail(f"Only {tables_created}/{len(EXPECTED_TABLES)} tables created")
        else:
            log(f"All {tables_created} tables ready")

        # 4. Create indexes
        print()
        print("Creating indexes...")
        idx_created = create_indexes(conn)
        ok(f"{idx_created} indexes created")

        # 5. Validate schema
        print()
        print("Validating schema...")
        schema_valid = validate_schema(conn)
        index_valid = validate_indexes(conn)
        if schema_valid and index_valid:
            ok("Schema validation passed")
        else:
            fail("Schema validation found issues (see above)")

        # 6. Test connection
        print()
        print("Testing database connection...")
        test_ok = test_database_connection(conn)

        # 7. Summary
        print_database_summary(conn)

        # 8. Final status
        print()
        if tables_created == len(EXPECTED_TABLES) and test_ok and schema_valid:
            print("Database initialized successfully!")
            print()
            return 0
        else:
            fail("Database initialization completed with warnings")
            print()
            return 1

    except sqlite3.Error as exc:
        fail(f"Unexpected database error: {exc}")
        return 1
    finally:
        conn.close()
        log("Database connection closed")


if __name__ == "__main__":
    sys.exit(main())
