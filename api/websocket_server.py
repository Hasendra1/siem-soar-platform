"""
WebSocket push server
======================
Background thread that polls the DB and pushes new events,
anomalies, and isolation changes to connected clients in real-time.
"""

import time, sqlite3, threading
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "dataset" / "siem_database.db"


class WebSocketPusher:
    """Polls DB for new events/anomalies/isolations and emits them via SocketIO."""

    def __init__(self, socketio, interval=1.0):
        self.sio = socketio
        self.interval = interval
        self.last_event_id = 0
        self.last_anomaly_id = 0
        self.last_isolation_id = 0
        self.last_isolation_count = 0
        self.running = False
        self._init_cursors()

    def _init_cursors(self):
        try:
            conn = sqlite3.connect(str(DB))
            r = conn.execute("SELECT MAX(event_id) FROM events").fetchone()
            self.last_event_id = r[0] or 0
            r = conn.execute("SELECT MAX(anomaly_id) FROM anomalies").fetchone()
            self.last_anomaly_id = r[0] or 0
            r = conn.execute("SELECT MAX(isolation_id) FROM isolations").fetchone()
            self.last_isolation_id = r[0] or 0
            r = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM isolations WHERE success=1").fetchone()
            self.last_isolation_count = r[0] or 0
            conn.close()
        except Exception:
            pass

    def start(self):
        self.running = True
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

    def _poll_loop(self):
        while self.running:
            try:
                self._check_new_events()
                self._check_new_anomalies()
                self._check_new_isolations()
                self._push_summary_update()
            except Exception:
                pass
            time.sleep(self.interval)

    def _check_new_events(self):
        conn = sqlite3.connect(str(DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events WHERE event_id > ? ORDER BY event_id LIMIT 20",
            (self.last_event_id,)).fetchall()
        conn.close()
        for r in rows:
            self.sio.emit("new_event", dict(r))
            self.last_event_id = r["event_id"]

    def _check_new_anomalies(self):
        conn = sqlite3.connect(str(DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM anomalies WHERE anomaly_id > ? ORDER BY anomaly_id LIMIT 10",
            (self.last_anomaly_id,)).fetchall()
        conn.close()
        for r in rows:
            self.sio.emit("anomaly_detected", dict(r))
            self.last_anomaly_id = r["anomaly_id"]

    def _check_new_isolations(self):
        """Push new isolation events to the frontend in real-time."""
        conn = sqlite3.connect(str(DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM isolations WHERE isolation_id > ? ORDER BY isolation_id LIMIT 10",
            (self.last_isolation_id,)).fetchall()
        conn.close()
        for r in rows:
            self.sio.emit("new_isolation", dict(r))
            self.last_isolation_id = r["isolation_id"]

    def _push_summary_update(self):
        """Push updated summary counts every poll cycle so dashboard stays in sync."""
        try:
            conn = sqlite3.connect(str(DB))
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            isolations = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM isolations WHERE success=1").fetchone()[0]
            anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
            conn.close()

            # Only emit when counts change
            if isolations != self.last_isolation_count:
                self.last_isolation_count = isolations
                self.sio.emit("summary_update", {
                    "total_events": total_events,
                    "isolations":   isolations,
                    "anomalies":    anomalies,
                })
        except Exception:
            pass
