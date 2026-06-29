#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Flask API Backend
========================================
Main application entry point. Serves the dashboard and REST API.
Integrates real-time ML inference monitor via WebSocket.
"""

import sys, os
from pathlib import Path
from flask import Flask, render_template, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

app = Flask(__name__,
            template_folder=str(BASE_DIR / "frontend" / "templates"),
            static_folder=str(BASE_DIR / "frontend" / "static"))
app.config["SECRET_KEY"] = "siem-soar-secret-key-2026"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Register blueprints
from routes_dashboard import dashboard_bp
from routes_data import data_bp
from routes_investigation import investigation_bp
from routes_system import system_bp

app.register_blueprint(dashboard_bp,     url_prefix="/api/dashboard")
app.register_blueprint(data_bp,          url_prefix="/api/data")
app.register_blueprint(investigation_bp, url_prefix="/api/investigation")
app.register_blueprint(system_bp,        url_prefix="/api/system")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok", "service": "SIEM+SOAR API"}


# SocketIO event handlers
@socketio.on("connect")
def handle_connect():
    print("[WS] Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("[WS] Client disconnected")


def get_socketio():
    return socketio


if __name__ == "__main__":
    print("=" * 60)
    print("  SIEM+SOAR Platform — Dynamic Dashboard Server")
    print("=" * 60)
    print("  Dashboard:   http://localhost:5000")
    print("  API:         http://localhost:5000/api/dashboard/summary")
    print("  System:      http://localhost:5000/api/system/status")
    print("  Reset:       POST /api/system/reset")
    print("  ML Monitor:  POST /api/system/monitor/start")
    print("=" * 60)
    from websocket_server import WebSocketPusher
    pusher = WebSocketPusher(socketio, interval=1.0)
    pusher.start()
    print("  WebSocket pusher started (polling DB every 1s)")
    print("  System ready — waiting for events...")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                 allow_unsafe_werkzeug=True)
