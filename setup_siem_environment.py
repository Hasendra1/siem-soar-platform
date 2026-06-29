#!/usr/bin/env python3
"""
SIEM+SOAR Platform Environment Setup Script
============================================
Enterprise IoT/OT Cybersecurity Research Platform
Creates complete directory structure, copies configs, validates dependencies.
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path

# --- Configuration -----------------------------------------------------------

PLATFORM_ROOT = Path(r"C:\siem-soar-platform")
IOT_OT_DEMO = Path(r"C:\iot-ot-demo")

REQUIRED_PYTHON_VERSION = "3.12.4"

FILES_TO_COPY = [
    "docker-compose.yml",
    "mosquitto.conf",
]

# Complete directory structure (all 45 directories)
DIRECTORIES = [
    # Root-level directories (11)
    "agents",
    "processors",
    "ml_models",
    "enforcement",
    "database",
    "api",
    "frontend",
    "dataset",
    "wazuh_integration",
    "results",
    "logs",
    # Frontend sub-directories (6)
    "frontend/static",
    "frontend/static/css",
    "frontend/static/js",
    "frontend/static/images",
    "frontend/static/images/icons",
    "frontend/templates",
    # Results sub-directories (1)
    "results/reports",
    # Config & docs (3)
    "config",
    "config/environments",
    "docs",
    # Tests (6)
    "tests",
    "tests/unit",
    "tests/integration",
    "tests/unit/agents",
    "tests/unit/processors",
    "tests/unit/ml_models",
    # Scripts & tools (2)
    "scripts",
    "scripts/migrations",
    # Backup & archive (2)
    "backups",
    "backups/snapshots",
    # Integrations (4)
    "integrations",
    "integrations/splunk",
    "integrations/elastic",
    "integrations/kafka",
    # ML pipeline (3)
    "ml_models/trained",
    "ml_models/evaluation",
    "ml_models/datasets",
    # API sub-directories (2)
    "api/middleware",
    "api/schemas",
    # Wazuh sub-directories (2)
    "wazuh_integration/rules",
    "wazuh_integration/decoders",
    # Logs sub-directories (1)
    "logs/archive",
    # Additional (2)
    "docs/architecture",
    "enforcement/policies",
]


# Files that will be created (placeholder/empty files for structure validation)
PLACEHOLDER_FILES = {
    # agents
    "agents/zeek_collector.py": "# Zeek network traffic collector agent\n",
    "agents/wazuh_aggregator.py": "# Wazuh alert aggregation agent\n",
    "agents/wireshark_capture.py": "# Wireshark packet capture agent\n",
    "agents/live_attack_simulator.py": "# Live attack simulation agent\n",
    # processors
    "processors/event_normalizer.py": "# Event normalization processor\n",
    "processors/feature_extractor.py": "# Feature extraction processor\n",
    "processors/real_time_indexer.py": "# Real-time event indexer\n",
    # ml_models
    "ml_models/clustering_engine.py": "# ML clustering engine\n",
    "ml_models/anomaly_detector.py": "# Anomaly detection model\n",
    "ml_models/behavior_profiler.py": "# Behavior profiling model\n",
    "ml_models/real_time_inference.py": "# Real-time ML inference engine\n",
    "ml_models/attacker_identification.py": "# Attacker identification model\n",
    "ml_models/threat_scorer.py": "# Threat scoring model\n",
    # enforcement
    "enforcement/ml_based_segmentation.py": "# ML-based network segmentation\n",
    "enforcement/containment_engine.py": "# Threat containment engine\n",
    "enforcement/playbook_executor.py": "# SOAR playbook executor\n",
    # database
    "database/init_database.py": "# Database initialization script\n",
    "database/db_manager.py": "# Database manager\n",
    # api
    "api/app.py": "# Flask API application\n",
    "api/routes_dashboard.py": "# Dashboard API routes\n",
    "api/routes_data.py": "# Data API routes\n",
    "api/routes_investigation.py": "# Investigation API routes\n",
    "api/routes_response.py": "# Response API routes\n",
    "api/websocket_server.py": "# WebSocket server for real-time updates\n",
    # frontend/static
    "frontend/static/css/style.css": "/* SIEM+SOAR Platform Stylesheet */\n",
    "frontend/static/js/dashboard.js": "// Dashboard JavaScript\n",
    "frontend/static/js/realtime.js": "// Real-time monitoring JavaScript\n",
    "frontend/static/js/investigation.js": "// Investigation JavaScript\n",
    # frontend/templates
    "frontend/templates/index.html": "<!-- SIEM Dashboard -->\n",
    "frontend/templates/threat_hunting.html": "<!-- Threat Hunting View -->\n",
    "frontend/templates/incidents.html": "<!-- Incidents View -->\n",
    "frontend/templates/investigation.html": "<!-- Investigation View -->\n",
    # wazuh_integration
    "wazuh_integration/dockerfile.agent": "# Wazuh agent Dockerfile\n",
    "wazuh_integration/wazuh_config.yml": "# Wazuh configuration\n",
    "wazuh_integration/agent_setup.sh": "#!/bin/bash\n# Wazuh agent setup script\n",
    "wazuh_integration/ossec.conf": "<!-- OSSEC configuration -->\n",
    # results
    "results/ml_models.pkl": "",
    "results/threat_intel.json": "{}\n",
    "results/reports/analysis_report.md": "# Analysis Report\n",
    # logs
    "logs/system.log": "",
    "logs/detection.log": "",
    "logs/response.log": "",
}

# README content for major folders
README_CONTENT = {
    "agents": (
        "# Agents\n\n"
        "Data collection agents for the SIEM platform.\n\n"
        "- `zeek_collector.py` – Zeek network traffic collector\n"
        "- `wazuh_aggregator.py` – Wazuh alert aggregator\n"
        "- `wireshark_capture.py` – Wireshark packet capture\n"
        "- `live_attack_simulator.py` – Attack simulation agent\n"
    ),
    "processors": (
        "# Processors\n\n"
        "Event processing and normalization pipeline.\n\n"
        "- `event_normalizer.py` – Normalizes raw events to common schema\n"
        "- `feature_extractor.py` – Extracts ML features from events\n"
        "- `real_time_indexer.py` – Indexes events for fast retrieval\n"
    ),
    "ml_models": (
        "# ML Models\n\n"
        "Machine learning models for threat detection.\n\n"
        "- `clustering_engine.py` – Traffic clustering (KMeans/DBSCAN)\n"
        "- `anomaly_detector.py` – Anomaly detection (Isolation Forest)\n"
        "- `behavior_profiler.py` – Device behavior profiling\n"
        "- `real_time_inference.py` – Real-time ML inference engine\n"
        "- `attacker_identification.py` – Attacker identification\n"
        "- `threat_scorer.py` – Threat scoring and prioritization\n"
    ),
    "enforcement": (
        "# Enforcement\n\n"
        "Automated response and containment modules.\n\n"
        "- `ml_based_segmentation.py` – ML-based network segmentation\n"
        "- `containment_engine.py` – Threat containment engine\n"
        "- `playbook_executor.py` – SOAR playbook execution\n"
    ),
    "database": (
        "# Database\n\n"
        "Database initialization and management.\n\n"
        "- `init_database.py` – Creates SQLite schema\n"
        "- `db_manager.py` – Database CRUD operations\n"
    ),
    "api": (
        "# API\n\n"
        "Flask REST API and WebSocket server.\n\n"
        "- `app.py` – Main Flask application\n"
        "- `routes_dashboard.py` – Dashboard endpoints\n"
        "- `routes_data.py` – Data retrieval endpoints\n"
        "- `routes_investigation.py` – Investigation endpoints\n"
        "- `routes_response.py` – Incident response endpoints\n"
        "- `websocket_server.py` – Real-time WebSocket server\n"
    ),
    "frontend": (
        "# Frontend\n\n"
        "Web-based dashboard for the SIEM+SOAR platform.\n\n"
        "- `templates/` – HTML templates (Jinja2)\n"
        "- `static/css/` – Stylesheets\n"
        "- `static/js/` – JavaScript modules\n"
        "- `static/images/icons/` – Icon assets\n"
    ),
    "dataset": (
        "# Dataset\n\n"
        "Data storage for the SIEM platform.\n\n"
        "- `siem_database.db` – SQLite database (auto-created)\n"
        "- `traffic_events.csv` – Normalized traffic events\n"
        "- `anomalies.json` – Detected anomalies\n"
        "- `clusters.json` – Traffic clustering results\n"
    ),
    "wazuh_integration": (
        "# Wazuh Integration\n\n"
        "Wazuh HIDS agent configuration and deployment.\n\n"
        "- `dockerfile.agent` – Docker image for Wazuh agent\n"
        "- `wazuh_config.yml` – Wazuh configuration\n"
        "- `agent_setup.sh` – Agent bootstrap script\n"
        "- `ossec.conf` – OSSEC configuration\n"
    ),
    "results": (
        "# Results\n\n"
        "ML model artifacts and analysis outputs.\n\n"
        "- `ml_models.pkl` – Serialized ML models\n"
        "- `threat_intel.json` – Threat intelligence data\n"
        "- `reports/` – Generated analysis reports\n"
    ),
    "logs": (
        "# Logs\n\n"
        "Platform log files.\n\n"
        "- `system.log` – System-level logs\n"
        "- `detection.log` – Detection engine logs\n"
        "- `response.log` – Response action logs\n"
    ),
}

REQUIRED_PACKAGES = [
    "flask>=3.0",
    "flask-socketio>=5.3",
    "flask-cors>=4.0",
    "scikit-learn>=1.4",
    "pandas>=2.2",
    "numpy>=1.26",
    "matplotlib>=3.8",
    "seaborn>=0.13",
    "plotly>=5.18",
    "paho-mqtt>=2.0",
    "scapy>=2.5",
    "docker>=7.0",
    "requests>=2.31",
    "websockets>=12.0",
    "eventlet>=0.35",
    "pyshark>=0.6",
    "watchdog>=4.0",
    "python-dateutil>=2.8",
    "jinja2>=3.1",
    "colorama>=0.4",
    "rich>=13.7",
    "pyyaml>=6.0",
    "joblib>=1.3",
    "psutil>=5.9",
    "cryptography>=42.0",
]


# --- Helpers ------------------------------------------------------------------

def print_status(message: str, success: bool = True) -> None:
    """Print a status message with a check or cross mark."""
    try:
        mark = "\u2713" if success else "\u2717"
        print(f"  {message}... {mark}")
    except UnicodeEncodeError:
        mark = "[OK]" if success else "[FAIL]"
        print(f"  {message}... {mark}")


def validate_python_version() -> bool:
    """Check that we are running on the required Python version."""
    current = platform.python_version()
    ok = current == REQUIRED_PYTHON_VERSION
    print_status(f"Validating Python {REQUIRED_PYTHON_VERSION} (found {current})", ok)
    return ok


def check_docker() -> bool:
    """Check that Docker Desktop is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=15,
        )
        ok = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ok = False
    print_status("Checking Docker Desktop", ok)
    return ok


def clean_platform_directory() -> None:
    """Remove existing siem-soar-platform contents (except this script and .git)."""
    keep = {"setup_siem_environment.py", ".git", ".gitignore"}
    if PLATFORM_ROOT.exists():
        for item in PLATFORM_ROOT.iterdir():
            if item.name in keep:
                continue
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)


def create_directories() -> int:
    """Create all required directories and return the count."""
    created = 0
    for d in DIRECTORIES:
        path = PLATFORM_ROOT / d
        path.mkdir(parents=True, exist_ok=True)
        created += 1
    return created


def copy_config_files() -> None:
    """Copy docker-compose.yml and mosquitto.conf from iot-ot-demo."""
    for filename in FILES_TO_COPY:
        src = IOT_OT_DEMO / filename
        dst = PLATFORM_ROOT / filename
        if src.exists():
            shutil.copy2(src, dst)
            print_status(f"Copying {filename}")
        else:
            print_status(f"Copying {filename} (source not found)", success=False)


def create_placeholder_files() -> int:
    """Create placeholder/stub files and return the count."""
    count = 0
    for rel_path, content in PLACEHOLDER_FILES.items():
        filepath = PLATFORM_ROOT / rel_path
        filepath.parent.mkdir(parents=True, exist_ok=True)
        if not filepath.exists():
            filepath.write_text(content, encoding="utf-8")
        count += 1
    return count


def create_readme_files() -> int:
    """Create README.md in each major folder."""
    count = 0
    for folder, content in README_CONTENT.items():
        readme_path = PLATFORM_ROOT / folder / "README.md"
        readme_path.parent.mkdir(parents=True, exist_ok=True)
        readme_path.write_text(content, encoding="utf-8")
        count += 1
    return count


def create_root_readme() -> None:
    """Create the top-level README.md."""
    content = (
        "# SIEM+SOAR Platform\n\n"
        "Enterprise IoT/OT Cybersecurity Research Platform with ML-based threat detection.\n\n"
        "## Architecture\n\n"
        "| Layer | Components |\n"
        "|-------|------------|\n"
        "| **Collection** | Zeek, Wazuh, Wireshark agents |\n"
        "| **Processing** | Event normalizer, feature extractor, indexer |\n"
        "| **Detection** | Clustering, anomaly detection, behavior profiling |\n"
        "| **Response** | ML segmentation, containment, playbook execution |\n"
        "| **Presentation** | Flask API, WebSocket, web dashboard |\n\n"
        "## Quick Start\n\n"
        "```bash\n"
        "python setup_siem_environment.py   # Setup environment\n"
        "pip install -r requirements.txt     # Install dependencies\n"
        "python database/init_database.py    # Initialize database\n"
        "python api/app.py                   # Start API server\n"
        "```\n"
    )
    (PLATFORM_ROOT / "README.md").write_text(content, encoding="utf-8")


def create_requirements_txt() -> None:
    """Write requirements.txt with all needed packages."""
    content = "# SIEM+SOAR Platform Dependencies\n"
    content += "# Install with: pip install -r requirements.txt\n\n"
    content += "\n".join(REQUIRED_PACKAGES) + "\n"
    (PLATFORM_ROOT / "requirements.txt").write_text(content, encoding="utf-8")


def count_all_directories() -> int:
    """Recursively count all directories under PLATFORM_ROOT."""
    count = 0
    for item in PLATFORM_ROOT.rglob("*"):
        if item.is_dir():
            count += 1
    return count


def validate_structure() -> bool:
    """Validate that all expected directories and key files exist."""
    all_ok = True
    # Check directories
    for d in DIRECTORIES:
        if not (PLATFORM_ROOT / d).is_dir():
            print(f"    MISSING DIR: {d}")
            all_ok = False
    # Check copied files
    for f in FILES_TO_COPY:
        if not (PLATFORM_ROOT / f).is_file():
            print(f"    MISSING FILE: {f}")
            all_ok = False
    return all_ok


# --- Main ---------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("  SIEM+SOAR Platform - Environment Setup")
    print("  Enterprise IoT/OT Cybersecurity Research")
    print("=" * 60)
    print()

    print("Setting up SIEM+SOAR Platform...")
    print()

    # 1. Validate Python
    py_ok = validate_python_version()

    # 2. Check Docker
    docker_ok = check_docker()
    print()

    # 3. Clean existing structure (preserve this script)
    print("  Cleaning existing directory structure...")
    clean_platform_directory()
    print()

    # 4. Create directories
    print("Creating directory structure...")
    dir_count = create_directories()

    # 5. Copy config files
    copy_config_files()

    # 6. Create placeholder files
    file_count = create_placeholder_files()

    # 7. Create README files
    readme_count = create_readme_files()
    create_root_readme()

    # 8. Create requirements.txt
    create_requirements_txt()

    # 9. Count and validate
    total_dirs = count_all_directories()
    print_status(f"Creating {total_dirs} folders")
    print()

    # 10. Validate
    print("  Validating structure...")
    valid = validate_structure()
    print_status("Structure validation", valid)
    print()

    # Summary
    print("-" * 60)
    print(f"  Directories created : {total_dirs}")
    print(f"  Files created       : {file_count}")
    print(f"  README files        : {readme_count + 1}")
    _ok = "[OK]" ; _fail = "[FAIL]"
    print(f"  Python {REQUIRED_PYTHON_VERSION}      : {_ok if py_ok else _fail}")
    print(f"  Docker Desktop      : {_ok if docker_ok else _fail}")
    print("-" * 60)
    print()

    # Required packages listing
    print("  Required packages (install via pip install -r requirements.txt):")
    for pkg in REQUIRED_PACKAGES:
        print(f"    - {pkg}")
    print()

    print("Setup complete!")
    print()

    if not py_ok:
        print(f"  [!] Python version mismatch - expected {REQUIRED_PYTHON_VERSION}")
    if not docker_ok:
        print("  [!] Docker Desktop not detected - start it before running containers")


if __name__ == "__main__":
    main()
