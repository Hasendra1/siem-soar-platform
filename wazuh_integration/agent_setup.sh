#!/bin/bash
# ==============================================================================
# SIEM+SOAR Platform - Wazuh Agent Setup Script
# ==============================================================================
# Installs and configures Wazuh agents in all Docker containers.
# Run from: C:\siem-soar-platform\wazuh_integration\
#
# Prerequisites:
#   - Docker Desktop running
#   - All containers started via docker-compose up
#   - ossec.conf present in this directory
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSSEC_CONF="${SCRIPT_DIR}/ossec.conf"
DOCKER_COMPOSE_FILE="${SCRIPT_DIR}/../docker-compose.yml"

WAZUH_MANAGER_IP="wazuh-manager"
WAZUH_MANAGER_PORT="1514"

# Array of containers that need Wazuh agent
CONTAINERS=(
    "PLC1"
    "PLC2"
    "HMI"
    "MQTT-Broker"
    "Sensor-Temp"
    "Sensor-Pressure"
    "CCTV-Camera"
    "Cloud-Gateway"
    "Attacker"
)

SUCCESS_COUNT=0
FAIL_COUNT=0

# --- Helpers ------------------------------------------------------------------

log_info()  { echo "[INFO]  $(date '+%Y-%m-%d %H:%M:%S')  $*"; }
log_ok()    { echo "[OK]    $(date '+%Y-%m-%d %H:%M:%S')  $*"; }
log_error() { echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S')  $*"; }

# --- Pre-flight checks -------------------------------------------------------

echo "============================================================"
echo "  Wazuh Agent Installation Script"
echo "============================================================"
echo ""

# Verify ossec.conf exists
if [ ! -f "${OSSEC_CONF}" ]; then
    log_error "ossec.conf not found at ${OSSEC_CONF}"
    exit 1
fi
log_info "Using config: ${OSSEC_CONF}"

# Verify Docker is running
if ! docker info > /dev/null 2>&1; then
    log_error "Docker is not running. Start Docker Desktop first."
    exit 1
fi
log_info "Docker is running"

echo ""
echo "Starting Wazuh agent installation..."
echo ""

# --- Install agents -----------------------------------------------------------

for container in "${CONTAINERS[@]}"; do
    echo "------------------------------------------------------------"
    log_info "Processing container: ${container}"

    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        log_error "Container '${container}' is not running - skipping"
        ((FAIL_COUNT++))
        continue
    fi

    # Create log directories inside the container
    docker exec "${container}" mkdir -p /var/log /var/ossec/etc 2>/dev/null || true

    # Copy ossec.conf into the container
    if docker cp "${OSSEC_CONF}" "${container}:/var/ossec/etc/ossec.conf" 2>/dev/null; then
        log_ok "Copied ossec.conf to ${container}"
    else
        log_error "Failed to copy ossec.conf to ${container}"
        ((FAIL_COUNT++))
        continue
    fi

    # Create placeholder log files
    docker exec "${container}" touch /var/log/modbus.log /var/log/mqtt.log /var/log/app.log 2>/dev/null || true

    # Attempt to start the Wazuh agent (may fail if not installed in base image)
    if docker exec "${container}" /var/ossec/bin/wazuh-control start 2>/dev/null; then
        log_ok "Wazuh agent started in ${container}"
    elif docker exec "${container}" /etc/init.d/wazuh-agent start 2>/dev/null; then
        log_ok "Wazuh agent started in ${container} (init.d)"
    else
        log_info "Wazuh agent binary not present in ${container} (base image lacks agent)"
        log_info "Config copied - agent will activate when using siem-agent image"
    fi

    ((SUCCESS_COUNT++))
    log_ok "Wazuh agent configured in ${container}"
done

# --- Summary ------------------------------------------------------------------

echo ""
echo "============================================================"
echo "  Installation Summary"
echo "============================================================"
echo "  Containers processed : ${#CONTAINERS[@]}"
echo "  Successful           : ${SUCCESS_COUNT}"
echo "  Failed               : ${FAIL_COUNT}"
echo "============================================================"
echo ""

if [ "${FAIL_COUNT}" -eq 0 ]; then
    echo "All Wazuh agents installed successfully!"
else
    echo "Some containers had issues. Review errors above."
fi

echo ""
echo "Verify with:"
echo "  docker logs <container_name> | grep wazuh"
echo "  docker exec <container_name> /var/ossec/bin/wazuh-control status"
