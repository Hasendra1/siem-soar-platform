#!/usr/bin/env python3
"""
SIEM+SOAR Platform - Live Attack Simulator
============================================
Simulates real cyberattacks on the Docker IoT/OT network.
5 attack phases over ~150 seconds generating ~75 database events.

Phases:
  1. PORT_SCAN         (0-30s)   ~50 events
  2. UNAUTHORIZED_READ (30-60s)  ~10 events
  3. MALICIOUS_WRITE   (60-90s)  ~5 events
  4. LATERAL_MOVEMENT  (90-120s) ~8 events
  5. DATA_EXFIL        (120-150s) ~3 events

Works in two modes:
  - Docker mode: executes real Modbus/MQTT/HTTP inside containers
  - Standalone mode: generates identical DB events without Docker
"""

import os, sys, time, socket, struct, random, argparse, sqlite3, csv, logging
from pathlib import Path
from datetime import datetime

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
LOGS_DIR = BASE_DIR / "logs"
DB_PATH = DATASET_DIR / "siem_database.db"
TRAFFIC_LOG = DATASET_DIR / "traffic_log.csv"

for d in (DATASET_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOGS_DIR / "attack_simulator.log", encoding="utf-8"),
              logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("AttackSimulator")

# --- Network targets ---
ATTACKER_IP = "192.168.10.50"
PLC1_IP     = "192.168.10.10"
PLC2_IP     = "192.168.10.11"
HMI_IP      = "192.168.10.20"
MQTT_IP     = "192.168.20.100"
CCTV_IP     = "192.168.30.10"
GATEWAY_IP  = "192.168.30.100"
EXTERNAL_IP = "10.0.0.1"

# --- Docker helper ---
def get_docker_client():
    """Try to connect to Docker. Returns client or None."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return client
    except Exception:
        return None

def docker_exec(client, container_name, cmd):
    """Execute command inside a Docker container."""
    if not client:
        return None
    try:
        container = client.containers.get(container_name)
        result = container.exec_run(cmd, demux=True)
        stdout = result.output[0].decode("utf-8", errors="replace") if result.output[0] else ""
        return stdout.strip()
    except Exception as e:
        return None


class LiveAttackSimulator:
    """Simulates 5-phase cyberattack sequence on IoT/OT network."""

    def __init__(self):
        self.docker = get_docker_client()
        self.docker_mode = self.docker is not None
        self.events_generated = 0
        self.stolen_data = {}
        self.db_conn = None
        self._init_db()
        self._init_traffic_log()

        mode = "Docker" if self.docker_mode else "Standalone"
        print(f"\nLive Attack Simulator initialized ({mode} mode)")
        print(f"Attacker: {ATTACKER_IP}")
        print(f"Targets:  PLC1={PLC1_IP}, PLC2={PLC2_IP}")
        print(f"Database: {DB_PATH}")

    def _init_db(self):
        """Open persistent DB connection."""
        try:
            self.db_conn = sqlite3.connect(str(DB_PATH))
            self.db_conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error as e:
            logger.error("DB connection failed: %s", e)

    def _init_traffic_log(self):
        """Create traffic_log.csv with header if not exists."""
        if not TRAFFIC_LOG.exists():
            with open(TRAFFIC_LOG, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "src_ip", "dst_ip", "src_port",
                            "dst_port", "protocol", "action", "severity",
                            "payload_size", "zone"])

    def _log_event(self, dst_ip, dst_port, protocol, action, severity,
                   payload_size=64, zone="OT", src_port=None):
        """Write one attack event to both the database and traffic_log.csv."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        s_port = src_port or random.randint(40000, 65000)

        # Database
        if self.db_conn:
            try:
                self.db_conn.execute(
                    """INSERT INTO events (timestamp, src_ip, dst_ip, src_port,
                       dst_port, protocol, action, severity, payload_size,
                       zone, device_ip, packet_count)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (ts, ATTACKER_IP, dst_ip, s_port, dst_port,
                     protocol, action, severity, payload_size,
                     zone, ATTACKER_IP, 1))
                self.db_conn.commit()
            except sqlite3.Error as e:
                logger.error("DB insert failed: %s", e)

        # CSV log
        try:
            with open(TRAFFIC_LOG, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts, ATTACKER_IP, dst_ip, s_port,
                    dst_port, protocol, action, severity, payload_size, zone])
        except IOError:
            pass

        self.events_generated += 1

    def _try_tcp_connect(self, ip, port, timeout=1):
        """Attempt a real TCP connection (works outside Docker too)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    # ================================================================== #
    # PHASE 1: PORT SCANNING                                              #
    # ================================================================== #

    def phase_1_port_scan(self, duration_sec=30):
        """Scan ports 500-510 on PLC subnet."""
        print(f"\n{'='*60}")
        print(f"  [PHASE 1] Port Scanning (0-{duration_sec}s)")
        print(f"{'='*60}")

        targets = [PLC1_IP, PLC2_IP, HMI_IP]
        ports = list(range(500, 511))
        packet_count = 0
        delay = duration_sec / (len(targets) * len(ports) + 1)

        for target in targets:
            print(f"  [ATTACKER] Scanning {target} ports 500-510...")
            for port in ports:
                # Try real connection if Docker is up
                if self.docker_mode:
                    self._try_tcp_connect(target, port, timeout=0.3)

                status = "OPEN" if port == 502 else "closed"
                if status == "OPEN":
                    print(f"    Port {port} OPEN")
                    self._log_event(target, port, "TCP", "PORT_SCAN", "HIGH",
                                    payload_size=44)
                else:
                    self._log_event(target, port, "TCP", "PORT_SCAN", "HIGH",
                                    payload_size=44)

                packet_count += 1
                time.sleep(delay)

        # Extra random scan packets to reach ~50
        extra = max(0, 50 - packet_count)
        for _ in range(extra):
            ip = f"192.168.10.{random.randint(1, 25)}"
            port = random.randint(1, 1024)
            self._log_event(ip, port, "TCP", "PORT_SCAN", "HIGH", payload_size=44)
            packet_count += 1
            time.sleep(delay * 0.3)

        print(f"  [ATTACKER] Port scan complete - {packet_count} packets sent")
        return packet_count

    # ================================================================== #
    # PHASE 2: UNAUTHORIZED READS                                         #
    # ================================================================== #

    def phase_2_unauthorized_reads(self, duration_sec=30):
        """Read PLC holding registers via Modbus TCP (unauthorized)."""
        print(f"\n{'='*60}")
        print(f"  [PHASE 2] Unauthorized Reads ({duration_sec}s)")
        print(f"{'='*60}")

        targets = [(PLC1_IP, "PLC1"), (PLC2_IP, "PLC2")]
        read_count = 0
        delay = duration_sec / 11

        for ip, name in targets:
            print(f"  [ATTACKER] Connecting to {ip}:502 (Modbus)...")

            # Try real Modbus read if Docker is available
            registers = None
            if self.docker_mode:
                result = docker_exec(self.docker, "Attacker",
                    f"python3 -c \"from pymodbus.client import ModbusTcpClient; "
                    f"c=ModbusTcpClient('{ip}',port=502); c.connect(); "
                    f"r=c.read_holding_registers(0,5); "
                    f"print(r.registers if not r.isError() else 'ERROR'); c.close()\"")
                if result and "ERROR" not in str(result):
                    registers = result
                    print(f"  [ATTACKER] Read registers: {registers}")

            if not registers:
                # Simulated register values
                if name == "PLC1":
                    registers = [100, 100, 100, 100, 100]
                else:
                    registers = [200, 200, 200, 200, 200]
                print(f"  [ATTACKER] Read registers: {registers}")

            self.stolen_data[name] = registers

            # Generate 5 read events per PLC
            for reg_addr in range(0, 5):
                self._log_event(ip, 502, "Modbus", "UNAUTHORIZED_READ",
                                "CRITICAL", payload_size=256)
                read_count += 1
                time.sleep(delay)

        print(f"  [ATTACKER] Unauthorized reads complete - {read_count} operations")
        return read_count

    # ================================================================== #
    # PHASE 3: MALICIOUS WRITES                                           #
    # ================================================================== #

    def phase_3_malicious_writes(self, duration_sec=30):
        """Write malicious value 9999 to PLC registers."""
        print(f"\n{'='*60}")
        print(f"  [PHASE 3] Malicious Writes ({duration_sec}s)")
        print(f"{'='*60}")
        print("  [!] CRITICAL: Attempting to modify PLC state!")

        targets = [(PLC1_IP, "PLC1"), (PLC2_IP, "PLC2")]
        write_count = 0
        delay = duration_sec / 6

        for ip, name in targets:
            print(f"  [ATTACKER] Writing to {ip}:502 register 0 = 9999")

            if self.docker_mode:
                docker_exec(self.docker, "Attacker",
                    f"python3 -c \"from pymodbus.client import ModbusTcpClient; "
                    f"c=ModbusTcpClient('{ip}',port=502); c.connect(); "
                    f"c.write_register(0,9999); c.close()\"")

            print(f"  [ATTACKER] Write successful - register modified")
            self._log_event(ip, 502, "Modbus", "MALICIOUS_WRITE",
                            "CRITICAL", payload_size=128)
            write_count += 1
            time.sleep(delay)

            # Additional write attempts
            for reg in [1, 2]:
                print(f"  [ATTACKER] Writing to {ip}:502 register {reg} = 9999")
                if self.docker_mode:
                    docker_exec(self.docker, "Attacker",
                        f"python3 -c \"from pymodbus.client import ModbusTcpClient; "
                        f"c=ModbusTcpClient('{ip}',port=502); c.connect(); "
                        f"c.write_register({reg},9999); c.close()\"")
                self._log_event(ip, 502, "Modbus", "MALICIOUS_WRITE",
                                "CRITICAL", payload_size=128)
                write_count += 1
                time.sleep(delay * 0.5)

        print(f"  [ATTACKER] Malicious writes complete - CRITICAL payload "
              f"({write_count} operations)")
        return write_count

    # ================================================================== #
    # PHASE 4: LATERAL MOVEMENT                                           #
    # ================================================================== #

    def phase_4_lateral_movement(self, duration_sec=30):
        """Attempt cross-zone movement from OT to IoT and DMZ."""
        print(f"\n{'='*60}")
        print(f"  [PHASE 4] Lateral Movement ({duration_sec}s)")
        print(f"{'='*60}")

        movements = [
            (MQTT_IP, 1883, "MQTT", "IoT", "MQTT Broker"),
            (MQTT_IP, 1883, "MQTT", "IoT", "MQTT subscribe"),
            (MQTT_IP, 1883, "MQTT", "IoT", "MQTT publish"),
            (CCTV_IP, 80, "HTTP", "DMZ", "CCTV Camera"),
            (CCTV_IP, 443, "HTTP", "DMZ", "CCTV HTTPS"),
            (GATEWAY_IP, 80, "HTTP", "DMZ", "Cloud Gateway"),
            (GATEWAY_IP, 443, "HTTP", "DMZ", "Gateway HTTPS"),
            (GATEWAY_IP, 8080, "TCP", "DMZ", "Gateway admin"),
        ]

        move_count = 0
        delay = duration_sec / (len(movements) + 1)

        for ip, port, proto, zone, desc in movements:
            print(f"  [ATTACKER] Lateral movement attempt - {desc} ({ip}:{port})...")

            if self.docker_mode:
                self._try_tcp_connect(ip, port, timeout=1)
                if proto == "MQTT":
                    docker_exec(self.docker, "Attacker",
                        f"python3 -c \"import paho.mqtt.client as m; "
                        f"c=m.Client(); c.connect('{ip}',{port},5)\" 2>/dev/null")

            self._log_event(ip, port, proto, "LATERAL_MOVEMENT",
                            "CRITICAL", payload_size=96, zone=zone)
            move_count += 1
            time.sleep(delay)

        print(f"  [ATTACKER] Cross-zone movement attempted - {move_count} connections")
        return move_count

    # ================================================================== #
    # PHASE 5: DATA EXFILTRATION                                          #
    # ================================================================== #

    def phase_5_data_exfiltration(self, duration_sec=30):
        """Exfiltrate stolen PLC data to external network."""
        print(f"\n{'='*60}")
        print(f"  [PHASE 5] Data Exfiltration ({duration_sec}s)")
        print(f"{'='*60}")

        stolen_str = str(self.stolen_data) if self.stolen_data else "PLC_DATA_DUMP"
        data_size_gb = 8.5
        print(f"  [ATTACKER] Exfiltrating stolen PLC data...")
        print(f"  [ATTACKER] Stolen registers: {self.stolen_data}")
        print(f"  [ATTACKER] Sending {data_size_gb}GB to external network...")

        exfil_count = 0
        delay = duration_sec / 4

        # 3 large exfil bursts
        for burst in range(3):
            burst_size = int(data_size_gb * 1024 * 1024 * 1024 / 3)
            print(f"  [ATTACKER] Burst {burst+1}/3 - {burst_size // (1024*1024)}MB sent")
            self._log_event(EXTERNAL_IP, 443, "TCP", "DATA_EXFIL",
                            "HIGH", payload_size=burst_size, zone="EXTERNAL")
            exfil_count += 1
            time.sleep(delay)

        print(f"  [ATTACKER] Exfiltration complete - {exfil_count} bursts")
        return exfil_count

    # ================================================================== #
    # Full sequence orchestrator                                          #
    # ================================================================== #

    def run_full_attack_sequence(self):
        """Execute all 5 attack phases in sequence."""
        print(f"\n{'='*60}")
        print(f"  FULL ATTACK SEQUENCE - 5 PHASES")
        print(f"  Attacker: {ATTACKER_IP}")
        print(f"  Duration: ~150 seconds")
        print(f"{'='*60}")

        start = time.time()
        counts = {}

        counts["PORT_SCAN"] = self.phase_1_port_scan(duration_sec=8)
        counts["UNAUTHORIZED_READ"] = self.phase_2_unauthorized_reads(duration_sec=6)
        counts["MALICIOUS_WRITE"] = self.phase_3_malicious_writes(duration_sec=5)
        counts["LATERAL_MOVEMENT"] = self.phase_4_lateral_movement(duration_sec=5)
        counts["DATA_EXFIL"] = self.phase_5_data_exfiltration(duration_sec=4)

        elapsed = time.time() - start

        print(f"\n{'='*60}")
        print(f"  ATTACK SEQUENCE COMPLETE")
        print(f"{'='*60}")
        print(f"  Total events generated: {self.events_generated}")
        print(f"  Duration: {elapsed:.1f} seconds")
        print(f"  Breakdown:")
        for phase, count in counts.items():
            print(f"    {phase:<22} {count} events")
        print(f"{'='*60}")

        self._close()
        return counts

    def run_individual_attack(self, phase):
        """Run a single attack phase."""
        phases = {
            1: self.phase_1_port_scan,
            2: self.phase_2_unauthorized_reads,
            3: self.phase_3_malicious_writes,
            4: self.phase_4_lateral_movement,
            5: self.phase_5_data_exfiltration,
        }
        fn = phases.get(phase)
        if not fn:
            print(f"Invalid phase: {phase}. Use 1-5.")
            return
        print(f"\nRunning Phase {phase} only...")
        fn(duration_sec=5)
        print(f"\nPhase {phase} complete - {self.events_generated} events generated")
        self._close()

    def _close(self):
        if self.db_conn:
            self.db_conn.close()
            self.db_conn = None


def main():
    parser = argparse.ArgumentParser(description="Live Attack Simulator")
    parser.add_argument("--full-sequence", action="store_true",
                        help="Run all 5 attack phases")
    parser.add_argument("--phase", type=int, choices=[1,2,3,4,5],
                        help="Run a specific phase (1-5)")
    parser.add_argument("--fast", action="store_true",
                        help="Run with minimal delays")
    args = parser.parse_args()

    sim = LiveAttackSimulator()

    if args.phase:
        sim.run_individual_attack(args.phase)
    else:
        sim.run_full_attack_sequence()


if __name__ == "__main__":
    main()
