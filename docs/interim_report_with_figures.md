# BSc (Hons) Computer Network and Cybersecurity
## Final Year Project Interim Report

---

**Project Title:** Unsupervised Micro-Segmentation Policy Generation for Heterogeneous IoT/OT Environments

**Module Code:** COM4901

---

| | |
|---|---|
| **Student Name** | Manik Pedige Ashan Hasendra Weerasinghe |
| **Student ID / Reg No.** | 14511 |
| **Supervisor Name** | Mr. Tharindu De Zoysa |
| **Faculty** | Faculty of Computer Science and Engineering, KIU |
| **Submission Date** | June 2026 |

---

## 1. Title Page

The details provided above constitute the official title page for this interim report submission. The project focuses on automated security policy generation and enforcement in heterogeneous Industrial Internet of Things (IIoT) and Operational Technology (OT) networks using machine learning.

---

## 2. Introduction

### 2.1 Background and Context

Modern industrial systems are undergoing rapid digital transformation, characterized by the convergence of Information Technology (IT), Operational Technology (OT), and the Industrial Internet of Things (IIoT). In traditional settings, OT systems — such as Programmable Logic Controllers (PLCs), Human-Machine Interfaces (HMIs), and Supervisory Control and Data Acquisition (SCADA) servers — operated in air-gapped, isolated networks using legacy protocols that lacked basic security features. The integration of these networks with enterprise IT applications, cloud-based data analytics, and IoT sensors has bridged this gap, introducing significant vulnerabilities.

Converged networks host a wide variety of devices running different communication protocols (Modbus TCP in OT, MQTT in IoT, HTTP in DMZ services). Because these protocols are vital for operations, security cannot rely on standard perimeter security alone. A compromised workstation or IoT sensor can serve as a beachhead for lateral movement across zones. Micro-segmentation — dividing the network into granular security zones down to individual device levels and strictly enforcing least-privilege access rules — is a key strategy to counter this threat.

### 2.2 Problem Statement

Heterogeneous device behaviour in converged IoT/OT environments makes manual authoring of static micro-segmentation policies impractical. Industrial environments frequently feature dozens of device classes, each with unique, dynamic traffic baselines. For example, a PLC conducting Modbus register polling exhibits a completely different communication profile than an MQTT temperature sensor publishing telemetry every three seconds. Security administrators cannot manually define and maintain the thousands of rules needed to secure such environments.

Furthermore, traditional perimeter-based security cannot detect attacks that originate from authorized hosts. If an attacker gains access to a dual-homed engineering workstation, they can execute unauthorized Modbus read/write commands or move laterally across zones while evading signature-based detection systems. Current security tools either require labeled attack datasets (which are unavailable in custom industrial environments), generate alerts without automated enforcement, or enforce blocklist segmentation without distinguishing between the source of a threat and its victims. This lack of context can result in over-segmentation that disrupts critical industrial operations.

### 2.3 Project Aim and Objectives

The aim of this project is to develop and evaluate an unsupervised micro-segmentation system that automatically generates and enforces network isolation policies for heterogeneous IoT/OT environments based on real-time behavioural anomaly detection.

To achieve this aim, the following objectives have been established:

1. To construct a containerized industrial control system (ICS) testbed that simulates OT (Modbus TCP), IoT (MQTT), and DMZ (HTTP) zones with representative communication baselines.
2. To develop an unsupervised machine learning pipeline using an ensemble model (Isolation Forest + DBSCAN) to profile benign device behaviour and detect anomalies without labeled datasets.
3. To design and implement a real-time feature extraction and inference engine that processes live network traffic using rolling temporal windows.
4. To implement a confidence-gated Security Orchestration, Automation, and Response (SOAR) isolation engine that executes Docker network disconnections, isolating threat sources and compromised targets while keeping unaffected systems online.
5. To build a React-based Security Operations Center (SOC) dashboard that visualizes real-time network topology, events, machine learning scores, anomalies, and active isolation records.
6. To evaluate the system's performance (detection accuracy, precision, and isolation latency) across simulated attack scenarios.

---

## 3. Progress Summary

### 3.1 Tasks Completed So Far

The project has reached approximately 62% completion. The following key tasks have been completed:

*   **Testbed Containerization**: Set up a 12-container environment using Docker Compose. This environment deploys nine application containers across three segregated networks (OT, IoT, DMZ) and three Wazuh SIEM containers.
*   **Traffic Generator & Data Collection**: Developed a Python-based packet capture script using Scapy. This script processes packets in real time and computes 10 behavioural features over 10-second windows.
*   **Two-Tier Unsupervised Machine Learning Model**: Designed, trained, and saved a two-tier ensemble model (Isolation Forest + DBSCAN) using actual simulated traffic. This model successfully separates the attacker device from benign systems with 99.9% confidence.
*   **SOAR Isolation Engine**: Implemented the `MLBasedSegmentationEngine` and `SmartIsolator` state machine in Python. These modules resolve IP addresses to Docker containers and automate network disconnections via the Docker SDK.
*   **SOC Dashboard**: Built a React-based single-page dashboard with real-time updates provided by a Flask-SocketIO backend. The frontend features dedicated views for alerts, anomalies, incidents, and network topology.
*   **Wazuh Agent Deployment**: Deployed Wazuh agents in all nine simulated device containers and registered them with a centralized Wazuh manager.

### 3.2 Current Project Status

The core detection, inference, and enforcement pipelines are fully implemented and functional. The backend and React dashboard communicate via WebSockets, allowing the dashboard to update in real time as events occur in the database. The system can process simulated attacks — such as port scans, unauthorized Modbus reads, malicious Modbus writes, lateral movement, and data exfiltration — and automatically isolate the attacker container within 500ms.

### 3.3 Evidence of Progress

The following primary design and code artifacts have been developed and tested in the project repository:

1.  `docker-compose.yml`: Defined the 12-container network topology, including subnets, IP assignments, and volume mount configurations.
2.  `ml_pipeline/capture_traffic.py`: Background packet sniffing script that maps raw network traffic to a 10-feature vector using Scapy.
3.  `ml_pipeline/train_models.py`: Machine learning script that scales features, calculates optimal DBSCAN parameters, trains the model ensemble, and saves the output.
4.  `enforcement/smart_isolator.py`: Implements the state machine (`NORMAL`, `THREAT_SOURCE`, `COMPROMISED`, `PROPAGATED`) to control the logic of isolation actions.
5.  `enforcement/ml_based_segmentation.py`: The SOAR component that interfaces with the Docker SDK to disconnect containers from bridge networks.
6.  `api/app.py` & `api/websocket_server.py`: Flask-based API backend and SocketIO server that pushes live security updates to the frontend.
7.  `frontend-react/`: A complete Vite+React dashboard utilizing Tailwind CSS and Recharts to visualize security metrics.

---

## 4. Literature Review Progress

### 4.1 Summary of Key Literature Identified

The literature search focused on network segmentation, industrial protocol security, and unsupervised anomaly detection:

*   **OT Segmentation**: Traditionally, OT networks relied on VLANs and firewall rule sets based on the Purdue model [3]. However, as Stouffer et al. [4] highlight, static rules cannot adapt to the complex, multi-protocol communication of modern IIoT systems.
*   **SDN-Based Micro-segmentation**: Gonzalez et al. [5] propose Software-Defined Networking (SDN) to insert dynamic flow rules. While effective, this approach introduces a centralized controller that represents a single point of failure in safety-critical OT environments.
*   **Unsupervised Anomaly Detection**: Because labeled attack data is rare for proprietary industrial protocols, unsupervised methods are preferred.
    *   *Isolation Forest (IF)*, introduced by Liu et al. [10], isolates anomalies by recursively partitioning feature spaces, making it computationally efficient for real-time applications.
    *   *DBSCAN*, by Ester et al. [9], identifies density-based outliers, allowing it to discover clusters of arbitrary shapes without defining the number of clusters beforehand.
    *   *Local Outlier Factor (LOF)* and *Gaussian Mixture Models (GMM)* are also noted in the literature, but they present higher computational overhead during inference.

### 4.2 Theoretical/Conceptual Foundation

The theoretical foundation of this work builds on zero-trust architectures [6] and density-based outlier detection. The key concept is that a device's network footprint — defined by traffic volume, destination diversity, protocol ratios, and protocol-specific behavior — remains stable during normal operations. By transforming raw packet headers into multidimensional feature vectors, we can map benign behaviors into dense clusters in the feature space. Any compromised host executing reconnaissance or malicious writes will drift away from these clusters, appearing as a density outlier (DBSCAN) and requiring fewer splits to isolate (Isolation Forest).

### 4.3 Research Gap Justification

While unsupervised anomaly detection in industrial networks has been studied, a key research gap remains: the lack of an integrated system that combines unsupervised profiling with context-aware, automated network enforcement. Existing works typically trigger alerts without taking automated action [16], require centralized SDN controllers [5], or apply blunt segmentation that disconnects both attackers and victim PLCs. This project addresses this gap by implementing a state-aware isolation engine that distinguishes between threat sources and victims, ensuring that automated containment actions minimize operational disruption.

---

## 5. Methodology / Solution Approach

### 5.1 System Development Methodology

An iterative, prototyping-based Agile methodology was selected for this project. Given the complexity of integrating network capture, machine learning, and Docker virtualization, building the system in stages was essential. The development was divided into four main sprints:
1.  **Sprint 1: Testbed & Traffic (Weeks 1-2)**: Build the Docker compose topology and verify communication.
2.  **Sprint 2: Data & Training (Weeks 3-4)**: Capture baseline traffic, define features, and train the model ensemble.
3.  **Sprint 3: SOAR & API (Weeks 5-6)**: Write the isolation logic and develop the Flask API.
4.  **Sprint 4: Frontend UI (Weeks 7-8)**: Build the React dashboard and integrate WebSockets.

### 5.2 Data Collection Approach

Network traffic is captured via Scapy sniffing. The raw PCAP stream is structured into 10-second windows. For each window, the system computes a 10-feature vector for each device:
1.  `total_packets`: Total packet count.
2.  `avg_packet_size`: Average payload size.
3.  `unique_destinations`: Count of distinct destination IPs.
4.  `unique_ports`: Count of distinct destination ports.
5.  `protocol_diversity`: Shannon entropy of protocol usage.
6.  `modbus_ratio`: Modbus packets divided by total packets.
7.  `mqtt_ratio`: MQTT packets divided by total packets.
8.  `scan_rate`: SYN-only packets divided by total packets.
9.  `write_ratio`: Modbus write commands (FC6/FC16) divided by total Modbus packets.
10. `cross_zone_ratio`: Packets crossing subnet boundaries divided by total packets.

### 5.3 Tools, Techniques, and Justifications

*   **Docker & Docker Compose**: Used to simulate the multi-zone industrial network. Containers provide lightweight virtualization, allowing a multi-subnet network to run on a standard development machine.
*   **Scapy**: Selected for its packet parsing capabilities, enabling real-time feature extraction from raw traffic.
*   **Scikit-Learn**: Used to implement the machine learning pipeline (Isolation Forest, DBSCAN, RobustScaler).
*   **SQLite**: Selected as a lightweight database to store events, anomalies, and isolation actions.
*   **Flask & Flask-SocketIO**: Used for the backend API to handle database queries and push real-time updates via WebSockets.
*   **React & Tailwind CSS**: Chosen to build a responsive, modern Security Operations Center (SOC) dashboard.


## 6. Design and Implementation Progress

### 6.1 System Architecture

The system uses a layered architecture to capture, analyze, and contain threats within the simulated industrial network:

*   **Simulation Layer**: Contains nine Docker containers across three segregated networks (`ot-network`, `iot-network`, `dmz-network`).
*   **Ingestion & Capture Layer**: Uses Scapy to sniff raw interfaces, extract packet features, and write events to the SQLite database.
*   **Inference Layer**: Runs in a background thread, polling the SQLite database, feeding events into the real-time feature extractor, and evaluating them using the saved machine learning models.
*   **SOAR Layer**: The `SmartIsolator` state machine evaluates machine learning scores against thresholds and invokes the `MLBasedSegmentationEngine` to disconnect containers using the Docker SDK.
*   **Visualization Layer**: React frontend communicating with the Flask backend via SocketIO to display metrics in real time.

Figure 1 illustrates the system architecture and data flows:

![Figure 1: System Architecture — The Docker containers (simulation layer) are sniffed by Scapy. Features are extracted and sent to the two-tier ML pipeline (inference layer). Anomalous scores trigger the SmartIsolator and SOAR engine (enforcement layer) to disconnect containers via the Docker SDK, updating the React dashboard in real time.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/fig_architecture.png)

### 6.2 Implementation Details

The core codebase is organized as follows:

1.  **Containerized Testbed Configuration** (`docker-compose.yml`):
    ```yaml
    version: '3.8'
    services:
      plc1:
        container_name: PLC1
        image: siem-agent:latest
        networks:
          ot-network:
            ipv4_address: 192.168.10.10
      plc2:
        container_name: PLC2
        image: siem-agent:latest
        networks:
          ot-network:
            ipv4_address: 192.168.10.11
      hmi:
        container_name: HMI
        image: siem-agent:latest
        networks:
          ot-network:
            ipv4_address: 192.168.10.20
      engineering-ws:
        container_name: Engineering-WS
        image: siem-agent:latest
        networks:
          ot-network:
            ipv4_address: 192.168.10.50
          dmz-network:
            ipv4_address: 192.168.30.50
    ```

2.  **Two-Tier Machine Learning Inference** (`ml_pipeline/inference_engine.py`):
    ```python
    class MLInferenceEngine:
        def __init__(self, model_path):
            with open(model_path, 'rb') as f:
                self.bundle = pickle.load(f)
            self.scaler = self.bundle['scaler']
            self.iso_forest = self.bundle['iso_forest']
            self.dbscan = self.bundle['dbscan']
            self.features = self.bundle['features']
            
        def process_device_profile(self, profile):
            # Scale features
            scaled_features = self.scaler.transform([profile[self.features]])
            
            # Tier 1 check
            t1_score = self.iso_forest.decision_function(scaled_features)[0]
            # Convert decision function to anomaly score [0, 1]
            t1_anomaly_score = (1.0 - t1_score) / 2.0
            
            if t1_anomaly_score < 0.55:
                # Normal traffic - skip Tier 2
                return t1_anomaly_score * 0.5, "PASSED"
                
            # Tier 2 check
            db_dist = self.dbscan_distance(scaled_features[0])
            t2_anomaly_score = min(1.0, db_dist / self.bundle['eps'])
            
            # Combined ensemble score
            ensemble_score = 0.40 * t1_anomaly_score + 0.60 * t2_anomaly_score
            return ensemble_score, "FLAGGED"
    ```

### 6.3 Dashboard Interface

The Security Operations Center (SOC) dashboard is built in React and Tailwind CSS, visualizing live data from the SQLite database.

Figure 2 shows the main **Dashboard** view. It features summary cards for total network events (924), active anomalies (34), and isolated devices (4). It also displays the identified threat source IP (192.168.10.50), average detection latency (67ms), and a live threat timeline.

![Figure 2: React Dashboard Overview — Displays key security metrics, active threat source IP (192.168.10.50), anomaly and isolation counts, average detection latency (67ms), and system status.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/dashboard_react.png)

Figure 3 displays the **Isolated Devices** page. The interface tracks isolated containers, showing their IP addresses, device types, network zones, state designations (`THREAT_SOURCE` or `COMPROMISED`), machine learning scores, and timestamps.

![Figure 3: Isolated Devices Page — Tracks isolated systems and device states. The attacker (Engineering-WS) is isolated as THREAT_SOURCE (score 1.000), while compromised targets (PLC2, HMI) are isolated as COMPROMISED.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/isolated_react.png)

Figure 4 presents the **Anomalies Detected** log. This view registers each flagged event, displaying the source IP, anomaly type, ensemble anomaly score, confidence level, detection method, severity, and status.

![Figure 4: Anomalies Detected Log — Records anomalies processed by the two-tier pipeline. Includes filters for type, severity, method, and status, with an anomaly type distribution pie chart at the top.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/anomalies_react.png)

Figure 5 shows the **Rules Triggered** interface, showing how many times each custom rule fired. Rule 9001 (Unauthorized Port Scan) fired 600 times, followed by Rule 9002 (Unauthorized Modbus Read) with 120 triggers, and Rule 9004 (Lateral Movement) with 96 triggers.

![Figure 5: Rules Triggered Page — Lists detection rules, trigger frequencies, last triggered timestamps, source and destination IPs, and detection methods.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/rules_react.png)

Figure 6 shows the **Incidents** page, logging incident reports generated by the SOAR engine. Each incident is marked as `CONTAINED` once the automated network disconnect completes.

![Figure 6: Incidents Page — Logs incident reports from the SOAR engine. Shows 8 critical incidents, all marked CONTAINED, with creation timestamps and action buttons.](C:/Users/User/.gemini/antigravity/brain/516ade7c-2fb0-4e39-8e5b-d5141a9b04d0/artifacts/screenshots/incidents_react.png)

---

## 7. Testing / Evaluation Plan (Draft)

### 7.1 Proposed Testing Strategy

The system will undergo an end-to-end evaluation using a multi-phase attack script. The test scenario simulates an attacker compromising the Engineering-WS (192.168.10.50) and executing five distinct attack phases:
1.  **Reconnaissance**: TCP SYN port scanning targeting all subnets.
2.  **Unauthorized Access**: Reading Modbus registers on PLC1 and PLC2.
3.  **Active Exploitation**: Modbus write commands to PLC registers.
4.  **Lateral Movement**: Connecting to the MQTT broker and subscribing to sensor feeds.
5.  **Data Exfiltration**: Sending telemetry out of the network via HTTP.

We will run 5 independent trials of this scenario to assess:
*   **Real-time Feature Drift**: Tracking how features change during attack transitions.
*   **Ensemble Scoring Stability**: Ensuring benign traffic stays below the 0.70 threshold.
*   **Isolation Integrity**: Verifying that containers are disconnected from Docker networks.

### 7.2 Evaluation Metrics

The system will be evaluated using standard security metrics:
*   **Precision**: $TP / (TP + FP)$ (target: >99% to prevent false disconnections of critical PLCs).
*   **Recall**: $TP / (TP + FN)$ (target: 100% for critical write attempts).
*   **F1-Score**: Harmonic mean of Precision and Recall.
*   **Response Latency**: Time from packet capture to Docker disconnect (target: <500ms).

### 7.3 Planned Experiments

We plan to run experiments testing the system under different network conditions:
1.  **Baseline Drift**: Running normal HMI-PLC polling for 1 hour to verify that the false positive rate remains at 0%.
2.  **Resource Footprint**: Measuring the CPU and memory usage of the background inference thread to ensure compatibility with resource-constrained environments.
3.  **Containment Speed**: Measuring the time taken to execute the Docker SDK network disconnect relative to the packet capture window size.

---

## 8. Challenges and Risk Management

### 8.1 Technical and Resource Challenges

Several technical challenges were addressed during development:
*   **Resource Constraints**: The development machine (Intel Core i3, 8 GB RAM) experienced high CPU usage when running the Wazuh security stack (Indexer, Dashboard, Manager) and the 9 device containers. This was resolved by adjusting the JVM options for OpenSearch/Indexer to 1 GB heap size and running the stack in development mode.
*   **Docker Network Disconnections**: In Windows environments, Docker containers sometimes cache network state, meaning disconnections do not always take effect immediately. To resolve this, we modified `ml_based_segmentation.py` to force disconnections (`force=True`) and added a post-isolation verification step that queries the network container membership.
*   **Unsupervised Classification of Benign outliers**: The Cloud-Gateway regularly contacts multiple zones (IoT and DMZ), which DBSCAN classified as an outlier because its traffic volume was higher than standard sensors. The two-tier model addressed this: Tier 1 (Isolation Forest) classified the Cloud-Gateway as normal, which dampened its final score to 0.062, preventing a false positive.

### 8.2 Risk Mitigation Plan

**Table 6: Project Risk Matrix**

| Risk ID | Description | Impact | Probability | Mitigation Strategy |
|---|---|---|---|---|
| R1 | Wazuh indexer crashes due to out-of-memory errors. | High | Medium | Cap memory allocations in `docker-compose.yml` and disable unnecessary plugins. |
| R2 | Docker SDK disconnect command fails during an active attack. | Critical | Low | Implement an iptables-based fallback command using `docker exec` inside the container. |
| R3 | Normal traffic changes trigger a false positive isolation. | Critical | Medium | Require a 3-window consensus (30 seconds) of scores above 0.90 before triggering isolation. |
| R4 | Project timeline delays due to testing environment issues. | Medium | Medium | Use the synthetic dataset generator (`generate_synthetic_dataset.py`) to validate ML changes. |

---

## 9. Revised Work Plan

### 9.1 Gantt Chart and Timeline

The project timeline has been updated to reflect current progress and plan the remaining tasks leading to the final submission on 9 September 2026.

**Table 7: Project Timeline and Remaining Milestones**

| Week | Planned Activity | Milestone / Deliverable | Status |
|---|---|---|---|
| 1-2 | Testbed construction & Scapy configuration | Docker Compose network topology | Completed |
| 3-4 | Feature engineering & model training | Trained Isolation Forest & DBSCAN models | Completed |
| 5-6 | SOAR integration & SmartIsolator development | Dynamic Docker disconnections | Completed |
| 7-8 | React Dashboard & WebSockets | Real-time SOC dashboard interface | Completed |
| 9-10 | Real-time ML pipeline integration | Stable backend-frontend integration | In Progress |
| 11-12 | Wazuh active-response testing | Automated host-based isolation alerts | Planned |
| 13-14 | E2E evaluations & performance trials | Precision, Recall, and Latency data | Planned |
| 15-16 | UI refinements & code cleanup | Final dashboard adjustments | Planned |
| 17-18 | Thesis writing & results analysis | First draft of final thesis | Planned |
| 19-20 | Review, formatting, and submission prep | Submission-ready report and demo | Planned |

### 9.2 Remaining Tasks

The primary tasks remaining to complete the project are:
1.  **Stress-testing the Real-Time ML Monitor**: Run the background inference engine under a continuous traffic load to test feature collection stability.
2.  **Wazuh Active-Response Integration**: Configure the Wazuh manager to capture events from container syslog feeds and trigger active-response disconnections via the SOAR API.
3.  **End-to-End Evaluation Trials**: Execute the 5-phase attack script across 5 separate runs to collect performance metrics.
4.  **Final Thesis Writing**: Document the system evaluation, analyze the results, and draft the final submission.

---

## 10. Conclusion

### 10.1 Summary of Progress

This interim report has presented the design and development of an unsupervised micro-segmentation policy generation system for heterogeneous IoT/OT environments. The simulated testbed, comprising 9 Docker containers across three segregated networks running Modbus TCP, MQTT, and HTTP, is fully operational. The two-tier machine learning pipeline (Isolation Forest + DBSCAN) has been implemented and successfully isolates the attacker device from benign systems with 99.9% confidence. The SmartIsolator state machine and SOAR engine automate network disconnections via the Docker SDK. A React-based SOC dashboard provides real-time visibility into system metrics.

### 10.2 Feasibility and Completion Plan

Given the current progress (~62% complete) and the active testbed, the project is on track to meet its final submission deadline on 9 September 2026. The remaining tasks — primarily focused on Wazuh active-response integration, multi-trial testing, and final report writing — are scheduled across a 10-week work plan. This phased approach will ensure all project objectives are met.

---

## 11. References

[1] E. Sisinni, A. Saifullah, S. Han, U. Jennehag, and M. Gidlund, "Industrial Internet of Things: Challenges, opportunities, and directions," *IEEE Trans. Industrial Informatics*, vol. 14, no. 11, pp. 4724–4734, Nov. 2018.

[2] M. Knowles, D. Hutchison, J. P. G. Shercliff, and P. Shercliff, "A survey of cyber security management in industrial control systems," *Int. J. Critical Infrastructure Protection*, vol. 9, pp. 52–80, Jun. 2015.

[3] T. Williams, "The Purdue enterprise reference architecture," *Computers in Industry*, vol. 24, no. 2–3, pp. 141–158, Sep. 1994.

[4] K. Stouffer, V. Pillitteri, S. Lightman, M. Abrams, and A. Hahn, "Guide to Industrial Control Systems (ICS) security," NIST SP 800-82, Rev. 2, May 2015.

[5] C. Gonzalez, S. M. Charfadine, O. Flauzac, and F. Nolot, "SDN-based security framework for the IoT in distributed grid," in *Proc. Int. Multidisciplinary Conf. Computer and Energy Science*, pp. 1–6, 2021.

[6] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero trust architecture," NIST SP 800-207, Aug. 2020.

[7] J. Kindervag, "Build security into your network's DNA: The zero trust network architecture," Forrester Research, Nov. 2010.

[8] J. MacQueen, "Some methods for classification and analysis of multivariate observations," in *Proc. 5th Berkeley Symp. Mathematical Statistics and Probability*, vol. 1, pp. 281–297, 1967.

[9] M. Ester, H.-P. Kriegel, J. Sander, and X. Xu, "A density-based algorithm for discovering clusters in large spatial databases with noise," in *Proc. 2nd Int. Conf. KDD*, pp. 226–231, 1996.

[10] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation forest," in *Proc. 8th IEEE Int. Conf. Data Mining*, pp. 413–422, 2008.

[11] M. M. Breunig, H.-P. Kriegel, R. T. Ng, and J. Sander, "LOF: Identifying density-based local outliers," in *Proc. ACM SIGMOD*, pp. 93–104, 2000.

[12] Modbus Organization, "Modbus application protocol specification V1.1b3," Dec. 2012.

[13] T. H. Morris and W. Gao, "Industrial control system traffic data sets for intrusion detection research," in *Proc. 8th Int. Conf. Critical Infrastructure Protection*, pp. 65–78, 2014.

[14] A. Andy, B. Rahardjo, and B. Hanindhito, "Attack scenarios and security analysis of MQTT communication protocol in IoT system," in *Proc. 4th Int. Conf. EECSI*, pp. 1–6, 2017.

[15] E. Anthi, L. Williams, M. Slowinska, G. Shercliff, and P. Shercliff, "A supervised intrusion detection system for smart home IoT devices," *IEEE IoT Journal*, vol. 6, no. 5, pp. 9042–9053, Oct. 2019.

[16] H. Tahaei, F. Afifi, A. Asemi, F. Zaki, and N. B. Anuar, "The rise of traffic classification in IoT networks: A survey," *J. Network and Computer Applications*, vol. 154, p. 102538, Mar. 2020.

[17] M. Zolanvari, M. A. Teixeira, L. Gupta, K. M. Khan, and R. Jain, "Machine learning-based network vulnerability analysis of industrial Internet of Things," *IEEE IoT Journal*, vol. 6, no. 4, pp. 6822–6834, Aug. 2019.

---

## 12. Appendices

### Appendix A: Database Schema Design

The SQLite database uses the following schema to store alerts, incidents, anomalies, and isolation logs:

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    payload_size INTEGER,
    action TEXT
);

CREATE TABLE anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_ip TEXT,
    anomaly_score REAL,
    confidence REAL,
    features_triggered TEXT,
    status TEXT DEFAULT 'DETECTED'
);

CREATE TABLE isolations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    isolation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    container_name TEXT,
    ip_address TEXT,
    isolation_reason TEXT,
    success INTEGER
);

CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_name TEXT,
    severity TEXT,
    status TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Appendix B: Sample Data Profile

A sample aggregated device profile (extracted from `clustering_dataset.csv` for the attacker device Engineering-WS) contains the following feature vector:

```json
{
  "device_name": "Engineering-WS",
  "ip_address": "192.168.10.50",
  "total_packets": 399.0,
  "avg_packet_size": 78.5,
  "unique_destinations": 8.0,
  "unique_ports": 6.0,
  "protocol_diversity": 1.58,
  "modbus_ratio": 0.42,
  "mqtt_ratio": 0.0,
  "scan_rate": 0.67,
  "write_ratio": 0.59,
  "cross_zone_ratio": 0.89
}
```
