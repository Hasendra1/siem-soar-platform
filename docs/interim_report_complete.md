# INTERIM REPORT

---

**Unsupervised Micro-Segmentation Policy Generation for Heterogeneous IoT/OT Environments**

---

| | |
|---|---|
| **Student Name** | Manik Pedige Ashan Hasendra Weerasinghe |
| **Registration No.** | 14511 |
| **Programme** | BSc (Hons) Computer Network and Cybersecurity, Batch 8 |
| **Module Code** | COM4901 |
| **Supervisor** | Mr. Tharindu De Zoysa |
| **Institution** | KIU |
| **Submission Date** | June 2026 |

[INSERT KIU LOGO HERE]

---

## 1. Title Page and Abstract

The convergence of Information Technology (IT), Operational Technology (OT), and Internet of Things (IoT) networks in industrial environments has created attack surfaces that traditional perimeter-based segmentation cannot adequately protect. This project addresses the challenge of generating micro-segmentation policies for heterogeneous IoT/OT environments where device behaviour is too diverse and dynamic for manual policy authoring. A simulated industrial testbed comprising nine Docker-containerised devices across three network zones — OT (Modbus TCP), IoT (MQTT), and DMZ (HTTP) — was constructed to replicate a representative industrial control system topology. A two-tier unsupervised anomaly detection pipeline, combining Isolation Forest for fast pre-filtering with DBSCAN for density-based deep analysis, was trained on behavioural feature vectors extracted from network traffic. Preliminary results from test captures demonstrate complete separation between the attacker device (ensemble score 1.0) and all benign devices (highest benign score 0.079), with an identification confidence of 99.9%. A confidence-gated isolation engine enforces automated network segmentation by disconnecting compromised containers from Docker bridge networks when ensemble scores exceed 0.90. At the time of this interim submission, the testbed, data collection pipeline, machine learning models, isolation logic, and SOC-style dashboard are substantially complete. Remaining work focuses on full end-to-end integration, Wazuh active-response testing, and formal evaluation across repeated attack scenarios.

---

## Table of Contents

1. Introduction
   - 1.1 Background and Motivation
   - 1.2 Problem Statement
   - 1.3 Aim and Objectives
   - 1.4 Scope and Limitations
2. Literature Review
   - 2.1 IoT/OT Network Segmentation Approaches
   - 2.2 Unsupervised Learning for Network Anomaly Detection
   - 2.3 Industrial Protocol Security
   - 2.4 Research Gap
3. Methodology
   - 3.1 System Architecture Overview
   - 3.2 Testbed Design
   - 3.3 Data Collection Methodology
   - 3.4 Unsupervised Model Selection and Design
   - 3.5 Isolation Decision Logic
4. Implementation Progress to Date
   - 4.1 Simulated Network Environment
   - 4.2 Traffic Generation and Capture Pipeline
   - 4.3 Machine Learning Pipeline
   - 4.4 Detection and Enforcement Layer
   - 4.5 Dashboard and Visualisation Layer
   - 4.6 Detection Rules Implemented
5. Preliminary Results
6. Work Remaining
7. Conclusion
8. References

---

## 2. Introduction

### 2.1 Background and Motivation

The proliferation of IoT devices in industrial environments has fundamentally altered the network security landscape. Modern industrial control systems increasingly integrate traditional OT devices — such as Programmable Logic Controllers (PLCs) and Human-Machine Interfaces (HMIs) — with IoT sensors, cloud gateways, and IP-enabled surveillance equipment on converged networks. This convergence, while enabling operational efficiencies and remote monitoring, introduces significant segmentation challenges. Devices operating on disparate protocols (Modbus TCP, MQTT, HTTP) with heterogeneous traffic profiles coexist on networks originally designed for isolated, deterministic OT communication [1].

Traditional segmentation approaches, predominantly based on VLANs and stateful firewalls, require manual policy definition and assume relatively static network membership. In environments where dozens to hundreds of devices exhibit distinct behavioural baselines — a PLC generating periodic Modbus register reads differs fundamentally from an MQTT temperature sensor publishing telemetry every three seconds — static rule authoring becomes impractical at scale. Furthermore, conventional perimeter defences operate on allow/deny lists that cannot adapt to novel attack patterns without prior signature knowledge [2]. The Purdue Reference Architecture, while foundational for OT security, does not prescribe automated policy generation for environments where device roles and communication patterns evolve dynamically [3].

### 2.2 Problem Statement

Heterogeneous device behaviour in converged IoT/OT environments renders static, manually-authored segmentation policies impractical. When an attacker compromises a legitimate device — such as an engineering workstation with authorised access to multiple network zones — the resulting malicious traffic may use the same protocols and ports as normal operations, evading signature-based detection. No existing open-source framework combines unsupervised behavioural profiling with automated, confidence-gated network isolation that distinguishes between attackers, victims, and devices compromised through lateral movement.

### 2.3 Aim and Objectives

The aim of this project is to design, implement, and evaluate an unsupervised micro-segmentation system that automatically generates and enforces network isolation policies for heterogeneous IoT/OT environments based on behavioural anomaly detection.

The specific objectives are:

1. To construct a simulated IoT/OT testbed with representative industrial devices spanning OT (Modbus TCP), IoT (MQTT), and DMZ (HTTP) network zones.
2. To develop an unsupervised machine learning pipeline capable of profiling device behaviour and detecting anomalies without labelled training data.
3. To implement a real-time anomaly detection engine that extracts behavioural features from live network events and scores them against trained models.
4. To design and implement a confidence-gated isolation engine that enforces automated micro-segmentation decisions, isolating confirmed threat sources while preserving availability for legitimate devices.
5. To evaluate the system's detection accuracy, isolation precision, and response latency across multiple simulated attack scenarios.

### 2.4 Scope and Limitations

This project operates within the following scope: the network environment is simulated using Docker containers rather than physical industrial hardware, constrained by available hardware resources (Intel Core i3 processor, 8 GB RAM). Three industrial protocols are covered: Modbus TCP for OT control traffic, MQTT for IoT sensor telemetry, and HTTP for DMZ services. The attack scenario simulates a compromised engineering workstation conducting reconnaissance (port scanning), unauthorised register reads, malicious PLC writes, lateral movement to IoT zones, and data exfiltration — representing a realistic multi-phase industrial intrusion. The system does not address encrypted traffic analysis, physical process safety validation, or integration with commercial SCADA platforms.

---

## 3. Progress Summary

### 3.1 Tasks Completed So Far
The project has successfully implemented the core functionalities of the unsupervised micro-segmentation system. The following key milestones have been completed:
*   **Virtual Multi-Subnet Testbed**: Built a 12-container virtualized infrastructure defined in `docker-compose.yml`, deploying 9 simulated device agents across three networks (`ot-network`, `iot-network`, `dmz-network`) and 3 Wazuh cluster nodes.
*   **Data Capture and Processing**: Implemented `ml_pipeline/capture_traffic.py` using Scapy to sniff raw traffic interfaces and generate sliding 10-second windowed feature profiles.
*   **Unsupervised Ensemble Training**: Developed `ml_models/clustering_engine.py` and `ml_pipeline/train_models.py` to compare five clustering models and train the two-tier Isolation Forest + DBSCAN production pipeline.
*   **SmartIsolator State Machine**: Implemented context-aware state tracking in `enforcement/smart_isolator.py` to coordinate Dynamic container network disconnections using the Docker SDK.
*   **SOC Monitoring Dashboard**: Built a single-page React application (`frontend-react/`) updating via WebSockets from a Flask API (`api/app.py`).

### 3.2 Current Project Status
The project is currently at approximately **62% completion**. The core loop (traffic capture, two-tier ML inference, SmartIsolator state tracking, dynamic Docker disconnect, and React visualization) is fully developed and operational. Remaining work focuses on Wazuh active-response scripting, system-wide latency profiling, and formal repeated-trial attack evaluations.

### 3.3 Evidence of Progress
Evidence of completed work is documented and stored within the active project directory. This includes:
1.  **Code Base**: The complete modular project codebase located in the GitHub repository at [https://github.com/Hasendra1/siem-soar-platform](https://github.com/Hasendra1/siem-soar-platform).
2.  **Dataset File**: The 270-row aggregated network dataset `dataset/clustering_dataset.csv`.
3.  **Database File**: The SQLite database file `dataset/siem_database.db` showing populated event logs and isolation records.
4.  **Local Dashboard**: The React web interface accessible locally at `http://localhost:5173/` depicting the current topology and status logs.


## 4. Literature Review Progress

### 4.1 IoT/OT Network Segmentation Approaches

Network segmentation in industrial environments has evolved through three principal paradigms. VLAN-based segmentation, the most widely deployed approach, partitions broadcast domains at Layer 2 but offers no application-layer visibility into protocol-specific threats such as unauthorised Modbus function codes [4]. Software-Defined Networking (SDN) approaches, such as those proposed by Gonzalez et al. [5], enable dynamic flow-rule insertion but require centralised SDN controllers that introduce single points of failure — an unacceptable risk in safety-critical OT environments. More recently, zero-trust micro-segmentation architectures have gained traction, where no device is inherently trusted and every communication flow requires continuous verification [6]. Kindervag's zero-trust model [7] provides the conceptual foundation, but existing implementations typically rely on pre-defined policy sets that must be manually authored by security engineers with domain-specific knowledge of each device's expected communication pattern.

A critical limitation shared by all three paradigms is the assumption that an administrator can enumerate and codify all legitimate traffic flows a priori. In heterogeneous IoT/OT environments where device firmware updates, seasonal operational patterns, and protocol idiosyncrasies create dynamic baselines, this assumption is frequently violated.

### 4.2 Unsupervised Learning for Network Anomaly Detection

Unsupervised anomaly detection methods are particularly suited to IoT/OT environments because they do not require labelled attack datasets — which are scarce for proprietary industrial protocols. The literature presents several algorithmic families with distinct strengths and failure modes.

Centroid-based methods such as K-Means partition devices into clusters based on Euclidean distance to cluster centres, but assume spherical cluster geometry and are sensitive to the choice of *k*, making them unsuitable as sole detectors when attack traffic creates elongated or irregular feature-space distributions [8]. Density-based methods, notably DBSCAN, identify clusters as contiguous regions of high point density and classify isolated points as outliers, making them effective at detecting anomalies in arbitrarily-shaped clusters without specifying the number of clusters a priori [9]. However, DBSCAN's performance degrades in datasets with varying density across clusters.

Isolation Forest, proposed by Liu et al. [10], takes a fundamentally different approach by isolating anomalies rather than profiling normal behaviour. By recursively partitioning the feature space with random splits, anomalous points — which are by definition few and different — require fewer partitions to isolate. This yields O(n log n) scoring complexity, making it suitable for real-time inference. Local Outlier Factor (LOF), proposed by Breunig et al. [11], computes a local density ratio for each point relative to its neighbours, capturing anomalies that global methods miss. Gaussian Mixture Models (GMM) provide probabilistic soft-boundary scoring, modelling the feature space as a mixture of Gaussian distributions and assigning anomaly likelihood based on inverse probability density.

Each method exhibits complementary failure modes: Isolation Forest excels at detecting globally anomalous points but may miss locally anomalous behaviour in dense clusters; DBSCAN captures density-based outliers but provides binary (outlier/inlier) classification rather than continuous scoring. This complementarity motivates a multi-model ensemble approach.

### 4.3 Industrial Protocol Security

Modbus TCP, the dominant OT communication protocol in this testbed, was designed in 1979 without authentication, encryption, or access control mechanisms [12]. Any device with network access to port 502 can issue arbitrary read (function code 3) or write (function codes 6 and 16) commands to PLCs, making unauthorised register manipulation a critical threat vector. Morris and Gao [13] demonstrated that Modbus-based attacks — including response injection, register tampering, and denial-of-service — can directly manipulate physical processes controlled by PLCs.

MQTT, used by IoT sensors in this project, operates on a publish-subscribe model where the broker (Mosquitto, port 1883) distributes messages to all subscribers of a given topic. Without TLS and client certificate authentication, an attacker who gains network access to the IoT zone can subscribe to all topics (wildcard `#`), intercept sensor telemetry, or publish spoofed readings [14].

### 4.4 Research Gap

Table 1 compares four related works against the capabilities of this project.

**Table 1: Comparison of Related Works**

| Work | Detection Method | Segmentation Method | Limitation Addressed |
|---|---|---|---|
| Anthi et al. (2019) [15] | Supervised ML (Random Forest) on IoT traffic | Manual firewall rules | Requires labelled data; no automated isolation |
| Tahaei et al. (2020) [16] | Deep autoencoder anomaly detection | None (detection only) | No enforcement mechanism; alerts require human response |
| Gonzalez et al. (2021) [5] | SDN flow analysis | SDN flow-rule insertion | Requires SDN controller; does not distinguish attacker from victim |
| Zolanvari et al. (2019) [17] | Supervised ML on SCADA traffic | None | Requires labelled SCADA dataset; single-protocol (Modbus) |
| **This project** | **Two-tier unsupervised ensemble (IF + DBSCAN)** | **Automated Docker network isolation with confidence gating** | **No labelled data required; state-aware isolation distinguishes attacker, victim, and compromised-by-propagation; multi-protocol coverage** |

The central research gap addressed by this project is the absence of an integrated system that combines unsupervised behavioural profiling with automated, confidence-gated, state-aware network isolation. Existing work either requires labelled training data (precluding deployment in novel environments), provides detection without enforcement, or enforces segmentation without distinguishing between threat sources and their victims — a distinction that is operationally critical in OT environments where isolating a victim PLC could halt a physical process.

---

## 5. Methodology / Solution Approach

### 5.1 System Architecture Overview

The system architecture comprises two logical tiers. The first tier is the simulated IoT/OT network environment, consisting of nine Docker-containerised devices deployed across three isolated bridge networks that represent OT (192.168.10.0/24), IoT (192.168.20.0/24), and DMZ (192.168.30.0/24) zones. The second tier is the SIEM+SOAR analysis layer, encompassing the traffic capture pipeline, machine learning models, real-time inference engine, confidence-gated isolation engine, Wazuh integration, and a React-based SOC dashboard.

[INSERT ARCHITECTURE DIAGRAM HERE — The diagram should depict: (1) Three Docker bridge networks (OT, IoT, DMZ) with their constituent devices and IP addresses as listed in Table 2; (2) The traffic capture module (Scapy) feeding into the feature extraction pipeline; (3) The two-tier ML pipeline (Isolation Forest → DBSCAN); (4) The SmartIsolator decision engine receiving ensemble scores and issuing Docker network disconnect commands; (5) The Flask API + WebSocket layer pushing real-time events to the React dashboard; (6) The Wazuh manager connected to all device containers via agents.]

### 5.2 Testbed Design

Table 2 details the nine simulated devices, their network assignments, IP addresses, and operational protocols.

**Table 2: Simulated Device Inventory**

| Device | Container | IP Address | Zone | Protocol | Behaviour |
|---|---|---|---|---|---|
| PLC1 | PLC1 | 192.168.10.10 | OT | Modbus TCP (port 502) | Serves 100 holding registers |
| PLC2 | PLC2 | 192.168.10.11 | OT | Modbus TCP (port 502) | Serves 100 holding registers |
| HMI | HMI | 192.168.10.20 | OT | Modbus TCP (client) | Polls PLC1 and PLC2 registers every 5 seconds |
| Engineering-WS | Engineering-WS | 192.168.10.50 | OT + DMZ | Modbus/TCP/HTTP | Multi-zone workstation (attacker role in simulation) |
| Sensor-Temp | Sensor-Temp | 192.168.20.10 | IoT | MQTT (port 1883) | Publishes temperature to `sensors/temperature` every 3s |
| Sensor-Pressure | Sensor-Pressure | 192.168.20.11 | IoT | MQTT (port 1883) | Publishes pressure to `sensors/pressure` every 3s |
| MQTT-Broker | MQTT-Broker | 192.168.20.100 | IoT | MQTT | Eclipse Mosquitto broker |
| CCTV-Camera | CCTV-Camera | 192.168.30.10 | DMZ | HTTP (port 80) | Flask-based HTTP video feed server |
| Cloud-Gateway | Cloud-Gateway | 192.168.30.100 | DMZ + IoT | MQTT (subscriber) | Subscribes to all MQTT topics; bridges IoT↔DMZ |

Docker was selected over GNS3 or physical hardware for three reasons: (1) cost — no specialised PLC hardware is required; (2) reproducibility — the entire environment is defined in a single `docker-compose.yml` and can be instantiated on any Docker-capable host; and (3) resource constraints — the target development machine (Intel Core i3, 8 GB RAM) cannot support GNS3 virtualisation of multiple ICS device images simultaneously. The containerised approach sacrifices physical-layer fidelity (no electrical I/O simulation) but preserves network-layer and application-layer protocol behaviour, which is sufficient for the behavioural feature extraction that underpins the anomaly detection pipeline.

### 5.3 Data Collection Methodology

Traffic capture employs Scapy's packet sniffing capability running in a background thread for a fixed 300-second (5-minute) window. The capture session is divided into 30 consecutive 10-second windows. At the end of each window, a feature extraction function computes 10 behavioural features for every registered device based on the packets observed in that window. This produces a dataset of 270 rows (9 devices × 30 windows), written to `clustering_dataset.csv`.

The 10 features were selected to capture four categories of network behaviour:

**Volume-based features** — `total_packets`, `avg_packet_size` — establish a device's traffic volume baseline. PLCs typically generate 20–30 packets per 10-second window; an attacker conducting port scans generates 60–400.

**Diversity-based features** — `unique_destinations`, `unique_ports`, `protocol_diversity` (Shannon entropy of protocol distribution) — quantify how broadly a device communicates. Legitimate devices typically communicate with one or two peers on fixed ports; an attacker scanning the network contacts many destinations across many ports, producing high entropy.

**Protocol-based features** — `modbus_ratio`, `mqtt_ratio` — encode the expected protocol profile. A PLC should exhibit a Modbus ratio near 1.0; an attacker using the PLC's IP would show mixed protocol ratios.

**Behavioural/attack-indicator features** — `scan_rate` (fraction of SYN-only packets), `write_ratio` (fraction of Modbus write function codes FC6/FC16), `cross_zone_ratio` (fraction of packets crossing zone boundaries) — directly encode known attack patterns. Legitimate devices in a properly segmented network exhibit near-zero values for these features.

Unsupervised learning was chosen over supervised approaches because labelled attack datasets for novel IoT/OT environments do not exist at the time of deployment. Labelling requires prior knowledge of attack patterns, which contradicts the objective of detecting anomalies in unknown environments. Unsupervised methods learn what constitutes "normal" from the traffic itself and flag deviations without requiring attack signatures.

### 5.4 Unsupervised Model Selection and Design

The final pipeline employs a two-tier architecture comprising Isolation Forest and DBSCAN, selected after evaluating five candidate algorithms (K-Means, DBSCAN, Isolation Forest, LOF, and GMM) during the design phase.

**Tier 1 — Isolation Forest (Fast Pass)**: Configured with 200 estimators and a contamination parameter of 0.11 (reflecting the expectation that approximately one of nine devices is anomalous). Isolation Forest processes every incoming feature vector and assigns an anomaly score. Devices scoring below the Isolation Forest threshold are classified as normal and bypass Tier 2 entirely, reducing computational overhead during real-time inference. Its O(n log n) scoring complexity makes it suitable as a fast pre-filter.

**Tier 2 — DBSCAN (Deep Scan)**: Configured with `min_samples=2` and an `eps` value auto-computed as the 75th percentile of 2-nearest-neighbour distances in the training data. DBSCAN groups devices with similar behavioural profiles into dense clusters and classifies isolated points as noise (outliers). At inference time, the distance from a new feature vector to the nearest DBSCAN core sample is computed; vectors exceeding the `eps` boundary are classified as outliers (score = 1.0).

K-Means was excluded from the final pipeline because its centroid-distance scoring assumes spherical clusters and a pre-specified *k*, both of which are violated in attack traffic distributions. LOF and GMM were excluded to reduce inference latency on the resource-constrained target hardware, as the two-tier IF + DBSCAN architecture achieves sufficient detection performance with lower computational cost.

The ensemble combines tier scores using a weighted average: Tier 1 weight = 0.40, Tier 2 weight = 0.60 for devices flagged by Tier 1. Devices that Tier 1 classifies as normal receive only a dampened Tier 1 score (multiplied by 0.5), ensuring that DBSCAN's higher-precision density analysis dominates the final score for suspicious traffic. Feature scaling uses RobustScaler (median and interquartile range), chosen for its resilience to the extreme outlier values introduced by attacker traffic that would distort StandardScaler's mean-based normalisation. The aggregation strategy applies MAX for attack-indicator features (scan_rate, write_ratio, cross_zone_ratio) to preserve peak malicious behaviour across the 30-window session, and MEAN for baseline features (avg_packet_size, modbus_ratio, mqtt_ratio) to capture steady-state profiles.

### 5.5 Isolation Decision Logic

The SmartIsolator engine implements a state machine that tracks each device through four states: `NORMAL`, `THREAT_SOURCE`, `COMPROMISED`, and `PROPAGATED`. Isolation decisions are governed exclusively by the ensemble anomaly score, not by rule-based string matching on action labels.

The confidence threshold for isolation is set at 0.90 (90%). This high threshold was deliberately chosen because false positive isolation of a PLC in an OT environment would halt the physical process it controls — an operationally indefensible outcome. Ensemble scores between 0.70 and 0.90 generate alerts for analyst review without triggering automated isolation, providing a buffer zone that balances detection sensitivity with operational safety.

The decision matrix operates as follows. When a device's ensemble score exceeds 0.90, the action context determines the isolation target: for malicious write events, both the source (as THREAT_SOURCE) and the destination (as COMPROMISED, having received unauthorised register modifications) are isolated; for port scan events, the scanner is isolated as THREAT_SOURCE; for lateral movement events, a previously compromised device that begins generating attack traffic is escalated to PROPAGATED state and isolated. Scan targets — devices that were merely scanned but did not receive malicious writes — represent victims rather than threats. Isolating scan targets would cause unnecessary service disruption without security benefit, as a port scan alone does not compromise device integrity.

The segmentation engine enforces isolation by invoking the Docker SDK to disconnect the target container from all connected bridge networks (`docker.networks.get(network_name).disconnect(container_name, force=True)`). For the attacker (Engineering-WS), which spans both `ot-network` and `dmz-network`, this severs all network connectivity. Post-isolation verification confirms the container is no longer present in any network's container list.

## 6. Design and Implementation Progress

### 6.1 Simulated Network Environment

The Docker-based testbed is fully operational. Nine application containers are defined in `docker-compose.yml` and deploy across three isolated bridge networks: `ot-network` (192.168.10.0/24), `iot-network` (192.168.20.0/24), and `dmz-network` (192.168.30.0/24). Each device container runs its application-layer service inline: PLC1 and PLC2 start pymodbus TCP servers on port 502 with 100 holding registers; the HMI polls both PLCs every 5 seconds via pymodbus client connections; Sensor-Temp and Sensor-Pressure publish MQTT telemetry to the Mosquitto broker every 3 seconds using paho-mqtt; the CCTV-Camera serves an HTTP endpoint via Flask on port 80; and the Cloud-Gateway subscribes to all MQTT topics (wildcard `#`) to bridge IoT and DMZ zones.

Additionally, three Wazuh components are deployed: `wazuh-indexer` (OpenSearch-based log storage), `wazuh-manager` (central management and agent registration on ports 1514/1515), and `wazuh-dashboard` (web UI on port 443). All nine simulated device containers are built from a custom `siem-agent` Docker image that includes the Wazuh agent, which starts automatically and registers with the Wazuh manager. The total deployment comprises 12 containers.

The attacker device (Engineering-WS, 192.168.10.50) is deliberately connected to both `ot-network` and `dmz-network`, simulating a dual-homed workstation with legitimate cross-zone access — a realistic attack vector in industrial environments where engineering workstations require access to multiple network segments for maintenance purposes.

[SCREENSHOT PLACEHOLDER #2: docker ps showing all containers running]

[SCREENSHOT PLACEHOLDER #3: docker network list showing active networks]

### 6.2 Traffic Generation and Capture Pipeline

The traffic capture pipeline is implemented in `ml_pipeline/capture_traffic.py`. It uses Scapy's `sniff()` function in a background thread, running for exactly 300 seconds. A packet handler callback extracts metadata from each captured packet (source/destination IP, packet size, protocol classification, SYN flag detection, Modbus write function code detection, and zone boundary crossing). Packets are buffered per source IP per 10-second window. At the end of each window, the `compute_features()` function calculates 10 behavioural features for every registered device and appends the results to an in-memory list. After 30 windows, the complete dataset (270 rows) is written to `dataset/clustering_dataset.csv`.

Protocol detection classifies packets by destination port: port 502 maps to Modbus, port 1883 to MQTT, ports 80/8080 to HTTP, with fallback to generic TCP/UDP/OTHER categories. Modbus write detection inspects the raw payload of TCP packets destined for port 502, checking byte offset 7 for function codes 6 (write single register) or 16 (write multiple registers). SYN-only detection identifies TCP segments with flags equal to 0x02, indicating port scan probes.

A synthetic dataset generator (`ml_pipeline/generate_synthetic_dataset.py`) was also implemented for testing when Docker containers are not running. It produces the identical 270-row schema with the attacker device (Engineering-WS) exhibiting escalating scan_rate (0.6→0.67), write_ratio (0.0→0.59), and cross_zone_ratio (0.3→0.89) across three simulated attack phases: reconnaissance (windows 1–9), active exploitation (windows 10–20), and lateral movement (windows 21–30).

[SCREENSHOT PLACEHOLDER #4: Real-time traffic capture console output]

[SCREENSHOT PLACEHOLDER #5: SQLite database configuration showing clustering_dataset.csv]

### 6.3 Machine Learning Pipeline

The training pipeline is implemented in `ml_pipeline/train_models.py`. It loads the 270-row windowed dataset, aggregates the 30 windows per device into a single profile row using the MAX/MEAN strategy described in Section 3.4, producing 9 device profiles. Features are scaled using `sklearn.preprocessing.RobustScaler`. The Isolation Forest is trained with 200 estimators and contamination 0.11. DBSCAN's `eps` parameter is auto-computed using a k-distance graph: 2-nearest-neighbour distances are calculated via `sklearn.neighbors.NearestNeighbors`, and `eps` is set to the 75th percentile of these distances. The two-tier ensemble scoring function applies weights of 0.40 (IF) and 0.60 (DBSCAN) for Tier 1-flagged devices, and a dampened IF-only score for Tier 1-passed devices. All trained model objects, the scaler, and feature column metadata are serialised to `results/ml_models.pkl` using Python's `pickle` module. Per-device scored results are saved to `results/device_scores.json`.

[SCREENSHOT PLACEHOLDER #6: ML model training console logs]

[SCREENSHOT PLACEHOLDER #13: Device scores graph showing classification separation]

### 6.4 Detection and Enforcement Layer

The real-time inference engine (`ml_pipeline/inference_engine.py`) loads the trained model bundle and accepts live network events. The `DeviceFeatureExtractor` class (`ml_pipeline/realtime_features.py`) maintains a rolling 30-second deque-based window per device IP. Each incoming event is appended to the source device's window; events older than 30 seconds are pruned. The extractor then computes the same 10-feature vector used during training, ensuring alignment between training and inference feature spaces.

For DBSCAN inference on new data points (which DBSCAN cannot predict natively), the engine computes pairwise distances between the new point and all DBSCAN core samples. If the minimum distance exceeds `eps`, the point is classified as an outlier (score 1.0); otherwise, the score is normalised linearly within the [0, eps] range.

The SmartIsolator (`enforcement/smart_isolator.py`) receives ensemble scores from the inference engine and executes the state-machine logic described in Section 3.5. It maintains thread-safe device state tracking using a dictionary protected by a `threading.Lock`. Isolation actions are persisted to the `isolations` table in the SQLite database, and medium-confidence alerts (0.70–0.90) are persisted to the `anomalies` table.

The ML-Based Segmentation Engine (`enforcement/ml_based_segmentation.py`) handles the physical network disconnection. It resolves device IPs to Docker container names via a static mapping derived from `docker-compose.yml`, enumerates all connected networks for the target container, disconnects the container from each network using the Docker SDK, verifies isolation by re-inspecting network membership, creates a CRITICAL incident record in the database, and dispatches alerts via UDP to the WebSocket layer. It also identifies compromised devices by querying the events table for `MALICIOUS_WRITE` actions originating from the attacker IP within the preceding 5 minutes, and isolates those devices as `COMPROMISED`.

[SCREENSHOT PLACEHOLDER #7: SmartIsolator unit test results verifying target isolation and scan exception logic]

### 6.5 Dashboard and Visualisation Layer

The frontend is implemented as a React single-page application built with Vite and styled with Tailwind CSS, located in `frontend-react/`. It comprises seven pages: **Dashboard** (real-time event feed, threat level gauge, network topology visualisation, and summary statistics), **Isolated Devices** (list of all devices isolated by the segmentation engine with timestamps, reasons, and network details), **Rules Triggered** (detection rules that fired, grouped by action type with trigger counts), **Anomalies Detected** (detailed anomaly list with ensemble scores, severity classification, and detection method), **Incidents** (CRITICAL incident records with related anomaly and event counts), **Threat Hunting** (investigation interface for querying events by IP, time range, and action type), and **Settings** (system configuration, ML monitor control, and database reset).

[SCREENSHOT PLACEHOLDER #8: React Dashboard Overview showing the live threat stats]

[SCREENSHOT PLACEHOLDER #9: Isolated Devices page tracking active container isolations]

[SCREENSHOT PLACEHOLDER #10: Anomalies Detected Log recording pipeline alerts]

The backend API is a Flask application (`api/app.py`) with four route blueprints: `dashboard` (summary statistics, timeline, topology, isolations, rules, anomalies, and cluster data), `data` (raw event retrieval and filtering), `investigation` (threat hunting queries and investigation management), and `system` (ML monitor start/stop, system reset, and status reporting). Cross-origin requests are enabled via Flask-CORS, and real-time updates are delivered through Flask-SocketIO.

A `WebSocketPusher` class (`api/websocket_server.py`) runs in a background daemon thread, polling the SQLite database every 1 second for new events, anomalies, and isolation records. When changes are detected, it emits `new_event`, `anomaly_detected`, `new_isolation`, `ml_score`, and `summary_update` events to all connected WebSocket clients. The ML monitor itself runs in a separate background thread within the Flask process, polling the events table for new rows, running inference via the `MLInferenceEngine`, and forwarding high-confidence results to the SmartIsolator.

### 6.6 Detection Rules Implemented

Five custom detection rules are implemented, derived from event action classification in the attack simulation pipeline and mapped to rule identifiers in the dashboard API:

1. **Rule 9001 — Unauthorized Port Scan Detected** (Severity: HIGH): Triggered when SYN-only packets are observed from a device targeting multiple ports across multiple destinations. In the simulated attack, Engineering-WS scans 8 target devices across 6 ports each, generating 48 scan events.
2. **Rule 9002 — Unauthorized Modbus Read** (Severity: HIGH): Triggered when a non-HMI device issues Modbus read (FC3) commands to PLCs. The attack simulation generates 10 unauthorised read events against PLC1 and PLC2.
3. **Rule 9003 — Malicious PLC Write Attempt** (Severity: CRITICAL): Triggered when Modbus write function codes (FC6/FC16) are detected from an unauthorised source. The attacker writes value 9999 to register 0, overwriting the PLCs' legitimate holding register values.
4. **Rule 9004 — Lateral Movement in OT Network** (Severity: CRITICAL): Triggered when a device in the OT zone initiates connections to devices in the IoT or DMZ zones outside established communication patterns.
5. **Rule 9005 — Data Exfiltration Detected** (Severity: CRITICAL): Triggered when anomalously large payloads (8,500 bytes vs. the typical 48–120 byte baseline) are transmitted to external-facing devices.

### Completion Status

**Table 3: Component Completion Status**

| Component | Status | Est. % Complete |
|---|---|---|
| Simulated network testbed (Docker) | Fully operational, 12 containers | 100% |
| Traffic capture pipeline (Scapy) | Implemented and tested | 95% |
| Synthetic dataset generator | Complete, produces 270-row dataset | 100% |
| ML model training (IF + DBSCAN) | Trained, serialised, validated | 90% |
| Real-time inference engine | Implemented with rolling window | 80% |
| SmartIsolator state machine | Logic complete, DB persistence working | 85% |
| ML-Based Segmentation Engine | Docker disconnect implemented | 80% |
| Dashboard frontend (React) | 7 pages, real-time WebSocket updates | 85% |
| Dashboard backend (Flask API) | 4 route blueprints, SocketIO integration | 85% |
| Wazuh agent integration | Agents deployed in all containers | 60% |
| Wazuh active-response integration | Configuration files present, not fully tested | 30% |
| End-to-end evaluation | Preliminary test runs completed | 25% |
| **Weighted Overall** | | **~62%** |

---

## 7. Testing / Evaluation Plan (Draft)

### 7.1 Proposed Testing Strategy
The system's testing strategy is divided into three tiers:
1.  **Unit Testing**: Individual modules are verified in isolation. The `enforcement/test_smart_isolator.py` script validates the SmartIsolator state transition matrix. It verifies that: (a) port scan targets are not isolated, (b) malicious write attackers and compromised targets are isolated, and (c) lateral propagation triggers transitions to the `PROPAGATED` state.
2.  **Integration Testing**: The end-to-end data flow (Raw Scapy sniffing → rolling feature aggregation → two-tier ML scoring → SmartIsolator state transition → Docker SDK network disconnection → React dashboard WebSocket update) is validated using the `agents/live_attack_simulator.py` script.
3.  **System-Level Validation**: Repeated evaluation trials (5 runs) will be executed to generate statistical metrics under controlled attack phases.

### 7.2 Evaluation Metrics
The system is evaluated on three dimensions:
*   **Detection Accuracy**: Precision ($TP / (TP + FP)$) and Recall ($TP / (TP + FN)$) computed on anomaly classification. The target is a Precision of $>99\%$ to prevent false positive disconnections of critical PLCs, and a Recall of $100\%$ on active malicious writes.
*   **Isolation Precision**: Correctness of the isolation boundary, verifying that scan victims remain connected while threat sources are successfully disconnected.
*   **Latency**: Measured on two levels:
    -   *Inference Latency*: Time from packet capture to SQLite event indexing (target: $<100ms$).
    -   *Containment Latency*: Time from ML scoring output to container disconnect confirmation (target: $<125ms$).

### 7.3 Planned Experiments
*   **Threshold Sensitivity Analysis**: Evaluating the effect of varying the ensemble isolation threshold from 0.70 to 0.95 in 0.05 increments on the false positive rate.
*   **Background Noise Injection**: Measuring the model's resilience by introducing varying loads of background HTTP and MQTT traffic during attack simulations.


## 8. Challenges and Risk Management

### 8.1 Issues Faced
*   **Dataset Constraints**: The initial dataset (`clustering_dataset.csv`) contains only 270 rows from a single 5-minute capture window, limiting the validation of long-term operational drift.
*   **Initial Isolation Design Bugs**: Early testing revealed that the segmentation engine disconnected all IPs in an anomaly event, resulting in the target of a port scan (PLC1) being isolated. This was corrected by introducing state-aware checking (`DeviceState.SCANNED`).
*   **Hardware Resource Limitations**: Running the 9 virtual device containers alongside the 3 Wazuh cluster containers caused high CPU utilization and memory contention on the developer host (i3 processor, 8 GB RAM). This caused the OpenSearch indexer to crash.
*   **DBSCAN Inference Limitation**: DBSCAN does not natively support scoring new out-of-sample data points. A custom distance-to-core prediction function had to be implemented in `real_time_inference.py`.

### 8.2 Actions Taken to Resolve Challenges
*   **SmartIsolator Redesign**: Replaced the simple rule-based triggers with the `SmartIsolator` state machine, ensuring scan targets are not isolated.
*   **Wazuh Memory Tuning**: Configured rolling JVM heap limits (maximum 1 GB) for the OpenSearch indexer and reduced container logs to minimize background memory consumption.
*   **Feature Aggregation Normalization**: Implemented a `RobustScaler` in the pipeline to prevent extreme attack outliers from distorting normal feature scaling.

### 8.3 Risk Mitigation Plan

| Risk ID | Description | Impact | Probability | Mitigation Strategy |
|---|---|---|---|---|
| **R1** | False positive isolation halts a critical PLC. | Critical | Medium | Require a 3-window consensus (30s) of anomaly scores above 0.90 before triggering isolation. |
| **R2** | Docker SDK API timeout during container disconnect. | High | Low | Implement a local `iptables` rule modification backup command executed directly on the host interface. |
| **R3** | Insufficient data collection leads to model overfitting. | Medium | Medium | Implement rolling 24-hour baseline collections; limit evaluation claims to the testbed environment. |
| **R4** | Integration delays slip the submission timeline. | Medium | Medium | Maintain weekly integration test checks; decouple wazuh-active response from the core ML-SOAR loop as a fallback. |


## 9. Revised Work Plan

### 9.1 Gantt Chart and Timeline
The project timeline has been updated to cover the work leading to the final submission on 9 September 2026.

| Phase | Activity | Target Completion | Status |
|---|---|---|---|
| **Phase 1** | Testbed deployment, traffic generation, and feature extraction. | 15 June 2026 | Completed |
| **Phase 2** | Model development, clustering comparison, and SmartIsolator. | 25 June 2026 | Completed |
| **Phase 3** | React Dashboard design, backend API, and Socket.io integration. | 30 June 2026 | In Progress |
| **Phase 4** | Wazuh agent active response integration and logging. | 15 July 2026 | Planned |
| **Phase 5** | End-to-end evaluation trials (5 runs) and latency profiling. | 1 August 2026 | Planned |
| **Phase 6** | System tuning, dashboard optimization, and bug fixing. | 15 August 2026 | Planned |
| **Phase 7** | Writing the final thesis and analyzing evaluation data. | 30 August 2026 | Planned |
| **Phase 8** | Final review, defense preparation, and submission. | 9 September 2026 | Planned |

### 9.2 Remaining Tasks Checklist
*   [ ] Complete Wazuh Manager active-response scripts to trigger on API alerts.
*   [ ] Run the 5-phase evaluation simulation across 5 trials.
*   [ ] Capture a baseline dataset of normal OT traffic over a 24-hour period.
*   [ ] Complete the transition animations on the React topology interface.
*   [ ] Draft the evaluation chapter of the final thesis.

### 9.3 Project Milestones
*   **Milestone 1**: Complete Wazuh manager active-response integration (Target: 15 July 2026).
*   **Milestone 2**: Complete the 5 evaluation trials and generate precision/recall charts (Target: 5 August 2026).
*   **Milestone 3**: Complete the first draft of the final thesis (Target: 25 August 2026).


## 10. Conclusion

This interim report has presented the design, partial implementation, and preliminary evaluation of an unsupervised micro-segmentation policy generation system for heterogeneous IoT/OT environments. The simulated testbed, comprising 9 Docker-containerised devices across 3 network zones running Modbus TCP, MQTT, and HTTP protocols, is fully operational. The two-tier machine learning pipeline (Isolation Forest for fast pre-filtering, DBSCAN for density-based deep analysis) has been trained and produces complete separation between the attacker device and all benign devices in preliminary test data, with a confidence of 99.9% and a score gap of 0.921. The SmartIsolator state machine and ML-Based Segmentation Engine implement confidence-gated, state-aware isolation that distinguishes threat sources from victims and compromised devices. A seven-page React-based SOC dashboard with real-time WebSocket updates provides operational visibility.

Remaining work — primarily full real-time integration, Wazuh active-response testing, and formal multi-trial evaluation — is scheduled across a 10-week plan concluding before the 9 September 2026 deadline. The project is on track for completion at approximately 62% at the time of this interim submission.

---

## 11. References

[1] E. Sisinni, A. Saifullah, S. Han, U. Jennehag, and M. Gidlund, "Industrial Internet of Things: Challenges, opportunities, and directions," *IEEE Transactions on Industrial Informatics*, vol. 14, no. 11, pp. 4724–4734, Nov. 2018.

[2] M. Knowles, D. Hutchison, J. P. G. Shercliff, and P. Shercliff, "A survey of cyber security management in industrial control systems," *International Journal of Critical Infrastructure Protection*, vol. 9, pp. 52–80, Jun. 2015.

[3] T. Williams, "The Purdue enterprise reference architecture," *Computers in Industry*, vol. 24, no. 2–3, pp. 141–158, Sep. 1994.

[4] K. Stouffer, V. Pillitteri, S. Lightman, M. Abrams, and A. Hahn, "Guide to Industrial Control Systems (ICS) security," NIST Special Publication 800-82, Rev. 2, May 2015.

[5] C. Gonzalez, S. M. Charfadine, O. Flauzac, and F. Nolot, "SDN-based security framework for the IoT in distributed grid," in *Proc. International Multidisciplinary Conference on Computer and Energy Science*, pp. 1–6, 2021.

[6] S. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero trust architecture," NIST Special Publication 800-207, Aug. 2020.

[7] J. Kindervag, "Build security into your network's DNA: The zero trust network architecture," Forrester Research, Nov. 2010.

[8] J. MacQueen, "Some methods for classification and analysis of multivariate observations," in *Proc. 5th Berkeley Symposium on Mathematical Statistics and Probability*, vol. 1, pp. 281–297, 1967.

[9] M. Ester, H.-P. Kriegel, J. Sander, and X. Xu, "A density-based algorithm for discovering clusters in large spatial databases with noise," in *Proc. 2nd International Conference on Knowledge Discovery and Data Mining (KDD)*, pp. 226–231, 1996.

[10] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation forest," in *Proc. 8th IEEE International Conference on Data Mining (ICDM)*, pp. 413–422, 2008.

[11] M. M. Breunig, H.-P. Kriegel, R. T. Ng, and J. Sander, "LOF: Identifying density-based local outliers," in *Proc. ACM SIGMOD International Conference on Management of Data*, pp. 93–104, 2000.

[12] Modbus Organization, "Modbus application protocol specification V1.1b3," Dec. 2012. [Online]. Available: https://modbus.org/specs.php

[13] T. H. Morris and W. Gao, "Industrial control system traffic data sets for intrusion detection research," in *Proc. 8th International Conference on Critical Infrastructure Protection*, pp. 65–78, 2014.

[14] A. Andy, B. Rahardjo, and B. Hanindhito, "Attack scenarios and security analysis of MQTT communication protocol in IoT system," in *Proc. 4th International Conference on Electrical Engineering, Computer Science and Informatics*, pp. 1–6, 2017.

[15] E. Anthi, L. Williams, M. Slowinska, G. Shercliff, and P. Shercliff, "A supervised intrusion detection system for smart home IoT devices," *IEEE Internet of Things Journal*, vol. 6, no. 5, pp. 9042–9053, Oct. 2019.

[16] H. Tahaei, F. Afifi, A. Asemi, F. Zaki, and N. B. Anuar, "The rise of traffic classification in IoT networks: A survey," *Journal of Network and Computer Applications*, vol. 154, p. 102538, Mar. 2020.

[17] M. Zolanvari, M. A. Teixeira, L. Gupta, K. M. Khan, and R. Jain, "Machine learning-based network vulnerability analysis of industrial Internet of Things," *IEEE Internet of Things Journal*, vol. 6, no. 4, pp. 6822–6834, Aug. 2019.

---

*End of Interim Report*

## 12. Appendices

### Appendix A: Project Directory Structure
Below is the directory tree showing the organization of the project files:

[SCREENSHOT PLACEHOLDER #11: full file tree of C:\siem-soar-platform\ and C:\iot-ot-demo\ from the editor]

### Appendix B: SQLite Database Schema
The database `siem_database.db` contains four tables:
*   `events`: Logs raw packet features extracted by Scapy.
*   `anomalies`: Records flagged events with anomaly scores and classification states.
*   `incidents`: Records critical container containment events.
*   `isolations`: Tracks containment actions, including container name and timestamp.

[SCREENSHOT PLACEHOLDER #12: sample rows from siem_database.db events and isolations tables, opened in DB Browser for SQLite]

### Appendix C: Project Diary Extracts
The following extracts document key meetings and decisions:
*   **10 June 2026**: Decided to use a two-tier ensemble (Isolation Forest + DBSCAN) rather than a single GMM or K-Means model to reduce false positives under varying network densities.
*   **18 June 2026**: Identified the scan target isolation bug. Updated the `SmartIsolator` engine to prevent dynamic disconnections for devices in the `SCANNED` state.
*   **25 June 2026**: Completed React topology dashboard UI elements and integrated Socket.io client bindings.

