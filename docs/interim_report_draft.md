# 1. TITLE PAGE

**UNIVERSITY NAME:** KIU  
**FACULTY:** Faculty of Computer Science and Engineering  
**PROGRAMME:** BSc (Hons) Computer Network and Cybersecurity, Batch 8  
**MODULE CODE:** COM4901 (Individual Project - Interim Report)  

---

**PROJECT TITLE:**  
# Unsupervised Micro-Segmentation Policy Generation for Heterogeneous IoT/OT Environments

---

**STUDENT NAME:** Manik Pedige Ashan Hasendra Weerasinghe  
**STUDENT ID / REGISTRATION NO:** 14511  
**SUPERVISOR NAME:** Mr. Tharindu De Zoysa  
**SUBMISSION DATE:** [CONFIRM EXACT SUBMISSION DATE]  
**FINAL DEMO DEADLINE:** 9 September 2026  

---

\newpage

# 2. INTRODUCTION

## 2.1 Background and Context
The digital transformation of industrial enterprises has led to the convergence of Information Technology (IT) and Operational Technology (OT) networks, creating what is now referred to as the Industrial Internet of Things (IIoT). Traditionally, OT networks — containing Programmable Logic Controllers (PLCs), Human-Machine Interfaces (HMIs), and Supervisory Control and Data Acquisition (SCADA) systems — were isolated from the internet through physical air-gaps. They relied on proprietary communication protocols that lacked basic security controls like encryption and authentication. However, the modern requirement for real-time telemetry, remote diagnostics, and cloud-based predictive maintenance has forced these networks to interconnect.

This convergence exposes legacy OT devices to external threat vectors. A converged environment is highly heterogeneous, hosting legacy PLCs (running Modbus TCP), smart sensors (running MQTT), and monitoring servers (running HTTP) on the same shared subnets. Traditional network security relies on perimeter firewalls and virtual local area networks (VLANs). These static segmentation strategies are no longer sufficient. They require manual rule authoring, which does not scale across hundreds of devices with distinct behavioral baselines. If an attacker gains entry to a high-privilege system, such as a dual-homed engineering workstation, perimeter firewalls cannot prevent lateral movement within the trust zone. Micro-segmentation is therefore required to enforce security policies down to the individual device interface.

## 2.2 Problem Statement
Implementing micro-segmentation in heterogeneous IoT/OT environments faces three major challenges:
1.  **Absence of Labeled Datasets**: Real-world industrial control systems rarely have labeled historical logs of network intrusions. Supervised machine learning algorithms cannot be trained to recognize novel or zero-day threats in these environments without generating high rates of false negatives or requiring expensive, manual labelling.
2.  **Manual Authoring and Scalability Constraints**: Heterogeneous networks exhibit complex, varying communication profiles. A PLC polling a Modbus server every 100 milliseconds produces a vastly different network fingerprint than an MQTT publisher sending status reports every three seconds. Manually defining access policies for each device type is labor-intensive and error-prone.
3.  **Lack of Context in Automated Enforcement**: Existing intrusion detection systems (IDS) evaluate anomalies based on isolated packets or connection attempts. They do not distinguish between the initiator of an attack (the threat source), the target of a scan (the victim), and a device that has been compromised through lateral movement. Naive automated segmentation policies that isolate every flagged IP can lead to self-inflicted denial-of-service (DoS) conditions, taking critical, uncompromised PLCs offline and disrupting physical operations.

## 2.3 Project Aim and Objectives
The aim of this project is to develop and evaluate an unsupervised micro-segmentation system that automatically generates and enforces network isolation policies for heterogeneous IoT/OT environments using real-time behavioral anomaly detection and context-aware enforcement logic.

To achieve this aim, the project is structured around the following objectives:
1.  **Objective 1**: To design and implement a containerized multi-subnet testbed representing OT (Modbus TCP), IoT (MQTT), and DMZ (HTTP) zones with representative traffic profiles.
2.  **Objective 2**: To develop a Scapy-based network capture and feature extraction pipeline that processes raw traffic streams into windowed behavioral vectors.
3.  **Objective 3**: To implement and train an unsupervised machine learning ensemble using five distinct algorithms (K-Means, DBSCAN, Hierarchical Clustering, Spectral Clustering, and Gaussian Mixture Models) to identify behavioral anomalies without labeled data.
4.  **Objective 4**: To design and build a state-aware isolation engine (SmartIsolator) that tracks device states and coordinates with the Docker SDK to disconnect compromised nodes while maintaining availability for normal hosts.
5.  **Objective 5**: To implement a web-based Security Operations Center (SOC) dashboard that visualizes real-time network topology, active alerts, machine learning scores, and isolation history.

---

# 3. PROGRESS SUMMARY

## 3.1 Tasks Completed So Far
The project's key milestones completed to date include:
*   **Multi-Zone Docker Testbed**: Built a 12-container virtualized infrastructure defined in `docker-compose.yml`. The testbed partitions the network into three subnets: `ot-network` (`192.168.10.0/24`), `iot-network` (`192.168.20.0/24`), and `dmz-network` (`192.168.30.0/24`). It deploys nine simulated device agents (PLCs, HMI, Sensors, Gateway, Broker, CCTV) and three Wazuh SIEM containers.
*   **Traffic Capture and Feature Extraction**: Completed the `capture_traffic.py` background sniffing agent. The script uses Scapy to sniff virtual network interfaces and aggregates packets into 10-second sliding windows, extracting 14 network features per window.
*   **Clustering Engine and Model Training**: Developed `ml_models/clustering_engine.py` and `ml_pipeline/train_models.py`. These scripts implement a two-tier ensemble consisting of Isolation Forest (Tier 1) for fast pre-filtering and DBSCAN (Tier 2) for deep outlier analysis. They aggregate the 14-feature dataset and output normalized anomaly scores.
*   **SmartIsolator State Machine**: Designed and unit-tested the `SmartIsolator` state tracking logic in `enforcement/smart_isolator.py`. The class tracks device transition rules and restricts network disconnections to verified threats and compromised targets.
*   **Automated Docker Segmentation**: Implemented `enforcement/ml_based_segmentation.py`, which uses the Docker SDK to dynamically disconnect container network interfaces when anomaly scores exceed 0.90.
*   **API and Socket.io Backend**: Built a Flask-based API (`api/app.py`) to query the SQLite backend (`siem_database.db`) and push real-time alerts to the frontend via WebSockets.
*   **React Dashboard**: Implemented a modern web-based monitoring dashboard in Vite+React, featuring live event streams, anomaly score breakdowns, and network state tables.

## 3.2 Current Project Status
The project is currently at approximately **60% completion**. The core data collection, unsupervised training, inference, dynamic containment, and dashboard visualization layers are fully developed and integrated. The remaining work focuses on integrating Wazuh host-based active responses and conducting formal evaluation trials across varying network loads.

## 3.3 Evidence of Progress
The primary evidence of progress lies in the operational code repository located at `C:\siem-soar-platform\`. Specifically, the system's ability to run traffic sniffing, run unsupervised classification models, write anomaly records to the SQLite database, and trigger container network disconnections constitutes the core project prototype. A canonical copy of the development history, commit logs, and documentation is maintained in the project's GitHub repository: [INSERT GITHUB REPOSITORY LINK]. Visual evidence demonstrating the runtime execution of these components is described in detail in Section 6.

---

# 4. LITERATURE REVIEW PROGRESS

## 4.1 Summary of Key Literature Identified
The literature review surveyed three primary areas of research:

### 4.1.1 IoT/OT Network Segmentation Approaches
Traditional industrial control systems rely on static network segmentation strategies defined by the Purdue Reference Architecture [3]. This model partitions enterprise networks, SCADA servers, and field device controllers into logical layers separated by firewalls. Stouffer et al. [4] highlight that while firewalls are effective for static environments, they fail to scale in heterogeneous IoT settings where devices are frequently added or reassigned. Gonzalez et al. [5] propose Software-Defined Networking (SDN) to insert dynamic flow rules at the switch level. However, SDN solutions require centralized control planes and specialized hardware, which introduces safety risks and high deployment costs in legacy OT facilities. More recently, zero-trust micro-segmentation architectures have emerged as an alternative. Rose et al. [6] discuss the concept of zero-trust, where every packet flow must be authenticated and authorized. However, zero-trust requires a policy decision engine that can automatically define what constitutes "normal" communication, a problem that remains unresolved in heterogeneous networks.

### 4.1.2 Unsupervised Anomaly Detection in Network Security
Unsupervised machine learning algorithms are suited for industrial security because they build behavioral models directly from raw traffic data. The literature categorizes these algorithms into three families:
*   **Clustering-Based Methods**: K-Means [8] groups points based on Euclidean distance to centroid coordinates. However, K-Means is sensitive to initialization and assumes spherical cluster distributions.
*   **Density-Based Methods**: DBSCAN [9] identifies clusters based on spatial density, classifying isolated points in low-density regions as noise/outliers. This makes DBSCAN suitable for identifying anomalous traffic flows without specifying the cluster count in advance.
*   **Isolation-Based Methods**: Isolation Forest [10] isolates anomalies by recursively splitting features. Since anomalous points require fewer partitions to isolate, their path lengths in the trees are shorter. Isolation Forest has a low computational footprint ($O(n \log n)$ complexity), making it suitable for real-time packet stream processing.

Other density estimators, such as Local Outlier Factor (LOF) [11] and Gaussian Mixture Models (GMM), provide detailed local density ratios but require significant memory overhead during continuous training, making them less suitable as single detectors for resource-constrained systems.

### 4.1.3 Industrial Protocol Security
Industrial networks rely on legacy application layer protocols that lack security-by-design features. Modbus TCP, operating on port 502, was developed in 1979 for serial links and lacks encryption or authentication [12]. Any host on an OT network can read holding registers (Function Code 3) or write coil values (Function Codes 6/16), allowing attackers to disrupt physical processes. MQTT, used in IoT sensing layers, relies on a publish-subscribe broker architecture [14]. Without Transport Layer Security (TLS) or client certificates, attackers can intercept telemetry data or publish spoofed control commands.

## 4.2 Theoretical/Conceptual Foundation
Unsupervised learning models network traffic by mapping behavioral features to multi-dimensional coordinate spaces. The theoretical foundation of this project is that benign device communication patterns form dense, stable clusters, while attack activities create feature drift. For example, a PLC's normal state is defined by a low destination count, a single protocol (Modbus), and a constant packet rate. When an attacker compromises this PLC and executes a port scan, the device's behavioral vector drifts due to increases in `unique_destinations`, `unique_ports`, and `scan_rate`.

Rather than relying on a single algorithm, this project uses an ensemble model. Combining multiple algorithms covers a wider range of anomaly distributions. Isolation Forest quickly flags global outliers, while DBSCAN identifies local, density-based anomalies that might be missed by distance-based centroid methods.

## 4.3 Research Gap Justification
Although unsupervised intrusion detection has been studied, existing literature does not address the automated containment of anomalies in heterogeneous environments. Most existing network intrusion detection systems (NIDS) log alerts but do not interface with the network control plane to isolate threats. Those that do implement response capabilities usually apply binary disconnections to all flagged IP addresses. In industrial settings, this approach can isolate a scan target (victim PLC), causing unnecessary operational downtime. This project addresses this research gap by implementing a context-aware isolation engine that evaluates both source and destination states before taking containment actions.

**Table 1: Comparison of Related Works**

| Author / Work | Detection Method | Segmentation Method | Primary Limitation Addressed by This Project |
|---|---|---|---|
| Anthi et al. (2019) [15] | Supervised Random Forest | Manual firewall rules | Requires labeled datasets; no automated isolation. |
| Tahaei et al. (2020) [16] | Deep Autoencoder Anomaly Detection | None (detection only) | No automated response or containment capability. |
| Gonzalez et al. (2021) [5] | SDN flow analysis | SDN flow-rule insertion | Requires specialized SDN controllers and switches. |
| Zolanvari et al. (2019) [17] | Supervised SCADA ML | None (alert logging) | Requires labeled SCADA datasets; lacks multi-protocol context. |
| **This Project** | **Two-tier Unsupervised Ensemble (IF + DBSCAN)** | **Automated Docker container network disconnection via SOAR** | **Unsupervised (no labels); context-aware containment.** |

---

# 5. METHODOLOGY / SOLUTION APPROACH

## 5.1 System Development Methodology
This project uses an iterative, prototyping-based Agile methodology. Given the experimental nature of unsupervised threshold tuning, a waterfall approach would not allow for the continuous adjustments needed to refine the detection models. 

Development was divided into four main sprints:
1.  **Sprint 1: Testbed and Simulation (Weeks 1-2)**: Configure the Docker networks and verify baseline traffic.
2.  **Sprint 2: Capture and Modeling (Weeks 3-4)**: Implement the Scapy sniffing pipeline and train the unsupervised models.
3.  **Sprint 3: Response Integration (Weeks 5-6)**: Develop the SmartIsolator state machine and integrate the Docker SDK.
4.  **Sprint 4: Frontend Development (Weeks 7-8)**: Create the React dashboard and Flask-SocketIO backend API.

This iterative approach enabled early identification of issues, such as the initial isolation engine incorrectly disconnecting scan victims, which was corrected in Sprint 3.

## 5.2 Data Collection Approach
To build the behavioral models, raw network traffic was captured directly from the virtual interfaces of the Docker testbed.

Public datasets (such as ToN_IoT or CICIoT2023) were not used for training because they do not match the specific network topology, IP scheme, and protocol mix of this project's testbed. Using an external dataset would prevent the machine learning models from learning the correct baseline for the local containers. Public datasets are used only for literature context and comparison.

Traffic collection uses the following parameters:
*   **Capture Duration**: 300 seconds (5 minutes) of baseline operational traffic.
*   **Aggregation Interval**: 10-second sliding windows, producing 30 windows per device.
*   **Dataset Dimensions**: 270 rows (9 devices $\times$ 30 windows).

This small initial dataset (270 rows) is a recognized constraint of the current prototype. The mitigation plan, scheduled for the evaluation phase, involves running repeated capture sessions under different operational states to build a more robust dataset.

## 5.3 Tools, Techniques, and Technologies Selected
*   **Docker & Docker Compose**: Selected for virtualization to simulate a multi-subnet OT/IoT network on a single development machine (Intel Core i3, 8 GB RAM).
*   **Scapy**: Used for raw packet capture and parsing because of its support for industrial protocols.
*   **Scikit-Learn**: Used to implement the unsupervised models (Isolation Forest, DBSCAN, K-Means, Spectral Clustering, GMM, and RobustScaler).
*   **SQLite**: A lightweight database used to store events, alerts, and isolation logs without high memory overhead.
*   **Flask & Socket.io**: Selected for the backend API to handle REST queries and push real-time updates to the dashboard via WebSockets.
*   **React & Tailwind CSS**: Chosen to build a responsive, single-page Security Operations Center (SOC) dashboard.


# 6. DESIGN AND IMPLEMENTATION PROGRESS

## 6.1 Architecture and Design
The system topology is organized into three virtual networks representing distinct industrial zones:
*   **Operational Technology (OT) Network**: `ot-network` (`192.168.10.0/24`) hosts the high-priority industrial control components: PLC1 (`192.168.10.10`), PLC2 (`192.168.10.11`), HMI (`192.168.10.20`), and the dual-homed Engineering-WS (`192.168.10.50`).
*   **Internet of Things (IoT) Network**: `iot-network` (`192.168.20.0/24`) hosts sensing devices: Sensor-Temp (`192.168.20.10`), Sensor-Pressure (`192.168.20.11`), and the MQTT-Broker (`192.168.20.100`).
*   **Demilitarized Zone (DMZ)**: `dmz-network` (`192.168.30.0/24`) hosts perimeter devices: CCTV-Camera (`192.168.30.10`) and the Cloud-Gateway (`192.168.30.100`).

The data flow is illustrated by the architecture diagram:

[SCREENSHOT PLACEHOLDER #1: System architecture diagram — I will need to create this separately, e.g. in draw.io, showing the 9 Docker containers across 3 zones connecting to the Flask backend, SQLite database, and React dashboard]

## 6.2 Implementation Progress — Network Testbed
The containerized testbed simulates physical devices as isolated Linux processes. Network segregation is enforced through Docker bridge networks, configured with specific IP subnets. The manager stack runs three Wazuh nodes (`wazuh-indexer`, `wazuh-manager`, and `wazuh-dashboard`) for centralized monitoring.

[SCREENSHOT PLACEHOLDER #2: terminal output of `docker ps` showing all 9 containers running]

[SCREENSHOT PLACEHOLDER #3: terminal output of `docker network ls` showing the 3 isolated networks]

## 6.3 Implementation Progress — Data Capture Pipeline
The script `capture_traffic.py` sniffs the interfaces of the Docker networks using Scapy. It runs as a background service, accumulating packets into 10-second windows. For each window, it extracts 14 behavioral features per device, including packet counts, payload size statistics, destination entropy, protocol ratios (Modbus TCP, MQTT, HTTP), port scan indicators, and cross-zone access frequency.

[SCREENSHOT PLACEHOLDER #4: terminal output of running capture_traffic.py showing the live window-by-window capture log]

[SCREENSHOT PLACEHOLDER #5: clustering_dataset.csv opened in Excel/VS Code showing real captured rows]

## 6.4 Implementation Progress — Unsupervised ML Pipeline
The training pipeline in `train_models.py` normalizes raw feature windows using a `RobustScaler`. The scaled dataset is used to train five unsupervised models:
1.  **K-Means**: Groups similar communication profiles.
2.  **DBSCAN**: Identifies outliers in low-density space.
3.  **Hierarchical Clustering**: Builds a tree-like dendrogram to partition devices.
4.  **Spectral Clustering**: Evaluates affinity matrices for non-convex partitions.
5.  **Gaussian Mixture Models**: Estimates probability distributions.

The production inference model uses a two-tier ensemble. Tier 1 (Isolation Forest) acts as a fast filter ($O(n \log n)$). Tier 2 (DBSCAN) computes the Euclidean distance to core clusters for events flagged by Tier 1.

[SCREENSHOT PLACEHOLDER #6: terminal output of running train_models.py showing silhouette scores, BIC values, and the final ranked device ensemble scores table]

## 6.5 Implementation Progress — Isolation Decision Engine
The `SmartIsolator` state machine evaluates incoming ensemble scores against thresholds. The decision logic is structured around four device states:
*   `NORMAL`: Device exhibits benign communication profiles.
*   `SCANNED`: Device is a target of scanning traffic. The isolator does NOT disconnect scanned nodes.
*   `THREAT_SOURCE`: Device is the source of an attack (ensemble score $\ge 0.90$). The engine isolates the container interface.
*   `COMPROMISED`: Device received a malicious write or was accessed by a compromised node. The engine isolates it to prevent lateral movement.
*   `PROPAGATED`: A compromised device starts initiating attacks.

[SCREENSHOT PLACEHOLDER #7: terminal output of the smart_isolator.py test sequence showing scan target marked SCANNED (not isolated) vs malicious-write source/target isolated as ATTACKER/COMPROMISED]

## 6.6 Implementation Progress — Dashboard and Backend
The Flask API queries `siem_database.db` and pushes live updates to the frontend via WebSockets. The React dashboard displays the status of the network.

[SCREENSHOT PLACEHOLDER #8: Dashboard overview page showing threat gauge, stat cards, and network topology]

[SCREENSHOT PLACEHOLDER #9: Isolated Devices page showing the state legend and a table with ATTACKER/COMPROMISED/SCANNED badges]

[SCREENSHOT PLACEHOLDER #10: Anomalies Detected page showing charts and the model-score breakdown]

**Table 2: Module Completion Status**

| Module | Status | Estimated % Complete |
|---|---|---|
| Network Testbed Deployment | Completed | 100% |
| Data Capture & Feature Extraction | Completed | 100% |
| ML Clustering Models Training | Completed | 100% |
| Real-Time Inference Integration | In Progress | 50% |
| SmartIsolator Decision Logic | Completed | 100% |
| SOAR Action Execution | Completed | 100% |
| Dashboard Frontend (React) | Completed | 85% |
| Dashboard Backend API (Flask) | Completed | 90% |
| Wazuh Active Response Integration | In Progress | 20% |
| System Evaluation Trials | Planned | 0% |
| **Overall Project Completion** | **Weighted Average** | **~60%** |

---

# 7. TESTING / EVALUATION PLAN (DRAFT)

## 7.1 Proposed Testing Strategy
The testing plan is divided into three tiers:
1.  **Unit Testing**: Validating individual components. The `test_smart_isolator.py` test suite validates three core scenarios: verifying that port scan targets remain online, verifying that malicious write sources and destinations are isolated, and verifying that lateral propagation updates states to `PROPAGATED`.
2.  **Integration Testing**: Simulating a full attack workflow using `live_attack_simulator.py`. The simulation executes 75 events across 5 phases: reconnaissance, unauthorized reading, active exploitation (malicious writes), lateral movement, and data exfiltration. We will verify that the Scapy sensor captures the traffic, the inference engine flags the anomalies, the SOAR engine disconnects the containers, and the React dashboard displays the state changes.
3.  **Repeated-Trial testing**: Running the 5-phase attack simulation 5 times under identical conditions to assess the stability of the unsupervised ensemble scores and isolation times.

## 7.2 Evaluation Metrics
*   **Precision**: $TP / (TP + FP)$ (Target: $>99\%$). This is critical because false disconnections in OT environments can halt production.
*   **Recall (Sensitivity)**: $TP / (TP + FN)$ (Target: $100\%$). All malicious writes must be detected and isolated.
*   **F1-Score**: Harmonic mean of Precision and Recall.
*   **Detection Latency**: Time elapsed from raw packet capture to the SQLite database log (Target: $<100ms$).
*   **Isolation Execution Latency**: Time elapsed from the generation of an anomaly score to the Docker SDK disconnect call (Target: $<125ms$).

## 7.3 Planned Experiments
*   **Varying Attack Intensity**: We will run attack scenarios with different packet rates (10 packets/sec to 1000 packets/sec) to evaluate the model's sensitivity.
*   **Propagation Scenarios**: Evaluating the state transitions when the attacker compromises an intermediate node and uses it to scan adjacent subnets.
*   **Threshold Sensitivity Analysis**: Testing ensemble isolation thresholds from 0.70 to 0.95 in 0.05 increments to find the optimal balance between detection and false alarms.

---

# 8. CHALLENGES AND RISK MANAGEMENT

## 8.1 Issues Faced
*   **Dataset Constraints**: The initial dataset (`clustering_dataset.csv`) contains 270 rows from a single 5-minute capture session. This limited sample size makes it difficult to validate long-term baseline drift.
*   **Initial Isolation Design Errors**: The initial version of the isolation logic disconnected all IPs involved in an anomaly. During testing, this resulted in the target of a port scan (PLC1) being isolated along with the attacker, violating availability requirements.
*   **Hardware Limitations**: Running the 9 virtual devices alongside the Wazuh indexer and dashboard caused high CPU and memory utilization on the host machine (Intel Core i3, 8 GB RAM).
*   **DBSCAN Inference Limitation**: DBSCAN is a clustering algorithm and does not natively support predictions on new data points. It requires calculating distances to all core points in the trained model, which increases memory usage during continuous operation.

## 8.2 Actions Taken to Resolve Challenges
*   **State-Aware Decision Logic**: We replaced the simple rule-based isolation triggers with a state machine (`SmartIsolator`) that checks device states before taking action.
*   **Additional Capture Sessions**: We scheduled repeated capture sessions under different network states to expand the dataset.
*   **Resource Tuning**: We reduced the memory allocation of the Wazuh OpenSearch indexer to 1 GB heap size and configured rolling 10-second capture windows to decrease RAM usage.
*   **Distance-to-Core Workaround**: We implemented a custom distance-based scoring function in `real_time_inference.py` to evaluate new points against DBSCAN clusters without retraining.

## 8.3 Risk Mitigation Plan

**Table 3: Risk Matrix and Mitigation Strategies**

| Risk ID | Risk Description | Impact | Probability | Mitigation Strategy |
|---|---|---|---|---|
| **R1** | High false positive rate leads to uncompromised PLCs being disconnected. | Critical | Medium | Require a 3-window consensus (30 seconds) of anomaly scores above 0.90 before triggering isolation. |
| **R2** | Docker SDK API call fails due to engine lockups. | High | Low | Implement a local `iptables` ruleset fallback executed via container command execution. |
| **R3** | Insufficient dataset size leads to poor model generalization. | Medium | Medium | Limit evaluation claims to the testbed environment; schedule additional capture sessions. |
| **R4** | Project timeline slippage due to integration delays. | Medium | Medium | Establish a weekly integration test schedule and use generated synthetic datasets for model verification. |

---

# 9. REVISED WORK PLAN

## 9.1 Gantt Chart and Timeline
The project timeline has been updated to cover the work leading to the final submission on 9 September 2026.

**Table 4: Revised Project Timeline**

| Phase | Planned Activity | Target Completion | Status |
|---|---|---|---|
| **Phase 1** | Testbed deployment, traffic generation, and feature extraction. | 15 June 2026 | Completed |
| **Phase 2** | Model development, clustering comparison, and SmartIsolator. | 25 June 2026 | Completed |
| **Phase 3** | React Dashboard design, backend API, and Socket.io integration. | 30 June 2026 | In Progress |
| **Phase 4** | Wazuh agent active response integration and logging. | 15 July 2026 | Planned |
| **Phase 5** | End-to-end evaluation trials (5 runs) and latency profiling. | 1 August 2026 | Planned |
| **Phase 6** | System tuning, dashboard optimization, and bug fixing. | 15 August 2026 | Planned |
| **Phase 7** | Writing the final thesis and analyzing evaluation data. | 30 August 2026 | Planned |
| **Phase 8** | Final review, defense preparation, and submission. | 9 September 2026 | Planned |

## 9.2 Remaining Tasks Checklist
*   [ ] Configure Wazuh Manager active-response scripts to trigger on API alerts.
*   [ ] Run the 5-phase evaluation simulation across 5 trials.
*   [ ] Capture a baseline dataset of normal OT traffic over a 24-hour period.
*   [ ] Complete the transition animations on the React topology interface.
*   [ ] Draft the evaluation chapter of the final thesis.

## 9.3 Project Milestones
*   **Milestone 1**: Complete Wazuh manager active-response integration (Target: 15 July 2026).
*   **Milestone 2**: Complete the 5 evaluation trials and generate precision/recall charts (Target: 5 August 2026).
*   **Milestone 3**: Complete the first draft of the final thesis (Target: 25 August 2026).

---

# 10. CONCLUSION
This interim report has presented the design, implementation, and progress of an unsupervised micro-segmentation policy generation system for heterogeneous IoT/OT environments. The virtualized testbed (9 containers, 3 networks) and Scapy capture agent are operational. The trained machine learning models identify behavioral anomalies, and the SmartIsolator state machine coordinates network disconnections via the Docker SDK to isolate compromised hosts. The Flask API and Vite+React dashboard provide real-time monitoring of network states.

The project is currently at approximately 60% completion. With the core layers developed, the remaining integration and evaluation tasks are feasible within the timeline leading to the final submission on 9 September 2026.

---

# 11. REFERENCES

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

# 12. APPENDICES

## Appendix A: Project Directory Structure
Below is the directory tree showing the organization of the project files:

[SCREENSHOT PLACEHOLDER #11: full file tree of C:\siem-soar-platform\ and C:\iot-ot-demo\ from the editor]

## Appendix B: SQLite Database Schema
The database `siem_database.db` contains four tables:
*   `events`: Logs raw packet features extracted by Scapy.
*   `anomalies`: Records flagged events with anomaly scores and classification states.
*   `isolations`: Tracks containment actions, including container name and timestamp.
*   `incidents`: Contains security incident logs.

[SCREENSHOT PLACEHOLDER #12: sample rows from siem_database.db events and isolations tables, opened in DB Browser for SQLite]

## Appendix C: Project Diary Extracts
The following extracts document key meetings and decisions:

[DIARY EXTRACTS PLACEHOLDER]

---

# SCREENSHOT CHECKLIST TABLE

| # | What to Capture | Exact Command/Page | Save As Filename |
|---|---|---|---|
| #1 | System architecture diagram | draw.io or Visio diagram showing the container networks | `fig_architecture.png` |
| #2 | docker ps container status | Run `docker ps` in Windows Powershell | `docker_ps.png` |
| #3 | docker network configuration | Run `docker network ls` in Windows Powershell | `docker_networks.png` |
| #4 | capture_traffic.py live console output | Run `python ml_pipeline/capture_traffic.py` in terminal | `traffic_capture_log.png` |
| #5 | csv dataset rows | Open `C:\siem-soar-platform\dataset\clustering_dataset.csv` in VS Code | `dataset_csv.png` |
| #6 | train_models.py console logs | Run `python ml_pipeline/train_models.py` in terminal | `ml_train_console.png` |
| #7 | smart_isolator.py test outputs | Run `python enforcement/test_smart_isolator.py` in terminal | `isolator_test_console.png` |
| #8 | Dashboard Main Page | Browse to `http://localhost:5173/` dashboard view | `dashboard_react.png` |
| #9 | Isolated Devices View | Browse to `http://localhost:5173/isolated-devices` | `isolated_react.png` |
| #10| Anomalies Detected Page | Browse to `http://localhost:5173/anomalies` | `anomalies_react.png` |
| #11| Project directory tree structure | Expand folder list in VS Code editor view | `directory_tree.png` |
| #12| SQLite tables and database rows | Open DB Browser for SQLite showing tables | `sqlite_browser.png` |
